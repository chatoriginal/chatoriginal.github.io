'use strict';

/**
 * server.js — TerminalChat backend (Express + Socket.IO + Supabase).
 *
 * Security model in one paragraph: the browser is never trusted. Usernames are validated with a
 * strict allow-list and claimed server-side; the role (guest / member / admin) is set ONLY after
 * the server verifies a password or a signed token; every socket event goes through a wrapper that
 * rate-limits it and checks the caller's role; every handler validates its own payload; and
 * ownership ("can this person edit/delete that message?") is always re-checked from the database.
 */

const http = require('http');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const { Server } = require('socket.io');

const { createDatabase } = require('./database');
const { AdminAuth, loadAdminConfig } = require('./admin');
const { UserDirectory, AccountAuth } = require('./accounts');
const {
  RoomManager,
  UserError,
  GUEST_ROOM,
  isUuid,
  validateUsername,
  validateLoginName,
  validateDisplayName,
  displayKey,
  validateBio,
  validatePassword,
  validateEmoji,
  extractMentions,
  snippetOf,
  cleanMessage,
  cleanReason,
  attachmentInfo,
  validateAttachmentName,
  sniffFile,
} = require('./rooms');
const { version: APP_VERSION } = require('./package.json');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

function intEnv(name, def, min, max) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}.`);
  }
  return n;
}

const PORT = Number(process.env.PORT) || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const SERVE_FRONTEND = process.env.SERVE_FRONTEND === 'true';

const MAX_MESSAGE_LENGTH = intEnv('MAX_MESSAGE_LENGTH', 1000, 20, 2000);
const MAX_UPLOAD_MB = intEnv('MAX_UPLOAD_MB', 8, 1, 50); // Supabase free plan caps single files at 50 MB
const MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024;
const STORAGE_BUCKET = 'attachments';
const HISTORY_LIMIT = intEnv('HISTORY_LIMIT', 100, 10, 500);
// Rooms keep only this many (unpinned) messages; older ones delete themselves. Private DMs are never pruned.
const MAX_STORED_MESSAGES_PER_ROOM = intEnv('MAX_STORED_MESSAGES_PER_ROOM', 100, 20, 100000);
const MAX_CONNECTIONS_PER_IP = intEnv('MAX_CONNECTIONS_PER_IP', 10, 1, 200);
const TRUST_PROXY_HOPS = intEnv('TRUST_PROXY_HOPS', 2, 0, 5);

const NAME_GRACE_MS = 15_000; // how long a username is reserved for its owner after a disconnect
const KICK_COOLDOWN_MS = 30_000; // how long a kicked user must wait before signing in again
const MAX_PINS_PER_ROOM = 25;
const DM_PAGE = 100;

function normalizeOrigin(o) {
  return String(o).trim().replace(/\/+$/, '').toLowerCase();
}

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(normalizeOrigin)
  .filter(Boolean);

function originAllowed(origin) {
  if (!origin) return !IS_PROD; // non-browser clients; only tolerated outside production
  return ALLOWED_ORIGINS.includes(normalizeOrigin(origin));
}

function fatal(messages) {
  console.error('\nTerminalChat cannot start:\n' + messages.map((m) => `  - ${m}`).join('\n') + '\n');
  process.exit(1);
}

const adminConfig = loadAdminConfig();
const startupProblems = [...adminConfig.problems];
if (!process.env.SUPABASE_URL) startupProblems.push('SUPABASE_URL is not set.');
if (!process.env.SUPABASE_SERVICE_ROLE_KEY) startupProblems.push('SUPABASE_SERVICE_ROLE_KEY is not set.');
if (ALLOWED_ORIGINS.length === 0) {
  startupProblems.push('ALLOWED_ORIGINS is not set (comma-separated list of frontend origins, e.g. https://you.github.io).');
}
if (startupProblems.length) fatal(startupProblems);

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

const db = createDatabase({
  url: process.env.SUPABASE_URL,
  serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
  bucket: STORAGE_BUCKET,
});
const rooms = new RoomManager(db);
const adminAuth = new AdminAuth(adminConfig);
const accountAuth = new AccountAuth({ jwtSecret: adminConfig.jwtSecret });
const directory = new UserDirectory(db);
const ADMIN_NAMES = adminAuth.usernames; // one or two administrator accounts
const isAdminName = (name) => ADMIN_NAMES.some((n) => n.toLowerCase() === String(name).trim().toLowerCase());
let uploadsReady = false; // set once the storage bucket is confirmed at startup

const IP_HASH_KEY = process.env.IP_HASH_SALT || adminConfig.jwtSecret;
function hashIp(ip) {
  return crypto.createHmac('sha256', IP_HASH_KEY).update(String(ip)).digest('hex');
}

function sha256Hex(v) {
  return crypto.createHash('sha256').update(v).digest('hex');
}

function clientIp(headers, remoteAddress) {
  const xff = headers['x-forwarded-for'];
  if (TRUST_PROXY_HOPS > 0 && typeof xff === 'string' && xff) {
    const parts = xff.split(',').map((s) => s.trim()).filter(Boolean);
    // Entries are appended by each proxy, so count from the RIGHT (the left side is client-controlled).
    const idx = parts.length - TRUST_PROXY_HOPS;
    if (idx >= 0) return parts[idx];
    if (parts.length) return parts[0];
  }
  return (remoteAddress || 'unknown').replace(/^::ffff:/, '');
}

// ---------------------------------------------------------------------------
// HTTP (health check + optional static frontend for local development)
// ---------------------------------------------------------------------------

const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
  next();
});
app.use(
  cors({
    origin: (origin, cb) => cb(null, !origin || originAllowed(origin)),
    methods: ['GET', 'HEAD', 'POST'],
    allowedHeaders: ['Content-Type', 'X-Upload-Ticket'],
  })
);

app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: APP_VERSION, uptime: Math.round(process.uptime()) });
});

// Shows the IP the server sees for YOU, so you can verify TRUST_PROXY_HOPS after deploying.
app.get('/whoami', (req, res) => {
  res.json({ ip: clientIp(req.headers, req.socket.remoteAddress), trustProxyHops: TRUST_PROXY_HOPS });
});

if (SERVE_FRONTEND) {
  // Local convenience only: serves the single-file frontend (../index.html), nothing else from the repo.
  app.get('/', (req, res) => res.sendFile(path.join(__dirname, '..', 'index.html')));
} else {
  app.get('/', (req, res) => res.type('text/plain').send('TerminalChat backend is running.'));
}

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: (origin, cb) => cb(null, !origin || originAllowed(origin)),
    methods: ['GET', 'POST'],
  },
  // CORS headers do not apply to raw WebSocket upgrades, so check the Origin header explicitly.
  allowRequest: (req, cb) => {
    if (originAllowed(req.headers.origin)) return cb(null, true);
    return cb('Origin not allowed', false);
  },
  maxHttpBufferSize: 10_000,
  pingInterval: 25_000,
  pingTimeout: 20_000,
});

// ---------------------------------------------------------------------------
// Bans and mutes (persisted in Supabase, cached in memory)
// ---------------------------------------------------------------------------

/** @type {Array<{id:number, usernameLower:string|null, ipHash:string|null, reason:string, createdBy:string, createdAt:string}>} */
let bans = [];

function mapBan(r) {
  return {
    id: r.id,
    usernameLower: r.username_lower,
    ipHash: r.ip_hash,
    reason: r.reason || '',
    createdBy: r.created_by || '',
    createdAt: r.created_at,
  };
}

async function loadBans() {
  bans = (await db.listBans()).map(mapBan);
}

const isIpBanned = (ipHash) => bans.some((b) => b.ipHash && b.ipHash === ipHash);
const isNameBanned = (lower) => bans.some((b) => b.usernameLower && b.usernameLower === lower);

/** @type {Map<string, {until:number|null, reason:string}>} */
const mutes = new Map();

async function loadMutes() {
  mutes.clear();
  const now = Date.now();
  for (const m of await db.listMutes()) {
    const until = m.until ? Date.parse(m.until) : null;
    if (until && until <= now) db.removeMute(m.username_lower).catch(() => {});
    else mutes.set(m.username_lower, { until, reason: m.reason || '' });
  }
}

function muteOf(lower) {
  const m = mutes.get(lower);
  if (!m) return null;
  if (m.until && m.until <= Date.now()) {
    mutes.delete(lower);
    db.removeMute(lower).catch(() => {});
    return null;
  }
  return m;
}

function fmtDuration(ms) {
  const mins = Math.max(1, Math.ceil(ms / 60_000));
  if (mins < 60) return `${mins} minute${mins === 1 ? '' : 's'}`;
  const hrs = Math.round(mins / 60);
  if (hrs < 48) return `${hrs} hour${hrs === 1 ? '' : 's'}`;
  return `${Math.round(hrs / 24)} days`;
}

function assertNotMuted(socket) {
  const m = muteOf(socket.data.username.toLowerCase());
  if (!m) return;
  throw new UserError(m.until ? `You are muted for another ${fmtDuration(m.until - Date.now())}.` : 'You are muted.');
}

// ---------------------------------------------------------------------------
// Rate limiting helpers
// ---------------------------------------------------------------------------

/** Token bucket. Returns true if the action is allowed. */
function takeToken(bucket, capacity, refillPerSec) {
  const now = Date.now();
  bucket.tokens = Math.min(capacity, bucket.tokens + ((now - bucket.last) / 1000) * refillPerSec);
  bucket.last = now;
  if (bucket.tokens < 1) return false;
  bucket.tokens -= 1;
  return true;
}

const newBucket = (capacity) => ({ tokens: capacity, last: Date.now() });

const connectionsByIp = new Map(); // ip -> active connection count
const connectAttempts = new Map(); // ip -> { count, resetAt }
const sessionStarts = new Map(); // ip -> { count, resetAt }
const cooldowns = new Map(); // `name:<lower>` | `ip:<hash>` -> until (ms)
const uploadTickets = new Map(); // one-time upload tickets
const TICKET_TTL_MS = 120_000;

function windowCounter(map, key, max, windowMs) {
  const now = Date.now();
  let e = map.get(key);
  if (!e || e.resetAt < now) {
    e = { count: 0, resetAt: now + windowMs };
    map.set(key, e);
  }
  e.count += 1;
  return e.count <= max;
}

/** Per-person flood control: burst limit, minimum gap, duplicate detection, temporary self-mute. */
function checkFlood(socket, content) {
  const d = socket.data;
  const now = Date.now();
  if (d.mutedUntil > now) {
    throw new UserError(`You are sending messages too fast. Try again in ${Math.ceil((d.mutedUntil - now) / 1000)}s.`);
  }
  d.msgTimes = d.msgTimes.filter((t) => now - t < 6000);
  const tooFast = d.msgTimes.length >= 5 || (d.msgTimes.length && now - d.msgTimes[d.msgTimes.length - 1] < 350);
  const duplicate = d.lastContent === content && now - d.lastContentAt < 10_000;
  if (tooFast || duplicate) {
    d.strikes = (d.strikes || []).filter((t) => now - t < 60_000);
    d.strikes.push(now);
    if (d.strikes.length >= 3) {
      d.mutedUntil = now + 30_000;
      d.strikes = [];
      throw new UserError('Flood detected. You are muted for 30 seconds.');
    }
    throw new UserError(duplicate ? 'You already sent that message.' : 'Slow down — you are sending messages too fast.');
  }
  d.msgTimes.push(now);
  d.lastContent = content;
  d.lastContentAt = now;
}

// ---------------------------------------------------------------------------
// Room-wide slowmode: when many messages arrive at once the room goes into slowmode at 2 s,
// and every time people keep hammering it, the delay goes up by 1 s (max 30 s). After a quiet
// minute it switches itself off. Admins are exempt.
// ---------------------------------------------------------------------------

const SLOW_BURST = 6; // this many messages inside SLOW_WINDOW_MS starts slowmode
const SLOW_WINDOW_MS = 4000;
const SLOW_START_MS = 2000;
const SLOW_STEP_MS = 1000;
const SLOW_MAX_MS = 30_000;
const SLOW_REJECTS_TO_ESCALATE = 3; // rejected attempts inside the window that bump the delay
const SLOW_STEP_COOLDOWN_MS = 3000;
const SLOW_QUIET_RESET_MS = 60_000;

/** @type {Map<string, {delay:number, times:number[], rejects:number[], lastStep:number, lastPressure:number, lastSend:Map<string, number>}>} */
const roomStates = new Map();
const roomKey = (roomId) => `room:${roomId}`;
const userKey = (lower) => `user:${lower}`;

function roomState(roomId) {
  let st = roomStates.get(roomId);
  if (!st) {
    st = { delay: 0, times: [], rejects: [], lastStep: 0, lastPressure: 0, lastSend: new Map() };
    roomStates.set(roomId, st);
  }
  return st;
}

function announceSlowmode(roomId, st, text) {
  const ts = Date.now();
  io.to(roomKey(roomId)).emit('room:slowmode', { roomId, seconds: Math.round(st.delay / 1000) });
  io.to(roomKey(roomId)).emit('system:event', { roomId, kind: 'info', text, ts });
}

/** Call before accepting a room message. Throws UserError if the sender must wait. */
function checkSlowmode(roomId, socket) {
  const st = roomState(roomId);
  const now = Date.now();
  st.times = st.times.filter((t) => now - t < SLOW_WINDOW_MS);
  st.rejects = st.rejects.filter((t) => now - t < SLOW_WINDOW_MS);
  st.times.push(now);

  if (st.delay === 0 && st.times.length >= SLOW_BURST) {
    st.delay = SLOW_START_MS;
    st.lastStep = now;
    st.lastPressure = now;
    announceSlowmode(roomId, st, `Slowmode enabled: one message every ${st.delay / 1000}s per person, because messages were arriving too fast.`);
  }
  if (st.delay > 0 && !socket.data.isAdmin) {
    const last = st.lastSend.get(socket.data.username.toLowerCase()) || 0;
    const wait = st.delay - (now - last);
    if (wait > 0) {
      st.rejects.push(now);
      st.lastPressure = now;
      if (st.rejects.length >= SLOW_REJECTS_TO_ESCALATE && now - st.lastStep >= SLOW_STEP_COOLDOWN_MS && st.delay < SLOW_MAX_MS) {
        st.delay = Math.min(SLOW_MAX_MS, st.delay + SLOW_STEP_MS);
        st.lastStep = now;
        announceSlowmode(roomId, st, `Slowmode increased to ${st.delay / 1000}s.`);
      }
      throw new UserError(`Slowmode is on: wait ${Math.ceil(wait / 1000)}s before sending another message.`);
    }
  }
}

function noteSent(roomId, socket) {
  roomState(roomId).lastSend.set(socket.data.username.toLowerCase(), Date.now());
}

// ---------------------------------------------------------------------------
// Typing indicators
// ---------------------------------------------------------------------------

const TYPING_TTL_MS = 5000;
/** @type {Map<string, Map<string, {name:string, exp:number}>>} roomId -> username -> state */
const typingRooms = new Map();

function broadcastTyping(roomId) {
  const m = typingRooms.get(roomId);
  const now = Date.now();
  const names = m ? [...m.values()].filter((t) => t.exp > now).map((t) => t.name) : [];
  io.to(roomKey(roomId)).emit('typing:update', { scope: 'room', roomId, count: names.length, names: names.slice(0, 3) });
}

function setTyping(roomId, socket) {
  let m = typingRooms.get(roomId);
  if (!m) {
    m = new Map();
    typingRooms.set(roomId, m);
  }
  const lower = socket.data.username.toLowerCase();
  const now = Date.now();
  const existing = m.get(lower);
  const changed = !existing || existing.exp <= now || existing.name !== socket.data.displayName;
  m.set(lower, { name: socket.data.displayName, exp: now + TYPING_TTL_MS });
  if (changed) broadcastTyping(roomId);
}

function clearTyping(roomId, lower) {
  const m = typingRooms.get(roomId);
  if (m && m.delete(lower)) {
    if (m.size === 0) typingRooms.delete(roomId);
    broadcastTyping(roomId);
  }
}

setInterval(() => {
  const now = Date.now();
  for (const [roomId, m] of typingRooms) {
    let removed = false;
    for (const [k, t] of m) {
      if (t.exp <= now) {
        m.delete(k);
        removed = true;
      }
    }
    if (m.size === 0) typingRooms.delete(roomId);
    if (removed) broadcastTyping(roomId);
  }
  for (const [roomId, st] of roomStates) {
    if (st.delay > 0 && now - st.lastPressure > SLOW_QUIET_RESET_MS) {
      st.delay = 0;
      st.times = [];
      st.rejects = [];
      if (rooms.get(roomId)) announceSlowmode(roomId, st, 'Slowmode is off.');
    }
  }
  for (const m of [connectAttempts, sessionStarts]) for (const [k, v] of m) if (v.resetAt < now) m.delete(k);
  for (const [k, until] of cooldowns) if (until < now) cooldowns.delete(k);
  for (const [k, t] of uploadTickets) if (t.exp < now) uploadTickets.delete(k);
}, 1000).unref();

// ---------------------------------------------------------------------------
// Sessions (username ownership)
// ---------------------------------------------------------------------------

/**
 * usernameLower -> { username, displayLower, role, socketId|null, tokenHash, releaseTimer }
 * A GUEST name belongs to whoever holds its resume token; after a disconnect it stays reserved for
 * NAME_GRACE_MS so only the same client can reclaim it. Members and admins prove ownership with a
 * password/token, so signing in again simply replaces their older connection.
 */
const sessions = new Map();

function onlineCount() {
  let n = 0;
  for (const s of sessions.values()) if (s.socketId) n += 1;
  return n;
}

const canEnterRoom = (socket, room) => socket.data.role !== 'guest' || room.name === GUEST_ROOM;
const roomsFor = (socket) => rooms.list({ guest: socket.data.role === 'guest' });

let broadcastTimer = null;
function scheduleBroadcastRooms() {
  if (broadcastTimer) return;
  broadcastTimer = setTimeout(() => {
    broadcastTimer = null;
    const online = onlineCount();
    io.to('members').emit('rooms:list', { rooms: rooms.list(), online });
    io.to('guests').emit('rooms:list', { rooms: rooms.list({ guest: true }), online });
  }, 200);
}

function leaveRoom(socket) {
  const roomId = socket.data.roomId;
  if (!roomId) return;
  socket.data.roomId = null;
  rooms.leave(roomId, socket.id);
  socket.leave(roomKey(roomId));
  if (socket.data.username) clearTyping(roomId, socket.data.username.toLowerCase());
  if (rooms.get(roomId) && socket.data.username) {
    io.to(roomKey(roomId)).emit('system:event', {
      roomId,
      kind: 'leave',
      text: `${socket.data.displayName} left the room`,
      ts: Date.now(),
    });
    io.to(roomKey(roomId)).emit('room:users', { roomId, users: rooms.users(roomId) });
  }
  scheduleBroadcastRooms();
}

function endSession(socket, { immediate }) {
  const username = socket.data.username;
  if (!username) return;
  leaveRoom(socket);
  const key = username.toLowerCase();
  const s = sessions.get(key);
  if (s && s.socketId === socket.id) {
    if (immediate || s.role !== 'guest') {
      clearTimeout(s.releaseTimer);
      sessions.delete(key);
    } else {
      s.socketId = null;
      s.releaseTimer = setTimeout(() => {
        const cur = sessions.get(key);
        if (cur && cur.socketId === null) sessions.delete(key);
      }, NAME_GRACE_MS);
      if (s.releaseTimer.unref) s.releaseTimer.unref();
    }
  }
  for (const ch of ['members', 'guests', userKey(key)]) socket.leave(ch);
  Object.assign(socket.data, {
    username: null, displayName: null, role: null, isAdmin: false, userId: null, bio: '',
    adminExpiresAt: 0, adminJti: null,
  });
  scheduleBroadcastRooms();
}

/** Claims `username` for this socket and returns a fresh resume token. Throws UserError if a guest name is taken. */
function claimName(socket, user, resumeToken) {
  const key = user.username.toLowerCase();
  const existing = sessions.get(key);
  const authenticated = user.role !== 'guest';
  if (existing) {
    const tokenMatches =
      typeof resumeToken === 'string' &&
      resumeToken.length <= 128 &&
      crypto.timingSafeEqual(Buffer.from(sha256Hex(resumeToken)), Buffer.from(existing.tokenHash));
    if (!authenticated && !tokenMatches) throw new UserError('That username is currently in use. Please choose another.');
    if (authenticated && existing.role === 'guest' && !tokenMatches && existing.socketId) {
      throw new UserError('That username is in use right now. Please try again in a moment.');
    }
    clearTimeout(existing.releaseTimer);
    if (existing.socketId && existing.socketId !== socket.id) {
      const old = io.sockets.sockets.get(existing.socketId);
      if (old) {
        old.emit('session:replaced', { message: 'You signed in from another tab or device.' });
        endSession(old, { immediate: true });
        old.disconnect(true);
      }
    }
  }
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(key, {
    username: user.username,
    displayLower: displayKey(user.displayName),
    role: user.role,
    socketId: socket.id,
    tokenHash: sha256Hex(token),
    releaseTimer: null,
  });
  return token;
}

/** user = { username, displayName, role: 'guest'|'member'|'admin', userId?, bio?, adminExpiresAt?, adminJti? } */
function startSession(socket, user, resumeToken) {
  const token = claimName(socket, user, resumeToken);
  Object.assign(socket.data, {
    username: user.username,
    displayName: user.displayName,
    role: user.role,
    isAdmin: user.role === 'admin',
    userId: user.userId || null,
    bio: user.bio || '',
    adminExpiresAt: user.adminExpiresAt || 0,
    adminJti: user.adminJti || null,
  });
  socket.join(user.role === 'guest' ? 'guests' : 'members');
  socket.join(userKey(user.username.toLowerCase()));
  scheduleBroadcastRooms();
  return token;
}

function nameCase(lower) {
  const u = directory.cache.get(lower);
  if (u) return u.username;
  return ADMIN_NAMES.find((n) => n.toLowerCase() === lower) || lower;
}

async function listDmThreads(username) {
  const me = username.toLowerCase();
  const threads = await db.listThreads(me);
  const partners = threads.map((t) => (t.user_a === me ? t.user_b : t.user_a));
  await directory.load(partners);
  return threads
    .map((t) => {
      const partner = t.user_a === me ? t.user_b : t.user_a;
      const read = t.user_a === me ? t.read_a : t.read_b;
      const unread = !!t.last_sender && t.last_sender !== me && (!read || Date.parse(t.updated_at) > Date.parse(read));
      return { with: nameCase(partner), displayName: directory.display(nameCase(partner)), updatedAt: t.updated_at, unread };
    })
    .sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt));
}

async function buildSession(socket, resumeToken, extra = {}) {
  const d = socket.data;
  const payload = {
    ok: true,
    username: d.username,
    displayName: d.displayName,
    bio: d.bio,
    role: d.role,
    isAdmin: d.role === 'admin',
    resumeToken,
    rooms: roomsFor(socket),
    online: onlineCount(),
    maxMessageLength: MAX_MESSAGE_LENGTH,
    maxUploadBytes: uploadsReady ? MAX_UPLOAD_BYTES : 0,
    dms: [],
    ...extra,
  };
  if (d.role !== 'guest') {
    try {
      payload.dms = await listDmThreads(d.username);
    } catch (err) {
      console.error('[dm] could not list threads:', err.message);
    }
  }
  return payload;
}

// ---------------------------------------------------------------------------
// Messages: hydration (display names, replies, attachments) and delivery
// ---------------------------------------------------------------------------

function messageScope(row) {
  return row.room_id ? { scope: 'room', roomId: row.room_id } : { scope: 'dm', dmKey: row.dm_key };
}

function toClientMessage(row, lookup) {
  const sys = row.kind === 'system';
  const msg = {
    id: row.id,
    ...messageScope(row),
    kind: sys ? 'system' : 'user',
    username: row.username,
    displayName: sys ? 'System Message' : directory.display(row.username),
    isAdmin: !!row.is_admin || isAdminName(row.username),
    content: row.content,
    createdAt: row.created_at,
    edited: !!row.edited,
    pinned: !!row.pinned,
    reactions: row.reactions || {},
  };
  if (row.reply_to) {
    const orig = lookup.get(row.reply_to);
    msg.replyTo = orig
      ? {
          id: orig.id,
          username: orig.username,
          displayName: orig.kind === 'system' ? 'System Message' : directory.display(orig.username),
          snippet: snippetOf(orig.content, orig.attachment_name),
        }
      : { id: row.reply_to, deleted: true };
  }
  if (row.attachment_path) {
    const info = attachmentInfo(row.attachment_path.split('.').pop());
    const kind = info ? info.kind : 'file';
    msg.attachment = {
      kind,
      name: row.attachment_name || 'file',
      size: row.attachment_size || 0,
      // Non-images are served with a download header so the browser never renders them.
      url: db.publicUrl(row.attachment_path, kind === 'image' ? null : row.attachment_name || 'file'),
    };
  }
  return msg;
}

async function hydrate(rows) {
  if (!rows.length) return [];
  const lookup = new Map(rows.map((r) => [r.id, r]));
  const need = [...new Set(rows.map((r) => r.reply_to).filter((id) => id && !lookup.has(id)))];
  if (need.length) for (const r of await db.getMessagesByIds(need)) lookup.set(r.id, r);
  const names = new Set(rows.map((r) => r.username.toLowerCase()));
  for (const r of rows) {
    const o = r.reply_to && lookup.get(r.reply_to);
    if (o) names.add(o.username.toLowerCase());
  }
  await directory.load([...names]);
  return rows.map((r) => toClientMessage(r, lookup));
}

const dmKeyOf = (a, b) => {
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  return x < y ? `${x}|${y}` : `${y}|${x}`;
};

/** Sends an event to everyone who may see a room or DM row. */
function emitToScope(row, event, payload) {
  if (row.room_id) io.to(roomKey(row.room_id)).emit(event, payload);
  else {
    const [a, b] = row.dm_key.split('|');
    io.to(userKey(a)).to(userKey(b)).emit(event, payload);
  }
}

/** Finds an online session by username, or by a one-word display name. */
function findOnline(token) {
  const direct = sessions.get(token);
  if (direct && direct.socketId) return direct;
  for (const s of sessions.values()) if (s.socketId && s.displayLower === token) return s;
  return null;
}

// ---------------------------------------------------------------------------
// Web Push: real OS notifications (Windows / macOS / Android / iOS home-screen app), delivered even
// when the tab is in the background or closed. Keys are generated once and kept in Supabase.
// ---------------------------------------------------------------------------

let webpush = null;
let vapidPublic = '';
// Only real browser push services are accepted as destinations (stops the server being aimed at other URLs).
const PUSH_HOSTS = ['googleapis.com', 'push.services.mozilla.com', 'push.apple.com', 'notify.windows.com'];
const PUSH_KINDS = new Set(['dm', 'mention', 'reply']);

function validPushEndpoint(raw) {
  if (typeof raw !== 'string' || raw.length > 600) return false;
  let u;
  try { u = new URL(raw); } catch { return false; }
  if (u.protocol !== 'https:' || u.username || u.password || u.port) return false;
  return PUSH_HOSTS.some((h) => u.hostname === h || u.hostname.endsWith('.' + h));
}

async function initPush() {
  try {
    webpush = require('web-push');
  } catch {
    console.warn('[push] the "web-push" package is not installed; push notifications are OFF.');
    return;
  }
  let pub = process.env.VAPID_PUBLIC_KEY;
  let priv = process.env.VAPID_PRIVATE_KEY;
  if (!pub || !priv) {
    pub = await db.getSetting('vapid_public');
    priv = await db.getSetting('vapid_private');
    if (!pub || !priv) {
      const k = webpush.generateVAPIDKeys();
      pub = k.publicKey;
      priv = k.privateKey;
      await db.setSetting('vapid_public', pub);
      await db.setSetting('vapid_private', priv);
      console.log('[push] generated new push keys');
    }
  }
  const subject = ALLOWED_ORIGINS.find((o) => o.startsWith('https://')) || 'mailto:admin@example.com';
  webpush.setVapidDetails(subject, pub, priv);
  vapidPublic = pub;
}

function pushPayload(p) {
  const who = p.from || 'Someone';
  const title = p.kind === 'dm' ? `${who} sent you a message`
    : p.kind === 'mention' ? `${who} mentioned you in #${p.roomName || 'chat'}`
    : `${who} replied to you in #${p.roomName || 'chat'}`;
  return { title, body: p.snippet || '', tag: `tc-${p.messageId}`, scope: p.scope, roomId: p.roomId || null, from: p.fromUsername || null };
}

async function sendPush(lower, payload) {
  if (!webpush) return;
  let subs;
  try { subs = await db.listPushSubs(lower); } catch (err) { console.error('[push]', err.message); return; }
  if (!subs.length) return;
  const body = JSON.stringify(pushPayload(payload));
  for (const sub of subs) {
    webpush
      .sendNotification({ endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } }, body, { TTL: 3600, urgency: 'high' })
      .catch((err) => {
        if (err && (err.statusCode === 404 || err.statusCode === 410)) db.removePushSub(sub.endpoint).catch(() => {});
        else console.error('[push] send failed:', err && (err.statusCode || err.message));
      });
  }
}

function notify(lower, payload) {
  io.to(userKey(lower)).emit('notify', { ts: Date.now(), ...payload });
  if (PUSH_KINDS.has(payload.kind)) sendPush(lower, payload);
}

/** Is this username a real account (member or admin)? Used so offline people still get push for @mentions. */
async function isAccount(lower) {
  if (isAdminName(lower)) return true;
  try { return !!(await directory.get(lower)); } catch { return false; }
}

async function deliverMessage(row, sender) {
  const [msg] = await hydrate([row]);
  emitToScope(row, 'message:new', msg);
  const base = {
    scope: msg.scope,
    roomId: msg.roomId,
    messageId: msg.id,
    from: msg.displayName,
    fromUsername: msg.username,
    snippet: snippetOf(msg.content, row.attachment_name, 100),
  };
  const senderLower = sender.data.username.toLowerCase();
  const told = new Set([senderLower]);

  if (row.dm_key) {
    const other = row.dm_key.split('|').find((k) => k !== senderLower) || senderLower;
    if (other !== senderLower) notify(other, { ...base, kind: 'dm' });
    return msg;
  }
  const room = rooms.get(row.room_id);
  base.roomName = room ? room.name : '';

  // @mentions
  for (const token of extractMentions(row.content)) {
    const target = findOnline(token);
    let lower;
    if (target) {
      lower = target.username.toLowerCase();
      if (target.role === 'guest' && (!room || room.name !== GUEST_ROOM)) continue;
    } else {
      lower = token.toLowerCase();
      if (!(await isAccount(lower))) continue; // offline members still get a push notification
    }
    if (told.has(lower)) continue;
    told.add(lower);
    notify(lower, { ...base, kind: 'mention' });
  }
  // replies
  if (msg.replyTo && !msg.replyTo.deleted) {
    const lower = msg.replyTo.username.toLowerCase();
    const target = sessions.get(lower);
    const reachable = target && target.socketId ? !(target.role === 'guest' && (!room || room.name !== GUEST_ROOM)) : await isAccount(lower);
    if (!told.has(lower) && reachable) {
      told.add(lower);
      notify(lower, { ...base, kind: 'reply' });
    }
  }
  return msg;
}

// Pruning: rooms keep only their newest MAX_STORED_MESSAGES_PER_ROOM unpinned messages.
const pruning = new Map(); // roomId -> 'running' | 'dirty'
function schedulePrune(roomId) {
  if (pruning.has(roomId)) {
    pruning.set(roomId, 'dirty');
    return;
  }
  (async () => {
    try {
      do {
        pruning.set(roomId, 'running');
        const cutoff = await db.pruneRoom(roomId, MAX_STORED_MESSAGES_PER_ROOM);
        if (cutoff) io.to(roomKey(roomId)).emit('room:pruned', { roomId, beforeId: cutoff });
      } while (pruning.get(roomId) === 'dirty');
    } catch (err) {
      console.error('[prune]', err.message);
    } finally {
      pruning.delete(roomId);
    }
  })();
}

async function resolveReply(replyTo, { roomId, dmKey }) {
  if (replyTo === undefined || replyTo === null) return null;
  if (!Number.isSafeInteger(replyTo) || replyTo <= 0) throw new UserError('Invalid reply.');
  const row = await db.getMessage(replyTo);
  const ok = row && (roomId ? row.room_id === roomId : row.dm_key === dmKey);
  if (!ok) throw new UserError('The message you replied to no longer exists.');
  return row;
}

function findSocketByUsername(username) {
  if (typeof username !== 'string') return null;
  const s = sessions.get(username.trim().toLowerCase());
  if (!s || !s.socketId) return null;
  return io.sockets.sockets.get(s.socketId) || null;
}

/** Serialises async work per key (so two people reacting at once cannot overwrite each other). */
const locks = new Map();
function serialize(key, fn) {
  const prev = locks.get(key) || Promise.resolve();
  const run = prev.then(fn);
  const tail = run.catch(() => {});
  locks.set(key, tail);
  tail.then(() => {
    if (locks.get(key) === tail) locks.delete(key);
  });
  return run;
}

// ---------------------------------------------------------------------------
// Event plumbing
// ---------------------------------------------------------------------------

function reqObject(payload) {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new UserError('Invalid request.');
  }
  return payload;
}

/**
 * Registers a socket event handler with: per-socket rate limiting, ack safety,
 * authentication level checks ('none' | 'user' = any signed-in person incl. guests |
 * 'member' = account holders and admins | 'admin') and error handling.
 * Nothing the client sends is trusted — handlers validate their own payloads.
 */
function on(socket, event, auth, handler) {
  socket.on(event, async (payload, ack) => {
    if (typeof payload === 'function') {
      ack = payload;
      payload = undefined;
    }
    const reply = typeof ack === 'function' ? (r) => { try { ack(r); } catch { /* ignore */ } } : () => {};
    try {
      if (!takeToken(socket.data.eventBucket, 30, 5)) {
        socket.data.eventViolations += 1;
        if (socket.data.eventViolations > 60) socket.disconnect(true);
        return reply({ ok: false, error: 'Too many requests. Please slow down.' });
      }
      if (auth !== 'none' && !socket.data.username) return reply({ ok: false, error: 'You are not signed in.' });
      if (auth === 'member' && socket.data.role === 'guest') {
        return reply({ ok: false, error: 'Guests cannot do that. Create a free account to unlock it.' });
      }
      if (auth === 'admin') {
        if (!socket.data.isAdmin || socket.data.adminExpiresAt < Date.now()) {
          return reply({ ok: false, error: 'Administrator access required.' });
        }
      }
      const result = await handler(payload, socket);
      reply(result === undefined ? { ok: true } : result);
    } catch (err) {
      if (err instanceof UserError) return reply({ ok: false, error: err.message });
      console.error(`[error] event "${event}":`, err);
      reply({ ok: false, error: 'Something went wrong on the server.' });
    }
  });
}

/** Checks done before ANY message is accepted (room or DM). */
function preSend(socket, content) {
  assertNotMuted(socket);
  checkFlood(socket, content);
}

const strictName = (v) => {
  if (typeof v !== 'string' || v.length > 64 || !/^[A-Za-z][A-Za-z0-9_-]{2,19}$/.test(v)) {
    throw new UserError('Invalid username.');
  }
  return v;
};

function assertNotBanned(socket, lower) {
  if (socket.data.ipBanned || isNameBanned(lower)) throw new UserError('You are banned from this server.');
  const until = Math.max(cooldowns.get(`name:${lower}`) || 0, cooldowns.get(`ip:${socket.data.ipHash}`) || 0);
  if (until > Date.now()) {
    throw new UserError(`You were removed by a moderator. Try again in ${Math.ceil((until - Date.now()) / 1000)}s.`);
  }
}

// ---------------------------------------------------------------------------
// File uploads
//
// Flow: (1) the client asks for a one-time ticket over its authenticated socket
// ("upload:ticket", which validates the file name, size, caption and destination);
// (2) it POSTs the raw file bytes to /upload with that ticket;
// (3) the server re-checks everything, stores the file in Supabase Storage,
// creates the chat message itself and broadcasts it.
// The browser never gets storage credentials and cannot choose the stored path or type.
// ---------------------------------------------------------------------------

function uploadPrecheck(req, res, next) {
  const origin = req.headers.origin;
  if (origin && !originAllowed(origin)) return res.status(403).json({ ok: false, error: 'Origin not allowed.' });
  const key = req.get('x-upload-ticket');
  const ticket = typeof key === 'string' ? uploadTickets.get(key) : undefined;
  if (!ticket || ticket.exp < Date.now()) {
    return res.status(401).json({ ok: false, error: 'Upload ticket is invalid or expired. Please try again.' });
  }
  uploadTickets.delete(key); // single use
  const length = Number(req.headers['content-length']);
  if (!Number.isSafeInteger(length) || length !== ticket.size) {
    return res.status(400).json({ ok: false, error: 'The file size did not match.' });
  }
  req.ticket = ticket;
  return next();
}

app.post(
  '/upload',
  uploadPrecheck,
  express.raw({ type: () => true, limit: MAX_UPLOAD_BYTES }),
  async (req, res) => {
    const t = req.ticket;
    try {
      const sock = io.sockets.sockets.get(t.socketId);
      const stillThere =
        sock && sock.data.username === t.username && (t.dmKey || (sock.data.roomId === t.roomId && rooms.get(t.roomId)));
      if (!stillThere) return res.status(409).json({ ok: false, error: 'You left before the upload finished.' });
      try {
        assertNotMuted(sock);
      } catch (e) {
        return res.status(403).json({ ok: false, error: e.message });
      }
      const body = req.body;
      if (!Buffer.isBuffer(body) || body.length !== t.size) {
        return res.status(400).json({ ok: false, error: 'The upload was incomplete.' });
      }
      if (!sniffFile(body, t.file.ext)) {
        return res.status(400).json({ ok: false, error: `That does not look like a real .${t.file.ext} file.` });
      }
      const filePath = `${t.dmKey ? 'dm' : t.roomId}/${crypto.randomUUID()}.${t.file.ext}`;
      await db.uploadFile(filePath, body, t.file.mime);
      let row;
      try {
        row = await db.insertMessage({
          roomId: t.roomId,
          dmKey: t.dmKey,
          username: sock.data.username,
          isAdmin: sock.data.isAdmin,
          content: t.caption,
          replyTo: t.replyTo,
          attachment: { path: filePath, name: t.file.name, size: t.size },
        });
      } catch (err) {
        await db.removeFiles([filePath]);
        if (err.code === '23503') return res.status(409).json({ ok: false, error: 'That room no longer exists.' });
        throw err;
      }
      if (t.dmKey) {
        const [a, b] = t.dmKey.split('|');
        await db.touchThread(a, b, sock.data.username.toLowerCase());
      } else {
        noteSent(t.roomId, sock);
      }
      await deliverMessage(row, sock);
      if (t.roomId) schedulePrune(t.roomId);
      return res.json({ ok: true });
    } catch (err) {
      console.error('[upload]', err.message);
      return res.status(500).json({ ok: false, error: 'The upload failed on the server.' });
    }
  }
);

// Last-resort error handler for the routes above (e.g. body larger than the limit).
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ ok: false, error: `Files can be at most ${MAX_UPLOAD_MB} MB.` });
  }
  console.error('[http]', err && err.message);
  return res.status(500).json({ ok: false, error: 'Server error.' });
});

// ---------------------------------------------------------------------------
// Admin commands:  .mute .unmute .ban .unban .purge   and   /announce
// Only administrators can run them. Anything that is not a recognised command — including a
// regular person typing ".ban bob" — is sent as an ordinary chat message, with no error.
// ---------------------------------------------------------------------------

const COMMANDS = {
  '.': new Set(['mute', 'unmute', 'ban', 'unban', 'purge']),
  '/': new Set(['announce']),
};
const COMMAND_RE = /^([./])([A-Za-z]{2,12})(?:\s+([\s\S]*))?$/;

function removeUser(target, { reason, ban }) {
  target.data.lastName = target.data.username;
  target.emit(ban ? 'banned' : 'kicked', { reason: reason || '' });
  endSession(target, { immediate: true });
  cooldowns.set(`name:${(target.data.lastName || '').toLowerCase()}`, Date.now() + KICK_COOLDOWN_MS);
  cooldowns.set(`ip:${target.data.ipHash}`, Date.now() + KICK_COOLDOWN_MS);
  target.disconnect(true);
}

async function banUser(admin, usernameRaw, { reason, banIp }) {
  const username = strictName(usernameRaw);
  const lower = username.toLowerCase();
  if (isAdminName(lower)) throw new UserError('You cannot ban an administrator.');
  if (isNameBanned(lower)) throw new UserError('That username is already banned.');
  const target = findSocketByUsername(username);
  let ipHash = null;
  if (banIp === true && target) {
    if (target.data.ipHash === admin.data.ipHash) {
      throw new UserError('That user shares your IP address — banning it would lock you out. Ban the username only.');
    }
    ipHash = target.data.ipHash;
  }
  const row = await db.addBan({ usernameLower: lower, ipHash, reason: cleanReason(reason), createdBy: admin.data.username });
  bans.unshift(mapBan(row));
  if (target) removeUser(target, { reason: cleanReason(reason), ban: true });
  console.log(`[admin] banned a user (ip ban: ${!!ipHash})`);
}

/** Returns null when `text` is not a command this admin can run; otherwise { ok, command, info }. */
async function runCommand(admin, text) {
  const m = COMMAND_RE.exec(text.trim());
  if (!m) return null;
  const prefix = m[1];
  const name = m[2].toLowerCase();
  if (!COMMANDS[prefix].has(name)) return null;
  const args = (m[3] || '').trim();
  const done = (info) => ({ ok: true, command: true, info });

  if (prefix === '/' && name === 'announce') {
    const message = cleanMessage(args, MAX_MESSAGE_LENGTH, { allowEmpty: true });
    if (!message) throw new UserError('Usage: /announce <message>');
    const roomIds = [...rooms.rooms.keys()];
    const rows = await db.insertSystemMessages(roomIds, message);
    for (const row of rows) {
      const [msg] = await hydrate([row]);
      io.to(roomKey(row.room_id)).emit('message:new', msg);
      schedulePrune(row.room_id);
    }
    io.emit('notify', { kind: 'announce', text: message, ts: Date.now() });
    console.log('[admin] announcement');
    return done(`Announcement sent to ${roomIds.length} room${roomIds.length === 1 ? '' : 's'}.`);
  }

  const [first, ...rest] = args.split(/\s+/).filter(Boolean);
  const usage = {
    mute: 'Usage: .mute <username> [minutes]',
    unmute: 'Usage: .unmute <username>',
    ban: 'Usage: .ban <username> [reason]',
    unban: 'Usage: .unban <username>',
    purge: 'Usage: .purge <amount 1-100>',
  };

  if (name === 'purge') {
    const n = Number(first);
    if (!first || !Number.isInteger(n) || n < 1 || n > 100 || rest.length) throw new UserError(usage.purge);
    const roomId = admin.data.roomId;
    if (!roomId || !rooms.get(roomId)) throw new UserError('Join a room first — .purge works on the room you are in.');
    const ids = await db.purgeRoom(roomId, n);
    if (ids.length) io.to(roomKey(roomId)).emit('messages:deleted', { roomId, ids });
    console.log(`[admin] purged ${ids.length} messages`);
    return done(`Purged ${ids.length} message${ids.length === 1 ? '' : 's'}.`);
  }

  if (!first || !/^[A-Za-z][A-Za-z0-9_-]{2,19}$/.test(first)) throw new UserError(usage[name]);
  const lower = first.toLowerCase();

  if (name === 'mute') {
    if (isAdminName(lower)) throw new UserError('You cannot mute an administrator.');
    let minutes = 10;
    if (rest.length) {
      minutes = Number(rest[0]);
      if (rest.length > 1 || !Number.isInteger(minutes) || minutes < 1 || minutes > 10080) throw new UserError(usage.mute);
    }
    const until = Date.now() + minutes * 60_000;
    await db.setMute({ usernameLower: lower, until, reason: '', createdBy: admin.data.username });
    mutes.set(lower, { until, reason: '' });
    notify(lower, { kind: 'muted', text: `A moderator muted you for ${fmtDuration(minutes * 60_000)}.` });
    return done(`Muted ${first} for ${fmtDuration(minutes * 60_000)}.`);
  }
  if (name === 'unmute') {
    if (!mutes.has(lower)) throw new UserError(`${first} is not muted.`);
    await db.removeMute(lower);
    mutes.delete(lower);
    notify(lower, { kind: 'muted', text: 'You were unmuted.' });
    return done(`Unmuted ${first}.`);
  }
  if (name === 'ban') {
    await banUser(admin, first, { reason: rest.join(' '), banIp: false });
    return done(`Banned ${first}.`);
  }
  // unban
  const removed = await db.removeBansByUsername(lower);
  if (!removed) throw new UserError(`${first} is not banned.`);
  bans = bans.filter((b) => b.usernameLower !== lower);
  return done(`Unbanned ${first}.`);
}

// ---------------------------------------------------------------------------
// Connection handling
// ---------------------------------------------------------------------------

io.use((socket, next) => {
  const ip = clientIp(socket.handshake.headers, socket.handshake.address);
  if (!windowCounter(connectAttempts, ip, 60, 60_000)) return next(new Error('Too many connection attempts. Wait a minute.'));
  const active = connectionsByIp.get(ip) || 0;
  if (active >= MAX_CONNECTIONS_PER_IP) return next(new Error('Too many connections from your network.'));
  connectionsByIp.set(ip, active + 1);
  socket.data.ip = ip;
  socket.data.ipCounted = true;
  socket.data.ipHash = hashIp(ip);
  // Banned IPs may still connect (so an admin who locked themselves out can log in),
  // but cannot start an ordinary session.
  socket.data.ipBanned = isIpBanned(socket.data.ipHash);
  next();
});

io.on('connection', (socket) => {
  Object.assign(socket.data, {
    username: null,
    displayName: null,
    role: null,
    isAdmin: false,
    userId: null,
    bio: '',
    adminExpiresAt: 0,
    adminJti: null,
    roomId: null,
    eventBucket: newBucket(30),
    eventViolations: 0,
    msgTimes: [],
    lastContent: '',
    lastContentAt: 0,
    mutedUntil: 0,
    strikes: [],
    uploadTimes: [],
    uploadTicket: null,
  });

  socket.on('disconnect', () => {
    if (socket.data.ipCounted) {
      const n = (connectionsByIp.get(socket.data.ip) || 1) - 1;
      if (n <= 0) connectionsByIp.delete(socket.data.ip);
      else connectionsByIp.set(socket.data.ip, n);
    }
    if (socket.data.uploadTicket) uploadTickets.delete(socket.data.uploadTicket);
    endSession(socket, { immediate: false });
  });

  const throttleStarts = (s) => {
    if (!windowCounter(sessionStarts, s.data.ip, 20, 60_000)) {
      throw new UserError('Too many sign-in attempts. Please wait a minute.');
    }
  };

  // ===== guests: any free username, only #general, no DMs =====

  on(socket, 'guest:start', 'none', async (payload, s) => {
    const { username: rawName, resumeToken } = reqObject(payload);
    if (s.data.username) throw new UserError('You are already signed in.');
    throttleStarts(s);
    const username = validateUsername(rawName, ADMIN_NAMES);
    const lower = username.toLowerCase();
    assertNotBanned(s, lower);
    // A guest may not borrow the name of a registered member (username OR display name).
    if (await db.nameTaken(lower, lower)) {
      throw new UserError('That name belongs to a registered account. Please choose another, or log in.');
    }
    const token = startSession(s, { username, displayName: username, role: 'guest' }, resumeToken);
    return buildSession(s, token);
  });

  // ===== accounts =====

  on(socket, 'auth:signup', 'none', async (payload, s) => {
    const { username: rawName, displayName: rawDisplay, password } = reqObject(payload);
    if (s.data.username) throw new UserError('You are already signed in.');
    throttleStarts(s);
    if (!accountAuth.allowSignup(s.data.ip)) throw new UserError('Too many accounts were created from your network. Please try again later.');
    const username = validateUsername(rawName, ADMIN_NAMES);
    const displayName = validateDisplayName(rawDisplay, ADMIN_NAMES);
    validatePassword(password, username);
    const lower = username.toLowerCase();
    const dkey = displayKey(displayName);
    assertNotBanned(s, lower);
    const active = sessions.get(lower) || sessions.get(dkey);
    if (active && active.socketId) throw new UserError('That name is in use right now. Please choose another.');
    if (await db.nameTaken(lower, dkey)) throw new UserError('That username or display name is already taken.');
    const passwordHash = await accountAuth.hash(password);
    let row;
    try {
      row = await db.createUser({ username, displayName, displayLower: dkey, passwordHash });
    } catch (err) {
      if (err.code === '23505') throw new UserError('That username or display name is already taken.');
      throw err;
    }
    const user = directory.remember(row);
    const token = startSession(s, { username: user.username, displayName: user.displayName, role: 'member', userId: user.id, bio: user.bio }, null);
    console.log('[accounts] new account');
    return buildSession(s, token, { authToken: accountAuth.issueToken(user, passwordHash) });
  });

  on(socket, 'auth:login', 'none', async (payload, s) => {
    const { username: rawName, password } = reqObject(payload);
    if (s.data.username) throw new UserError('You are already signed in.');
    throttleStarts(s);
    const fail = () => new UserError('Invalid username or password.');
    let lower;
    try {
      lower = validateLoginName(rawName).toLowerCase();
    } catch {
      accountAuth.recordFailure(s.data.ip, '-');
      throw fail();
    }
    if (typeof password !== 'string' || password.length === 0 || Buffer.byteLength(password, 'utf8') > 72) {
      accountAuth.recordFailure(s.data.ip, lower);
      throw fail();
    }
    if (accountAuth.isLocked(s.data.ip, lower)) throw new UserError('Too many failed attempts. Try again in 15 minutes.');
    const row = await db.getUserWithHash(lower);
    const ok = await accountAuth.verify(password, row && row.password_hash);
    if (!row || !ok) {
      accountAuth.recordFailure(s.data.ip, lower);
      throw fail();
    }
    accountAuth.clearFailures(s.data.ip, lower);
    assertNotBanned(s, lower);
    const user = directory.remember(row);
    const token = startSession(s, { username: user.username, displayName: user.displayName, role: 'member', userId: user.id, bio: user.bio }, null);
    return buildSession(s, token, { authToken: accountAuth.issueToken(user, row.password_hash) });
  });

  on(socket, 'auth:resume', 'none', async (payload, s) => {
    const { token } = reqObject(payload);
    if (s.data.username) throw new UserError('You are already signed in.');
    throttleStarts(s);
    const claims = accountAuth.verifyToken(token);
    const stale = new UserError('Your login expired. Please log in again.');
    if (!claims) throw stale;
    const lower = claims.username.toLowerCase();
    const row = await db.getUserWithHash(lower);
    if (!row || accountAuth.pv(row.password_hash) !== claims.pv) throw stale;
    assertNotBanned(s, lower);
    const user = directory.remember(row);
    const resume = startSession(s, { username: user.username, displayName: user.displayName, role: 'member', userId: user.id, bio: user.bio }, null);
    return buildSession(s, resume, { authToken: token });
  });

  on(socket, 'session:end', 'user', async (payload, s) => {
    if (s.data.isAdmin && s.data.adminJti) adminAuth.revoke(s.data.adminJti, s.data.adminExpiresAt);
    endSession(s, { immediate: true });
    return { ok: true };
  });

  // ===== administrator authentication =====

  on(socket, 'admin:login', 'none', async (payload, s) => {
    const { username, password } = reqObject(payload);
    const result = await adminAuth.verifyLogin(s.data.ip, username, password);
    if (!result.ok) {
      console.warn(`[admin] failed login from ${s.data.ipHash.slice(0, 8)}`);
      throw new UserError(
        result.locked ? 'Too many failed attempts. Try again in 15 minutes.' : 'Invalid administrator credentials.'
      );
    }
    if (s.data.username) endSession(s, { immediate: true });
    const { token, jti, expiresAt } = adminAuth.issueToken(result.username);
    const resume = startSession(s, { username: result.username, displayName: result.username, role: 'admin', adminExpiresAt: expiresAt, adminJti: jti }, null);
    console.log(`[admin] login: ${result.username}`);
    return buildSession(s, resume, { adminToken: token });
  });

  on(socket, 'admin:resume', 'none', async (payload, s) => {
    const { token } = reqObject(payload);
    if (s.data.username) throw new UserError('You are already signed in.');
    throttleStarts(s);
    const verified = adminAuth.verifyToken(token);
    if (!verified) throw new UserError('Your administrator session has expired. Please log in again.');
    const resume = startSession(s, { username: verified.username, displayName: verified.username, role: 'admin', adminExpiresAt: verified.expiresAt, adminJti: verified.jti }, null);
    return buildSession(s, resume, { adminToken: token });
  });

  // ===== push notifications =====

  on(socket, 'push:key', 'member', async () => ({ ok: true, key: vapidPublic || null }));

  on(socket, 'push:subscribe', 'member', async (payload, s) => {
    const { endpoint, keys } = reqObject(payload);
    if (!webpush) throw new UserError('Push notifications are not available on this server.');
    const b64 = /^[A-Za-z0-9_-]{16,200}$/;
    if (!validPushEndpoint(endpoint) || !keys || typeof keys !== 'object' || !b64.test(keys.p256dh) || !b64.test(keys.auth)) {
      throw new UserError('Invalid push subscription.');
    }
    const lower = s.data.username.toLowerCase();
    const existing = await db.listPushSubs(lower);
    if (existing.length >= 10 && !existing.some((e) => e.endpoint === endpoint)) {
      throw new UserError('You have too many devices registered for notifications.');
    }
    await db.savePushSub({ endpoint, usernameLower: lower, p256dh: keys.p256dh, auth: keys.auth });
    return { ok: true };
  });

  on(socket, 'push:unsubscribe', 'member', async (payload) => {
    const { endpoint } = reqObject(payload);
    if (typeof endpoint === 'string' && endpoint.length <= 600) await db.removePushSub(endpoint);
    return { ok: true };
  });

  // ===== profiles =====

  on(socket, 'profile:get', 'user', async (payload) => {
    const { username } = reqObject(payload);
    const name = strictName(username);
    const lower = name.toLowerCase();
    if (isAdminName(lower)) {
      return { ok: true, profile: { username: nameCase(lower), displayName: nameCase(lower), bio: 'Administrator of TerminalChat.', role: 'admin', online: !!findOnline(lower) } };
    }
    const u = await directory.get(lower);
    if (u) {
      return { ok: true, profile: { username: u.username, displayName: u.displayName, bio: u.bio, role: 'member', createdAt: u.createdAt, online: !!findOnline(lower) } };
    }
    const g = sessions.get(lower);
    if (g && g.socketId && g.role === 'guest') {
      return { ok: true, profile: { username: g.username, displayName: g.username, bio: '', role: 'guest', online: true } };
    }
    throw new UserError('No such user.');
  });

  on(socket, 'profile:update', 'member', async (payload, s) => {
    if (s.data.role !== 'member') throw new UserError('Administrator profiles are fixed.');
    const { displayName: rawDisplay, bio: rawBio } = reqObject(payload);
    const lower = s.data.username.toLowerCase();
    const current = await directory.get(lower);
    if (!current) throw new UserError('Account not found.');
    const patch = {};
    if (rawDisplay !== undefined) {
      const displayName = validateDisplayName(rawDisplay, ADMIN_NAMES);
      const dkey = displayKey(displayName);
      if (displayName !== current.displayName) {
        const guest = sessions.get(dkey);
        if (await db.displayNameConflict(dkey, lower) || (guest && guest.role === 'guest' && guest.socketId)) {
          throw new UserError('That display name is already taken.');
        }
        patch.displayName = displayName;
        patch.displayLower = dkey;
      }
    }
    if (rawBio !== undefined) patch.bio = validateBio(rawBio);
    if (!Object.keys(patch).length) return { ok: true, profile: current };
    let row;
    try {
      row = await db.updateProfile(current.id, patch);
    } catch (err) {
      if (err.code === '23505') throw new UserError('That display name is already taken.');
      throw err;
    }
    const u = directory.remember({ ...row, username_lower: lower });
    // keep live connections and presence in step
    const sess = sessions.get(lower);
    if (sess) sess.displayLower = displayKey(u.displayName);
    for (const sk of io.sockets.sockets.values()) {
      if (sk.data.username && sk.data.username.toLowerCase() === lower) {
        sk.data.displayName = u.displayName;
        sk.data.bio = u.bio;
      }
    }
    rooms.renameUser(u.username, u.displayName);
    io.emit('profile:updated', { username: u.username, displayName: u.displayName, bio: u.bio });
    for (const sk of io.sockets.sockets.values()) {
      if (sk.data.username && sk.data.username.toLowerCase() === lower && sk.data.roomId) {
        io.to(roomKey(sk.data.roomId)).emit('room:users', { roomId: sk.data.roomId, users: rooms.users(sk.data.roomId) });
      }
    }
    return { ok: true, profile: u };
  });

  on(socket, 'account:password', 'member', async (payload, s) => {
    if (s.data.role !== 'member') throw new UserError('Administrator passwords are set in the server settings.');
    const { current, next } = reqObject(payload);
    const lower = s.data.username.toLowerCase();
    if (!windowCounter(sessionStarts, `pw:${lower}`, 5, 15 * 60_000)) throw new UserError('Too many attempts. Please wait a few minutes.');
    if (typeof current !== 'string' || Buffer.byteLength(current, 'utf8') > 72) throw new UserError('Your current password is incorrect.');
    const row = await db.getUserWithHash(lower);
    if (!row || !(await accountAuth.verify(current, row.password_hash))) throw new UserError('Your current password is incorrect.');
    validatePassword(next, s.data.username);
    const hash = await accountAuth.hash(next);
    await db.updatePasswordHash(row.id, hash);
    return { ok: true, authToken: accountAuth.issueToken(directory.remember(row), hash) };
  });

  // ===== rooms =====

  on(socket, 'room:join', 'user', async (payload, s) => {
    const { roomId } = reqObject(payload);
    if (!isUuid(roomId)) throw new UserError('Invalid room.');
    const room = rooms.get(roomId);
    if (!room) throw new UserError('That room no longer exists.');
    if (!canEnterRoom(s, room)) throw new UserError('Guests can only use #general. Create a free account to join other rooms.');

    if (s.data.roomId !== roomId) {
      leaveRoom(s);
      rooms.join(roomId, s.id, { username: s.data.username, displayName: s.data.displayName, isAdmin: s.data.isAdmin, isGuest: s.data.role === 'guest' });
      s.join(roomKey(roomId));
      s.data.roomId = roomId;
    }

    let history;
    let pins;
    try {
      history = await hydrate(await db.getRecentMessages(roomId, HISTORY_LIMIT));
      pins = await hydrate(await db.listPinned(roomId));
    } catch (err) {
      leaveRoom(s);
      throw err;
    }
    // The room may have been deleted, or the user may have moved on, while we waited.
    if (!rooms.get(roomId) || s.data.roomId !== roomId) throw new UserError('That room no longer exists.');

    s.to(roomKey(roomId)).emit('system:event', { roomId, kind: 'join', text: `${s.data.displayName} joined the room`, ts: Date.now() });
    io.to(roomKey(roomId)).emit('room:users', { roomId, users: rooms.users(roomId) });
    scheduleBroadcastRooms();

    const st = roomStates.get(roomId);
    return {
      ok: true,
      room: { id: room.id, name: room.name, description: room.description },
      history,
      pins,
      users: rooms.users(roomId),
      slowmode: st ? Math.round(st.delay / 1000) : 0,
    };
  });

  on(socket, 'room:leave', 'user', async (payload, s) => {
    leaveRoom(s);
    return { ok: true };
  });

  // ===== sending messages =====

  on(socket, 'message:send', 'user', async (payload, s) => {
    const { content: raw, replyTo } = reqObject(payload);
    const content = cleanMessage(raw, MAX_MESSAGE_LENGTH);
    const roomId = s.data.roomId;
    if (!roomId || !rooms.get(roomId)) throw new UserError('Join a room first.');

    if (s.data.role === 'admin') {
      const cmd = await runCommand(s, content);
      if (cmd) return cmd;
    }
    preSend(s, content);
    checkSlowmode(roomId, s);
    const replyRow = await resolveReply(replyTo, { roomId });
    let row;
    try {
      row = await db.insertMessage({ roomId, username: s.data.username, isAdmin: s.data.isAdmin, content, replyTo: replyRow && replyRow.id });
    } catch (err) {
      if (err.code === '23503') throw new UserError('That room no longer exists.'); // FK violation: deleted meanwhile
      throw err;
    }
    noteSent(roomId, s);
    clearTyping(roomId, s.data.username.toLowerCase());
    await deliverMessage(row, s);
    schedulePrune(roomId);
    return { ok: true };
  });

  on(socket, 'typing', 'user', async (payload, s) => {
    const { scope, to } = reqObject(payload);
    if (muteOf(s.data.username.toLowerCase())) return { ok: true };
    if (scope === 'room') {
      if (s.data.roomId && rooms.get(s.data.roomId)) setTyping(s.data.roomId, s);
    } else if (scope === 'dm' && s.data.role !== 'guest') {
      const target = strictName(to).toLowerCase();
      if (target !== s.data.username.toLowerCase()) {
        io.to(userKey(target)).emit('typing:update', { scope: 'dm', with: s.data.username, displayName: s.data.displayName, count: 1 });
      }
    }
    return { ok: true };
  });

  // ===== private messages =====

  async function dmPartner(s, withName) {
    const name = strictName(withName);
    const lower = name.toLowerCase();
    if (lower === s.data.username.toLowerCase()) throw new UserError("You can't message yourself.");
    if (isAdminName(lower)) return { username: nameCase(lower), displayName: nameCase(lower), lower, role: 'admin' };
    const u = await directory.get(lower);
    if (!u) throw new UserError('No member has that username. (Guests have no inbox.)');
    return { username: u.username, displayName: u.displayName, lower, role: 'member' };
  }

  on(socket, 'dm:list', 'member', async (payload, s) => ({ ok: true, dms: await listDmThreads(s.data.username) }));

  on(socket, 'dm:open', 'member', async (payload, s) => {
    const { with: withName } = reqObject(payload);
    const partner = await dmPartner(s, withName);
    const key = dmKeyOf(s.data.username, partner.lower);
    const history = await hydrate(await db.getDmMessages(key, DM_PAGE));
    const [a, b] = key.split('|');
    db.markThreadRead(a, b, s.data.username.toLowerCase()).catch(() => {});
    return { ok: true, partner: { username: partner.username, displayName: partner.displayName, role: partner.role }, dmKey: key, history, hasMore: history.length >= DM_PAGE };
  });

  on(socket, 'dm:history', 'member', async (payload, s) => {
    const { with: withName, before } = reqObject(payload);
    const partner = await dmPartner(s, withName);
    if (!Number.isSafeInteger(before) || before <= 0) throw new UserError('Invalid request.');
    const history = await hydrate(await db.getDmMessages(dmKeyOf(s.data.username, partner.lower), 50, before));
    return { ok: true, history, hasMore: history.length >= 50 };
  });

  on(socket, 'dm:read', 'member', async (payload, s) => {
    const { with: withName } = reqObject(payload);
    const partner = await dmPartner(s, withName);
    const [a, b] = dmKeyOf(s.data.username, partner.lower).split('|');
    await db.markThreadRead(a, b, s.data.username.toLowerCase());
    return { ok: true };
  });

  on(socket, 'dm:send', 'member', async (payload, s) => {
    const { to, content: raw, replyTo } = reqObject(payload);
    const content = cleanMessage(raw, MAX_MESSAGE_LENGTH);
    const partner = await dmPartner(s, to);
    preSend(s, content);
    const key = dmKeyOf(s.data.username, partner.lower);
    const replyRow = await resolveReply(replyTo, { dmKey: key });
    const row = await db.insertMessage({ dmKey: key, username: s.data.username, isAdmin: s.data.isAdmin, content, replyTo: replyRow && replyRow.id });
    const [a, b] = key.split('|');
    await db.touchThread(a, b, s.data.username.toLowerCase());
    await deliverMessage(row, s);
    return { ok: true };
  });

  on(socket, 'upload:ticket', 'user', async (payload, s) => {
    if (!uploadsReady) throw new UserError('File uploads are not available on this server right now.');
    const { name: rawName, size, caption, replyTo, to } = reqObject(payload);
    const now = Date.now();
    assertNotMuted(s);
    s.data.uploadTimes = (s.data.uploadTimes || []).filter((t) => now - t < 60_000);
    if (s.data.uploadTimes.length >= 5) throw new UserError('You are uploading too fast. Please wait a minute.');
    const file = validateAttachmentName(rawName);
    if (!Number.isSafeInteger(size) || size < 1) throw new UserError('Invalid file size.');
    if (size > MAX_UPLOAD_BYTES) throw new UserError(`Files can be at most ${MAX_UPLOAD_MB} MB.`);
    const cleanCaption = cleanMessage(caption === undefined || caption === null ? '' : caption, MAX_MESSAGE_LENGTH, { allowEmpty: true });

    const target = { roomId: null, dmKey: null };
    if (to !== undefined && to !== null) {
      if (s.data.role === 'guest') throw new UserError('Guests cannot send private messages.');
      const partner = await dmPartner(s, to);
      target.dmKey = dmKeyOf(s.data.username, partner.lower);
    } else {
      target.roomId = s.data.roomId;
      if (!target.roomId || !rooms.get(target.roomId)) throw new UserError('Join a room first.');
      checkSlowmode(target.roomId, s);
    }
    const replyRow = await resolveReply(replyTo, target);
    s.data.uploadTimes.push(now);
    if (s.data.uploadTicket) uploadTickets.delete(s.data.uploadTicket); // one outstanding ticket per user
    const ticket = crypto.randomBytes(24).toString('hex');
    s.data.uploadTicket = ticket;
    uploadTickets.set(ticket, {
      socketId: s.id,
      username: s.data.username,
      ...target,
      file,
      size,
      caption: cleanCaption,
      replyTo: replyRow ? replyRow.id : null,
      exp: now + TICKET_TTL_MS,
    });
    return { ok: true, ticket };
  });

  // ===== editing, deleting, reacting, pinning =====

  /** May this connection see/react to this message? (room members, or the two DM participants) */
  function canSee(s, row) {
    if (row.room_id) return s.data.roomId === row.room_id && !!rooms.get(row.room_id);
    return row.dm_key.split('|').includes(s.data.username.toLowerCase());
  }

  on(socket, 'message:edit', 'user', async (payload, s) => {
    const { id, content: raw } = reqObject(payload);
    if (!Number.isSafeInteger(id) || id <= 0) throw new UserError('Invalid message.');
    assertNotMuted(s);
    const row = await db.getMessage(id);
    if (!row || row.kind === 'system') throw new UserError('That message no longer exists.');
    if (row.username.toLowerCase() !== s.data.username.toLowerCase()) throw new UserError('You can only edit your own messages.');
    const content = cleanMessage(raw, MAX_MESSAGE_LENGTH, { allowEmpty: !!row.attachment_path });
    if (content === row.content) return { ok: true };
    const updated = await db.updateContent(id, content);
    if (!updated) throw new UserError('That message no longer exists.');
    const [msg] = await hydrate([updated]);
    emitToScope(updated, 'message:updated', msg);
    return { ok: true };
  });

  on(socket, 'message:delete', 'user', async (payload, s) => {
    const { id } = reqObject(payload);
    if (!Number.isSafeInteger(id) || id <= 0) throw new UserError('Invalid message.');
    const row = await db.getMessage(id);
    if (!row) throw new UserError('That message no longer exists.');
    const mine = row.kind !== 'system' && row.username.toLowerCase() === s.data.username.toLowerCase();
    // Admins may delete anything in public rooms, but never read or remove other people's private DMs.
    const adminOverride = s.data.isAdmin && !!row.room_id;
    if (!mine && !adminOverride) throw new UserError('You can only delete your own messages.');
    const gone = await db.deleteMessage(id);
    if (!gone) throw new UserError('That message no longer exists.');
    if (gone.attachment_path) db.removeFiles([gone.attachment_path]);
    emitToScope(row, 'message:deleted', { id, ...messageScope(row) });
    return { ok: true };
  });

  on(socket, 'reaction:toggle', 'user', async (payload, s) => {
    const { id, emoji: rawEmoji } = reqObject(payload);
    if (!Number.isSafeInteger(id) || id <= 0) throw new UserError('Invalid message.');
    const emoji = validateEmoji(rawEmoji);
    assertNotMuted(s);
    const me = s.data.username.toLowerCase();
    return serialize(`reaction:${id}`, async () => {
      const row = await db.getMessage(id);
      if (!row || !canSee(s, row)) throw new UserError('That message no longer exists.');
      const reactions = { ...(row.reactions || {}) };
      const users = [...(reactions[emoji] || [])];
      const at = users.indexOf(me);
      if (at >= 0) users.splice(at, 1);
      else {
        if (!reactions[emoji] && Object.keys(reactions).length >= 12) throw new UserError('That message already has the maximum number of different reactions.');
        if (users.length >= 200) throw new UserError('Too many people have already used that reaction.');
        users.push(me);
      }
      if (users.length) reactions[emoji] = users;
      else delete reactions[emoji];
      await db.setReactions(id, Object.keys(reactions).length ? reactions : null);
      emitToScope(row, 'message:reactions', { id, ...messageScope(row), reactions });
      return { ok: true };
    });
  });

  on(socket, 'message:pin', 'admin', async (payload) => {
    const { id, pinned } = reqObject(payload);
    if (!Number.isSafeInteger(id) || id <= 0 || typeof pinned !== 'boolean') throw new UserError('Invalid request.');
    const row = await db.getMessage(id);
    if (!row || !row.room_id) throw new UserError('Only messages in public rooms can be pinned.');
    if (pinned && !row.pinned && (await db.countPinned(row.room_id)) >= MAX_PINS_PER_ROOM) {
      throw new UserError(`A room can have at most ${MAX_PINS_PER_ROOM} pinned messages.`);
    }
    const updated = await db.setPinned(id, pinned);
    if (!updated) throw new UserError('That message no longer exists.');
    const [msg] = await hydrate([updated]);
    io.to(roomKey(row.room_id)).emit('message:pinned', { roomId: row.room_id, message: msg });
    return { ok: true };
  });

  // ===== administrator room & user management =====

  on(socket, 'admin:createRoom', 'admin', async (payload, s) => {
    const { name, description } = reqObject(payload);
    const room = await rooms.create(name, description, s.data.username);
    console.log(`[admin] created room #${room.name}`);
    scheduleBroadcastRooms();
    return { ok: true, room: { id: room.id, name: room.name, description: room.description } };
  });

  on(socket, 'admin:deleteRoom', 'admin', async (payload) => {
    const { roomId } = reqObject(payload);
    if (!isUuid(roomId)) throw new UserError('Invalid room.');
    const filePaths = await db.listRoomAttachmentPaths(roomId); // must be read before the cascade delete
    const { room, socketIds } = await rooms.remove(roomId);
    db.removeFiles(filePaths); // best effort, in the background
    typingRooms.delete(roomId);
    roomStates.delete(roomId);
    io.to(roomKey(roomId)).emit('room:deleted', { roomId, name: room.name });
    for (const id of socketIds) {
      const member = io.sockets.sockets.get(id);
      if (member) {
        member.data.roomId = null;
        member.leave(roomKey(roomId));
      }
    }
    console.log(`[admin] deleted room #${room.name}`);
    scheduleBroadcastRooms();
    return { ok: true };
  });

  on(socket, 'admin:kick', 'admin', async (payload) => {
    const { username, reason } = reqObject(payload);
    const target = findSocketByUsername(username);
    if (!target) throw new UserError('That user is not online.');
    if (target.data.isAdmin) throw new UserError('You cannot kick an administrator.');
    removeUser(target, { reason: cleanReason(reason), ban: false });
    return { ok: true };
  });

  on(socket, 'admin:ban', 'admin', async (payload, s) => {
    const { username, reason, banIp } = reqObject(payload);
    await banUser(s, username, { reason, banIp });
    return { ok: true };
  });

  on(socket, 'admin:listBans', 'admin', async () => ({
    ok: true,
    bans: bans.map((b) => ({
      id: b.id,
      username: b.usernameLower,
      ipBanned: !!b.ipHash,
      reason: b.reason,
      createdBy: b.createdBy,
      createdAt: b.createdAt,
    })),
  }));

  on(socket, 'admin:unban', 'admin', async (payload) => {
    const { banId } = reqObject(payload);
    if (!Number.isSafeInteger(banId) || banId <= 0) throw new UserError('Invalid ban.');
    const removed = await db.removeBan(banId);
    if (!removed) throw new UserError('That ban no longer exists.');
    bans = bans.filter((b) => b.id !== banId);
    return { ok: true };
  });
});

// ---------------------------------------------------------------------------
// Startup / shutdown
// ---------------------------------------------------------------------------

async function main() {
  try {
    await rooms.load();
    await loadBans();
    await db.checkSchema();
    await loadMutes();
  } catch (err) {
    fatal([
      `Could not read from Supabase: ${err.message}`,
      'Check SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY and make sure you ran the latest backend/schema.sql in the Supabase SQL editor.',
    ]);
  }
  try {
    await initPush();
  } catch (err) {
    webpush = null;
    console.warn(`[push] disabled: ${err.message}`);
  }
  try {
    await db.ensureBucket(MAX_UPLOAD_BYTES);
    uploadsReady = true;
  } catch (err) {
    // Chat keeps working; only file uploads are switched off.
    console.warn(`[uploads] disabled: ${err.message}`);
  }
  server.listen(PORT, () => {
    console.log(`TerminalChat v${APP_VERSION} backend listening on port ${PORT}`);
    console.log(`Admin accounts: ${ADMIN_NAMES.length}; file uploads: ${uploadsReady ? `on (max ${MAX_UPLOAD_MB} MB)` : 'OFF'}; push: ${webpush ? 'on' : 'OFF'}`);
    console.log(`Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
    console.log(`Loaded ${rooms.rooms.size} room(s), ${bans.length} ban(s), ${mutes.size} mute(s). Rooms keep ${MAX_STORED_MESSAGES_PER_ROOM} messages.`);
  });
}

function shutdown() {
  console.log('Shutting down...');
  io.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
process.on('unhandledRejection', (err) => console.error('[unhandledRejection]', err));

main();
