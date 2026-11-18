'use strict';

/**
 * rooms.js — input validation/sanitising helpers and the in-memory room manager.
 *
 * The database is the source of truth for rooms; the manager keeps a cache so
 * that joins/lists do not hit Supabase every time, plus live presence (who is
 * in which room right now), which is never persisted.
 */

class UserError extends Error {
  /** An error whose message is safe to show to the end user. */
  constructor(message) {
    super(message);
    this.name = 'UserError';
  }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const USERNAME_RE = /^[A-Za-z][A-Za-z0-9_-]{2,19}$/;
const ROOM_NAME_RE = /^[a-z0-9][a-z0-9-]{1,23}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Words (and look-alikes) ordinary users may not start/end/equal, to stop impersonation.
const RESERVED_WORDS = [
  'admin', 'administrator', 'moderator', 'system', 'terminalchat',
  'staff', 'server', 'root', 'sysop', 'operator',
];

// Control chars, zero-width chars and bidi overrides — they enable spoofing and invisible text.
// eslint-disable-next-line no-control-regex
const INVISIBLE_RE = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F​-‏‪-‮⁠-⁩﻿]/g;

function normalizeForReserved(name) {
  return name
    .toLowerCase()
    .replace(/[-_]/g, '')
    .replace(/0/g, 'o')
    .replace(/1/g, 'i')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't');
}

function isReservedName(name, exactReserved = []) {
  const n = normalizeForReserved(name);
  if (RESERVED_WORDS.some((w) => n === w || n.startsWith(w) || n.endsWith(w))) return true;
  return exactReserved.some((x) => n === normalizeForReserved(x));
}

function isUuid(value) {
  return typeof value === 'string' && UUID_RE.test(value);
}

/**
 * Returns the username or throws UserError. Whitespace is NEVER allowed — not inside, and not
 * leading/trailing either (the value is not trimmed). Only a strict allow-list of characters
 * passes, so nothing odd can ever reach a database query.
 * `exactReserved` = extra names ordinary users can't take (the admin names).
 */
function validateUsername(input, exactReserved = []) {
  if (typeof input !== 'string' || input.length === 0) throw new UserError('Please enter a username.');
  if (input.length > 64) throw new UserError('That username is too long.');
  if (/\s/.test(input)) throw new UserError('Usernames cannot contain spaces.');
  if (!USERNAME_RE.test(input)) {
    throw new UserError(
      'Usernames must be 3–20 characters, start with a letter, and use only letters, numbers, "_" or "-".'
    );
  }
  if (isReservedName(input, exactReserved)) {
    throw new UserError('That username is reserved. Please choose another.');
  }
  return input;
}

/** Same strict shape check, but without the "reserved" rules — used when LOGGING IN to an existing account. */
function validateLoginName(input) {
  if (typeof input !== 'string' || input.length === 0) throw new UserError('Please enter your username.');
  if (input.length > 64 || /\s/.test(input) || !USERNAME_RE.test(input)) {
    throw new UserError('Invalid username or password.');
  }
  return input;
}

const DISPLAY_NAME_RE = /^[\p{L}\p{N}][\p{L}\p{N} _.'-]{0,23}$/u;

/** Display names: what people see in chat. 1–24 chars, letters/numbers/spaces/_.'- ; must not imitate staff. */
function validateDisplayName(input, exactReserved = []) {
  if (typeof input !== 'string') throw new UserError('Please enter a display name.');
  const name = input.normalize('NFKC').replace(INVISIBLE_RE, '').replace(/\s+/g, ' ').trim();
  if (!name) throw new UserError('Please enter a display name.');
  if ([...name].length > 24 || !DISPLAY_NAME_RE.test(name)) {
    throw new UserError('Display names must be 1–24 characters: letters, numbers, spaces and _ . \' - only.');
  }
  if (isReservedName(name.replace(/ /g, ''), exactReserved)) {
    throw new UserError('That display name is reserved. Please choose another.');
  }
  return name;
}

const displayKey = (name) => name.normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim();

function validateBio(input) {
  if (input === undefined || input === null) return '';
  if (typeof input !== 'string') throw new UserError('Invalid bio.');
  const text = input.normalize('NFKC').replace(INVISIBLE_RE, '').replace(/\s+/g, ' ').trim();
  if ([...text].length > 160) throw new UserError('Bios can be at most 160 characters.');
  return text;
}

/** Passwords: 8+ characters, at most 72 bytes (a bcrypt limit), no control characters. */
function validatePassword(input, username = '') {
  if (typeof input !== 'string' || input.length === 0) throw new UserError('Please enter a password.');
  if (input.length < 8) throw new UserError('Passwords must be at least 8 characters.');
  if (Buffer.byteLength(input, 'utf8') > 72) throw new UserError('Passwords can be at most 72 bytes (about 72 characters).');
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001F\u007F]/.test(input)) throw new UserError('Passwords cannot contain control characters.');
  if (username && input.toLowerCase() === String(username).toLowerCase()) {
    throw new UserError('Your password cannot be the same as your username.');
  }
  return input;
}

// One emoji (with optional skin tone / ZWJ sequence / variation selector / keycap / flag). Anything else is rejected.
const EMOJI_RE = /^(?:\p{Regional_Indicator}{2}|[0-9#*]️?⃣|\p{Extended_Pictographic}(?:️|\p{Emoji_Modifier})?(?:‍\p{Extended_Pictographic}(?:️|\p{Emoji_Modifier})?)*)$/u;

function validateEmoji(input) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 24 || !EMOJI_RE.test(input)) {
    throw new UserError('Please pick a single emoji.');
  }
  return input;
}

/** Usernames mentioned as @name (lowercase, unique, at most 10). */
function extractMentions(text) {
  const out = new Set();
  const re = /(^|[^\w])@([A-Za-z][A-Za-z0-9_-]{2,19})(?![\w-])/g;
  let m;
  while ((m = re.exec(text)) && out.size < 10) out.add(m[2].toLowerCase());
  return [...out];
}

/** Short one-line preview of a message for reply bars and notifications. */
function snippetOf(content, attachmentName, max = 80) {
  const flat = String(content || '').replace(/\s+/g, ' ').trim();
  const base = flat || (attachmentName ? `📎 ${attachmentName}` : '');
  const chars = [...base];
  return chars.length > max ? `${chars.slice(0, max - 1).join('')}…` : base;
}

/** Room names are lowercase slugs: 2–24 chars of a-z, 0-9 and "-". */
function validateRoomName(input) {
  if (typeof input !== 'string') throw new UserError('Please enter a room name.');
  const name = input.trim().toLowerCase().replace(/^#/, '');
  if (!ROOM_NAME_RE.test(name)) {
    throw new UserError(
      'Room names must be 2–24 characters: lowercase letters, numbers and "-", starting with a letter or number.'
    );
  }
  return name;
}

function validateRoomDescription(input) {
  if (input === undefined || input === null || input === '') return '';
  if (typeof input !== 'string') throw new UserError('Invalid description.');
  const text = input.replace(INVISIBLE_RE, '').replace(/\s+/g, ' ').trim();
  if ([...text].length > 80) throw new UserError('Room descriptions can be at most 80 characters.');
  return text;
}

const MAX_MESSAGE_LINES = 20;

/**
 * Chat message (may span several lines, e.g. Markdown). Strips invisible/control characters,
 * normalises line endings, removes trailing spaces, collapses runs of blank lines and enforces
 * length and line limits. With allowEmpty, an empty result is returned instead of throwing
 * (used for optional file captions).
 */
function cleanMessage(input, maxLength, { allowEmpty = false } = {}) {
  if (typeof input !== 'string') throw new UserError('Invalid message.');
  if (input.length > maxLength * 4) throw new UserError(`Messages can be at most ${maxLength} characters.`);
  const text = input
    .replace(/\r\n?/g, '\n')
    .replace(INVISIBLE_RE, '')
    .replace(/\t/g, '  ')
    .replace(/ +\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  if (!text) {
    if (allowEmpty) return '';
    throw new UserError('Message is empty.');
  }
  if ([...text].length > maxLength) throw new UserError(`Messages can be at most ${maxLength} characters.`);
  if (text.split('\n').length > MAX_MESSAGE_LINES) {
    throw new UserError(`Messages can have at most ${MAX_MESSAGE_LINES} lines.`);
  }
  return text;
}

// ---------------------------------------------------------------------------
// File attachments
// ---------------------------------------------------------------------------

/**
 * Allow-list of attachment types. The server decides the stored content type from the
 * extension (never from what the client claims). No HTML, SVG, scripts or executables.
 */
const ATTACHMENT_TYPES = {
  png: { mime: 'image/png', kind: 'image' },
  jpg: { mime: 'image/jpeg', kind: 'image' },
  jpeg: { mime: 'image/jpeg', kind: 'image' },
  gif: { mime: 'image/gif', kind: 'image' },
  webp: { mime: 'image/webp', kind: 'image' },
  pdf: { mime: 'application/pdf', kind: 'file' },
  txt: { mime: 'text/plain', kind: 'file' },
  md: { mime: 'text/plain', kind: 'file' },
  csv: { mime: 'text/csv', kind: 'file' },
  json: { mime: 'application/json', kind: 'file' },
  zip: { mime: 'application/zip', kind: 'file' },
  gz: { mime: 'application/gzip', kind: 'file' },
  '7z': { mime: 'application/x-7z-compressed', kind: 'file' },
  docx: { mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', kind: 'file' },
  xlsx: { mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', kind: 'file' },
  pptx: { mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', kind: 'file' },
  mp3: { mime: 'audio/mpeg', kind: 'file' },
  wav: { mime: 'audio/wav', kind: 'file' },
  ogg: { mime: 'audio/ogg', kind: 'file' },
  mp4: { mime: 'video/mp4', kind: 'file' },
  webm: { mime: 'video/webm', kind: 'file' },
};

function attachmentInfo(ext) {
  return Object.prototype.hasOwnProperty.call(ATTACHMENT_TYPES, ext) ? ATTACHMENT_TYPES[ext] : null;
}

/** Cleans a client-supplied file name and checks its extension. Returns { name, ext, mime, kind }. */
function validateAttachmentName(input) {
  if (typeof input !== 'string') throw new UserError('Invalid file name.');
  const name = input
    .replace(INVISIBLE_RE, '')
    .split(/[\\/]/)
    .pop()
    .replace(/[<>:"|?*]/g, '_')
    .replace(/\s+/g, ' ')
    .trim();
  if (!name) throw new UserError('Invalid file name.');
  if ([...name].length > 100) throw new UserError('File names can be at most 100 characters.');
  const m = /\.([A-Za-z0-9]{1,5})$/.exec(name);
  const ext = m ? m[1].toLowerCase() : '';
  if (m && name.length === m[0].length) throw new UserError('Invalid file name.'); // nothing before the dot
  const info = attachmentInfo(ext);
  if (!info) {
    throw new UserError(
      'That file type is not allowed. Allowed: png, jpg, gif, webp, pdf, txt, md, csv, json, zip, gz, 7z, docx, xlsx, pptx, mp3, wav, ogg, mp4, webm.'
    );
  }
  return { name, ext, mime: info.mime, kind: info.kind };
}

/** Checks the first bytes of a file against its claimed extension (images, PDF, zip-based formats). */
function sniffFile(buf, ext) {
  const starts = (...bytes) => bytes.every((b, i) => buf[i] === b);
  switch (ext) {
    case 'png': return starts(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);
    case 'jpg':
    case 'jpeg': return starts(0xff, 0xd8, 0xff);
    case 'gif': return buf.subarray(0, 6).toString('latin1') === 'GIF87a' || buf.subarray(0, 6).toString('latin1') === 'GIF89a';
    case 'webp': return buf.subarray(0, 4).toString('latin1') === 'RIFF' && buf.subarray(8, 12).toString('latin1') === 'WEBP';
    case 'pdf': return buf.subarray(0, 5).toString('latin1') === '%PDF-';
    case 'zip':
    case 'docx':
    case 'xlsx':
    case 'pptx': return starts(0x50, 0x4b);
    default: return true;
  }
}

function cleanReason(input) {
  if (input === undefined || input === null || input === '') return '';
  if (typeof input !== 'string') throw new UserError('Invalid reason.');
  const text = input.replace(INVISIBLE_RE, '').replace(/\s+/g, ' ').trim();
  return [...text].slice(0, 120).join('');
}

// ---------------------------------------------------------------------------
// Room manager
// ---------------------------------------------------------------------------

const MAX_ROOMS = 50;
const GUEST_ROOM = 'general'; // the only room guests may enter

class RoomManager {
  constructor(db) {
    this.db = db;
    /** @type {Map<string, {id:string,name:string,description:string,createdAt:string}>} */
    this.rooms = new Map();
    /** @type {Map<string, Map<string, {username:string,isAdmin:boolean}>>} roomId -> socketId -> user */
    this.presence = new Map();
  }

  async load() {
    const rows = await this.db.listRooms();
    this.rooms.clear();
    for (const r of rows) {
      this.rooms.set(r.id, {
        id: r.id,
        name: r.name,
        description: r.description || '',
        createdAt: r.created_at,
      });
    }
  }

  get(id) {
    return this.rooms.get(id) || null;
  }

  count(roomId) {
    const members = this.presence.get(roomId);
    if (!members) return 0;
    return new Set([...members.values()].map((u) => u.username.toLowerCase())).size;
  }

  /** Public room list (with live user counts), sorted by name. Guests only ever see "general". */
  list({ guest = false } = {}) {
    return [...this.rooms.values()]
      .filter((r) => !guest || r.name === GUEST_ROOM)
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((r) => ({ id: r.id, name: r.name, description: r.description, count: this.count(r.id) }));
  }

  /** Keeps live presence in step when someone changes their display name. */
  renameUser(username, displayName) {
    const lower = username.toLowerCase();
    for (const members of this.presence.values()) {
      for (const u of members.values()) if (u.username.toLowerCase() === lower) u.displayName = displayName;
    }
  }

  async create(nameInput, descriptionInput, createdBy) {
    const name = validateRoomName(nameInput);
    const description = validateRoomDescription(descriptionInput);
    if (this.rooms.size >= MAX_ROOMS) throw new UserError(`The room limit (${MAX_ROOMS}) has been reached.`);
    for (const r of this.rooms.values()) {
      if (r.name === name) throw new UserError('A room with that name already exists.');
    }
    let row;
    try {
      row = await this.db.createRoom({ name, description, createdBy });
    } catch (err) {
      if (err.code === '23505') throw new UserError('A room with that name already exists.');
      throw err;
    }
    const room = { id: row.id, name: row.name, description: row.description || '', createdAt: row.created_at };
    this.rooms.set(room.id, room);
    return room;
  }

  /** Deletes the room (and its messages). Returns { room, socketIds } for cleanup. */
  async remove(id) {
    const room = this.rooms.get(id);
    if (!room) throw new UserError('That room does not exist.');
    await this.db.deleteRoom(id);
    this.rooms.delete(id);
    const members = this.presence.get(id);
    this.presence.delete(id);
    return { room, socketIds: members ? [...members.keys()] : [] };
  }

  join(roomId, socketId, user) {
    let members = this.presence.get(roomId);
    if (!members) {
      members = new Map();
      this.presence.set(roomId, members);
    }
    members.set(socketId, {
      username: user.username,
      displayName: user.displayName || user.username,
      isAdmin: !!user.isAdmin,
      isGuest: !!user.isGuest,
    });
  }

  leave(roomId, socketId) {
    const members = this.presence.get(roomId);
    if (!members) return;
    members.delete(socketId);
    if (members.size === 0) this.presence.delete(roomId);
  }

  /** Distinct users currently in a room: admins first, then alphabetical. */
  users(roomId) {
    const members = this.presence.get(roomId);
    if (!members) return [];
    const byName = new Map();
    for (const u of members.values()) byName.set(u.username.toLowerCase(), u);
    return [...byName.values()]
      .sort((a, b) => Number(b.isAdmin) - Number(a.isAdmin) || a.displayName.localeCompare(b.displayName))
      .map((u) => ({ username: u.username, displayName: u.displayName, isAdmin: u.isAdmin, isGuest: u.isGuest }));
  }
}

module.exports = {
  RoomManager,
  GUEST_ROOM,
  UserError,
  USERNAME_RE,
  isUuid,
  isReservedName,
  validateUsername,
  validateLoginName,
  validateDisplayName,
  displayKey,
  validateBio,
  validatePassword,
  validateEmoji,
  extractMentions,
  snippetOf,
  validateRoomName,
  validateRoomDescription,
  cleanMessage,
  cleanReason,
  ATTACHMENT_TYPES,
  attachmentInfo,
  validateAttachmentName,
  sniffFile,
};
