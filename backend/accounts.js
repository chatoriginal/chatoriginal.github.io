'use strict';

/**
 * accounts.js — ordinary user accounts (signup / login) and the display-name directory.
 *
 * - Passwords are hashed with bcrypt; only the hash is stored.
 * - Login yields a signed JWT (30 days) bound to the current password hash, so changing the
 *   password signs out every other device.
 * - Failed logins are throttled per IP address and per username.
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const BCRYPT_COST = 10; // balanced for free-tier CPUs
const USER_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
const FAIL_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILS_PER_USER = 8;
const MAX_FAILS_PER_IP = 20;
const MAX_SIGNUPS_PER_IP_PER_HOUR = 5;

// Compared against when the username does not exist, so response time does not reveal which names exist.
const DUMMY_HASH = bcrypt.hashSync('terminalchat-dummy-user-password', BCRYPT_COST);

const sha256hex = (v) => crypto.createHash('sha256').update(v).digest('hex');

/**
 * Cache of account profiles keyed by lowercase username, so chat history can show display
 * names without a database query per message. Guests and admins are not in the database; for
 * them the display name is simply their username.
 */
class UserDirectory {
  constructor(db) {
    this.db = db;
    /** @type {Map<string, {id:string, username:string, displayName:string, bio:string, createdAt:string}>} */
    this.cache = new Map();
  }

  remember(row) {
    if (this.cache.size > 3000) this.cache.clear();
    const u = {
      id: row.id,
      username: row.username,
      displayName: row.display_name,
      bio: row.bio || '',
      createdAt: row.created_at,
    };
    this.cache.set(row.username_lower || row.username.toLowerCase(), u);
    return u;
  }

  patch(lower, fields) {
    const u = this.cache.get(lower);
    if (u) Object.assign(u, fields);
  }

  /** Returns the account (or null if no such member). */
  async get(lower) {
    const hit = this.cache.get(lower);
    if (hit) return hit;
    const row = await this.db.getUser(lower);
    return row ? this.remember(row) : null;
  }

  /** Makes sure these usernames are cached — one query for all the ones that are missing. */
  async load(lowers) {
    const missing = [...new Set(lowers)].filter((l) => !this.cache.has(l));
    if (!missing.length) return;
    for (const row of await this.db.getUsers(missing)) this.remember(row);
  }

  /** Display name for a username (synchronous; call load() first for history). */
  display(username) {
    const u = this.cache.get(String(username).toLowerCase());
    return u ? u.displayName : username;
  }
}

class AccountAuth {
  constructor({ jwtSecret }) {
    this.jwtSecret = jwtSecret;
    /** @type {Map<string, {count:number, first:number}>} */
    this.failures = new Map();
    /** @type {Map<string, {count:number, first:number}>} */
    this.signups = new Map();
    const timer = setInterval(() => this.cleanup(), 5 * 60 * 1000);
    if (timer.unref) timer.unref();
  }

  cleanup() {
    const now = Date.now();
    for (const [k, f] of this.failures) if (now - f.first > FAIL_WINDOW_MS) this.failures.delete(k);
    for (const [k, f] of this.signups) if (now - f.first > 3600_000) this.signups.delete(k);
  }

  hash(password) {
    return bcrypt.hash(password, BCRYPT_COST);
  }

  /** Always runs bcrypt (against a dummy hash when there is no account) to keep timing uniform. */
  verify(password, hash) {
    return bcrypt.compare(password, hash || DUMMY_HASH);
  }

  // ----- login throttling -----
  _bump(map, key, windowMs) {
    const now = Date.now();
    const f = map.get(key);
    if (!f || now - f.first > windowMs) map.set(key, { count: 1, first: now });
    else f.count += 1;
  }

  _count(map, key, windowMs) {
    const f = map.get(key);
    return f && Date.now() - f.first <= windowMs ? f.count : 0;
  }

  isLocked(ip, usernameLower) {
    return (
      this._count(this.failures, `ip:${ip}`, FAIL_WINDOW_MS) >= MAX_FAILS_PER_IP ||
      this._count(this.failures, `user:${usernameLower}`, FAIL_WINDOW_MS) >= MAX_FAILS_PER_USER
    );
  }

  recordFailure(ip, usernameLower) {
    this._bump(this.failures, `ip:${ip}`, FAIL_WINDOW_MS);
    this._bump(this.failures, `user:${usernameLower}`, FAIL_WINDOW_MS);
  }

  clearFailures(ip, usernameLower) {
    this.failures.delete(`user:${usernameLower}`);
    // IP counter is left to expire on its own, so one good login cannot reset a brute-force counter.
    void ip;
  }

  /** Limits account creation per IP (stops scripted mass signups). */
  allowSignup(ip) {
    if (this._count(this.signups, ip, 3600_000) >= MAX_SIGNUPS_PER_IP_PER_HOUR) return false;
    this._bump(this.signups, ip, 3600_000);
    return true;
  }

  // ----- tokens -----
  pv(passwordHash) {
    return sha256hex(passwordHash).slice(0, 16);
  }

  issueToken(user, passwordHash) {
    return jwt.sign({ role: 'user', pv: this.pv(passwordHash), uid: user.id }, this.jwtSecret, {
      algorithm: 'HS256',
      expiresIn: USER_TOKEN_TTL_SECONDS,
      subject: user.username,
    });
  }

  /** Checks signature/expiry only. The caller compares `pv` with the user's current password hash. */
  verifyToken(token) {
    if (typeof token !== 'string' || token.length > 2000) return null;
    try {
      const p = jwt.verify(token, this.jwtSecret, { algorithms: ['HS256'] });
      if (p.role !== 'user' || typeof p.sub !== 'string' || typeof p.pv !== 'string') return null;
      return { username: p.sub, pv: p.pv, uid: p.uid };
    } catch {
      return null;
    }
  }
}

module.exports = { UserDirectory, AccountAuth, BCRYPT_COST };
