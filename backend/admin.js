'use strict';

/**
 * admin.js — administrator authentication (up to two accounts).
 *
 * - Credentials live only in environment variables:
 *     ADMIN_USERNAME  + ADMIN_PASSWORD_HASH (bcrypt) or ADMIN_PASSWORD   (account 1, required)
 *     ADMIN2_USERNAME + ADMIN2_PASSWORD_HASH or ADMIN2_PASSWORD          (account 2, optional)
 *     JWT_SECRET
 * - A plain *_PASSWORD is hashed with bcrypt in memory at startup; it is never stored in code.
 * - A successful login yields a signed JWT (12h). Each token is bound to that account's
 *   password hash, so changing a password invalidates that account's old tokens.
 * - Failed logins are throttled per IP address.
 *
 * CLI helpers:
 *     npm run hash-password   -> prompts for a password and prints a bcrypt hash
 *     npm run gen-secret      -> prints a random JWT secret
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const TOKEN_TTL_SECONDS = 12 * 60 * 60;
const MAX_FAILURES = 5;
const FAILURE_WINDOW_MS = 15 * 60 * 1000;
const MAX_PASSWORD_LENGTH = 200; // guard against absurdly large inputs reaching bcrypt
const ADMIN_NAME_RE = /^[A-Za-z][A-Za-z0-9_-]{2,19}$/;
const BCRYPT_RE = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;

// Compared against when the username is wrong, so timing does not reveal which part failed.
const DUMMY_HASH = bcrypt.hashSync('terminalchat-dummy-password', 10);

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest();
}

function safeEqual(a, b) {
  return crypto.timingSafeEqual(sha256(String(a)), sha256(String(b)));
}

/** Reads and validates admin-related env vars. `problems` is empty when everything is OK. */
function loadAdminConfig(env = process.env) {
  const jwtSecret = env.JWT_SECRET || '';
  const problems = [];
  const accounts = [];

  const slots = [
    { prefix: 'ADMIN', optional: false },
    { prefix: 'ADMIN2', optional: true },
  ];

  for (const { prefix, optional } of slots) {
    const username = (env[`${prefix}_USERNAME`] || '').trim();
    let passwordHash = (env[`${prefix}_PASSWORD_HASH`] || '').trim();
    const plain = env[`${prefix}_PASSWORD`] || '';

    // The second account is optional: leave all three variables unset to run with one admin.
    if (optional && !username && !passwordHash && !plain) continue;

    let ok = true;
    if (!username) {
      problems.push(`${prefix}_USERNAME is not set.`);
      ok = false;
    } else if (!ADMIN_NAME_RE.test(username)) {
      problems.push(`${prefix}_USERNAME must be 3–20 characters: letters, numbers, "_" or "-", starting with a letter.`);
      ok = false;
    }

    // Beginner-friendly: set *_PASSWORD instead of *_PASSWORD_HASH and the server hashes it
    // at startup. The plain password lives only in the host's private environment settings.
    if (!passwordHash && plain) {
      if (plain.length < 12) {
        problems.push(`${prefix}_PASSWORD must be at least 12 characters.`);
        ok = false;
      } else {
        passwordHash = bcrypt.hashSync(plain, 12);
      }
    }

    if (!passwordHash) {
      if (!plain) problems.push(`Set ${prefix}_PASSWORD (12+ characters), or ${prefix}_PASSWORD_HASH from "npm run hash-password".`);
      ok = false;
    } else if (!BCRYPT_RE.test(passwordHash)) {
      problems.push(`${prefix}_PASSWORD_HASH is not a valid bcrypt hash (it should start with "$2a$", "$2b$" or "$2y$").`);
      ok = false;
    }

    if (ok) accounts.push({ username, passwordHash });
  }

  const seen = new Set();
  for (const a of accounts) {
    const key = a.username.toLowerCase();
    if (seen.has(key)) problems.push('ADMIN_USERNAME and ADMIN2_USERNAME must be different.');
    seen.add(key);
  }

  if (jwtSecret.length < 32) problems.push('JWT_SECRET must be at least 32 characters (run "npm run gen-secret").');

  return { accounts, jwtSecret, problems };
}

class AdminAuth {
  constructor({ accounts, jwtSecret }) {
    this.jwtSecret = jwtSecret;
    this.accounts = accounts.map((a) => ({
      username: a.username,
      lower: a.username.toLowerCase(),
      passwordHash: a.passwordHash,
      // Ties issued tokens to this account's current password hash.
      pv: sha256(a.passwordHash).toString('hex').slice(0, 16),
    }));
    /** @type {Map<string, number>} revoked token ids -> expiry (ms). Memory only; cleared on restart. */
    this.revoked = new Map();
    /** @type {Map<string, {count:number, first:number}>} */
    this.failures = new Map();

    const timer = setInterval(() => this.cleanup(), 5 * 60 * 1000);
    if (timer.unref) timer.unref();
  }

  get usernames() {
    return this.accounts.map((a) => a.username);
  }

  /** Looks an account up by name without an early exit, so timing does not leak which names exist. */
  findAccount(username) {
    const candidate = String(username).trim().toLowerCase();
    let found = null;
    for (const a of this.accounts) {
      if (safeEqual(a.lower, candidate)) found = a;
    }
    return found;
  }

  cleanup() {
    const now = Date.now();
    for (const [ip, f] of this.failures) if (now - f.first > FAILURE_WINDOW_MS) this.failures.delete(ip);
    for (const [jti, exp] of this.revoked) if (exp < now) this.revoked.delete(jti);
  }

  isLocked(ip) {
    const f = this.failures.get(ip);
    if (!f) return false;
    if (Date.now() - f.first > FAILURE_WINDOW_MS) {
      this.failures.delete(ip);
      return false;
    }
    return f.count >= MAX_FAILURES;
  }

  recordFailure(ip) {
    const now = Date.now();
    const f = this.failures.get(ip);
    if (!f || now - f.first > FAILURE_WINDOW_MS) this.failures.set(ip, { count: 1, first: now });
    else f.count += 1;
  }

  /** Returns { ok: true, username } or { ok: false, locked: boolean }. */
  async verifyLogin(ip, username, password) {
    if (this.isLocked(ip)) return { ok: false, locked: true };
    if (
      typeof username !== 'string' || typeof password !== 'string' ||
      username.length > 64 || password.length === 0 || password.length > MAX_PASSWORD_LENGTH
    ) {
      this.recordFailure(ip);
      return { ok: false, locked: false };
    }
    const account = this.findAccount(username);
    // Always run bcrypt so response time is the same for a wrong username.
    const passOk = await bcrypt.compare(password, account ? account.passwordHash : DUMMY_HASH);
    if (account && passOk) {
      this.failures.delete(ip);
      return { ok: true, username: account.username };
    }
    this.recordFailure(ip);
    return { ok: false, locked: this.isLocked(ip) };
  }

  issueToken(username) {
    const account = this.findAccount(username);
    if (!account) throw new Error('Unknown administrator account.');
    const jti = crypto.randomBytes(16).toString('hex');
    const token = jwt.sign({ role: 'admin', pv: account.pv, jti }, this.jwtSecret, {
      algorithm: 'HS256',
      expiresIn: TOKEN_TTL_SECONDS,
      subject: account.username,
    });
    return { token, jti, expiresAt: Date.now() + TOKEN_TTL_SECONDS * 1000 };
  }

  /** Returns { jti, expiresAt, username } for a valid token, otherwise null. */
  verifyToken(token) {
    if (typeof token !== 'string' || token.length > 2000) return null;
    try {
      const p = jwt.verify(token, this.jwtSecret, { algorithms: ['HS256'] });
      if (p.role !== 'admin' || typeof p.sub !== 'string') return null;
      const account = this.findAccount(p.sub);
      if (!account || p.pv !== account.pv) return null;
      if (this.revoked.has(p.jti)) return null;
      return { jti: p.jti, expiresAt: p.exp * 1000, username: account.username };
    } catch {
      return null;
    }
  }

  revoke(jti, expiresAt) {
    if (jti) this.revoked.set(jti, expiresAt || Date.now() + TOKEN_TTL_SECONDS * 1000);
  }
}

// ---------------------------------------------------------------------------
// CLI: node admin.js hash | node admin.js secret
// ---------------------------------------------------------------------------

function promptHidden(question) {
  const readline = require('readline');
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl.stdoutMuted = false;
    rl._writeToOutput = function writeToOutput(str) {
      if (!rl.stdoutMuted) rl.output.write(str);
    };
    rl.question(question, (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
    rl.stdoutMuted = true;
  });
}

async function readPassword(question) {
  if (process.stdin.isTTY) return promptHidden(question);
  // Piped input: read the first line from stdin.
  return new Promise((resolve) => {
    let buf = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { buf += c; });
    process.stdin.on('end', () => resolve(buf.split(/\r?\n/)[0] || ''));
  });
}

async function cli() {
  const cmd = process.argv[2];
  if (cmd === 'secret') {
    console.log(crypto.randomBytes(48).toString('hex'));
    return;
  }
  if (cmd === 'hash') {
    console.log('Choose an administrator password (at least 12 characters). Input is hidden.');
    const pw = await readPassword('Password: ');
    if (pw.length < 12) {
      console.error('Password must be at least 12 characters.');
      process.exit(1);
    }
    if (process.stdin.isTTY) {
      const again = await readPassword('Repeat password: ');
      if (again !== pw) {
        console.error('Passwords did not match.');
        process.exit(1);
      }
    }
    const hash = await bcrypt.hash(pw, 12);
    console.log('\nPut this value in ADMIN_PASSWORD_HASH (or ADMIN2_PASSWORD_HASH):\n');
    console.log(hash);
    console.log('\n(The password itself is not stored anywhere. Keep the hash out of git.)');
    return;
  }
  console.log('Usage:\n  node admin.js hash     create a bcrypt hash for ADMIN_PASSWORD_HASH / ADMIN2_PASSWORD_HASH\n  node admin.js secret   print a random value for JWT_SECRET');
}

if (require.main === module) {
  cli().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { AdminAuth, loadAdminConfig, TOKEN_TTL_SECONDS };
