# TerminalChat 1.0.0

An IRC-inspired public chat. **Frontend = one file (`index.html`)**, backend = Node.js + Express + Socket.IO on Render, data in Supabase.

## Repo layout

```
index.html        <- the whole frontend (HTML + CSS + JS). Edit this one file to change the site.
backend/          <- server code (deployed to Render, Root Directory = backend)
  server.js  rooms.js  database.js  accounts.js  admin.js
  schema.sql  package.json  .env.example
README.md
```

Delete the old `style.css`, `app.js` and `config.js` from the repo root; they are no longer used.

## Updating an existing deployment (do these in order)

1. **Supabase → SQL Editor:** paste all of `backend/schema.sql` and Run. It is safe to re-run and only adds what is missing
   (accounts, DMs, replies, reactions, pins, mutes).
2. **GitHub:** upload the new `index.html` (root) and the `backend/` files, replacing the old ones.
3. **Render:** it redeploys automatically. Environment variables you already have keep working. New optional ones:
   `ADMIN2_USERNAME` + `ADMIN2_PASSWORD` (second admin), `MAX_STORED_MESSAGES_PER_ROOM` (default 100).
4. Hard-refresh the site (Ctrl+Shift+R).

If your backend URL is not `https://terminalchat-gsel.onrender.com`, change `PRODUCTION_BACKEND` near the top of the `<script>` in `index.html`.
To release a new version, change `APP_VERSION` on the line above it.

## Features

| Feature | How it works |
|---|---|
| Login / Sign up / Guest | Accounts have a **username** (no spaces, used to log in) and a **display name** (shown in chat). Passwords are bcrypt-hashed. Guests pick any username, can only use `#general`, and have no DMs. |
| Profiles | Click any name to see their profile and bio. Edit yours in ⚙ Settings. |
| Replies, edit, delete | Hover a message (tap on phones). You can edit/delete your own; admins can delete anything in rooms. |
| Reactions | Hover → 😊 → pick an emoji or type any emoji. |
| Markdown | `**bold**` `*italic*` `~~strike~~` `` `code` `` code blocks, `[links](https://…)`, `> quotes`, lists, `# headings`. No images or raw HTML. |
| Shift+Enter | New line. Enter sends. |
| Mentions & notifications | `@username` (or a one-word display name) notifies that person: toast, browser notification (if allowed), tab-title count. Replies and DMs notify too. Only people **online** get a ping. |
| Private DMs | Members only. Stored permanently (never auto-deleted). Unread markers. |
| Typing indicator | Names for 1–3, "A, B, C and N others" for 4–9, "Several people are typing…" for 10+. |
| Slowmode | If a room gets flooded it enters 2 s slowmode, and goes up 1 s at a time while people keep spamming (max 30 s). Turns off after a quiet minute. Admins are exempt. |
| Files & images | 📎, paste, or drag-and-drop (max `MAX_UPLOAD_MB`). |
| Lightweight storage | Each room keeps only its newest 100 messages (pinned ones stay). DMs are never pruned. |
| Version | Tiny text top-right. |

### Admin commands (admins only; type them in a room)

| Command | Effect |
|---|---|
| `.mute <user> [minutes]` / `.unmute <user>` | Default 10 minutes, max 7 days. |
| `.ban <user> [reason]` / `.unban <user>` | Username ban. For an **IP ban** use the profile popup (checkbox is unticked by default). |
| `.purge <1-100>` | Deletes the last N unpinned messages in the current room. |
| `/announce <text>` | Posts a **System Message** in every room and notifies everyone online. |

Anything that is not one of those commands, or anyone who is not an admin, just sends a normal message, with no "unknown command" error.
Admins can also pin/unpin messages (hover toolbar) and manage rooms and bans from the 🛡 panel.

## Security notes

- Every request is validated on the server; the browser is never trusted. Roles are decided only by the server after a password/token check.
- Database access uses the Supabase service-role key (backend only) through parameterised queries; usernames are checked against a strict allow-list (`A-Z a-z 0-9 _ -`, no spaces) **before** any query. Row Level Security is on with no public policies.
- Login throttling per IP and per username; signup limit per IP; per-socket rate limits; flood protection.
- The single-file frontend needs `'unsafe-inline'` in its Content-Security-Policy (inline script/style). Message text is never inserted as HTML.
- Never put secrets in `index.html`.

## Limits worth knowing

- Render's free plan sleeps when idle; the first load can take about a minute.
- Supabase free projects pause after ~1 week of inactivity.
- Mentions are not stored for people who are offline.
