'use strict';

/**
 * database.js — thin wrapper around Supabase (PostgreSQL + Storage).
 *
 * Uses the SERVICE ROLE key, which bypasses Row Level Security. That key must
 * only ever exist in the backend's environment variables, never in the browser.
 *
 * Injection safety: every query goes through supabase-js, which sends values as URL-encoded
 * parameters to PostgREST (no SQL strings are ever built here), and callers only pass values
 * that already passed the strict allow-list validators in rooms.js.
 */

const { createClient } = require('@supabase/supabase-js');

function createDatabase({ url, serviceRoleKey, bucket = 'attachments' }) {
  const sb = createClient(url, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const baseUrl = String(url).replace(/\/+$/, '');

  function fail(op, error) {
    const err = new Error(`${op} failed: ${error.message}`);
    err.code = error.code;
    throw err;
  }

  const MESSAGE_COLUMNS =
    'id, room_id, dm_key, username, is_admin, content, created_at, kind, edited, pinned, reactions, reply_to, ' +
    'attachment_path, attachment_name, attachment_size';
  const USER_COLUMNS = 'id, username, username_lower, display_name, bio, created_at';

  /** Deletes stored files. Failures are logged, never thrown (a leftover file is not fatal). */
  async function removeFiles(paths) {
    const list = (paths || []).filter(Boolean);
    for (let i = 0; i < list.length; i += 100) {
      try {
        const { error } = await sb.storage.from(bucket).remove(list.slice(i, i + 100));
        if (error) console.error('[storage] remove failed:', error.message);
      } catch (err) {
        console.error('[storage] remove failed:', err.message);
      }
    }
  }

  return {
    removeFiles,

    /** Throws if the database is missing anything the current version needs. */
    async checkSchema() {
      const checks = [
        ['messages', 'attachment_path, reply_to, edited, pinned, reactions, kind, dm_key'],
        ['users', 'id, username_lower, display_lower, password_hash, bio'],
        ['dm_threads', 'user_a, user_b, updated_at, last_sender, read_a, read_b'],
        ['mutes', 'username_lower, until'],
      ];
      for (const [table, cols] of checks) {
        const { error } = await sb.from(table).select(cols).limit(1);
        if (error) {
          throw new Error(`the database schema is out of date (${table}: ${error.message}). Re-run backend/schema.sql in the Supabase SQL editor`);
        }
      }
    },

    // ---------- rooms ----------
    async listRooms() {
      const { data, error } = await sb
        .from('rooms')
        .select('id, name, description, created_at')
        .order('name', { ascending: true });
      if (error) fail('listRooms', error);
      return data;
    },

    async createRoom({ name, description, createdBy }) {
      const { data, error } = await sb
        .from('rooms')
        .insert({ name, description, created_by: createdBy })
        .select('id, name, description, created_at')
        .single();
      if (error) fail('createRoom', error);
      return data;
    },

    async deleteRoom(id) {
      // messages are removed by ON DELETE CASCADE
      const { error } = await sb.from('rooms').delete().eq('id', id);
      if (error) fail('deleteRoom', error);
    },

    // ---------- users ----------
    async createUser({ username, displayName, displayLower, passwordHash }) {
      const { data, error } = await sb
        .from('users')
        .insert({
          username,
          username_lower: username.toLowerCase(),
          display_name: displayName,
          display_lower: displayLower,
          password_hash: passwordHash,
        })
        .select(USER_COLUMNS)
        .single();
      if (error) fail('createUser', error);
      return data;
    },

    /** Includes the password hash — only for logging in / changing a password. */
    async getUserWithHash(usernameLower) {
      const { data, error } = await sb
        .from('users')
        .select(`${USER_COLUMNS}, password_hash`)
        .eq('username_lower', usernameLower)
        .maybeSingle();
      if (error) fail('getUserWithHash', error);
      return data;
    },

    async getUser(usernameLower) {
      const { data, error } = await sb.from('users').select(USER_COLUMNS).eq('username_lower', usernameLower).maybeSingle();
      if (error) fail('getUser', error);
      return data;
    },

    async getUsers(usernameLowers) {
      if (!usernameLowers.length) return [];
      const { data, error } = await sb.from('users').select(USER_COLUMNS).in('username_lower', usernameLowers);
      if (error) fail('getUsers', error);
      return data;
    },

    /**
     * True if `usernameLower` / `displayKey` collide with any member's username or display name
     * (in either direction), so nobody can pose as someone else with a look-alike name.
     */
    async nameTaken(usernameLower, displayKey) {
      const probes = [
        ['username_lower', usernameLower],
        ['display_lower', displayKey],
        ['display_lower', usernameLower],
        ['username_lower', displayKey],
      ];
      for (const [column, value] of probes) {
        if (!value || (column === 'username_lower' && !/^[a-z][a-z0-9_-]{2,19}$/.test(value))) continue;
        const { data, error } = await sb.from('users').select('id').eq(column, value).maybeSingle();
        if (error) fail('nameTaken', error);
        if (data) return true;
      }
      return false;
    },

    /** Does this display name collide with someone ELSE's display name or username? */
    async displayNameConflict(displayKey, selfLower) {
      const a = await sb.from('users').select('username_lower').eq('display_lower', displayKey).maybeSingle();
      if (a.error) fail('displayNameConflict', a.error);
      if (a.data && a.data.username_lower !== selfLower) return true;
      if (/^[a-z][a-z0-9_-]{2,19}$/.test(displayKey)) {
        const b = await sb.from('users').select('username_lower').eq('username_lower', displayKey).maybeSingle();
        if (b.error) fail('displayNameConflict', b.error);
        if (b.data && b.data.username_lower !== selfLower) return true;
      }
      return false;
    },

    async updateProfile(id, { displayName, displayLower, bio }) {
      const patch = {};
      if (displayName !== undefined) {
        patch.display_name = displayName;
        patch.display_lower = displayLower;
      }
      if (bio !== undefined) patch.bio = bio;
      const { data, error } = await sb.from('users').update(patch).eq('id', id).select(USER_COLUMNS).single();
      if (error) fail('updateProfile', error);
      return data;
    },

    async updatePasswordHash(id, passwordHash) {
      const { error } = await sb.from('users').update({ password_hash: passwordHash }).eq('id', id);
      if (error) fail('updatePasswordHash', error);
    },

    // ---------- messages ----------
    async insertMessage({ roomId, dmKey, username, isAdmin, content, attachment, replyTo, kind }) {
      const row = { username, is_admin: !!isAdmin, content };
      if (roomId) row.room_id = roomId;
      if (dmKey) row.dm_key = dmKey;
      if (replyTo) row.reply_to = replyTo;
      if (kind && kind !== 'user') row.kind = kind;
      if (attachment) {
        row.attachment_path = attachment.path;
        row.attachment_name = attachment.name;
        row.attachment_size = attachment.size;
      }
      const { data, error } = await sb.from('messages').insert(row).select(MESSAGE_COLUMNS).single();
      if (error) fail('insertMessage', error);
      return data;
    },

    /** Same system message into many rooms at once (used by /announce). */
    async insertSystemMessages(roomIds, content) {
      if (!roomIds.length) return [];
      const rows = roomIds.map((room_id) => ({ room_id, username: 'System', is_admin: true, content, kind: 'system' }));
      const { data, error } = await sb.from('messages').insert(rows).select(MESSAGE_COLUMNS);
      if (error) fail('insertSystemMessages', error);
      return data;
    },

    async getMessage(id) {
      const { data, error } = await sb.from('messages').select(MESSAGE_COLUMNS).eq('id', id).maybeSingle();
      if (error) fail('getMessage', error);
      return data;
    },

    async getMessagesByIds(ids) {
      if (!ids.length) return [];
      const { data, error } = await sb.from('messages').select(MESSAGE_COLUMNS).in('id', ids);
      if (error) fail('getMessagesByIds', error);
      return data;
    },

    async getRecentMessages(roomId, limit) {
      const { data, error } = await sb
        .from('messages')
        .select(MESSAGE_COLUMNS)
        .eq('room_id', roomId)
        .order('id', { ascending: false })
        .limit(limit);
      if (error) fail('getRecentMessages', error);
      return data.reverse();
    },

    async getDmMessages(dmKey, limit, beforeId) {
      let q = sb.from('messages').select(MESSAGE_COLUMNS).eq('dm_key', dmKey);
      if (beforeId) q = q.lt('id', beforeId);
      const { data, error } = await q.order('id', { ascending: false }).limit(limit);
      if (error) fail('getDmMessages', error);
      return data.reverse();
    },

    async listPinned(roomId) {
      const { data, error } = await sb
        .from('messages')
        .select(MESSAGE_COLUMNS)
        .eq('room_id', roomId)
        .eq('pinned', true)
        .order('id', { ascending: true })
        .limit(50);
      if (error) fail('listPinned', error);
      return data;
    },

    async countPinned(roomId) {
      const { count, error } = await sb
        .from('messages')
        .select('id', { count: 'exact', head: true })
        .eq('room_id', roomId)
        .eq('pinned', true);
      if (error) fail('countPinned', error);
      return count || 0;
    },

    async updateContent(id, content) {
      const { data, error } = await sb
        .from('messages')
        .update({ content, edited: true })
        .eq('id', id)
        .select(MESSAGE_COLUMNS)
        .maybeSingle();
      if (error) fail('updateContent', error);
      return data;
    },

    async setPinned(id, pinned) {
      const { data, error } = await sb.from('messages').update({ pinned }).eq('id', id).select(MESSAGE_COLUMNS).maybeSingle();
      if (error) fail('setPinned', error);
      return data;
    },

    async setReactions(id, reactions) {
      const { error } = await sb.from('messages').update({ reactions }).eq('id', id);
      if (error) fail('setReactions', error);
    },

    /** Hard-deletes a message (rows stay small; nothing lingers). Returns the deleted row or null. */
    async deleteMessage(id) {
      const { data, error } = await sb
        .from('messages')
        .delete()
        .eq('id', id)
        .select('id, room_id, dm_key, attachment_path')
        .maybeSingle();
      if (error) fail('deleteMessage', error);
      return data;
    },

    /** Storage paths of every attachment in a room (used before deleting the room). */
    async listRoomAttachmentPaths(roomId) {
      const { data, error } = await sb
        .from('messages')
        .select('attachment_path')
        .eq('room_id', roomId)
        .not('attachment_path', 'is', null);
      if (error) fail('listRoomAttachmentPaths', error);
      return data.map((r) => r.attachment_path);
    },

    /**
     * Keeps only the newest `keep` UNPINNED messages of a room; older ones (and their files) are
     * deleted. Pinned messages are exempt. Returns the id below which messages were removed, or null.
     * Private DMs are never touched.
     */
    async pruneRoom(roomId, keep) {
      const { data, error } = await sb
        .from('messages')
        .select('id')
        .eq('room_id', roomId)
        .eq('pinned', false)
        .order('id', { ascending: false })
        .range(keep - 1, keep - 1);
      if (error) fail('pruneRoom', error);
      if (!data || !data.length) return null;
      const cutoff = data[0].id;
      const { data: old, error: oldError } = await sb
        .from('messages')
        .select('attachment_path')
        .eq('room_id', roomId)
        .eq('pinned', false)
        .lt('id', cutoff)
        .not('attachment_path', 'is', null);
      if (oldError) fail('pruneRoom list', oldError);
      const { data: gone, error: delError } = await sb
        .from('messages')
        .delete()
        .eq('room_id', roomId)
        .eq('pinned', false)
        .lt('id', cutoff)
        .select('id');
      if (delError) fail('pruneRoom delete', delError);
      await removeFiles(old.map((r) => r.attachment_path));
      return gone && gone.length ? cutoff : null;
    },

    /** Deletes the newest `count` unpinned messages of a room (the .purge command). Returns the deleted ids. */
    async purgeRoom(roomId, count) {
      const { data, error } = await sb
        .from('messages')
        .select('id, attachment_path')
        .eq('room_id', roomId)
        .eq('pinned', false)
        .order('id', { ascending: false })
        .limit(count);
      if (error) fail('purgeRoom', error);
      if (!data.length) return [];
      const ids = data.map((r) => r.id);
      const { error: delError } = await sb.from('messages').delete().in('id', ids);
      if (delError) fail('purgeRoom delete', delError);
      await removeFiles(data.map((r) => r.attachment_path));
      return ids;
    },

    // ---------- DM threads ----------
    async touchThread(a, b, sender) {
      const now = new Date().toISOString();
      const row = { user_a: a, user_b: b, updated_at: now, last_sender: sender };
      // the sender has, by definition, read the thread up to now
      row[sender === a ? 'read_a' : 'read_b'] = now;
      const { error } = await sb.from('dm_threads').upsert(row, { onConflict: 'user_a,user_b' });
      if (error) fail('touchThread', error);
    },

    async markThreadRead(a, b, reader) {
      const col = reader === a ? 'read_a' : 'read_b';
      const { error } = await sb
        .from('dm_threads')
        .update({ [col]: new Date().toISOString() })
        .eq('user_a', a)
        .eq('user_b', b);
      if (error) fail('markThreadRead', error);
    },

    async listThreads(me) {
      const [x, y] = await Promise.all([
        sb.from('dm_threads').select('*').eq('user_a', me).order('updated_at', { ascending: false }).limit(100),
        sb.from('dm_threads').select('*').eq('user_b', me).order('updated_at', { ascending: false }).limit(100),
      ]);
      if (x.error) fail('listThreads', x.error);
      if (y.error) fail('listThreads', y.error);
      return [...x.data, ...y.data];
    },

    // ---------- file storage (Supabase Storage) ----------
    /** Creates the public "attachments" bucket if it does not exist yet. */
    async ensureBucket(maxBytes) {
      const { error } = await sb.storage.createBucket(bucket, { public: true, fileSizeLimit: maxBytes });
      if (error && !/already exists|duplicate/i.test(error.message)) {
        throw new Error(`could not create the "${bucket}" storage bucket: ${error.message}`);
      }
    },

    async uploadFile(path, buffer, contentType) {
      const { error } = await sb.storage.from(bucket).upload(path, buffer, {
        contentType,
        upsert: false,
        cacheControl: '31536000',
      });
      if (error) throw new Error(`uploadFile failed: ${error.message}`);
    },

    /** Public URL of a stored file. With downloadName the browser downloads it instead of displaying it. */
    publicUrl(path, downloadName) {
      const encoded = path.split('/').map(encodeURIComponent).join('/');
      const u = `${baseUrl}/storage/v1/object/public/${bucket}/${encoded}`;
      return downloadName ? `${u}?download=${encodeURIComponent(downloadName)}` : u;
    },

    // ---------- bans ----------
    async listBans() {
      const { data, error } = await sb
        .from('bans')
        .select('id, username_lower, ip_hash, reason, created_by, created_at')
        .order('id', { ascending: false });
      if (error) fail('listBans', error);
      return data;
    },

    async addBan({ usernameLower, ipHash, reason, createdBy }) {
      const { data, error } = await sb
        .from('bans')
        .insert({
          username_lower: usernameLower || null,
          ip_hash: ipHash || null,
          reason: reason || null,
          created_by: createdBy,
        })
        .select('id, username_lower, ip_hash, reason, created_by, created_at')
        .single();
      if (error) fail('addBan', error);
      return data;
    },

    /** Returns the removed row, or null if it did not exist. */
    async removeBan(id) {
      const { data, error } = await sb.from('bans').delete().eq('id', id).select('id').maybeSingle();
      if (error) fail('removeBan', error);
      return data;
    },

    /** Removes every ban on a username (the .unban command). Returns how many were removed. */
    async removeBansByUsername(usernameLower) {
      const { data, error } = await sb.from('bans').delete().eq('username_lower', usernameLower).select('id');
      if (error) fail('removeBansByUsername', error);
      return data ? data.length : 0;
    },

    // ---------- mutes ----------
    async listMutes() {
      const { data, error } = await sb.from('mutes').select('username_lower, until, reason');
      if (error) fail('listMutes', error);
      return data;
    },

    async setMute({ usernameLower, until, reason, createdBy }) {
      const { error } = await sb
        .from('mutes')
        .upsert(
          { username_lower: usernameLower, until: until ? new Date(until).toISOString() : null, reason: reason || null, created_by: createdBy },
          { onConflict: 'username_lower' }
        );
      if (error) fail('setMute', error);
    },

    async removeMute(usernameLower) {
      const { error } = await sb.from('mutes').delete().eq('username_lower', usernameLower);
      if (error) fail('removeMute', error);
    },
  };
}

module.exports = { createDatabase };
