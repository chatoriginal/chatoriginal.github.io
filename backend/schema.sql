-- TerminalChat — Supabase / PostgreSQL schema
-- Run this in the Supabase dashboard: SQL Editor -> New query -> paste -> Run.
-- It is SAFE TO RE-RUN: on an existing database it only adds what is missing.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- Rooms
-- ---------------------------------------------------------------------------
create table if not exists public.rooms (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  description text not null default '',
  created_by  text,
  created_at  timestamptz not null default now(),
  constraint rooms_name_format check (name ~ '^[a-z0-9][a-z0-9-]{1,23}$'),
  constraint rooms_description_length check (char_length(description) <= 80)
);
create unique index if not exists rooms_name_unique on public.rooms (lower(name));

-- ---------------------------------------------------------------------------
-- Accounts (guests and the env-configured admins are NOT stored here)
-- ---------------------------------------------------------------------------
create table if not exists public.users (
  id            uuid primary key default gen_random_uuid(),
  username      text not null,                 -- login name, no spaces
  username_lower text not null,
  display_name  text not null,                 -- what other people see in chat
  display_lower text not null,
  password_hash text not null,                 -- bcrypt, never the password
  bio           text not null default '',
  created_at    timestamptz not null default now(),
  constraint users_username_format check (username ~ '^[A-Za-z][A-Za-z0-9_-]{2,19}$'),
  constraint users_display_length  check (char_length(display_name) between 1 and 24),
  constraint users_bio_length      check (char_length(bio) <= 160)
);
create unique index if not exists users_username_lower_idx on public.users (username_lower);
create unique index if not exists users_display_lower_idx  on public.users (display_lower);

-- ---------------------------------------------------------------------------
-- Messages — room messages AND private DMs live in one compact table.
--   room message : room_id set,  dm_key null
--   private DM   : room_id null, dm_key = "alice|bob" (sorted, lowercase)
-- ---------------------------------------------------------------------------
create table if not exists public.messages (
  id         bigint generated always as identity primary key,
  room_id    uuid references public.rooms (id) on delete cascade,
  username   text not null,
  is_admin   boolean not null default false,
  content    text not null,
  deleted    boolean not null default false,
  created_at timestamptz not null default now()
);

-- file attachments (files themselves live in Supabase Storage, bucket "attachments")
alter table public.messages add column if not exists attachment_path text;
alter table public.messages add column if not exists attachment_name text;
alter table public.messages add column if not exists attachment_size integer;

-- replies, edits, pins, reactions, system messages, DMs
alter table public.messages add column if not exists reply_to  bigint;                    -- id of the message replied to
alter table public.messages add column if not exists edited    boolean not null default false;
alter table public.messages add column if not exists pinned    boolean not null default false;
alter table public.messages add column if not exists reactions jsonb;                     -- {"👍":["alice","bob"]}; null = none
alter table public.messages add column if not exists kind      text not null default 'user';  -- 'user' | 'system'
alter table public.messages add column if not exists dm_key    text;
alter table public.messages alter column room_id drop not null;

alter table public.messages drop constraint if exists messages_content_length;
alter table public.messages drop constraint if exists messages_content_or_file;
alter table public.messages add constraint messages_content_or_file check (
  char_length(content) <= 2000
  and (char_length(content) >= 1 or attachment_path is not null)
);
alter table public.messages drop constraint if exists messages_scope;
alter table public.messages add constraint messages_scope check ((room_id is not null) <> (dm_key is not null));

create index if not exists messages_room_id_id_idx on public.messages (room_id, id desc);
create index if not exists messages_dm_key_id_idx  on public.messages (dm_key, id desc) where dm_key is not null;
create index if not exists messages_pinned_idx     on public.messages (room_id) where pinned;

-- ---------------------------------------------------------------------------
-- DM threads: a tiny index of who talks to whom, plus read markers (for "unread")
-- ---------------------------------------------------------------------------
create table if not exists public.dm_threads (
  user_a      text not null,
  user_b      text not null,
  updated_at  timestamptz not null default now(),
  last_sender text,
  read_a      timestamptz,
  read_b      timestamptz,
  primary key (user_a, user_b)
);
create index if not exists dm_threads_user_b_idx on public.dm_threads (user_b);

-- ---------------------------------------------------------------------------
-- Bans and mutes (IP addresses are stored only as keyed hashes)
-- ---------------------------------------------------------------------------
create table if not exists public.bans (
  id             bigint generated always as identity primary key,
  username_lower text,
  ip_hash        text,
  reason         text,
  created_by     text,
  created_at     timestamptz not null default now(),
  constraint bans_has_target check (username_lower is not null or ip_hash is not null)
);

create table if not exists public.mutes (
  username_lower text primary key,
  until          timestamptz,                  -- null = until unmuted
  reason         text,
  created_by     text,
  created_at     timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Security: Row Level Security ON with NO policies.
-- The browser never talks to Supabase. Only the backend does, using the
-- service-role key (which bypasses RLS). Anyone holding just the public anon
-- key therefore cannot read or write any of these tables.
-- ---------------------------------------------------------------------------
alter table public.rooms       enable row level security;
alter table public.users       enable row level security;
alter table public.messages    enable row level security;
alter table public.dm_threads  enable row level security;
alter table public.bans        enable row level security;
alter table public.mutes       enable row level security;

-- ---------------------------------------------------------------------------
-- Starter room (guests can only use the room called "general")
-- ---------------------------------------------------------------------------
insert into public.rooms (name, description, created_by)
values ('general', 'Welcome to TerminalChat — say hello.', 'setup')
on conflict do nothing;
