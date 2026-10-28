-- =============================================================================
-- Hermes: MLS (RFC 9420) group chat with Supabase as an untrusted relay.
-- =============================================================================
-- Replaces the v0.1 schema (one static key per group, invite code = key).
-- Nothing from v0.1 can be carried over: its ciphertext used keys that MLS
-- groups don't have, so the old tables are dropped.
-- -----------------------------------------------------------------------------
drop table if exists public.messages cascade;
drop table if exists public.members cascade;
drop table if exists public.groups cascade;
drop function if exists public.is_member(text);
drop function if exists public.create_group(text, text, text);
drop function if exists public.join_group(text, text);
drop function if exists public.drop_empty_group();
-- =============================================================================
-- The server never holds a key. It stores:
--   * opaque MLS messages (commits and application messages, all ciphertext)
--   * the epoch of every group, to totally order commits
--   * members: anonymous user id, role, and MLS signature public key
--   * invites: SHA-256 of a short random code, 5-minute lifetime, single use
--   * join requests: the requester's KeyPackage and, once accepted, the Welcome
--
-- Authorization lives here (roles, who may commit, invite lifetime, epoch
-- order). Confidentiality lives in MLS on the clients.
--
-- Every write goes through a SECURITY DEFINER RPC; authenticated users only
-- have SELECT on public tables, filtered by RLS. Error codes PTxyz are mapped
-- by PostgREST to HTTP status xyz.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Schemas and base grants
-- ---------------------------------------------------------------------------
create schema private;

revoke all on schema public from public;
revoke all on schema public from anon;
grant usage on schema public to authenticated, service_role;

-- private: closed. authenticated only gets USAGE so RLS policies can call the
-- helper functions; no table in it is granted.
revoke all on schema private from public;
revoke all on schema private from anon;
grant usage on schema private to authenticated;

-- Functions are not executable by PUBLIC unless granted explicitly below.
alter default privileges in schema public revoke execute on functions from public;
alter default privileges in schema private revoke execute on functions from public;
alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke all on sequences from anon, authenticated;
alter default privileges in schema public revoke execute on functions from anon, authenticated;

create type public.group_role as enum ('owner', 'admin', 'member');

-- ---------------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------------
create table public.groups (
  id         uuid primary key,
  -- Current MLS epoch. Only private.append_commit advances it.
  epoch      bigint not null default 0 check (epoch >= 0),
  created_at timestamptz not null default now()
);

create table public.members (
  group_id     uuid not null references public.groups (id) on delete cascade,
  user_id      uuid not null references auth.users (id) on delete cascade,
  role         public.group_role not null,
  -- Hex Ed25519 MLS signature key; lets admins find the member's leaf.
  credential   text not null check (credential ~ '^[0-9a-f]{64}$'),
  -- First epoch this member can read. Older messages are hidden by RLS (and
  -- undecryptable anyway: MLS never gave them those epoch secrets).
  joined_epoch bigint not null check (joined_epoch >= 0),
  joined_at    timestamptz not null default now(),
  primary key (group_id, user_id),
  unique (group_id, credential)
);
create index members_user_id_idx on public.members (user_id);
create unique index members_one_owner on public.members (group_id) where role = 'owner';

create table public.messages (
  id                bigint generated always as identity primary key,
  group_id          uuid not null references public.groups (id) on delete cascade,
  epoch             bigint not null check (epoch >= 0),
  kind              text not null check (kind in ('commit', 'application')),
  sender_credential text not null check (sender_credential ~ '^[0-9a-f]{64}$'),
  payload           text not null check (length(payload) between 1 and 131072), -- base64 MLSMessage
  created_at        timestamptz not null default now()
);
create index messages_group_id_id_idx on public.messages (group_id, id);
-- At most one commit per epoch: the second of two concurrent commits fails here
-- even if it somehow passed the epoch check.
create unique index messages_one_commit_per_epoch on public.messages (group_id, epoch) where kind = 'commit';

create table public.join_requests (
  id          uuid primary key default gen_random_uuid(),
  group_id    uuid not null references public.groups (id) on delete cascade,
  requester_id uuid not null references auth.users (id) on delete cascade,
  credential  text not null check (credential ~ '^[0-9a-f]{64}$'),
  key_package text not null check (length(key_package) between 1 and 16384),
  status      text not null default 'pending' check (status in ('pending', 'accepted')),
  welcome     text check (length(welcome) <= 1048576),
  -- Same as the invite's expiry: admins can only accept while the code is valid.
  expires_at  timestamptz not null,
  created_at  timestamptz not null default now(),
  check ((status = 'accepted') = (welcome is not null))
);
create index join_requests_group_status_idx on public.join_requests (group_id, status);
create index join_requests_requester_idx on public.join_requests (requester_id);

-- A member left; an admin must commit the MLS Remove for their leaf.
create table public.departures (
  id         uuid primary key default gen_random_uuid(),
  group_id   uuid not null references public.groups (id) on delete cascade,
  credential text not null check (credential ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  unique (group_id, credential)
);

create table private.invites (
  id         uuid primary key default gen_random_uuid(),
  group_id   uuid not null references public.groups (id) on delete cascade,
  code_hash  text not null unique check (code_hash ~ '^[0-9a-f]{64}$'),
  created_by uuid not null references auth.users (id) on delete cascade,
  expires_at timestamptz not null,
  used_at    timestamptz,
  created_at timestamptz not null default now()
);

-- One row per device: SHA-256 of a device secret kept in the OS keystore.
-- Lets a device that lost its anonymous session take its memberships back.
create table private.devices (
  secret_hash text primary key check (secret_hash ~ '^[0-9a-f]{64}$'),
  user_id     uuid not null unique references auth.users (id) on delete cascade,
  claimed_at  timestamptz not null default now()
);

create table private.rate_limit_events (
  id         bigint generated always as identity primary key,
  user_id    uuid not null references auth.users (id) on delete cascade,
  action     text not null,
  created_at timestamptz not null default now()
);
create index rate_limit_events_lookup on private.rate_limit_events (user_id, action, created_at desc);

alter table public.groups             enable row level security;
alter table public.members            enable row level security;
alter table public.messages           enable row level security;
alter table public.join_requests      enable row level security;
alter table public.departures         enable row level security;
alter table private.invites           enable row level security;
alter table private.devices           enable row level security;
alter table private.rate_limit_events enable row level security;
alter table public.groups             force row level security;
alter table public.members            force row level security;
alter table public.messages           force row level security;
alter table public.join_requests      force row level security;
alter table public.departures         force row level security;
alter table private.invites           force row level security;
alter table private.devices           force row level security;
alter table private.rate_limit_events force row level security;

revoke all on all tables in schema public from anon, authenticated;
revoke all on all tables in schema private from anon, authenticated;
grant select on public.groups, public.members, public.messages, public.join_requests, public.departures to authenticated;

-- ---------------------------------------------------------------------------
-- Helpers (used by policies and RPCs)
-- ---------------------------------------------------------------------------
create function private.my_role(p_group_id uuid)
returns public.group_role
language sql
stable
security definer
set search_path = ''
as $$
  select m.role from public.members m where m.group_id = p_group_id and m.user_id = auth.uid()
$$;

create function private.is_member(p_group_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.my_role(p_group_id) is not null
$$;

create function private.is_admin(p_group_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(private.my_role(p_group_id) in ('owner', 'admin'), false)
$$;

create function private.member_since(p_group_id uuid)
returns bigint
language sql
stable
security definer
set search_path = ''
as $$
  select m.joined_epoch from public.members m where m.group_id = p_group_id and m.user_id = auth.uid()
$$;

create function private.require_user()
returns uuid
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'Not signed in.' using errcode = 'PT401';
  end if;
  return auth.uid();
end
$$;

-- Counts attempts, not successes: callers that must also count failures (the
-- invite code guess) return a status instead of raising, so the event commits.
create function private.rate_limit(p_action text, p_max integer, p_window interval, p_message text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid   uuid := private.require_user();
  v_count integer;
begin
  -- serialize per user+action so parallel requests can't slip past the limit
  perform pg_advisory_xact_lock(hashtextextended('hermes:rate:' || p_action || ':' || v_uid::text, 0));

  delete from private.rate_limit_events e
  where e.user_id = v_uid and e.action = p_action and e.created_at <= now() - p_window;

  select count(*) into v_count
  from private.rate_limit_events e
  where e.user_id = v_uid and e.action = p_action;

  if v_count >= p_max then
    raise exception '%', p_message
      using errcode = 'PT429', detail = format('Limit: %s per %s.', p_max, p_window);
  end if;

  insert into private.rate_limit_events (user_id, action) values (v_uid, p_action);
end
$$;

-- Appends a commit for exactly the group's current epoch and advances it.
-- The row lock serializes commits and application messages per group, so ids
-- reflect epoch order and two commits can never both be accepted for one epoch.
create function private.append_commit(p_group_id uuid, p_epoch bigint, p_payload text, p_credential text)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_epoch bigint;
begin
  select g.epoch into v_epoch from public.groups g where g.id = p_group_id for update;
  if v_epoch is null then
    raise exception 'Group not found.' using errcode = 'PT404';
  end if;
  if p_epoch is distinct from v_epoch then
    raise exception 'Commit is for epoch %, but the group is at epoch %.', p_epoch, v_epoch
      using errcode = 'PT409', hint = 'Fetch and apply the newer commits, then retry.';
  end if;

  insert into public.messages (group_id, epoch, kind, sender_credential, payload)
  values (p_group_id, p_epoch, 'commit', p_credential, p_payload);

  update public.groups set epoch = epoch + 1 where id = p_group_id;
  return v_epoch + 1;
end
$$;

create function private.my_credential(p_group_id uuid)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select m.credential from public.members m where m.group_id = p_group_id and m.user_id = auth.uid()
$$;

create function private.require_admin(p_group_id uuid)
returns public.group_role
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_role public.group_role := private.my_role(p_group_id);
begin
  perform private.require_user();
  if v_role is null or v_role = 'member' then
    raise exception 'Only group admins can do this.' using errcode = 'PT403';
  end if;
  return v_role;
end
$$;

-- When the last member leaves, the group and all its ciphertext go with it.
create function private.drop_empty_group()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not exists (select 1 from public.members where group_id = old.group_id) then
    delete from public.groups where id = old.group_id;
  end if;
  return null;
end
$$;

create trigger members_drop_empty_group
  after delete on public.members
  for each row execute function private.drop_empty_group();

-- ---------------------------------------------------------------------------
-- Policies (read-only; writes go through RPCs)
-- ---------------------------------------------------------------------------
create policy "members read their groups"
  on public.groups for select to authenticated
  using (private.is_member(id));

create policy "members see co-members"
  on public.members for select to authenticated
  using (private.is_member(group_id));

create policy "members read messages from their join epoch on"
  on public.messages for select to authenticated
  using (epoch >= private.member_since(group_id));

create policy "requesters and admins read join requests"
  on public.join_requests for select to authenticated
  using (requester_id = (select auth.uid()) or private.is_admin(group_id));

create policy "admins read departures"
  on public.departures for select to authenticated
  using (private.is_admin(group_id));

-- ---------------------------------------------------------------------------
-- RPCs
-- ---------------------------------------------------------------------------

-- The client creates the MLS group locally (epoch 0) and registers it here.
create function public.create_group(p_id uuid, p_credential text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := private.require_user();
begin
  perform private.rate_limit('create_group', 10, interval '1 hour', 'You can create at most 10 groups per hour.');
  insert into public.groups (id) values (p_id);
  insert into public.members (group_id, user_id, role, credential, joined_epoch)
  values (p_id, v_uid, 'owner', p_credential, 0);
end
$$;

-- The admin's client generates a random code and sends it once; only its hash
-- is stored. Codes are 16 Crockford base32 characters (80 bits).
create function public.create_invite(p_group_id uuid, p_code text)
returns timestamptz
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_expires timestamptz := now() + interval '5 minutes';
begin
  perform private.require_admin(p_group_id);
  if p_code !~ '^[0-9A-HJKMNP-TV-Z]{16}$' then
    raise exception 'Malformed invite code.' using errcode = 'PT400';
  end if;
  perform private.rate_limit('create_invite', 20, interval '1 hour', 'You can create at most 20 invite codes per hour.');
  insert into private.invites (group_id, code_hash, created_by, expires_at)
  values (p_group_id, encode(extensions.digest(p_code, 'sha256'), 'hex'), auth.uid(), v_expires);
  return v_expires;
end
$$;

-- Consumes an invite and files a join request carrying the caller's KeyPackage.
-- Wrong, used and expired codes all return status 'invalid' (no oracle) and
-- still count toward the rate limit, because nothing is rolled back.
create function public.request_join(p_code text, p_credential text, p_key_package text)
returns table (status text, request_id uuid, group_id uuid, expires_at timestamptz)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid    uuid := private.require_user();
  v_invite private.invites;
  v_id     uuid;
begin
  perform private.rate_limit('request_join', 10, interval '1 hour', 'Too many join attempts. Try again later.');

  select i.* into v_invite
  from private.invites i
  where i.code_hash = encode(extensions.digest(upper(coalesce(p_code, '')), 'sha256'), 'hex')
  for update;

  if v_invite.id is null or v_invite.used_at is not null or v_invite.expires_at <= now() then
    return query select 'invalid'::text, null::uuid, null::uuid, null::timestamptz;
    return;
  end if;

  if exists (
    select 1 from public.members m
    where m.group_id = v_invite.group_id and (m.user_id = v_uid or m.credential = p_credential)
  ) then
    return query select 'already_member'::text, null::uuid, v_invite.group_id, null::timestamptz;
    return;
  end if;

  update private.invites set used_at = now() where id = v_invite.id;

  insert into public.join_requests (group_id, requester_id, credential, key_package, expires_at)
  values (v_invite.group_id, v_uid, p_credential, p_key_package, v_invite.expires_at)
  returning id into v_id;

  return query select 'ok'::text, v_id, v_invite.group_id, v_invite.expires_at;
end
$$;

-- Admin accepts a request: the Add commit and the Welcome are stored together
-- with the new membership, atomically.
create function public.add_member(p_request_id uuid, p_epoch bigint, p_commit text, p_welcome text)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_req   public.join_requests;
  v_epoch bigint;
begin
  perform private.require_user();
  select r.* into v_req from public.join_requests r where r.id = p_request_id for update;
  if v_req.id is null then
    raise exception 'Join request not found.' using errcode = 'PT404';
  end if;
  perform private.require_admin(v_req.group_id);
  if v_req.status <> 'pending' then
    raise exception 'Join request was already handled.' using errcode = 'PT409';
  end if;
  if v_req.expires_at <= now() then
    raise exception 'Join request expired with its invite code.' using errcode = 'PT410';
  end if;

  v_epoch := private.append_commit(v_req.group_id, p_epoch, p_commit, private.my_credential(v_req.group_id));

  insert into public.members (group_id, user_id, role, credential, joined_epoch)
  values (v_req.group_id, v_req.requester_id, 'member', v_req.credential, v_epoch);

  update public.join_requests set status = 'accepted', welcome = p_welcome where id = v_req.id;
  return v_epoch;
end
$$;

-- Admins remove members; only the owner removes admins; nobody removes the owner.
create function public.remove_member(p_group_id uuid, p_user_id uuid, p_epoch bigint, p_commit text)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_my_role     public.group_role := private.require_admin(p_group_id);
  v_target_role public.group_role;
  v_epoch       bigint;
begin
  select m.role into v_target_role from public.members m where m.group_id = p_group_id and m.user_id = p_user_id;
  if v_target_role is null then
    raise exception 'Not a member of this group.' using errcode = 'PT404';
  end if;
  if p_user_id = auth.uid() then
    raise exception 'Use leave_group to leave.' using errcode = 'PT400';
  end if;
  if v_target_role = 'owner' then
    raise exception 'The owner cannot be removed.' using errcode = 'PT403';
  end if;
  if v_target_role = 'admin' and v_my_role <> 'owner' then
    raise exception 'Only the owner can remove an admin.' using errcode = 'PT403';
  end if;

  v_epoch := private.append_commit(p_group_id, p_epoch, p_commit, private.my_credential(p_group_id));
  delete from public.members where group_id = p_group_id and user_id = p_user_id;
  return v_epoch;
end
$$;

-- An admin commits the MLS Remove for someone who left.
create function public.complete_departure(p_departure_id uuid, p_epoch bigint, p_commit text)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_dep   public.departures;
  v_epoch bigint;
begin
  perform private.require_user();
  select d.* into v_dep from public.departures d where d.id = p_departure_id for update;
  if v_dep.id is null then
    raise exception 'Departure not found.' using errcode = 'PT404';
  end if;
  perform private.require_admin(v_dep.group_id);
  v_epoch := private.append_commit(v_dep.group_id, p_epoch, p_commit, private.my_credential(v_dep.group_id));
  delete from public.departures where id = v_dep.id;
  return v_epoch;
end
$$;

-- Leaving stops delivery immediately; the MLS removal is committed by an admin.
-- The owner can only leave a group they are alone in (which deletes it).
create function public.leave_group(p_group_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid  uuid := private.require_user();
  v_role public.group_role := private.my_role(p_group_id);
  v_cred text := private.my_credential(p_group_id);
begin
  if v_role is null then
    raise exception 'Not a member of this group.' using errcode = 'PT404';
  end if;
  if v_role = 'owner' and exists (
    select 1 from public.members m where m.group_id = p_group_id and m.user_id <> v_uid
  ) then
    raise exception 'The owner cannot leave while others are in the group.' using errcode = 'PT403';
  end if;
  delete from public.members where group_id = p_group_id and user_id = v_uid;
  if exists (select 1 from public.groups where id = p_group_id) then
    insert into public.departures (group_id, credential) values (p_group_id, v_cred)
    on conflict do nothing;
  end if;
end
$$;

-- Only the owner promotes and demotes; the owner's own role never changes.
create function public.set_role(p_group_id uuid, p_user_id uuid, p_role public.group_role)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.require_user();
  if private.my_role(p_group_id) is distinct from 'owner' then
    raise exception 'Only the owner can change roles.' using errcode = 'PT403';
  end if;
  if p_role not in ('admin', 'member') then
    raise exception 'Role must be admin or member.' using errcode = 'PT400';
  end if;
  update public.members set role = p_role
  where group_id = p_group_id and user_id = p_user_id and role <> 'owner';
  if not found then
    raise exception 'Not a member, or the owner.' using errcode = 'PT404';
  end if;
end
$$;

-- Application messages must be encrypted for the current epoch.
create function public.post_message(p_group_id uuid, p_epoch bigint, p_payload text)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_cred  text;
  v_epoch bigint;
  v_id    bigint;
begin
  perform private.require_user();
  v_cred := private.my_credential(p_group_id);
  if v_cred is null then
    raise exception 'Not a member of this group.' using errcode = 'PT403';
  end if;
  perform private.rate_limit('post_message', 60, interval '1 minute', 'You can send at most 60 messages per minute.');

  -- shared lock: messages run in parallel, but never interleave with a commit
  select g.epoch into v_epoch from public.groups g where g.id = p_group_id for share;
  if p_epoch is distinct from v_epoch then
    raise exception 'Message is for epoch %, but the group is at epoch %.', p_epoch, v_epoch
      using errcode = 'PT409';
  end if;

  insert into public.messages (group_id, epoch, kind, sender_credential, payload)
  values (p_group_id, p_epoch, 'application', v_cred, p_payload)
  returning id into v_id;
  return v_id;
end
$$;

-- Registers this device (first call) or moves its memberships and pending
-- join requests from the anonymous user that lost its session to the caller.
-- The old anonymous user is deleted so it no longer counts as a member.
create function public.claim_device(p_secret text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid  uuid := private.require_user();
  v_hash text;
  v_old  uuid;
begin
  if p_secret !~ '^[0-9a-f]{64}$' then
    raise exception 'Malformed device secret.' using errcode = 'PT400';
  end if;
  perform private.rate_limit('claim_device', 10, interval '1 hour', 'Too many device claims. Try again later.');
  v_hash := encode(extensions.digest(p_secret, 'sha256'), 'hex');

  select d.user_id into v_old from private.devices d where d.secret_hash = v_hash for update;
  if v_old = v_uid then
    return;
  end if;
  if v_old is null then
    insert into private.devices (secret_hash, user_id) values (v_hash, v_uid);
    return;
  end if;

  update public.members set user_id = v_uid where user_id = v_old;
  update public.join_requests set requester_id = v_uid where requester_id = v_old;
  update private.devices set user_id = v_uid, claimed_at = now() where secret_hash = v_hash;
  delete from auth.users where id = v_old and is_anonymous;
end
$$;

-- ---------------------------------------------------------------------------
-- Function privileges
-- ---------------------------------------------------------------------------
revoke all on all functions in schema public from public, anon, authenticated;
revoke all on all functions in schema private from public, anon, authenticated;

-- policy helpers, evaluated as the querying user
grant execute on function private.is_member(uuid), private.is_admin(uuid),
  private.member_since(uuid), private.my_role(uuid) to authenticated;

grant execute on function
  public.create_group(uuid, text),
  public.create_invite(uuid, text),
  public.request_join(text, text, text),
  public.add_member(uuid, bigint, text, text),
  public.remove_member(uuid, uuid, bigint, text),
  public.complete_departure(uuid, bigint, text),
  public.leave_group(uuid),
  public.set_role(uuid, uuid, public.group_role),
  public.post_message(uuid, bigint, text),
  public.claim_device(text)
to authenticated;

-- ---------------------------------------------------------------------------
-- Realtime: clients use these as a doorbell and then fetch through the API.
-- Realtime applies the SELECT policies above per subscriber.
-- ---------------------------------------------------------------------------
alter publication supabase_realtime add table public.messages, public.join_requests, public.departures;
