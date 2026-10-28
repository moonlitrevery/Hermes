-- Hermes schema.
--
-- Supabase is an untrusted relay. It stores only:
--   * group ids          BLAKE3-derived from the group secret; not reversible
--   * sealed group names XChaCha20-Poly1305 ciphertext
--   * member public keys Ed25519, used to bind messages to members
--   * sealed messages    ciphertext + nonce + signature
-- Display names, message text and group names never reach the server in clear.
--
-- Users are Supabase *anonymous* users (Auth > Sign In / Providers > "Allow
-- anonymous sign-ins" must be enabled). A group id works as a bearer
-- capability: whoever knows it may join, but only invite-code holders can
-- derive the key needed to read anything.

create table public.groups (
  id         text primary key check (id ~ '^[0-9a-f]{64}$'),
  name_ct    text not null check (length(name_ct) <= 512),
  created_at timestamptz not null default now()
);

create table public.members (
  group_id  text not null references public.groups (id) on delete cascade,
  user_id   uuid not null references auth.users (id) on delete cascade,
  sign_pub  text not null check (sign_pub ~ '^[0-9a-f]{64}$'),
  joined_at timestamptz not null default now(),
  primary key (group_id, user_id)
);
create index members_user_id_idx on public.members (user_id);

create table public.messages (
  id         bigint generated always as identity primary key,
  group_id   text not null references public.groups (id) on delete cascade,
  sender_id  uuid not null default auth.uid() references auth.users (id) on delete cascade,
  sender_pub text not null check (sender_pub ~ '^[0-9a-f]{64}$'),
  nonce      text not null check (length(nonce) = 32),          -- base64 of 24 bytes
  ciphertext text not null check (length(ciphertext) <= 65536), -- ~48 KiB raw
  signature  text not null check (length(signature) = 88),      -- base64 of 64 bytes
  created_at timestamptz not null default now()
);
create index messages_group_id_id_idx on public.messages (group_id, id desc);

alter table public.groups   enable row level security;
alter table public.members  enable row level security;
alter table public.messages enable row level security;

-- Membership check used by every policy. SECURITY DEFINER avoids recursive
-- RLS evaluation on `members`.
create function public.is_member(gid text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.members m
    where m.group_id = gid and m.user_id = auth.uid()
  );
$$;

create policy "members read their groups"
  on public.groups for select to authenticated
  using (public.is_member(id));

create policy "members see co-members"
  on public.members for select to authenticated
  using (public.is_member(group_id));

create policy "users leave groups"
  on public.members for delete to authenticated
  using (user_id = (select auth.uid()));

create policy "members read messages"
  on public.messages for select to authenticated
  using (public.is_member(group_id));

-- A message must come from the caller, and its signing key must be the one
-- the caller registered for that group.
create policy "members post as themselves"
  on public.messages for insert to authenticated
  with check (
    sender_id = (select auth.uid())
    and exists (
      select 1 from public.members m
      where m.group_id = messages.group_id
        and m.user_id = (select auth.uid())
        and m.sign_pub = messages.sender_pub
    )
  );

-- Writes to groups/members go through the functions below; messages are
-- append-only. RLS already blocks these, so the grants are defence in depth.
revoke all on public.groups, public.members, public.messages from anon;
revoke insert, update, delete on public.groups from authenticated;
revoke insert, update on public.members from authenticated;
revoke update, delete on public.messages from authenticated;

create function public.create_group(p_id text, p_name_ct text, p_sign_pub text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'not authenticated' using errcode = '28000';
  end if;
  insert into public.groups (id, name_ct) values (p_id, p_name_ct);
  insert into public.members (group_id, user_id, sign_pub) values (p_id, auth.uid(), p_sign_pub);
end;
$$;

-- Joins (or re-registers the key for) a group and returns its sealed name.
create function public.join_group(p_id text, p_sign_pub text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_name text;
begin
  if auth.uid() is null then
    raise exception 'not authenticated' using errcode = '28000';
  end if;
  select name_ct into v_name from public.groups where id = p_id;
  if v_name is null then
    raise exception 'group not found' using errcode = 'P0002';
  end if;
  insert into public.members (group_id, user_id, sign_pub)
  values (p_id, auth.uid(), p_sign_pub)
  on conflict (group_id, user_id) do update set sign_pub = excluded.sign_pub;
  return v_name;
end;
$$;

-- When the last member leaves, the group and all its ciphertext are deleted.
create function public.drop_empty_group()
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
end;
$$;

create trigger members_drop_empty_group
  after delete on public.members
  for each row execute function public.drop_empty_group();

revoke all on function public.is_member(text) from public, anon;
revoke all on function public.create_group(text, text, text) from public, anon;
revoke all on function public.join_group(text, text) from public, anon;
revoke all on function public.drop_empty_group() from public, anon, authenticated;
grant execute on function public.is_member(text) to authenticated;
grant execute on function public.create_group(text, text, text) to authenticated;
grant execute on function public.join_group(text, text) to authenticated;

-- Live delivery. Realtime enforces the SELECT policy above per subscriber.
alter publication supabase_realtime add table public.messages;
