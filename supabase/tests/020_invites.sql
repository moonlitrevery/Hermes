-- =============================================================================
-- Invites: create_invite and request_join
-- =============================================================================
begin;
\ir _helpers.psql
select plan(26);

select tests.seed_world();

-- ---------------------------------------------------------------------------
-- create_invite: admins only, hash only, 5 minutes
-- ---------------------------------------------------------------------------
select tests.login('mia');
select throws_ok(
  format($$ select public.create_invite(%L, %L) $$, tests.gid(), tests.code(1)),
  'PT403', 'Only group admins can do this.',
  'create_invite: a plain member cannot create codes'
);
select tests.login('otto');
select throws_ok(
  format($$ select public.create_invite(%L, %L) $$, tests.gid(), tests.code(1)),
  'PT403', null,
  'create_invite: an outsider cannot create codes'
);
select tests.login('ada');
select is(
  public.create_invite(tests.gid(), tests.code(1)), now() + interval '5 minutes',
  'create_invite: an admin creates a code valid for 5 minutes'
);
select tests.login('olga');
select lives_ok(
  format($$ select public.create_invite(%L, %L) $$, tests.gid(), tests.code(2)),
  'create_invite: the owner creates codes too'
);
select throws_ok(
  format($$ select public.create_invite(%L, 'short') $$, tests.gid()),
  'PT400', null,
  'create_invite: malformed codes are refused'
);
select throws_ok(
  format($$ select public.create_invite(%L, %L) $$, tests.gid(), tests.code(1)),
  '23505', null,
  'create_invite: a code cannot be registered twice'
);
select tests.logout();
select is(
  (select count(*) from private.invites where code_hash = encode(extensions.digest(tests.code(1), 'sha256'), 'hex')),
  1::bigint,
  'create_invite: the server stores the SHA-256 of the code'
);
select is_empty(
  format($$ select 1 from private.invites i where i.code_hash = %L
              or exists (select 1 from jsonb_each_text(to_jsonb(i)) e where e.value = %L) $$,
         tests.code(1), tests.code(1)),
  'create_invite: the code itself is stored nowhere'
);
select tests.login('ada');
select throws_ok(
  $$ select * from private.invites $$, '42501', null,
  'invites: not even admins read the invite table'
);

-- ---------------------------------------------------------------------------
-- request_join
-- ---------------------------------------------------------------------------
select tests.login('nina');
select results_eq(
  format($$ select status, group_id from public.request_join(%L, %L, 'S1A=') $$, lower(tests.code(1)), tests.cred('nina')),
  format($$ values ('ok'::text, %L::uuid) $$, tests.gid()),
  'request_join: a valid code (any case) files a request for its group'
);
select results_eq(
  $$ select status, credential, key_package from public.join_requests where requester_id = auth.uid() $$,
  format($$ values ('pending'::text, %L::text, 'S1A='::text) $$, tests.cred('nina')),
  'request_join: the requester sees their pending request with the KeyPackage'
);
select is(
  (select expires_at from public.join_requests where requester_id = auth.uid()), now() + interval '5 minutes',
  'request_join: the request expires together with the code'
);
select is(
  (select count(*) from public.members where group_id = tests.gid()), 0::bigint,
  'request_join: requesting does not make anyone a member'
);

select tests.mk_user('rui');
select tests.login('rui');
select results_eq(
  format($$ select status from public.request_join(%L, %L, 'S1A=') $$, tests.code(1), tests.cred('rui')),
  $$ values ('invalid'::text) $$,
  'request_join: a code is single use'
);
select results_eq(
  format($$ select status, request_id, group_id from public.request_join(%L, %L, 'S1A=') $$, tests.code(99), tests.cred('rui')),
  $$ values ('invalid'::text, null::uuid, null::uuid) $$,
  'request_join: an unknown code reveals nothing'
);

-- expired code
select tests.logout();
update private.invites set expires_at = now() - interval '1 second'
 where code_hash = encode(extensions.digest(tests.code(2), 'sha256'), 'hex');
select tests.login('rui');
select results_eq(
  format($$ select status from public.request_join(%L, %L, 'S1A=') $$, tests.code(2), tests.cred('rui')),
  $$ values ('invalid'::text) $$,
  'request_join: an expired code is refused'
);
select tests.logout();
select is(
  (select used_at from private.invites where code_hash = encode(extensions.digest(tests.code(2), 'sha256'), 'hex')),
  null,
  'request_join: a refused attempt does not consume the code'
);

-- members cannot use a code on their own group
select tests.login('ada');
select public.create_invite(tests.gid(), tests.code(3));
select tests.login('mia');
select results_eq(
  format($$ select status from public.request_join(%L, %L, 'S1A=') $$, tests.code(3), tests.cred('mia')),
  $$ values ('already_member'::text) $$,
  'request_join: an existing member is told so'
);
select tests.logout();
select is(
  (select used_at from private.invites where code_hash = encode(extensions.digest(tests.code(3), 'sha256'), 'hex')),
  null,
  'request_join: an already-member attempt leaves the code usable'
);
select tests.login('rui');
select results_eq(
  format($$ select status from public.request_join(%L, %L, 'S1A=') $$, tests.code(3), tests.cred('mia')),
  $$ values ('already_member'::text) $$,
  'request_join: a credential already in the group cannot be reused by another user'
);
select throws_ok(
  format($$ select * from public.request_join(%L, 'nope', 'S1A=') $$, tests.code(3)),
  '23514', null,
  'request_join: the credential must be a hex Ed25519 key'
);

-- ---------------------------------------------------------------------------
-- join request visibility
-- ---------------------------------------------------------------------------
select tests.login('ada');
select is((select count(*) from public.join_requests), 1::bigint, 'join_requests: admins see requests for their group');
select tests.login('mia');
select is((select count(*) from public.join_requests), 0::bigint, 'join_requests: plain members do not');
select tests.login('rui');
select is((select count(*) from public.join_requests), 0::bigint, 'join_requests: other requesters do not see each other');
select throws_ok(
  $$ update public.join_requests set status = 'accepted' $$, '42501', null,
  'join_requests: nobody updates a request directly'
);
select tests.login_anon();
select throws_ok(
  format($$ select * from public.request_join(%L, %L, 'S1A=') $$, tests.code(3), tests.cred('x')),
  '42501', null,
  'request_join: anon cannot call it'
);

select * from finish();
rollback;
