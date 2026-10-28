-- =============================================================================
-- claim_device (lost anonymous sessions) and the remaining rate limits
-- =============================================================================
begin;
\ir _helpers.psql
select plan(19);

select tests.seed_world();
select tests.mk_request('nina') as req \gset

-- ---------------------------------------------------------------------------
-- claim_device
-- ---------------------------------------------------------------------------
select tests.login('mia');
select lives_ok(
  format($$ select public.claim_device(%L) $$, repeat('ab', 32)),
  'claim_device: the first call registers the device'
);
select lives_ok(
  format($$ select public.claim_device(%L) $$, repeat('ab', 32)),
  'claim_device: calling again from the same user is a no-op'
);
select tests.logout();
select is(
  (select user_id from private.devices where secret_hash = encode(extensions.digest(repeat('ab', 32), 'sha256'), 'hex')),
  tests.uid('mia'),
  'claim_device: only the hash of the device secret is stored'
);

-- mia's session is lost; the app signs in again as a new anonymous user
select tests.mk_user('mia2');
select tests.login('mia2');
select lives_ok(
  format($$ select public.claim_device(%L) $$, repeat('ab', 32)),
  'claim_device: a new session presents the device secret'
);
select results_eq(
  format($$ select role::text, credential from public.members where user_id = auth.uid() and group_id = %L $$, tests.gid()),
  format($$ values ('member', %L) $$, tests.cred('mia')),
  'claim_device: the membership (role and MLS credential) moved to the new user'
);
select is((select count(*) from public.members where group_id = tests.gid()), 3::bigint,
  'claim_device: the group still has three members, not a ghost fourth');
select tests.logout();
select is(
  (select count(*) from auth.users where id = tests.uid('mia')), 0::bigint,
  'claim_device: the abandoned anonymous user is deleted'
);

-- a pending join request follows the device too
select tests.login('nina');
select public.claim_device(repeat('cd', 32));
select tests.mk_user('nina2');
select tests.login('nina2');
select public.claim_device(repeat('cd', 32));
select is(
  (select requester_id from public.join_requests where id = :'req'), tests.uid('nina2'),
  'claim_device: a pending join request moves to the new user'
);

-- someone else's secret cannot be guessed into
select tests.login('otto');
select lives_ok(
  format($$ select public.claim_device(%L) $$, repeat('ef', 32)),
  'claim_device: another secret just registers another device'
);
select is((select count(*) from public.members where group_id = tests.gid()), 0::bigint,
  'claim_device: a wrong secret takes over nothing');
select throws_ok(
  $$ select public.claim_device('not hex') $$, 'PT400', null,
  'claim_device: malformed secrets are refused'
);

-- ---------------------------------------------------------------------------
-- rate limits
-- ---------------------------------------------------------------------------
select tests.mk_user('rita');
select tests.login('rita');
select lives_ok(
  $$ select public.create_group(gen_random_uuid(), tests.cred('rita')) $$,
  'create_group: passes under the limit'
);
select tests.logout();
insert into private.rate_limit_events (user_id, action) select tests.uid('rita'), 'create_group' from generate_series(1, 9);
select tests.login('rita');
select throws_ok(
  $$ select public.create_group(gen_random_uuid(), tests.cred('rita')) $$,
  'PT429', 'You can create at most 10 groups per hour.',
  'create_group: at most 10 per hour'
);

select tests.logout();
insert into private.rate_limit_events (user_id, action) select tests.uid('ada'), 'create_invite' from generate_series(1, 20);
select tests.login('ada');
select throws_ok(
  format($$ select public.create_invite(%L, %L) $$, tests.gid(), tests.code(7)),
  'PT429', 'You can create at most 20 invite codes per hour.',
  'create_invite: at most 20 per hour'
);

-- join attempts count even when the code is wrong (the guess is not rolled back)
select tests.mk_user('eve');
select tests.login('eve');
select results_eq(
  format($$ select count(*) from generate_series(1, 10) g, public.request_join(%L || lpad(g::text, 12, '0'), %L, 'S1A=') r
            where r.status = 'invalid' $$, 'XXXX', tests.cred('eve')),
  $$ values (10::bigint) $$,
  'request_join: 10 wrong guesses are answered'
);
select throws_ok(
  format($$ select * from public.request_join(%L, %L, 'S1A=') $$, tests.code(1), tests.cred('eve')),
  'PT429', 'Too many join attempts. Try again later.',
  'request_join: the 11th attempt in an hour is refused, so codes cannot be brute-forced'
);
select tests.logout();
select is(
  (select count(*) from private.rate_limit_events where user_id = tests.uid('eve') and action = 'request_join'),
  10::bigint,
  'request_join: failed attempts were recorded'
);

-- the window slides
update private.rate_limit_events set created_at = created_at - interval '61 minutes'
 where user_id = tests.uid('eve') and action = 'request_join';
select tests.login('eve');
select results_eq(
  format($$ select status from public.request_join(%L, %L, 'S1A=') $$, tests.code(1), tests.cred('eve')),
  $$ values ('invalid'::text) $$,
  'request_join: after an hour attempts are allowed again'
);

select tests.mk_user('cid');
select tests.logout();
insert into private.rate_limit_events (user_id, action) select tests.uid('cid'), 'claim_device' from generate_series(1, 10);
select tests.login('cid');
select throws_ok(
  format($$ select public.claim_device(%L) $$, repeat('12', 32)),
  'PT429', null,
  'claim_device: at most 10 per hour'
);

select * from finish();
rollback;
