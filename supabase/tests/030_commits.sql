-- =============================================================================
-- Commits: add_member, remove_member, complete_departure, epoch order
-- =============================================================================
begin;
\ir _helpers.psql
select plan(35);

select tests.seed_world();
select tests.mk_request('nina') as req \gset

-- ---------------------------------------------------------------------------
-- add_member
-- ---------------------------------------------------------------------------
select tests.login('mia');
select throws_ok(
  format($$ select public.add_member(%L, 0, 'Y29tbWl0', 'd2VsY29tZQ==') $$, :'req'),
  'PT403', null,
  'add_member: a plain member cannot accept requests'
);
select tests.login('ada');
select throws_ok(
  format($$ select public.add_member(%L, 1, 'Y29tbWl0', 'd2VsY29tZQ==') $$, :'req'),
  'PT409', 'Commit is for epoch 1, but the group is at epoch 0.',
  'add_member: a commit for a future epoch is refused'
);
select is(public.add_member(:'req', 0, 'Y29tbWl0', 'd2VsY29tZQ=='), 1::bigint,
  'add_member: an admin accepts with a commit for the current epoch');
select is(tests.epoch(), 1::bigint, 'add_member: the group moved to the next epoch');
select results_eq(
  format($$ select role::text, joined_epoch, credential from public.members where user_id = %L $$, tests.uid('nina')),
  format($$ values ('member', 1::bigint, %L) $$, tests.cred('nina')),
  'add_member: the requester is a member from the new epoch, with the requested credential'
);
select results_eq(
  $$ select epoch, kind, sender_credential, payload from public.messages $$,
  format($$ values (0::bigint, 'commit', %L, 'Y29tbWl0') $$, tests.cred('ada')),
  'add_member: the commit is stored for the old epoch, attributed to the committer'
);
select tests.login('nina');
select results_eq(
  $$ select status, welcome from public.join_requests where requester_id = auth.uid() $$,
  $$ values ('accepted'::text, 'd2VsY29tZQ=='::text) $$,
  'add_member: the requester receives the Welcome'
);
select tests.login('ada');
select throws_ok(
  format($$ select public.add_member(%L, 1, 'Y29tbWl0', 'd2VsY29tZQ==') $$, :'req'),
  'PT409', 'Join request was already handled.',
  'add_member: a request is accepted at most once'
);

-- stale commit: someone else already committed epoch 1
select tests.mk_user('rui');
select tests.mk_request('rui') as req_rui \gset
select tests.mk_user('sol');
select tests.mk_request('sol') as req_sol \gset
select tests.login('olga');
select is(public.add_member(:'req_rui', 1, 'Y29tbWl0Mg==', 'dw=='), 2::bigint, 'add_member: the owner accepts too');
select tests.login('ada');
select throws_ok(
  format($$ select public.add_member(%L, 1, 'Y29tbWl0Mw==', 'dw==') $$, :'req_sol'),
  'PT409', 'Commit is for epoch 1, but the group is at epoch 2.',
  'add_member: a second commit for an epoch that already has one is refused'
);
select tests.logout();
select is(
  (select status from public.join_requests where id = :'req_sol'), 'pending',
  'add_member: a refused commit leaves the request pending'
);
select is(
  (select count(*) from public.members where user_id = tests.uid('sol')), 0::bigint,
  'add_member: a refused commit adds nobody'
);
select throws_ok(
  format($$ insert into public.messages (group_id, epoch, kind, sender_credential, payload)
            values (%L, 1, 'commit', %L, 'eA==') $$, tests.gid(), tests.cred('ada')),
  '23505', null,
  'messages: the database itself holds at most one commit per epoch'
);

-- expired request: the admin is too late
update public.join_requests set expires_at = now() - interval '1 second' where id = :'req_sol';
select tests.login('ada');
select throws_ok(
  format($$ select public.add_member(%L, 2, 'Y29tbWl0Mw==', 'dw==') $$, :'req_sol'),
  'PT410', null,
  'add_member: a request cannot be accepted after its code expired'
);
select tests.login('otto');
select throws_ok(
  format($$ select public.add_member(%L, 2, 'eA==', 'dw==') $$, gen_random_uuid()),
  'PT404', null,
  'add_member: unknown request'
);

-- ---------------------------------------------------------------------------
-- remove_member
-- ---------------------------------------------------------------------------
select tests.login('mia');
select throws_ok(
  format($$ select public.remove_member(%L, %L, 2, 'cg==') $$, tests.gid(), tests.uid('nina')),
  'PT403', null,
  'remove_member: a plain member cannot remove'
);
select tests.login('ada');
select throws_ok(
  format($$ select public.remove_member(%L, %L, 2, 'cg==') $$, tests.gid(), tests.uid('olga')),
  'PT403', 'The owner cannot be removed.',
  'remove_member: an admin cannot remove the owner'
);
select tests.logout();
select tests.mk_user('abe');
select tests.add('abe', 'admin');
select tests.login('ada');
select throws_ok(
  format($$ select public.remove_member(%L, %L, 2, 'cg==') $$, tests.gid(), tests.uid('abe')),
  'PT403', 'Only the owner can remove an admin.',
  'remove_member: an admin cannot remove another admin'
);
select throws_ok(
  format($$ select public.remove_member(%L, %L, 2, 'cg==') $$, tests.gid(), tests.uid('ada')),
  'PT400', null,
  'remove_member: nobody removes themselves (that is leave_group)'
);
select throws_ok(
  format($$ select public.remove_member(%L, %L, 5, 'cg==') $$, tests.gid(), tests.uid('nina')),
  'PT409', null,
  'remove_member: an out-of-order commit is refused'
);
select tests.logout();
select is(
  (select count(*) from public.members where user_id = tests.uid('nina')), 1::bigint,
  'remove_member: a refused removal keeps the member'
);
select tests.login('ada');
select is(public.remove_member(tests.gid(), tests.uid('nina'), 2, 'cg=='), 3::bigint,
  'remove_member: an admin removes a member with a commit for the current epoch');
select tests.login('nina');
select is((select count(*) from public.messages), 0::bigint, 'remove_member: the removed member reads nothing any more');
select is((select count(*) from public.groups), 0::bigint, 'remove_member: nor sees the group');
select throws_ok(
  format($$ select public.post_message(%L, 3, 'bQ==') $$, tests.gid()),
  'PT403', null,
  'remove_member: nor can post'
);
select tests.login('olga');
select is(public.remove_member(tests.gid(), tests.uid('abe'), 3, 'cg=='), 4::bigint,
  'remove_member: the owner removes an admin');
select throws_ok(
  format($$ select public.remove_member(%L, %L, 4, 'cg==') $$, tests.gid(), tests.uid('otto')),
  'PT404', null,
  'remove_member: a non-member cannot be removed'
);

-- ---------------------------------------------------------------------------
-- complete_departure
-- ---------------------------------------------------------------------------
select tests.login('mia');
select public.leave_group(tests.gid());
select tests.logout();
select id as dep from public.departures where credential = tests.cred('mia') \gset
select tests.login('mia');
select throws_ok(
  format($$ select public.complete_departure(%L, 4, 'cg==') $$, :'dep'),
  'PT403', null,
  'complete_departure: someone who is no longer a member cannot commit'
);
select tests.login('ada');
select is((select count(*) from public.departures), 1::bigint, 'departures: admins see pending departures');
select throws_ok(
  format($$ select public.complete_departure(%L, 3, 'cg==') $$, :'dep'),
  'PT409', null,
  'complete_departure: a stale commit is refused'
);
select is(public.complete_departure(:'dep', 4, 'cg=='), 5::bigint, 'complete_departure: an admin commits the removal');
select is((select count(*) from public.departures), 0::bigint, 'complete_departure: the departure is done');
select tests.login('rui');
select is((select count(*) from public.departures), 0::bigint, 'departures: plain members do not see departures');

-- epochs and commits stayed in lockstep the whole time
select tests.logout();
select results_eq(
  format($$ select epoch from public.messages where group_id = %L and kind = 'commit' order by id $$, tests.gid()),
  $$ values (0::bigint), (1::bigint), (2::bigint), (3::bigint), (4::bigint) $$,
  'commits: exactly one commit per epoch, in id order'
);
select is(tests.epoch(), 5::bigint, 'commits: the group epoch equals the number of commits');

select * from finish();
rollback;
