-- =============================================================================
-- Groups and members: create_group, set_role, leave_group, read policies
-- =============================================================================
begin;
\ir _helpers.psql
select plan(32);

select tests.seed_world();

-- ---------------------------------------------------------------------------
-- create_group
-- ---------------------------------------------------------------------------
select tests.login('otto');
select lives_ok(
  format($$ select public.create_group('bbbbbbbb-0000-4000-8000-000000000002', %L) $$, tests.cred('otto')),
  'create_group: any signed-in user can create a group'
);
select results_eq(
  $$ select role::text, joined_epoch from public.members where group_id = 'bbbbbbbb-0000-4000-8000-000000000002' $$,
  $$ values ('owner', 0::bigint) $$,
  'create_group: the creator is the owner, reading from epoch 0'
);
select is(
  (select epoch from public.groups where id = 'bbbbbbbb-0000-4000-8000-000000000002'), 0::bigint,
  'create_group: a new group starts at epoch 0'
);
select throws_ok(
  format($$ select public.create_group(%L, %L) $$, tests.gid(), tests.cred('otto')),
  '23505', null,
  'create_group: an existing group id cannot be taken over'
);
select throws_ok(
  $$ select public.create_group(gen_random_uuid(), 'not-a-key') $$,
  '23514', null,
  'create_group: the credential must be a hex Ed25519 key'
);
select tests.login_anon();
select throws_ok(
  format($$ select public.create_group(gen_random_uuid(), %L) $$, tests.cred('x')),
  '42501', null,
  'create_group: anon cannot call it'
);

-- ---------------------------------------------------------------------------
-- read policies on groups and members
-- ---------------------------------------------------------------------------
select tests.login('mia');
select is((select count(*) from public.groups), 1::bigint, 'groups: a member sees only their own group');
select is((select count(*) from public.members), 3::bigint, 'members: a member sees every co-member');
select tests.login('otto');
select is(
  (select count(*) from public.groups where id = tests.gid()), 0::bigint,
  'groups: an outsider does not see the group'
);
select is(
  (select count(*) from public.members where group_id = tests.gid()), 0::bigint,
  'members: an outsider does not see who is in the group'
);
select throws_ok(
  format($$ insert into public.members (group_id, user_id, role, credential, joined_epoch)
            values (%L, auth.uid(), 'owner', %L, 0) $$, tests.gid(), tests.cred('otto')),
  '42501', null,
  'members: nobody inserts memberships directly'
);
select tests.login('mia');
select throws_ok(
  $$ update public.members set role = 'owner' where user_id = auth.uid() $$,
  '42501', null,
  'members: nobody updates their own role directly'
);
select throws_ok(
  $$ update public.groups set epoch = 99 $$,
  '42501', null,
  'groups: nobody moves the epoch directly'
);

-- ---------------------------------------------------------------------------
-- set_role: a commit; only the owner promotes and demotes, admins may step down
-- ---------------------------------------------------------------------------
select tests.login('ada');
select throws_ok(
  format($$ select public.set_role(%L, %L, 'admin', 0, 'cg==') $$, tests.gid(), tests.uid('mia')),
  'PT403', 'Only the owner can change roles.',
  'set_role: an admin cannot promote'
);
select tests.login('mia');
select throws_ok(
  format($$ select public.set_role(%L, %L, 'admin', 0, 'cg==') $$, tests.gid(), tests.uid('mia')),
  'PT403', null,
  'set_role: a member cannot promote themselves'
);
select tests.login('olga');
select throws_ok(
  format($$ select public.set_role(%L, %L, 'admin', 3, 'cg==') $$, tests.gid(), tests.uid('mia')),
  'PT409', null,
  'set_role: a role commit for the wrong epoch is refused'
);
select is(public.set_role(tests.gid(), tests.uid('mia'), 'admin', 0, 'cg=='), 1::bigint,
  'set_role: the owner promotes a member to admin, as a commit for the current epoch');
select is(public.set_role(tests.gid(), tests.uid('ada'), 'member', 1, 'cg=='), 2::bigint,
  'set_role: the owner demotes an admin');
select results_eq(
  format($$ select m.role::text from public.members m where m.group_id = %L order by m.role $$, tests.gid()),
  $$ select r from (values ('owner'), ('admin'), ('member')) v (r) $$,
  'set_role: roles changed as requested'
);
select is((select count(*) from public.messages where kind = 'commit'), 2::bigint,
  'set_role: each role change is stored as a commit');
select throws_ok(
  format($$ select public.set_role(%L, %L, 'owner', 2, 'cg==') $$, tests.gid(), tests.uid('mia')),
  'PT400', null,
  'set_role: ownership cannot be handed out through set_role'
);
select throws_ok(
  format($$ select public.set_role(%L, %L, 'member', 2, 'cg==') $$, tests.gid(), tests.uid('olga')),
  'PT403', 'The owner''s role cannot change.',
  'set_role: the owner cannot be demoted'
);
select tests.login('mia');
select throws_ok(
  format($$ select public.set_role(%L, %L, 'admin', 2, 'cg==') $$, tests.gid(), tests.uid('ada')),
  'PT403', null,
  'set_role: an admin cannot promote someone else'
);
select is(public.set_role(tests.gid(), tests.uid('mia'), 'member', 2, 'cg=='), 3::bigint,
  'set_role: an admin may step down');
select tests.login('olga');
select public.set_role(tests.gid(), tests.uid('ada'), 'admin', 3, 'cg==');

-- ---------------------------------------------------------------------------
-- leave_group
-- ---------------------------------------------------------------------------
select tests.login('olga');
select throws_ok(
  format($$ select public.leave_group(%L) $$, tests.gid()),
  'PT403', null,
  'leave_group: the owner cannot leave while others remain'
);
select tests.login('ada');
select throws_ok(
  format($$ select public.leave_group(%L) $$, tests.gid()),
  'PT409', 'Step down as admin before leaving.',
  'leave_group: an admin steps down before leaving (only the owner may remove an admin from MLS)'
);
select public.set_role(tests.gid(), tests.uid('ada'), 'member', 4, 'cg==');
select lives_ok(format($$ select public.leave_group(%L) $$, tests.gid()), 'leave_group: a member leaves');
select is(
  (select count(*) from public.groups where id = tests.gid()), 0::bigint,
  'leave_group: after leaving, the group is no longer visible'
);
select tests.logout();
select results_eq(
  format($$ select credential from public.departures where group_id = %L $$, tests.gid()),
  format($$ values (%L) $$, tests.cred('ada')),
  'leave_group: a departure is filed so an admin commits the MLS removal'
);
select tests.login('otto');
select throws_ok(
  format($$ select public.leave_group(%L) $$, tests.gid()),
  'PT404', null,
  'leave_group: a non-member cannot leave'
);

-- the last member leaving deletes the group and everything in it
select tests.login('otto');
select public.leave_group('bbbbbbbb-0000-4000-8000-000000000002');
select tests.logout();
select is(
  (select count(*) from public.groups where id = 'bbbbbbbb-0000-4000-8000-000000000002'), 0::bigint,
  'leave_group: an owner alone can leave, and the empty group is deleted'
);
select is(
  (select count(*) from public.departures where group_id = 'bbbbbbbb-0000-4000-8000-000000000002'), 0::bigint,
  'leave_group: no departure is left behind for a deleted group'
);

select * from finish();
rollback;
