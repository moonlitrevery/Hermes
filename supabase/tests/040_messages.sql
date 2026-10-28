-- =============================================================================
-- Messages: post_message and the read policy
-- =============================================================================
begin;
\ir _helpers.psql
select plan(14);

select tests.seed_world();

select tests.login('mia');
select ok(public.post_message(tests.gid(), 0, 'bWVuc2FnZW0=') > 0, 'post_message: a member posts for the current epoch');
select results_eq(
  $$ select epoch, kind, sender_credential from public.messages $$,
  format($$ values (0::bigint, 'application'::text, %L::text) $$, tests.cred('mia')),
  'post_message: the server records the sender''s credential, not one chosen by the client'
);
select throws_ok(
  format($$ select public.post_message(%L, 1, 'bQ==') $$, tests.gid()),
  'PT409', null,
  'post_message: a message for another epoch is refused'
);
select throws_ok(
  format($$ select public.post_message(%L, 0, '') $$, tests.gid()),
  '23514', null,
  'post_message: empty payloads are refused'
);
select throws_ok(
  format($$ select public.post_message(%L, 0, repeat('A', 131073)) $$, tests.gid()),
  '23514', null,
  'post_message: oversized payloads are refused'
);
select throws_ok(
  format($$ insert into public.messages (group_id, epoch, kind, sender_credential, payload)
            values (%L, 0, 'application', %L, 'eA==') $$, tests.gid(), tests.cred('olga')),
  '42501', null,
  'messages: nobody inserts directly (no spoofing the sender)'
);
select throws_ok(
  $$ delete from public.messages $$, '42501', null,
  'messages: nobody deletes messages'
);
select tests.login('otto');
select throws_ok(
  format($$ select public.post_message(%L, 0, 'bQ==') $$, tests.gid()),
  'PT403', null,
  'post_message: an outsider cannot post'
);
select is((select count(*) from public.messages), 0::bigint, 'messages: an outsider reads nothing');

-- a member who joined at epoch 2 does not see epochs 0 and 1
select tests.logout();
update public.groups set epoch = 2 where id = tests.gid();
insert into public.messages (group_id, epoch, kind, sender_credential, payload) values
  (tests.gid(), 1, 'application', tests.cred('olga'), 'ZXBvY2ggMQ=='),
  (tests.gid(), 1, 'commit', tests.cred('olga'), 'Y29tbWl0IDE='),
  (tests.gid(), 2, 'application', tests.cred('olga'), 'ZXBvY2ggMg==');
insert into public.members (group_id, user_id, role, credential, joined_epoch)
values (tests.gid(), tests.uid('nina'), 'member', tests.cred('nina'), 2);
select tests.login('nina');
select results_eq(
  $$ select payload from public.messages order by id $$,
  $$ values ('ZXBvY2ggMg=='::text) $$,
  'messages: a late joiner reads only from their join epoch on'
);
select tests.login('olga');
select is((select count(*) from public.messages), 4::bigint, 'messages: earlier members read everything since they joined');

-- ---------------------------------------------------------------------------
-- rate limit: 60 messages per minute per user
-- ---------------------------------------------------------------------------
select tests.login('ada');
select lives_ok(
  format($$ select public.post_message(%L, 2, 'bQ==') from generate_series(1, 60) $$, tests.gid()),
  'post_message: the first 60 messages in a minute pass'
);
select throws_ok(
  format($$ select public.post_message(%L, 2, 'bQ==') $$, tests.gid()),
  'PT429', 'You can send at most 60 messages per minute.',
  'post_message: the 61st is refused (PT429 -> HTTP 429)'
);
select tests.login('olga');
select lives_ok(
  format($$ select public.post_message(%L, 2, 'bQ==') $$, tests.gid()),
  'post_message: the limit is per user'
);

select * from finish();
rollback;
