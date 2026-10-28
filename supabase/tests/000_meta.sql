-- =============================================================================
-- META TESTS: fail if someone adds an object that breaks the general rules.
-- =============================================================================
begin;
\ir _helpers.psql
select plan(14);

-- ---------------------------------------------------------------------------
-- RLS
-- ---------------------------------------------------------------------------
select is_empty(
  $$ select c.oid::regclass::text
     from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relkind in ('r', 'p') and not c.relrowsecurity $$,
  'META: every table in public has RLS enabled'
);

select is_empty(
  $$ select c.oid::regclass::text
     from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relkind in ('r', 'p') and not c.relforcerowsecurity $$,
  'META: every table in public has RLS FORCED'
);

select is_empty(
  $$ select c.oid::regclass::text
     from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'private' and c.relkind in ('r', 'p')
       and not (c.relrowsecurity and c.relforcerowsecurity) $$,
  'META: private tables also have forced RLS (defence in depth)'
);

select is_empty(
  $$ select c.oid::regclass::text
     from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relkind in ('v', 'm') $$,
  'META: no views in public (nothing can bypass the table policies)'
);

-- ---------------------------------------------------------------------------
-- SECURITY DEFINER functions
-- ---------------------------------------------------------------------------
select is_empty(
  $$ select p.oid::regprocedure::text
     from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname in ('public', 'private') and p.prosecdef
       and not exists (
         select 1 from unnest(coalesce(p.proconfig, '{}')) c where c = 'search_path=""') $$,
  'META: every SECURITY DEFINER function has an empty search_path'
);

select is_empty(
  $$ select p.oid::regprocedure::text
     from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and not p.prosecdef and p.prokind = 'f' $$,
  'META: every function in public is SECURITY DEFINER (RPCs only)'
);

-- ---------------------------------------------------------------------------
-- anon gets nothing
-- ---------------------------------------------------------------------------
select ok(
  not has_schema_privilege('anon', 'public', 'usage')
  and not has_schema_privilege('anon', 'private', 'usage'),
  'META: anon has no USAGE on public or private'
);

select is_empty(
  $$ select c.oid::regclass::text
     from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname in ('public', 'private') and c.relkind in ('r', 'p', 'v', 'm', 'S')
       and (
         has_table_privilege('anon', c.oid, 'select, insert, update, delete, truncate, references, trigger')
         or (c.relkind <> 'S' and has_any_column_privilege('anon', c.oid, 'select, insert, update, references'))
       ) $$,
  'META: anon has no privilege on any table or sequence'
);

select is_empty(
  $$ select p.oid::regprocedure::text
     from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname in ('public', 'private')
       and has_function_privilege('anon', p.oid, 'execute') $$,
  'META: anon (and PUBLIC) cannot execute any function in public or private'
);

-- ---------------------------------------------------------------------------
-- authenticated: read-only on public, nothing in private
-- ---------------------------------------------------------------------------
select is_empty(
  $$ select c.oid::regclass::text || ' ' || priv
     from pg_class c join pg_namespace n on n.oid = c.relnamespace
     cross join unnest(array['insert', 'update', 'delete', 'truncate', 'references', 'trigger']) as priv
     where n.nspname = 'public' and c.relkind in ('r', 'p')
       and has_table_privilege('authenticated', c.oid, priv) $$,
  'META: authenticated cannot write any public table directly (writes go through RPCs)'
);

select is_empty(
  $$ select c.oid::regclass::text
     from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'private' and c.relkind in ('r', 'p', 'v', 'm')
       and (
         has_table_privilege('authenticated', c.oid, 'select, insert, update, delete, truncate, references, trigger')
         or has_any_column_privilege('authenticated', c.oid, 'select, insert, update, references')
       ) $$,
  'META: authenticated has no privilege on any private table (nor column)'
);

-- The RPC list is closed: adding one forces a review of this test.
select bag_eq(
  $$ select p.proname::text
     from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and has_function_privilege('authenticated', p.oid, 'execute') $$,
  $$ values
       ('create_group'), ('create_invite'), ('request_join'), ('add_member'), ('remove_member'),
       ('complete_departure'), ('leave_group'), ('set_role'), ('post_message'), ('claim_device') $$,
  'META: authenticated only executes the known public RPCs'
);

select bag_eq(
  $$ select p.proname::text
     from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'private' and has_function_privilege('authenticated', p.oid, 'execute') $$,
  $$ values ('is_member'), ('is_admin'), ('member_since'), ('my_role') $$,
  'META: authenticated only executes the read-only policy helpers in private'
);

-- no RPC takes "who is acting" as a parameter: the actor is always auth.uid()
select is_empty(
  $$ select p.oid::regprocedure::text
     from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     cross join lateral unnest(p.proargnames) as arg (name)
     where n.nspname = 'public'
       and arg.name in ('p_uid', 'p_actor', 'p_sender', 'p_sender_credential', 'p_requester_id', 'p_owner_id') $$,
  'META: no public RPC receives the actor by parameter'
);

select * from finish();
rollback;
