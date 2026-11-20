begin;
insert into auth.users(id,email) values
  ('99700000-0000-4000-8000-000000000001','cache-one@example.invalid'),
  ('99700000-0000-4000-8000-000000000002','cache-two@example.invalid'),
  ('99700000-0000-4000-8000-000000000003','cache-three@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('99700000-0000-4000-8000-000000000001','cache_one','Cache One'),
  ('99700000-0000-4000-8000-000000000002','cache_two','Cache Two'),
  ('99700000-0000-4000-8000-000000000003','cache_three','Cache Three');

do $$
declare
  first_space uuid:=gen_random_uuid();
  second_space uuid:=gen_random_uuid();
  first_owner constant uuid:='99700000-0000-4000-8000-000000000001';
  second_owner constant uuid:='99700000-0000-4000-8000-000000000002';
  member_id constant uuid:='99700000-0000-4000-8000-000000000003';
begin
  insert into public.st_v2_workspaces(id,name,owner) values
    (first_space,'Cache first workspace',first_owner),(second_space,'Cache second workspace',second_owner);
  insert into public.st_v2_members(workspace_id,user_id,role) values
    (first_space,first_owner,'owner'),(second_space,second_owner,'owner'),(second_space,member_id,'member');
  if sectalk_private.st_v6_cached_member_count(first_space)<>1 or sectalk_private.st_v6_cached_member_count(second_space)<>2
  then raise exception 'Counts were not scoped to their workspaces'; end if;
  if (select count(*) from sectalk_private.st_v6_tenant_metadata_cache where workspace_id in (first_space,second_space)
    and schema_version=1 and expires_at>clock_timestamp() and expires_at<=clock_timestamp()+interval '10 seconds')<>2
  then raise exception 'Expected two versioned cache entries with a bounded expiry'; end if;

  insert into sectalk_private.st_v6_tenant_metadata_cache(workspace_id,metric,schema_version,value,expires_at)
    values(first_space,'member_count',2,999,clock_timestamp()+interval '1 minute');
  if sectalk_private.st_v6_cached_member_count(first_space)<>1
  then raise exception 'A different schema version polluted the cached count'; end if;
  update sectalk_private.st_v6_tenant_metadata_cache set value=1000,expires_at=clock_timestamp()-interval '1 second'
    where workspace_id=first_space and schema_version=1;
  if sectalk_private.st_v6_cached_member_count(first_space)<>1
  then raise exception 'An expired count was served'; end if;
  insert into public.st_v2_members(workspace_id,user_id,role) values(first_space,member_id,'member');
  if exists(select 1 from sectalk_private.st_v6_tenant_metadata_cache where workspace_id=first_space)
    or not exists(select 1 from sectalk_private.st_v6_tenant_metadata_cache where workspace_id=second_space)
    or sectalk_private.st_v6_cached_member_count(first_space)<>2
  then raise exception 'A roster write did not invalidate exactly its workspace'; end if;
  if has_table_privilege('authenticated','sectalk_private.st_v6_tenant_metadata_cache','SELECT')
    or has_function_privilege('authenticated','sectalk_private.st_v6_cached_member_count(uuid)','EXECUTE')
  then raise exception 'The cache granted access to an unprivileged role'; end if;
end $$;
select 'passed: cache tenant and version isolation, TTL, roster invalidation and private access' as result;
rollback;
