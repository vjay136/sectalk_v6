\set ON_ERROR_STOP on
begin;

insert into auth.users(id,email) values
  ('66000001-0000-4000-8000-000000000001','tenant-operator@example.invalid'),
  ('66000001-0000-4000-8000-000000000002','tenant-owner@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('66000001-0000-4000-8000-000000000001','tenant_fixture_operator','Tenant operator'),
  ('66000001-0000-4000-8000-000000000002','tenant_fixture_owner','Tenant owner');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
  ('66000001-0001-4000-8000-000000000001','66000001-0000-4000-8000-000000000001','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
  ('66000001-0002-4000-8000-000000000001','66000001-0000-4000-8000-000000000001','aal2',
    '66000001-0001-4000-8000-000000000001');
insert into sectalk_private.st_v6_tenant_operators values ('66000001-0000-4000-8000-000000000001');
insert into sectalk_private.staff values ('66000001-0000-4000-8000-000000000002');

insert into public.st_v2_workspaces(id,name,owner) values
  ('66000001-0003-4000-8000-000000000001','Tenant QA %_ Special','66000001-0000-4000-8000-000000000002');
insert into public.st_v2_workspaces(name,owner)
  select 'Tenant QA '||n,'66000001-0000-4000-8000-000000000002' from generate_series(1,30) n;
insert into public.st_v2_members(workspace_id,user_id,role) values
  ('66000001-0003-4000-8000-000000000001','66000001-0000-4000-8000-000000000002','owner');

do $$
begin
  if has_table_privilege('authenticated','sectalk_private.st_v6_tenant_operators','insert')
    or has_table_privilege('authenticated','sectalk_private.st_v6_tenant_access_log','select')
    or has_function_privilege('anon','public.st_v6_tenant_search(text)','execute')
    or has_function_privilege('anon','public.st_v6_tenant_view(uuid)','execute')
  then raise exception 'Tenant operations privileges are exposed'; end if;
end
$$;

set local role authenticated;
do $$
declare
  operator_id constant uuid := '66000001-0000-4000-8000-000000000001';
  owner_id constant uuid := '66000001-0000-4000-8000-000000000002';
  session_id constant uuid := '66000001-0002-4000-8000-000000000001';
  target_id constant uuid := '66000001-0003-4000-8000-000000000001';
  detail jsonb;
begin
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'aal','aal2')::text,true);
  if public.st_v6_tenant_operations_status()<>'none' then raise exception 'Moderation grant gave tenant access'; end if;
  begin
    perform public.st_v6_tenant_search('Tenant QA');
    raise exception 'Moderator could search tenant metadata';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',operator_id,'aal','aal1','session_id',session_id)::text,true);
  if public.st_v6_tenant_operations_status()<>'mfa' then raise exception 'Operator MFA status was incorrect'; end if;
  begin
    perform public.st_v6_tenant_view(target_id);
    raise exception 'AAL1 operator could view tenant metadata';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',operator_id,'aal','aal2','session_id',gen_random_uuid())::text,true);
  if public.st_v6_tenant_operations_status()<>'mfa' then raise exception 'Inactive session authorized'; end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',operator_id,'aal','aal2','session_id',session_id)::text,true);
  if public.st_v6_tenant_operations_status()<>'verified' then raise exception 'Verified operator did not gain access'; end if;
  if (select count(*) from public.st_v6_tenant_search('tenant qa'))<>25
    or (select array_agg(s.id) from public.st_v6_tenant_search('Tenant QA %_') s) is distinct from array[target_id]
    or (select array_agg(s.id) from public.st_v6_tenant_search(target_id::text) s) is distinct from array[target_id]
  then raise exception 'Tenant name, literal prefix, exact ID, or result cap failed'; end if;
  begin
    perform public.st_v6_tenant_search(' ');
    raise exception 'Blank search was accepted';
  exception when invalid_parameter_value then null; end;
  select to_jsonb(d) into detail from public.st_v6_tenant_view(target_id) d;
  if detail is null or (detail->>'member_count')::int<>1 or detail - array['id','name','created_at','member_count']<>'{}'::jsonb
    or exists(select 1 from public.st_v2_members m where m.workspace_id=target_id)
    or public.st_staff_status()<>'none'
  then raise exception 'Tenant detail included unexpected fields, or access widened beyond metadata'; end if;
end
$$;
reset role;

do $$
begin
  if (select count(*) from sectalk_private.st_v6_tenant_access_log where actor='66000001-0000-4000-8000-000000000001'
      and action='search')<>3
    or not exists(select 1 from sectalk_private.st_v6_tenant_access_log where actor='66000001-0000-4000-8000-000000000001'
      and action='view' and workspace_id='66000001-0003-4000-8000-000000000001')
  then raise exception 'Tenant access was not recorded'; end if;
end
$$;

delete from sectalk_private.st_v6_tenant_operators where account_id='66000001-0000-4000-8000-000000000001';
set local role authenticated;
do $$
begin
  if public.st_v6_tenant_operations_status()<>'none' then raise exception 'Revoked operator grant remained active'; end if;
end
$$;
reset role;
select 'passed: tenant lookup and result caps, MFA and grant separation, metadata isolation, access log and revocation' as result;
rollback;
