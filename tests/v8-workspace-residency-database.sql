begin;

insert into auth.users(id,email,email_confirmed_at) values
  ('b8080000-0000-4000-8000-000000000001','residency-owner@example.invalid',now()),
  ('b8080000-0000-4000-8000-000000000002','residency-free@example.invalid',now());
insert into public.st_profiles(id,handle,name) values
  ('b8080000-0000-4000-8000-000000000001','residency_fixture_owner','Residency fixture owner'),
  ('b8080000-0000-4000-8000-000000000002','residency_fixture_free','Residency fixture free');
insert into auth.sessions(id,user_id,aal) values
  ('b8080000-0000-4000-8000-000000000011','b8080000-0000-4000-8000-000000000001','aal1'),
  ('b8080000-0000-4000-8000-000000000012','b8080000-0000-4000-8000-000000000002','aal1');
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
  (gen_random_uuid(),'b8080000-0000-4000-8000-000000000011','password',now(),now()-interval '20 minutes'),
  (gen_random_uuid(),'b8080000-0000-4000-8000-000000000012','password',now(),now());
insert into public.st_v2_subscriptions(user_id,plan,catalog_version,status,period_end)
  values('b8080000-0000-4000-8000-000000000001','enterprise',1,'active',now()+interval '90 days');
insert into public.st_v2_workspaces(id,name,owner) values
  ('b8080000-0000-4000-8000-000000000021','Enterprise residence fixture','b8080000-0000-4000-8000-000000000001'),
  ('b8080000-0000-4000-8000-000000000022','Free residence fixture','b8080000-0000-4000-8000-000000000002');
insert into public.st_v2_members(workspace_id,user_id,role) values
  ('b8080000-0000-4000-8000-000000000021','b8080000-0000-4000-8000-000000000001','owner'),
  ('b8080000-0000-4000-8000-000000000022','b8080000-0000-4000-8000-000000000002','owner');
insert into sectalk_private.st_v7_org_preferences values('b8080000-0000-4000-8000-000000000021','eu');
insert into sectalk_private.st_v8_residency_cells(id,region,project_reference,label,environment)
  values('b8080000-0000-4000-8000-000000000031','us','abcdefghijklmnopqrst','Planned test target','deployment');
insert into sectalk_private.st_v8_residency_provider_bindings values
  ('b8080000-0000-4000-8000-000000000031','us-east-1','synthetic-provider');
insert into sectalk_private.st_v8_residency_cell_authorizations(workspace,cell) values
  ('b8080000-0000-4000-8000-000000000021','b8080000-0000-4000-8000-000000000031'),
  ('b8080000-0000-4000-8000-000000000022','b8080000-0000-4000-8000-000000000031');

create function pg_temp.residency_actor(i integer) returns void
language sql set search_path='' as $$
  select set_config('request.jwt.claims',jsonb_build_object('sub','b8080000-0000-4000-8000-00000000000'||i,
    'role','authenticated','aal','aal1','session_id','b8080000-0000-4000-8000-00000000001'||i)::text,true);
$$;

do $$
declare enterprise uuid:='b8080000-0000-4000-8000-000000000021'; free_space uuid:='b8080000-0000-4000-8000-000000000022';
  destination uuid:='b8080000-0000-4000-8000-000000000031'; receipt uuid; result jsonb; ticket uuid;
  reviewer uuid:='b8080000-0000-4000-8000-000000000002'; factor uuid:=gen_random_uuid();
  reviewer_session uuid:=gen_random_uuid(); installation uuid:=gen_random_uuid();
begin
  if has_table_privilege('authenticated','sectalk_private.st_v8_residency_cells','select')
    or has_function_privilege('authenticated','public.st_v8_observe_residency_fixture(uuid,text,uuid)','execute') then
    raise exception 'Residency authority is directly exposed'; end if;
  set local role authenticated;
  perform pg_temp.residency_actor(2);
  if public.st_v8_workspace_residency(free_space)->'cells'<>'[]'::jsonb then raise exception 'Free caller saw target inventory'; end if;
  begin
    perform public.st_v8_workspace_residency_change(free_space,destination);
    raise exception 'Free workspace selected a dedicated target';
  exception when insufficient_privilege then null; end;
  perform pg_temp.residency_actor(1);
  begin
    perform public.st_v8_workspace_residency_change(enterprise,destination);
    raise exception 'Stale owner selected a dedicated target';
  exception when insufficient_privilege then null; end;
  reset role;
  update auth.mfa_amr_claims set updated_at=now() where session_id='b8080000-0000-4000-8000-000000000011';
  set local role authenticated;
  receipt:=public.st_v8_workspace_residency_change(enterprise,destination);
  if receipt<>public.st_v8_workspace_residency_change(enterprise,destination) then
    raise exception 'Selection retry changed request identity'; end if;
  result:=public.st_v8_workspace_residency(enterprise);
  if result#>>'{request,state}'<>'pending_verification' or result::text like '%abcdefghijklmnopqrst%' then
    raise exception 'Unverified request leaked placement or project identity'; end if;
  begin
    perform public.st_v8_begin_residency_provider_check(receipt);
    raise exception 'Owner bypassed independent placement review';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into sectalk_private.st_v8_residency_verifiers values(enterprise,reviewer);
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,reviewer,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(reviewer_session,reviewer,'aal2',factor);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),reviewer_session,'totp',now(),now());
  insert into sectalk_private.st_v8_residency_installation(cell,installation_nonce) values(destination,installation);
  set local role anon;
  if public.st_v8_residency_target_ready(destination,'abcdefghijklmnopqrst',gen_random_uuid())
    or not public.st_v8_residency_target_ready(destination,'abcdefghijklmnopqrst',installation) then
    raise exception 'Dedicated target installation proof did not match'; end if;
  reset role;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',reviewer,'role','authenticated',
    'aal','aal2','session_id',reviewer_session)::text,true);
  set local role authenticated;
  ticket:=public.st_v8_begin_residency_provider_check(receipt);
  if ticket is null or has_function_privilege('authenticated','public.st_v8_residency_provider_target(uuid)','execute') then
    raise exception 'Provider ticket missing or service scope exposed'; end if;
  reset role;
  set local role service_role;
  if public.st_v8_residency_provider_target(ticket)->>'region' is distinct from 'us-east-1'
    or public.st_v8_finish_residency_provider_check(ticket,destination,'abcdefghijklmnopqrst','us-east-2','synthetic-provider')
    or not public.st_v8_finish_residency_provider_check(ticket,destination,'abcdefghijklmnopqrst','us-east-1','synthetic-provider')
    or public.st_v8_finish_residency_provider_check(ticket,destination,'abcdefghijklmnopqrst','us-east-1','synthetic-provider') then
    raise exception 'Provider region, exact service artifact or replay did not preserve binding'; end if;
  reset role;
  perform pg_temp.residency_actor(1);
  set local role authenticated;
  if public.st_v8_workspace_residency(enterprise)#>>'{request,state}' is distinct from 'provider_target_verified' then
    raise exception 'Actual fixture scope did not project provider target configuration'; end if;
  reset role;
  delete from sectalk_private.st_v8_residency_verifiers v where (v.workspace,v.actor)=(enterprise,reviewer);
  set local role authenticated;
  if public.st_v8_workspace_residency(enterprise)#>>'{request,state}' is distinct from 'needs_verification' then
    raise exception 'Revoked verifier left target verified'; end if;
  perform public.st_v8_workspace_residency_change(enterprise,null);
  reset role;
  begin
    update sectalk_private.st_v8_residency_cells set region='eu' where id=destination;
    raise exception 'An existing project binding could be repointed to another region';
  exception when insufficient_privilege then null; end;
  if (select count(*) from sectalk_private.st_v8_residency_audit where request=receipt)<>3 then
    raise exception 'Selection and withdrawal were not audited exactly once'; end if;
  if (select requested_region from sectalk_private.st_v7_org_preferences where workspace=enterprise)<>'eu' then
    raise exception 'Dedicated selection changed shared region preference'; end if;
end $$;

select 'passed: residency entitlement, live assurance, private target scope, idempotence and separate preference' as result;
rollback;
