begin;
do $$
declare owner_id uuid:=gen_random_uuid(); member uuid:=gen_random_uuid();
  owner_session uuid:=gen_random_uuid(); member_session uuid:=gen_random_uuid(); factor uuid:=gen_random_uuid();
  device_id uuid:=gen_random_uuid(); workspace uuid; chosen uuid:=gen_random_uuid(); outside_group uuid:=gen_random_uuid();
  role_id uuid:=gen_random_uuid(); role_definition jsonb; decision jsonb; utc_hour integer:=extract(hour from now() at time zone 'UTC');
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  member_claim text:=jsonb_build_object('sub',member,'session_id',member_session,'role','authenticated','aal','aal1')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'custom-owner@example.invalid',now()),(member,'custom-member@example.invalid',now());
  insert into public.st_profiles values(owner_id,'custom_owner','Custom role owner'),(member,'custom_member','Custom role member');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),(member_session,member,'aal1',null);
  insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature)
    values(device_id,member,'trusted',repeat('G',87),repeat('H',87),repeat('I',86));
  insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id) values(member_session,member,device_id);
  insert into sectalk_private.st_v7_session_scores(session_id,user_id,score,signals,provider)
    values(member_session,member,10,'{}','matched');
  if has_function_privilege('authenticated','public.st_v7_builtin_group_change(uuid,uuid,text,text,text,uuid)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v7_custom_role_versions','select') then
    raise exception 'Internal delegation storage or baseline entry point exposed';
  end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  workspace:=public.st_v2_create_workspace('Role editor fixtures');
  perform public.st_v6_workspace_group_create(workspace,chosen,'team','Role managed team','');
  perform public.st_v6_workspace_group_create(workspace,outside_group,'team','Unrelated team','');
  role_definition:=jsonb_build_object('name','Test editing role','target',chosen,'permissions',array['rename'],
    'enabled',true,'device','trusted','risk_max',25,'utc_start',utc_hour,'utc_end',utc_hour+1);
  decision:=public.st_v7_workspace_custom_roles(workspace,'save',role_id,0,role_definition);
  if decision->>'access'<>'mfa' then raise exception 'Stale owner changed definitions'; end if;
  reset role;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,member,'member');
  set local role authenticated;
  perform public.st_v7_workspace_custom_roles(workspace,'save',role_id,0,role_definition);
  begin
    perform public.st_v7_workspace_custom_roles(workspace,'save',role_id,0,role_definition);
    raise exception 'Stale write replaced a newer definition';
  exception when others then if sqlstate<>'PT409' then raise; end if; end;
  perform public.st_v7_workspace_custom_roles(workspace,'assign',role_id,1,p_account=>member);
  decision:=public.st_v7_workspace_custom_roles(workspace,'simulate',role_id,1,
    jsonb_build_object('device','known','risk',30,'hour',(utc_hour+2)%24,'permission','archive'));
  if decision->>'allowed'<>'false' or not (decision->'conditions') ?& array['device','risk','time','permission'] then
    raise exception 'Simulated denial did not explain all relevant conditions';
  end if;
  perform set_config('request.jwt.claims',member_claim,true);
  if public.st_v7_custom_group_access(workspace,chosen)<>array['rename'] then raise exception 'Real trusted data did not authorize custom role'; end if;
  perform public.st_v6_workspace_group_change(workspace,chosen,'rename','Changed by assigned role','');
  begin
    perform public.st_v6_workspace_group_change(workspace,outside_group,'rename','Outside scope','');
    raise exception 'Role granted an unassigned target';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v7_session_scores set score=30 where session_id=member_session;
  set local role authenticated;
  begin
    perform public.st_v6_workspace_group_change(workspace,chosen,'rename','Denied by actual risk','');
    raise exception 'Real high risk was ignored';
  exception when insufficient_privilege then null; end;
  reset role;
  update public.st_v2_members set suspended_at=now() where workspace_id=workspace and user_id=member;
  update public.st_v2_members set suspended_at=null where workspace_id=workspace and user_id=member;
  set local role authenticated;
  if cardinality(public.st_v7_custom_group_access(workspace,chosen))<>0 then
    raise exception 'Suspension followed by restoration silently restored custom access';
  end if;
end
$$;
select 'passed: MFA owner, stale revisions, hypothetical explanation, trusted real ABAC and durable scoped revocation' as result;
rollback;
