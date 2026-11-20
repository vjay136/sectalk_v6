begin;
do $$
declare
  owner_id uuid:=gen_random_uuid();
  session_key uuid:=gen_random_uuid();
  factor_key uuid:=gen_random_uuid();
  device_key uuid:=gen_random_uuid();
  space uuid:=gen_random_uuid();
  target uuid:=gen_random_uuid();
  start_hour integer:=extract(hour from statement_timestamp() at time zone 'UTC');
  constraints jsonb;
  result jsonb;
  claims jsonb;
begin
  if has_function_privilege('anon','public.st_v7_explain_file_egress(text,uuid,uuid,text)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v7_file_egress_policies','select') then
    raise exception 'Private policy or public evaluator grant exposed';
  end if;
  insert into auth.users(id,email) values(owner_id,owner_id||'@example.invalid');
  insert into public.st_profiles(id,handle,name) values(owner_id,'abac_'||left(owner_id::text,8),'ABAC QA');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor_key,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id,ip) values(session_key,owner_id,'aal2',factor_key,'192.0.2.42');
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),session_key,'totp',now(),now());
  insert into public.st_v2_workspaces(id,owner,name) values(space,owner_id,'ABAC fixture');
  insert into public.st_v2_members(workspace_id,user_id,role) values(space,owner_id,'owner') on conflict do nothing;
  insert into public.st_v6_workspace_policy(workspace_id,workspace_type,template,room_kinds,bulk_admit,created_by,request_id)
    values(space,'business','standard',array['public','private'],false,owner_id,gen_random_uuid());
  insert into sectalk_private.st_v6_workspace_files(workspace,id,uploader,filename,size_bytes,published_at)
    values(space,target,owner_id,'abac-qa.txt',5,now());
  claims:=jsonb_build_object('sub',owner_id,'role','authenticated','session_id',session_key,'aal','aal2',
    'user_metadata',jsonb_build_object('device','managed','risk_max',0,'network','192.0.2.42'));
  perform set_config('request.jwt.claims',claims::text,true);
  perform set_config('request.headers','{"x-forwarded-for":"192.0.2.42","x-policy-device":"managed"}',true);

  set local role authenticated;
  if public.st_v7_explain_file_egress('workspace',space,target,'download')->>'allowed'<>'true' then
    raise exception 'Legacy members lost base access'; end if;
  begin
    perform public.st_v7_save_file_egress_policy(space,0,'{"mode":"require","device":"managed","custom":"accepted?"}');
    raise exception 'Unrecognized attribute accepted';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_v7_save_file_egress_policy(space,0,'{"mode":"require","network":"127.0.0.1"}');
    raise exception 'CIDR-free network accepted';
  exception when invalid_parameter_value then null; end;
  constraints:=jsonb_build_object('mode','require','device','managed','risk_max',30,'network','192.0.2.0/24',
    'utc_start',start_hour,'utc_end',(start_hour+1)%24,'classification_max','internal','tenant_type','business');
  if public.st_v7_save_file_egress_policy(space,0,constraints)<>1 then raise exception 'Policy not persisted'; end if;
  result:=public.st_v7_explain_file_egress('workspace',space,target,'download');
  if result->>'allowed'<>'false' or result->'reasons'<>'["device_trust","session_risk"]'::jsonb
    or result::text like '%192.0.2%' then raise exception 'Fail-closed missing attributes or safe explain failed: %',result; end if;
  begin
    perform public.st_v7_save_file_egress_policy(space,0,'{"mode":"inherit"}');
    raise exception 'Stale policy write succeeded';
  exception when sqlstate 'PT409' then null; end;
  reset role;

  insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature)
    values(device_key,owner_id,'managed',repeat('A',87),repeat('B',87),repeat('C',86));
  insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id) values(session_key,owner_id,device_key);
  insert into sectalk_private.st_v7_session_scores(session_id,user_id,score,signals,provider)
    values(session_key,owner_id,30,array[]::text[],'unavailable');
  set local role authenticated;
  result:=public.st_v7_explain_file_egress('workspace',space,target,'share');
  if result->>'allowed'<>'true' or result->'reasons'<>'["requirements_met"]'::jsonb then
    raise exception 'All six requirements failed to evaluate: %',result; end if;
  reset role;

  update auth.sessions set ip='198.51.100.2' where id=session_key;
  update sectalk_private.st_v7_session_scores set score=31 where session_id=session_key;
  update sectalk_private.st_v7_devices set state='known' where id=device_key;
  set local role authenticated;
  constraints:=constraints||jsonb_build_object('classification_max','public','tenant_type','healthcare',
    'utc_start',(start_hour+1)%24,'utc_end',(start_hour+2)%24);
  if public.st_v7_save_file_egress_policy(space,1,constraints)<>2 then raise exception 'Policy update failed'; end if;
  result:=public.st_v7_explain_file_egress('workspace',space,target,'download');
  if result->>'allowed'<>'false' or result->'reasons'<>
    '["device_trust","session_risk","session_network","utc_window","classification","tenant_type"]'::jsonb then
    raise exception 'The evaluator skipped a trusted mismatch or accepted supplied headers: %',result; end if;
  if public.st_v7_explain_file_egress('workspace',space,gen_random_uuid(),'download')
    <>'{"allowed":false,"reasons":["access_unavailable"]}'::jsonb then raise exception 'Missing file disclosed policy'; end if;
  reset role;

  perform set_config('request.jwt.claims',(claims||'{"aal":"aal1"}')::text,true);
  set local role authenticated;
  if public.st_v7_file_egress_policy(space)<>'{"access":"mfa"}'::jsonb then raise exception 'AAL1 exposed policy'; end if;
  begin
    perform public.st_v7_save_file_egress_policy(space,2,'{"mode":"inherit"}');
    raise exception 'AAL1 wrote policy';
  exception when insufficient_privilege then null; end;
  reset role;
  if (select count(*) from public.st_v2_workspace_audit where workspace_id=space and event='workspace.file_egress_require')<>2 then
    raise exception 'Policy change audit did not track successful writes'; end if;
end $$;
rollback;
