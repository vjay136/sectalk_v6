begin;

do $$
declare
  owner_id uuid:=gen_random_uuid();
  admin_id uuid:=gen_random_uuid();
  outside_id uuid:=gen_random_uuid();
  actor_id uuid;
  fixture_session uuid;
  factor_id uuid;
  owner_claim text;
  admin_claim text;
  outside_claim text;
  workspace_id uuid;
  external_workspace uuid;
  audit_id bigint;
  outside_audit bigint;
  case_identifier uuid;
  ticket_id uuid;
  artifact_id uuid;
  wrong_artifact uuid;
  material jsonb;
  picks jsonb;
  purpose text:='Exact records authorized for the synthetic case.';
begin
  foreach actor_id in array array[owner_id,admin_id,outside_id] loop
    factor_id:=gen_random_uuid();
    fixture_session:=gen_random_uuid();
    insert into auth.users(id,email) values(actor_id,actor_id||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor_id,'cex_'||left(actor_id::text,8),'Compliance QA');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor_id,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(fixture_session,actor_id,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),fixture_session,'totp',now(),now());
    perform set_config('request.jwt.claims',jsonb_build_object('sub',actor_id,'role','authenticated',
      'session_id',fixture_session,'aal','aal2')::text,true);
    if actor_id=owner_id then
      owner_claim:=current_setting('request.jwt.claims');
      set local role authenticated;
      workspace_id:=public.st_v2_create_workspace('Compliance SQL fixture');
      reset role;
    elsif actor_id=admin_id then admin_claim:=current_setting('request.jwt.claims');
    else
      outside_claim:=current_setting('request.jwt.claims');
      set local role authenticated;
      external_workspace:=public.st_v2_create_workspace('Compliance other tenant');
      reset role;
    end if;
  end loop;
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace_id,admin_id,'admin');
  insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(workspace_id,owner_id,'cex.exact')
    returning id into audit_id;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(external_workspace,outside_id,'cex.protected')
    returning id into outside_audit;
  picks:=jsonb_build_array(jsonb_build_object('kind','audit','id',audit_id::text));

  if has_table_privilege('authenticated','sectalk_private.st_v7_compliance_cases','select')
    or has_table_privilege('authenticated','sectalk_private.st_v7_compliance_audit','select')
    or has_function_privilege('authenticated','public.st_v7_read_compliance_operation(uuid)','execute')
    or has_function_privilege('authenticated','public.st_v7_finish_compliance_operation(uuid,uuid)','execute')
    or has_function_privilege('anon','public.st_v7_compliance_cases(uuid)','execute') then
    raise exception 'Internal export operations or audit were exposed';
  end if;
  perform set_config('request.jwt.claims',admin_claim,true);
  set local role authenticated;
  begin
    perform public.st_v7_request_compliance_export(workspace_id,'duplicate',purpose,picks||picks);
    raise exception 'Duplicate sources accepted';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_v7_request_compliance_export(workspace_id,'foreign',purpose,
      jsonb_build_array(jsonb_build_object('kind','audit','id',outside_audit::text)));
    raise exception 'Foreign audit escaped tenant scope';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_request_compliance_export(workspace_id,'group-plaintext',purpose,
      jsonb_build_array(jsonb_build_object('kind','group_message','id',gen_random_uuid()::text)));
    raise exception 'Encrypted group records were treated as export sources';
  exception when insufficient_privilege then null; end;
  case_identifier:=public.st_v7_request_compliance_export(workspace_id,'QA-CE-1',purpose,picks);
  begin
    perform public.st_v7_review_compliance_export(case_identifier,'approved',purpose);
    raise exception 'Self approval escaped separation of duties';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_begin_compliance_operation(case_identifier,'build');
    raise exception 'Pending case produced a build ticket';
  exception when insufficient_privilege then null; end;
  reset role;
  perform set_config('request.jwt.claims',outside_claim,true);
  set local role authenticated;
  begin
    perform public.st_v7_review_compliance_export(case_identifier,'approved',purpose);
    raise exception 'Another tenant owner approved the case';
  exception when insufficient_privilege then null; end;
  reset role;
  perform set_config('request.jwt.claims',owner_claim,true);
  set local role authenticated;
  perform public.st_v7_review_compliance_export(case_identifier,'approved',purpose);
  begin
    perform public.st_v7_begin_compliance_operation(case_identifier,'build');
    raise exception 'Owner approval also granted the requester’s export';
  exception when insufficient_privilege then null; end;
  reset role;

  perform set_config('request.jwt.claims',admin_claim,true);
  set local role authenticated;
  ticket_id:=public.st_v7_begin_compliance_operation(case_identifier,'build');
  reset role;
  update auth.mfa_amr_claims set updated_at=now()-interval '6 minutes'
    where session_id=(admin_claim::jsonb->>'session_id')::uuid;
  if public.st_v7_read_compliance_operation(ticket_id) is not null then
    raise exception 'A build ticket survived stale TOTP';
  end if;
  update auth.mfa_amr_claims set updated_at=now() where session_id=(admin_claim::jsonb->>'session_id')::uuid;
  material:=public.st_v7_read_compliance_operation(ticket_id);
  if material is null or material->>'sha256'<>encode(sha256(convert_to(material->>'bundle','UTF8')),'hex') then
    raise exception 'Approved snapshot did not have the expected digest';
  end if;
  wrong_artifact:=public.st_v6_begin_export_object(admin_id,'compliance',case_identifier,null,'fake-compliance.json',
    'application/json',(material->>'bytes')::integer,repeat('f',64));
  insert into storage.objects(bucket_id,name) values('sectalk-exports',wrong_artifact::text);
  if public.st_v6_finish_export_object(wrong_artifact)
    or public.st_v7_export_key_context(ticket_id,wrong_artifact,'write') is not null
    or public.st_v7_finish_compliance_operation(ticket_id,wrong_artifact) then
    raise exception 'An artifact with different bytes was attached';
  end if;
  artifact_id:=public.st_v6_begin_export_object(admin_id,'compliance',case_identifier,null,'proof-compliance.json',
    'application/json',(material->>'bytes')::integer,material->>'sha256');
  insert into storage.objects(bucket_id,name) values('sectalk-exports',artifact_id::text);
  if public.st_v6_finish_export_object(artifact_id)
    or not public.st_v7_provision_export_key(ticket_id,artifact_id,repeat('a',80))
    or not public.st_v7_bind_export_envelope(ticket_id,artifact_id,1,repeat('b',80),repeat('c',16),repeat('d',22)) then
    raise exception 'Managed artifact was not bound to its exact key context';
  end if;
  if not public.st_v6_finish_export_object(artifact_id) or not public.st_v7_finish_compliance_operation(ticket_id,artifact_id) then
    raise exception 'Matched artifact could not be attached';
  end if;
  set local role authenticated;
  ticket_id:=public.st_v7_begin_compliance_operation(case_identifier,'download');
  reset role;
  perform set_config('request.jwt.claims',owner_claim,true);
  set local role authenticated;
  perform public.st_v7_review_compliance_export(case_identifier,'revoked',purpose);
  reset role;
  if public.st_v7_read_compliance_operation(ticket_id) is not null
    or public.st_v7_finish_compliance_operation(ticket_id,artifact_id)
    or not exists(select 1 from sectalk_private.st_v6_export_objects a where a.id=artifact_id and a.expires_at<=clock_timestamp())
    or (select string_agg(action,',' order by id) from sectalk_private.st_v7_compliance_audit a where a.case_id=case_identifier)
      <> 'requested,approved,built,revoked' then
    raise exception 'Revocation failed to invalidate the in-progress download or preserve audit';
  end if;
end $$;

select 'passed: exact tenant scope, independent approval, private ticket, current MFA, digest binding and mid-transfer revocation' as result;
rollback;
