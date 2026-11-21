begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); outsider uuid:=gen_random_uuid(); actor uuid;
  session_id uuid; factor_id uuid; claims jsonb:='{}'; workspace uuid; request_id uuid:=gen_random_uuid();
  case_id uuid:=gen_random_uuid(); event_id uuid:=gen_random_uuid(); hold_id uuid:=gen_random_uuid();
  pin text:=repeat('P',43); event_sha text:=repeat('e',64);
  ticket jsonb; exported jsonb; payload jsonb;
begin
  foreach actor in array array[owner_id,reviewer_id,outsider] loop
    session_id:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'provider_'||left(actor::text,8),'Disposable custody actor');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',session_id,'aal','aal2'));
  end loop;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  workspace:=public.st_v2_create_workspace('Disposable exact provider export');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(workspace,reviewer_id);
  insert into sectalk_private.st_v7_tenant_destroy_reviewers values(workspace,reviewer_id);
  insert into sectalk_private.st_v7_compliance_cases(id,workspace_id,requester,reviewer,case_reference,reason,sources,state,approved_at)
    values(case_id,workspace,owner_id,reviewer_id,'Provider export fixture','Disposable external provider evidence',
      '[{"kind":"offboarding_inventory"}]','approved',now()-interval '3 minutes');
  insert into sectalk_private.st_v8_offboarding_requests(id,workspace,requester,reviewer,case_id,reason,state,
    snapshot,snapshot_sha256,created_at,staged_at,integration_shutdown)
  select request_id,workspace,owner_id,reviewer_id,case_id,'Disposable immutable provider export','read_only',
    s,encode(sha256(convert_to(s::text,'UTF8')),'hex'),now()-interval '3 minutes',now()-interval '2 minutes','{}'
    from (select sectalk_private.st_v8_offboarding_snapshot(workspace) s) inventory;
  insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values(workspace,1);
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,provider_ref,wrapped)
    values(workspace,1,'byok','synthetic_secret_reference','external_v2_'||pin||'_'||repeat('X',43));

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform public.st_v8_export_provider_key_evidence(workspace,1,workspace::text);
    raise exception 'Exported before an immutable receipt existed';
  exception when sqlstate 'PT409' then null; end;
  ticket:=public.st_v8_begin_tenant_provider_erasure(workspace,1,workspace::text);
  set local role service_role;
  if not public.st_v8_commit_tenant_provider_erasure((ticket->>'ticket')::uuid,reviewer_id,event_id,clock_timestamp(),event_sha) then
    raise exception 'Synthetic native receipt could not be committed'; end if;
  set local role authenticated;

  foreach actor in array array[owner_id,outsider] loop
    perform set_config('request.jwt.claims',claims->>actor::text,true);
    begin
      perform public.st_v8_export_provider_key_evidence(workspace,1,workspace::text);
      raise exception 'Unauthorized actor could export custody evidence';
    exception when insufficient_privilege then null; end;
  end loop;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform public.st_v8_export_provider_key_evidence(workspace,2,workspace::text);
    raise exception 'Accepted unrelated exact version';
  exception when sqlstate 'PT409' then null; end;
  begin
    perform public.st_v8_export_provider_key_evidence(workspace,1,gen_random_uuid()::text);
    raise exception 'Accepted wrong workspace confirmation';
  exception when insufficient_privilege then null; end;
  exported:=public.st_v8_export_provider_key_evidence(workspace,1,workspace::text);
  payload:=(exported->>'json')::jsonb;
  if exported->>'sha256'<>encode(sha256(convert_to(exported->>'json','UTF8')),'hex')
    or payload->>'format'<>'sectalk-provider-key-evidence-v1'
    or (payload->>'workspace',payload->>'version',payload->>'eventSha256')<>(workspace::text,'1',event_sha)
    or payload->>'pinCommitment'<>encode(sha256(convert_to('sectalk-provider-pin-commitment-v1:'||workspace||':1:'||pin,'UTF8')),'hex')
    or exported::text like '%'||pin||'%' or exported::text like '%synthetic_secret_reference%'
    or exported is distinct from public.st_v8_export_provider_key_evidence(workspace,1,workspace::text) then
    raise exception 'Provider export is unstable, excessive, or not bound to its exact receipt'; end if;
  reset role;

  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,workspace,owner_id,'Preserve synthetic key evidence.',owner_id);
  set local role authenticated;
  begin
    perform public.st_v8_export_provider_key_evidence(workspace,1,workspace::text);
    raise exception 'Evidence export proceeded during an active hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release the disposable test hold.' where h.id=hold_id;
  update auth.mfa_amr_claims a set updated_at=now()-interval '6 minutes'
    where a.session_id=(claims->reviewer_id::text->>'session_id')::uuid;
  set local role authenticated;
  begin
    perform public.st_v8_export_provider_key_evidence(workspace,1,workspace::text);
    raise exception 'Evidence export proceeded with stale MFA';
  exception when insufficient_privilege then null; end;
  reset role;
  if has_function_privilege('anon','public.st_v8_export_provider_key_evidence(uuid,integer,text)','EXECUTE')
    or has_function_privilege('service_role','public.st_v8_export_provider_key_evidence(uuid,integer,text)','EXECUTE')
    then raise exception 'Evidence export grants too broad'; end if;
end $$;

select 'passed: immutable provider receipt, exact scope commitment, no raw pin, role and MFA denials, legal hold';
rollback;
