begin;

do $$
<<fixture>>
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; workspace_id uuid; object_path text; file_id uuid:=gen_random_uuid(); request_id uuid:=gen_random_uuid();
  other_workspace uuid:=gen_random_uuid(); hold_id uuid:=gen_random_uuid();
  hold_token uuid; control_file uuid:=gen_random_uuid(); sheltered_path text; cleanup jsonb; status jsonb;
  cleanup_ticket uuid; export_id uuid:=gen_random_uuid(); case_id uuid; version text:=gen_random_uuid()::text;
  approved_hash text:=repeat('a',64); plan jsonb; token uuid; stale_token uuid; receipt uuid;
begin
  foreach actor in array array[owner_id,reviewer_id] loop
    session_id:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'st_cp_'||left(actor::text,8),'Retention receipt fixture');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',session_id,'aal','aal2'));
  end loop;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  workspace_id:=public.st_v2_create_workspace('Disposable Storage copy');
  reset role;
  object_path:=workspace_id::text||'/'||file_id::text;
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace_id,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(workspace_id,reviewer_id);
  insert into sectalk_private.st_v6_workspace_files(workspace,id,uploader,filename,size_bytes,fingerprint,published_at)
    values(workspace_id,file_id,owner_id,'disposable.txt',10,
      sectalk_private.st_v6_workspace_file_fingerprint(workspace_id,approved_hash),now()),
      (workspace_id,control_file,owner_id,'control.txt',10,
      sectalk_private.st_v6_workspace_file_fingerprint(workspace_id,approved_hash),now());
  insert into sectalk_private.st_v6_workspace_file_events(workspace,file_id,actor,event)
    values(workspace_id,file_id,owner_id,'download');
  insert into storage.objects(bucket_id,name,version,metadata) values('sectalk-workspace-files',object_path,version,'{"size":10}'),
    ('sectalk-workspace-files',workspace_id::text||'/'||control_file::text,gen_random_uuid()::text,'{"size":10}');
  sheltered_path:='disposable-fixture-retained/'||gen_random_uuid()::text;

  set local role authenticated;
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'requested',workspace_id::text,'Prepare scoped synthetic copy proof.');
  perform public.st_v8_offboarding_content(workspace_id,'export_content_files',export_id,workspace_id::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'approved',workspace_id::text);
  perform public.st_v8_offboarding_content(workspace_id,'approve',export_id,workspace_id::text);
  case_id:=(public.st_v8_workspace_offboarding(workspace_id)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(case_id,workspace_id,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'read_only',workspace_id::text);
  plan:=public.st_v8_offboarding_storage_plan(workspace_id,'capture',null,workspace_id::text);
  begin
    perform public.st_v8_begin_offboarding_storage_copy(workspace_id,(plan->>'plan')::uuid,export_id,file_id);
    raise exception 'Unreviewed Storage plan admitted';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_storage_plan(workspace_id,'confirm',(plan->>'plan')::uuid,workspace_id::text,plan->>'sha256');
  begin
    perform public.st_v8_begin_offboarding_storage_copy(workspace_id,(plan->>'plan')::uuid,export_id,file_id);
    raise exception 'Reviewer admitted to owner file bytes';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_begin_offboarding_storage_copy(other_workspace,(plan->>'plan')::uuid,export_id,file_id);
    raise exception 'An approved UUID was allowed in a different workspace';
  exception when insufficient_privilege then null; end;
  token:=public.st_v8_begin_offboarding_storage_copy(workspace_id,(plan->>'plan')::uuid,export_id,file_id);
  reset role;
  set local role service_role;
  if public.st_v8_finish_offboarding_storage_copy(token,repeat('b',64),10) is not null then raise exception 'Wrong byte hash produced proof'; end if;
  if public.st_v8_finish_offboarding_storage_copy(token,approved_hash,10) is not null then raise exception 'Spent ticket replayed'; end if;
  reset role;
  set local role authenticated;
  token:=public.st_v8_begin_offboarding_storage_copy(workspace_id,(plan->>'plan')::uuid,export_id,file_id);
  stale_token:=public.st_v8_begin_offboarding_storage_copy(workspace_id,(plan->>'plan')::uuid,export_id,file_id);
  hold_token:=public.st_v8_begin_offboarding_storage_copy(workspace_id,(plan->>'plan')::uuid,export_id,file_id);
  reset role;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,workspace_id,owner_id,'Preserve the scoped synthetic room file.',owner_id);
  set local role service_role;
  if public.st_v8_finish_offboarding_storage_copy(hold_token,approved_hash,10) is not null then
    raise exception 'An active hold admitted an already-issued ticket'; end if;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release the disposable test hold.' where h.id=hold_id;
  reset role;
  set local role service_role;
  receipt:=public.st_v8_finish_offboarding_storage_copy(token,approved_hash,10);
  if receipt is null then raise exception 'Exact proof unavailable'; end if;
  reset role;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  if (public.st_v8_offboarding_storage_copies(workspace_id,(plan->>'plan')::uuid)#>>'{verifiedCopies,0,id}')::uuid
    is distinct from receipt then raise exception 'Independent reviewer could not see exact receipt'; end if;
  reset role;

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform public.st_v8_begin_workspace_file_cleanup(workspace_id,receipt,'review',workspace_id::text);
    raise exception 'A present Storage path was reviewable for native cleanup';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  -- This synthetic row models an independently observed absent source path without deleting an object.
  update storage.objects o set name=sheltered_path where o.bucket_id='sectalk-workspace-files' and o.name=object_path;
  set local role authenticated;
  begin
    perform public.st_v8_begin_workspace_file_cleanup(workspace_id,gen_random_uuid(),'review',workspace_id::text);
    raise exception 'An unrelated copy qualified';
  exception when sqlstate 'PT409' then null; end;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_begin_workspace_file_cleanup(workspace_id,receipt,'review',workspace_id::text);
    raise exception 'Owner approved their own recovery';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_begin_workspace_file_cleanup(workspace_id,receipt,'remove',workspace_id::text);
    raise exception 'Owner acquired removal before independent recovery review';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  cleanup:=public.st_v8_begin_workspace_file_cleanup(workspace_id,receipt,'review',workspace_id::text);
  cleanup_ticket:=(cleanup->>'ticket')::uuid;
  set local role service_role;
  if public.st_v8_finish_workspace_file_cleanup(cleanup_ticket,repeat('d',64),10)
    or public.st_v8_finish_workspace_file_cleanup(cleanup_ticket,approved_hash,10) then
    raise exception 'Wrong or replayed recovery evidence accepted'; end if;
  set local role authenticated;
  cleanup:=public.st_v8_begin_workspace_file_cleanup(workspace_id,receipt,'review',workspace_id::text);
  set local role service_role;
  if not public.st_v8_finish_workspace_file_cleanup((cleanup->>'ticket')::uuid,approved_hash,10) then
    raise exception 'Correct recovery bytes rejected'; end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  status:=public.st_v8_workspace_file_cleanup_status(workspace_id);
  if status#>>'{candidates,0,file}' is distinct from file_id::text or status#>>'{candidates,0,reviewedAt}' is null then
    raise exception 'Current recovery approval unavailable'; end if;
  cleanup:=public.st_v8_begin_workspace_file_cleanup(workspace_id,receipt,'remove',workspace_id::text);
  reset role;
  update storage.objects o set name=object_path where o.bucket_id='sectalk-workspace-files' and o.name=sheltered_path;
  set local role service_role;
  if public.st_v8_finish_workspace_file_cleanup((cleanup->>'ticket')::uuid,null,null,clock_timestamp()) then
    raise exception 'A reappearing provider key was ignored'; end if;
  reset role;
  update storage.objects o set name=sheltered_path where o.bucket_id='sectalk-workspace-files' and o.name=object_path;
  set local role authenticated;
  cleanup:=public.st_v8_begin_workspace_file_cleanup(workspace_id,receipt,'remove',workspace_id::text);
  set local role service_role;
  if public.st_v8_finish_workspace_file_cleanup((cleanup->>'ticket')::uuid,null,null,clock_timestamp()-interval '15 seconds') then
    raise exception 'An old provider absence observation was accepted'; end if;
  set local role authenticated;
  cleanup:=public.st_v8_begin_workspace_file_cleanup(workspace_id,receipt,'remove',workspace_id::text);
  reset role;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(gen_random_uuid(),workspace_id,owner_id,'Preserve the disposable room under hold.',owner_id)
    returning id into hold_id;
  set local role service_role;
  if public.st_v8_finish_workspace_file_cleanup((cleanup->>'ticket')::uuid,null,null,clock_timestamp()) then
    raise exception 'A late hold did not preserve the source registration'; end if;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release the disposable fixture hold.' where h.id=hold_id;
  set local role authenticated;
  cleanup:=public.st_v8_begin_workspace_file_cleanup(workspace_id,receipt,'remove',workspace_id::text);
  set local role service_role;
  if not public.st_v8_finish_workspace_file_cleanup((cleanup->>'ticket')::uuid,null,null,clock_timestamp()) then
    raise exception 'Exact absent registration was not removed'; end if;
  reset role;
  if exists(select 1 from sectalk_private.st_v6_workspace_files x where (x.workspace,x.id)=(workspace_id,file_id))
    or not exists(select 1 from sectalk_private.st_v6_workspace_files x where (x.workspace,x.id)=(workspace_id,control_file))
    or not exists(select 1 from sectalk_private.st_v8_offboarding_workspace_file_retirements x
      where (x.workspace,x.file,x.copy_id)=(workspace_id,file_id,receipt))
    or not exists(select 1 from storage.objects o where o.bucket_id='sectalk-workspace-files' and o.name=sheltered_path)
    or not exists(select 1 from storage.objects o where o.bucket_id='sectalk-workspace-files'
      and o.name=workspace_id::text||'/'||control_file::text)
    or not exists(select 1 from sectalk_private.st_v6_workspace_retired_file_ids x where (x.workspace,x.id)=(workspace_id,file_id))
    or not exists(select 1 from sectalk_private.st_v6_workspace_file_history_subjects x
      where (x.workspace,x.id)=(workspace_id,file_id) and x.filename='disposable.txt' and x.removed_at is not null)
    or not exists(select 1 from sectalk_private.st_v6_workspace_file_events x
      where (x.workspace,x.file_id,x.actor,x.event)=(workspace_id,fixture.file_id,owner_id,'download'))
    or has_function_privilege('authenticated','public.st_v8_finish_workspace_file_cleanup(uuid,text,integer,timestamptz)','EXECUTE') then
    raise exception 'Collateral object/registration change, missing tombstone, or unsafe privilege'; end if;
  set local role authenticated;
  status:=public.st_v8_workspace_file_cleanup_status(workspace_id);
  if jsonb_array_length(status->'candidates')<>0 or status#>>'{retired,0,file}' is distinct from file_id::text then
    raise exception 'Final registered metadata cleanup status is incorrect'; end if;
end $$;

select 'passed: independent exact workspace recovery, fresh provider observation, hold and reappearance denials, immutable scoped metadata cleanup and retained access history';
rollback;
