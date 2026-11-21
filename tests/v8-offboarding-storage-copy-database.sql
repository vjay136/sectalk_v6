begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; workspace_id uuid; object_path text; file_id uuid:=gen_random_uuid(); request_id uuid:=gen_random_uuid();
  export_id uuid:=gen_random_uuid(); case_id uuid; version text:=gen_random_uuid()::text;
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
    values(workspace_id,file_id,owner_id,'disposable.txt',10,sectalk_private.st_v6_workspace_file_fingerprint(workspace_id,approved_hash),now());
  insert into storage.objects(bucket_id,name,version,metadata) values('sectalk-workspace-files',object_path,version,'{"size":10}');

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
  token:=public.st_v8_begin_offboarding_storage_copy(workspace_id,(plan->>'plan')::uuid,export_id,file_id);
  reset role;
  set local role service_role;
  if public.st_v8_finish_offboarding_storage_copy(token,repeat('b',64),10) is not null then raise exception 'Wrong byte hash produced proof'; end if;
  if public.st_v8_finish_offboarding_storage_copy(token,approved_hash,10) is not null then raise exception 'Spent ticket replayed'; end if;
  reset role;
  set local role authenticated;
  token:=public.st_v8_begin_offboarding_storage_copy(workspace_id,(plan->>'plan')::uuid,export_id,file_id);
  stale_token:=public.st_v8_begin_offboarding_storage_copy(workspace_id,(plan->>'plan')::uuid,export_id,file_id);
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
  update storage.objects o set version=gen_random_uuid()::text where o.bucket_id='sectalk-workspace-files' and o.name=object_path;
  set local role service_role;
  if public.st_v8_finish_offboarding_storage_copy(stale_token,approved_hash,10) is not null then raise exception 'Same-size replacement accepted'; end if;
  reset role;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_storage_copies(workspace_id,(plan->>'plan')::uuid);
    raise exception 'Stale receipt was presented as current';
  exception when insufficient_privilege then null; end;
  reset role;
  if (select count(*) from storage.objects o where o.bucket_id='sectalk-workspace-files' and o.name=object_path)<>1
    or has_function_privilege('authenticated','public.st_v8_finish_offboarding_storage_copy(uuid,text,integer)','EXECUTE')
    or has_function_privilege('anon','public.st_v8_begin_offboarding_storage_copy(uuid,uuid,uuid,uuid)','EXECUTE') then
    raise exception 'Unexpected object loss or privilege'; end if;
end $$;

select 'passed: independently scoped Storage copy receipts, wrong hash, replay, same-size drift and current byte preservation';
rollback;
