begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; workspace_id uuid;
  channel_id uuid:=gen_random_uuid(); room_id uuid:=gen_random_uuid(); request_id uuid:=gen_random_uuid(); export_id uuid:=gen_random_uuid();
  inventory_id uuid; channel_success uuid:=gen_random_uuid(); room_success uuid:=gen_random_uuid();
  room_task uuid:=gen_random_uuid(); workspace_task uuid:=gen_random_uuid(); channel_doomed uuid:=gen_random_uuid(); room_doomed uuid:=gen_random_uuid();
  hold_id uuid:=gen_random_uuid();
  first_review jsonb; second_review jsonb; status jsonb; report_id uuid; storage_id uuid:=gen_random_uuid();
begin
  foreach actor in array array[owner_id,reviewer_id] loop
    session_id:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'batch_'||left(actor::text,8),'Disposable batch actor');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',session_id,'aal','aal2'));
  end loop;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  workspace_id:=public.st_v2_create_workspace('Disposable batch offboarding source');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace_id,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(workspace_id,reviewer_id);
  insert into public.st_v2_channels(id,workspace_id,name) values(channel_id,workspace_id,'disposable-channel');
  insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator)
    values(room_id,workspace_id,'Disposable room','public','blank',owner_id);
  insert into public.st_v6_room_members(room_id,user_id,role) values(room_id,owner_id,'owner'),(room_id,reviewer_id,'moderator');
  insert into public.st_v2_posts(id,channel_id,sender,body) values
    (channel_success,channel_id,owner_id,'Disposable eligible channel source'),
    (channel_doomed,channel_id,owner_id,'This channel post remains after rollback');
  insert into public.st_v6_room_posts(id,room_id,sender,body,kind) values
    (room_success,room_id,owner_id,'Disposable eligible room source','message'),
    (room_doomed,room_id,owner_id,'This room post receives a late report','message');
  insert into public.st_v2_items(id,workspace_id,kind,created_by,title) values
    (workspace_task,workspace_id,'task',owner_id,'Disposable workspace task');
  insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values(workspace_id,1);
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,wrapped) values(workspace_id,1,'managed',repeat('a',80));
  set local role authenticated;
  perform public.st_v6_task_create(room_task,room_id,null,'Disposable room task');
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'requested',workspace_id::text,'Disposable batch approval');
  perform public.st_v8_offboarding_content(workspace_id,'export_content',export_id,workspace_id::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'approved',workspace_id::text);
  perform public.st_v8_offboarding_content(workspace_id,'approve',export_id,workspace_id::text);
  inventory_id:=(public.st_v8_workspace_offboarding(workspace_id)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action)
    values(inventory_id,workspace_id,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'read_only',workspace_id::text);

  reset role;
  insert into storage.objects(id,bucket_id,name,metadata,version)
    values(storage_id,'sectalk-workspace-files',workspace_id::text||'/private-disposable-name',
      '{"size":12}',gen_random_uuid()::text);
  set local role authenticated;
  first_review:=public.st_v8_offboarding_reconciliation(workspace_id,'capture',workspace_id::text);
  if first_review->>'current'<>'true' or first_review->>'providerBytes'<>'unverified'
    or first_review->>'backupErasure'<>'unverified' or first_review->>'fullTenantErasure'<>'unverified'
    or first_review#>>'{summary,nativeRows,roomPosts}'<>'2'
    or first_review#>>'{summary,nativeRows,roomTasks}'<>'1'
    or first_review#>>'{summary,nativeRows,tenantKeyVersions}'<>'1'
    or first_review#>>'{summary,storageMetadata,untracked}'<>'1'
    or first_review::text like '%private-disposable-name%'
    or first_review::text like '%Disposable eligible%'
    or first_review::text like '%'||channel_success::text||'%' then
    raise exception 'Scope, metadata/provider distinction, or privacy is incorrect'; end if;
  begin
    perform public.st_v8_offboarding_reconciliation(workspace_id,'confirm',workspace_id::text,
      (first_review->>'plan')::uuid,first_review->>'sha256');
    raise exception 'Owner confirmed their own reconciliation';
  exception when insufficient_privilege then null; end;

  -- Stable counts are insufficient. A replacement changes the native Storage revision.
  reset role;
  update storage.objects o set version=gen_random_uuid()::text where o.id=storage_id;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform public.st_v8_offboarding_reconciliation(workspace_id,'confirm',workspace_id::text,
      (first_review->>'plan')::uuid,first_review->>'sha256');
    raise exception 'Reviewer accepted drift at a same-size Storage path';
  exception when sqlstate 'PT409' then null; end;
  report_id:=public.st_v6_submit_room_report(room_id,room_doomed,'spam','Synthetic residual report.',true);
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  second_review:=public.st_v8_offboarding_reconciliation(workspace_id,'capture',workspace_id::text);
  if second_review->>'plan' is not distinct from first_review->>'plan'
    or second_review->>'observedAt' is distinct from first_review->>'observedAt'
    or second_review#>>'{summary,nativeRows,roomReports}'<>'1' then raise exception 'Residual report missing'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform public.st_v8_offboarding_reconciliation(workspace_id,'confirm',workspace_id::text,
      (second_review->>'plan')::uuid,repeat('a',64));
    raise exception 'Reviewer accepted a different digest';
  exception when sqlstate 'PT409' then null; end;
  status:=public.st_v8_offboarding_reconciliation(workspace_id,'confirm',workspace_id::text,
    (second_review->>'plan')::uuid,second_review->>'sha256');
  if status->>'reviewedAt' is null or status->>'current'<>'true' then raise exception 'Exact review receipt missing'; end if;
  reset role;
  if (select count(*) from sectalk_private.st_v8_offboarding_reconciliation_receipts q
    where q.reconciliation=(second_review->>'plan')::uuid and q.reviewer=reviewer_id)<>1 then
    raise exception 'Independent reviewer receipt is missing'; end if;
  begin
    delete from sectalk_private.st_v8_offboarding_reconciliation_receipts q
      where q.reconciliation=(second_review->>'plan')::uuid;
    raise exception 'Reviewer receipt was mutable';
  exception when insufficient_privilege then null; end;

  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,workspace_id,owner_id,'Protect disposable preserved records.',owner_id);
  set local role authenticated;
  status:=public.st_v8_offboarding_reconciliation(workspace_id);
  if status->>'current'<>'false' or status->>'held'<>'true' then raise exception 'A new hold did not invalidate current reconciliation'; end if;
  begin
    perform public.st_v8_offboarding_reconciliation(workspace_id,'confirm',workspace_id::text,
      (second_review->>'plan')::uuid,second_review->>'sha256');
    raise exception 'Legal hold did not block confirmation';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release test hold for bounded reconciliation.' where h.id=hold_id;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_offboarding_task_copy(workspace_id,workspace_task,workspace_id::text);
  first_review:=public.st_v8_offboarding_task_delete(workspace_id,workspace_task,'capture',workspace_id::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_task_delete(workspace_id,workspace_task,'approve',workspace_id::text,
    (first_review->>'plan')::uuid,first_review->>'sha256');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_offboarding_task_delete(workspace_id,workspace_task,'delete',workspace_id::text,
    (first_review->>'plan')::uuid,first_review->>'sha256');
  status:=public.st_v8_offboarding_reconciliation(workspace_id);
  if status->>'current'<>'false' or status#>>'{summary,nativeRows,workspaceItems}'<>'0'
    or status#>>'{summary,verifiedDeletionReceipts,workspaceTaskReceipts}'<>'1'
    or status->>'fullTenantErasure'<>'unverified' then raise exception 'Residual and deletion receipt reconciliation failed'; end if;
  reset role;
  insert into sectalk_private.st_v6_room_reports(workspace_id,room_id,post_id,reporter,subject,category,details,share_with_workspace)
    select workspace_id,room_id,gen_random_uuid(),reviewer_id,owner_id,'spam','Synthetic overflow '||n,true
    from generate_series(1,501) n;
  set local role authenticated;
  status:=public.st_v8_offboarding_reconciliation(workspace_id);
  if not (status#>'{summary,overflow}') @> '["roomReports"]'::jsonb or status->>'current'<>'false' then
    raise exception 'Coverage cap did not fail closed'; end if;
  begin
    perform public.st_v8_offboarding_reconciliation(workspace_id,'capture',workspace_id::text);
    raise exception 'Owner captured a sampled result';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  if has_function_privilege('service_role','public.st_v8_offboarding_reconciliation(uuid,text,text,uuid,text)','EXECUTE')
    or has_function_privilege('anon','public.st_v8_offboarding_reconciliation(uuid,text,text,uuid,text)','EXECUTE')
    then raise exception 'Unsafe reconciliation grants'; end if;
end $$;

select 'passed: counts only, exact revision drift, independent fresh review, hold invalidation, immutable receipt, scoped native deletion and overflow';
rollback;
