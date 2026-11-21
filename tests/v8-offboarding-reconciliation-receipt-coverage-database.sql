begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; workspace_id uuid;
  channel_id uuid:=gen_random_uuid(); room_id uuid:=gen_random_uuid(); request_id uuid:=gen_random_uuid(); export_id uuid:=gen_random_uuid();
  inventory_id uuid; channel_success uuid:=gen_random_uuid(); room_success uuid:=gen_random_uuid();
  room_task uuid:=gen_random_uuid(); workspace_task uuid:=gen_random_uuid(); channel_doomed uuid:=gen_random_uuid(); room_doomed uuid:=gen_random_uuid();
  hold_id uuid:=gen_random_uuid();
  first_review jsonb; current_review jsonb; provider_version text:=gen_random_uuid()::text;
  storage_plan uuid:=gen_random_uuid(); workspace_copy uuid:=gen_random_uuid(); room_copy uuid:=gen_random_uuid();
  workspace_file uuid:=gen_random_uuid(); room_file uuid:=gen_random_uuid(); other_workspace uuid:=gen_random_uuid();
  file_sha text:=repeat('a',64); thread_plan uuid:=gen_random_uuid(); retained_hash text:=repeat('d',64);
  workspace_path text; room_path text;
  residency_handoff uuid:=gen_random_uuid(); residency_review uuid:=gen_random_uuid();
  residency_receipt uuid:=gen_random_uuid(); recovery_object uuid:=gen_random_uuid(); recovery_path text;

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
  workspace_path:=workspace_id::text||'/'||workspace_file::text;
  room_path:=workspace_id::text||'/rooms/'||room_id::text||'/'||room_file::text;
  -- Seed immutable evidence from the separately verified native removal workflows.
  insert into sectalk_private.st_v8_offboarding_storage_plans(id,request,requester,reviewer,reviewed_at,snapshot,sha256)
    values(storage_plan,request_id,owner_id,reviewer_id,now(),'{}',repeat('b',64));
  insert into sectalk_private.st_v8_offboarding_storage_copy_receipts
    (id,plan,workspace,export_id,file,actor,object_id,object_version,bytes,sha256) values
    (workspace_copy,storage_plan,workspace_id,export_id,workspace_file,owner_id,gen_random_uuid(),provider_version,10,file_sha),
    (gen_random_uuid(),storage_plan,other_workspace,gen_random_uuid(),gen_random_uuid(),owner_id,gen_random_uuid(),provider_version,9,file_sha);
  insert into sectalk_private.st_v8_offboarding_room_storage_copy_receipts
    (id,plan,workspace,export_id,room,file,actor,object_id,object_version,bytes,sha256)
    values(room_copy,storage_plan,workspace_id,export_id,room_id,room_file,owner_id,gen_random_uuid(),provider_version,10,file_sha);
  insert into sectalk_private.st_v8_workspace_file_recovery_reviews(copy_id,request_id,reviewer,source_sha256)
    values(workspace_copy,request_id,reviewer_id,retained_hash);
  insert into sectalk_private.st_v8_room_file_recovery_reviews(copy_id,request_id,reviewer,source_sha256)
    values(room_copy,request_id,reviewer_id,retained_hash);
  insert into sectalk_private.st_v8_offboarding_workspace_file_retirements(workspace,file,copy_id,request_id,owner_id,
    source_sha256,provider_absence_observed_at)
    values(workspace_id,workspace_file,workspace_copy,request_id,owner_id,retained_hash,now());
  insert into sectalk_private.st_v8_offboarding_room_file_retirements(workspace,room,file,copy_id,request_id,owner_id,
    source_sha256,provider_absence_observed_at)
    values(workspace_id,room_id,room_file,room_copy,request_id,owner_id,retained_hash,now());
  insert into sectalk_private.st_v8_offboarding_room_thread_deletions
    (id,request,workspace,room,root,owner_id,reviewer,export_id,manifest_sha256,thread_sha256,manifest,message_count,key_sha256,sha256,expires_at)
    values(thread_plan,request_id,workspace_id,room_id,gen_random_uuid(),owner_id,reviewer_id,export_id,repeat('1',64),repeat('2',64),
      jsonb_build_array(gen_random_uuid(),gen_random_uuid()),2,repeat('3',64),repeat('4',64),now()+interval '10 minutes');
  insert into sectalk_private.st_v8_offboarding_room_thread_decisions(deletion,action,actor)
    values(thread_plan,'approved',reviewer_id),(thread_plan,'deleted',owner_id);
  set local role authenticated;
  first_review:=public.st_v8_offboarding_reconciliation(workspace_id,'capture',workspace_id::text);
  if first_review#>'{summary,recoveryEvidence}' is distinct from '{
      "workspaceFileCopyReceipts":1,"workspaceFileRecoveryReviews":1,"roomFileCopyReceipts":1,"roomFileRecoveryReviews":1
    }'::jsonb or first_review#>>'{summary,verifiedDeletionReceipts,roomThreadReceipts}'<>'1'
    or first_review#>>'{summary,verifiedDeletionReceipts,workspaceRegistrationReceipts}'<>'1'
    or first_review#>>'{summary,verifiedDeletionReceipts,roomRegistrationReceipts}'<>'1'
    or first_review#>>'{summary,storageMetadata,workspaceRetiredPathsPresent}'<>'0'
    or first_review#>>'{summary,storageMetadata,roomRetiredPathsPresent}'<>'0'
    or first_review#>>'{summary,storageMetadata,residencyRecoveryPaths}'<>'0'
    or first_review::text like '%'||room_path||'%'
    or first_review::text like '%'||workspace_copy::text||'%'
    or first_review::text like '%'||provider_version||'%' then
    raise exception 'The exact linked evidence census has missing, extra, or exposed scope'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  current_review:=public.st_v8_offboarding_reconciliation(workspace_id,'confirm',workspace_id::text,
    (first_review->>'plan')::uuid,first_review->>'sha256');
  if current_review->>'reviewedAt' is null or current_review->>'current'<>'true' then
    raise exception 'Independent reviewed snapshot was not current'; end if;
  reset role;
  recovery_path:=workspace_id::text||'/'||residency_handoff::text||'/'||workspace_file::text||'/'||file_sha;
  insert into storage.objects(bucket_id,name,version,metadata) values
    ('sectalk-residency-recovery',other_workspace::text||'/unrelated',gen_random_uuid()::text,'{"size":10}');
  set local role authenticated;
  current_review:=public.st_v8_offboarding_reconciliation(workspace_id);
  if current_review->>'current'<>'true' or current_review#>>'{summary,storageMetadata,residencyRecoveryPaths}'<>'0' then
    raise exception 'An unrelated recovery path contaminated this workspace review'; end if;
  reset role;
  insert into storage.objects(id,bucket_id,name,version,metadata) values
    (recovery_object,'sectalk-residency-recovery',recovery_path,provider_version,'{"size":10}');
  set local role authenticated;
  current_review:=public.st_v8_offboarding_reconciliation(workspace_id);
  if current_review->>'current'<>'false' or current_review#>>'{summary,storageMetadata,residencyRecoveryPaths}'<>'1'
    or current_review::text like '%'||recovery_path||'%' or current_review::text like '%'||recovery_object::text||'%' then
    raise exception 'An orphaned regional recovery object must stale the review without exposing its path or id'; end if;
  reset role;
  insert into sectalk_private.st_v8_residency_write_handoffs(workspace,approval,handoff,source_project,destination_project,phase)
    values(workspace_id,export_id,residency_handoff,'fixture-source','fixture-destination','restored');
  insert into sectalk_private.st_v8_residency_source_file_copies(handoff,file,review,sha256,bytes,object_id,object_version)
    values(residency_handoff,workspace_file,residency_review,file_sha,10,recovery_object,provider_version);
  insert into sectalk_private.st_v8_residency_retired_destinations(workspace,handoff,approval,source_project,destination_project,
    review,review_sha256,plan_sha256,owner,reviewer) values(workspace_id,residency_handoff,export_id,'fixture-source',
      'fixture-destination',residency_review,file_sha,file_sha,owner_id,reviewer_id);
  insert into sectalk_private.st_v8_residency_source_reactivations(handoff,workspace,destination_receipt,source_evidence,
    source_digest,proof_digest,actor) values(residency_handoff,workspace_id,residency_receipt,gen_random_uuid(),file_sha,file_sha,owner_id);
  set local role authenticated;
  current_review:=public.st_v8_offboarding_reconciliation(workspace_id);
  if current_review#>>'{summary,nativeRows,residencyRecoveryFileReceipts}'<>'1'
    or current_review#>>'{summary,nativeRows,residencyDestinationRetirements}'<>'1'
    or current_review#>>'{summary,nativeRows,residencySourceReactivations}'<>'1'
    or current_review#>>'{summary,workspaceRootDependencies,unclassifiedConstraints}'<>'0'
    or current_review::text like '%'||residency_receipt::text||'%' then
    raise exception 'The residency receipt census is missing, unclassified or exposed'; end if;
  reset role;
  insert into storage.objects(bucket_id,name,version,metadata) values
    ('sectalk-workspace-files',workspace_path,gen_random_uuid()::text,'{"size":10}'),
    ('sectalk-workspace-files',room_path,gen_random_uuid()::text,'{"size":10}');
  set local role authenticated;
  current_review:=public.st_v8_offboarding_reconciliation(workspace_id);
  if current_review->>'current'<>'false'
    or current_review#>>'{summary,storageMetadata,workspaceRetiredPathsPresent}'<>'1'
    or current_review#>>'{summary,storageMetadata,roomRetiredPathsPresent}'<>'1'
    or current_review#>>'{summary,verifiedDeletionReceipts,workspaceRegistrationReceipts}'<>'1'
    or current_review->>'providerBytes'<>'unverified' or current_review->>'backupErasure'<>'unverified'
    or current_review->>'fullTenantErasure'<>'unverified' then
    raise exception 'Returned Storage metadata did not invalidate exactly the prior observation'; end if;
  begin
    perform public.st_v8_offboarding_reconciliation(workspace_id,'confirm',workspace_id::text,
      (first_review->>'plan')::uuid,first_review->>'sha256');
    raise exception 'Reviewer confirmed an obsolete snapshot after paths reappeared';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  if (select count(*) from storage.objects o where o.bucket_id='sectalk-workspace-files' and o.name in (workspace_path,room_path))<>2
    or has_function_privilege('authenticated','sectalk_private.st_v8_offboarding_reconcile_receipts(uuid,uuid)','EXECUTE')
    then raise exception 'Reconciliation modified provider metadata or exposed the private helper'; end if;
  with extra as (
    insert into sectalk_private.st_v8_offboarding_room_thread_deletions
      (request,workspace,room,root,owner_id,reviewer,export_id,manifest_sha256,thread_sha256,manifest,message_count,key_sha256,sha256,expires_at)
    select request_id,workspace_id,room_id,gen_random_uuid(),owner_id,reviewer_id,export_id,repeat('1',64),repeat('2',64),
      jsonb_build_array(gen_random_uuid(),gen_random_uuid()),2,repeat('3',64),repeat('4',64),now()+interval '10 minutes'
    from generate_series(1,500) returning id
  )
  insert into sectalk_private.st_v8_offboarding_room_thread_decisions(deletion,action,actor)
    select e.id,x.action,x.actor from extra e cross join (values ('approved',reviewer_id),('deleted',owner_id)) x(action,actor);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  current_review:=public.st_v8_offboarding_reconciliation(workspace_id);
  if not (current_review#>'{summary,overflow}') @> '["roomThreadReceipts"]'::jsonb or current_review->>'current'<>'false' then
    raise exception 'New receipt family cap was not enforced'; end if;
  begin
    perform public.st_v8_offboarding_reconciliation(workspace_id,'capture',workspace_id::text);
    raise exception 'Overflowing receipt family could be certified';
  exception when sqlstate 'PT409' then null; end;
end $$;

select 'passed: joined copy/recovery/retirement/thread exact counts, isolation, no scope disclosure, stale receipt on reappearance';
rollback;
