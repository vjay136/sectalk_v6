begin;

do $$
<<fixture>>
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
  other_handoff uuid:=gen_random_uuid(); recovery_vault_id uuid:=gen_random_uuid();
  residency_receipt uuid:=gen_random_uuid(); recovery_object uuid:=gen_random_uuid(); recovery_path text;
  group_id uuid:=gen_random_uuid(); custom_role uuid:=gen_random_uuid(); classroom uuid:=gen_random_uuid();
  destination_cell uuid:=gen_random_uuid(); transfer_approval uuid:=gen_random_uuid(); claim_nonce uuid:=gen_random_uuid();
  history_vault_id uuid:=gen_random_uuid(); other_history_vault_id uuid:=gen_random_uuid();
  staged_revision text;

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
  insert into sectalk_private.st_v6_impersonation_watch(workspace_id,member_id,tier)
    values(workspace_id,reviewer_id,'vip');
  insert into sectalk_private.st_v7_billing_admins(workspace,account,assigned_by)
    values(workspace_id,reviewer_id,owner_id);
  insert into public.st_v6_workspace_groups(workspace_id,id,kind,name)
    values(workspace_id,group_id,'group','Disposable class group');
  insert into public.st_v6_workspace_group_members(workspace_id,group_id,user_id)
    values(workspace_id,group_id,reviewer_id);
  insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator)
    values(classroom,workspace_id,'Disposable classroom','public','blank',owner_id);
  insert into sectalk_private.st_v7_school_classes(workspace,id,room)
    values(workspace_id,group_id,classroom);
  insert into sectalk_private.st_v7_school_class_people(workspace,class,person,role)
    values(workspace_id,group_id,reviewer_id,'teacher');
  insert into sectalk_private.st_v7_custom_role_heads(workspace,id,revision)
    values(workspace_id,custom_role,1);
  insert into sectalk_private.st_v7_custom_role_assignments(workspace,role_id,account)
    values(workspace_id,custom_role,reviewer_id);
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
    or first_review#>>'{summary,nativeRows,impersonationWatchEntries}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,delegatedBillingAccounts}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,workspaceGroupMembers}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,schoolClassPeople}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,customRoleAssignments}' is distinct from '1'
    or first_review::text like '%'||group_id::text||'%'
    or first_review::text like '%'||custom_role::text||'%'
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
  insert into public.st_v2_workspaces(id,name,owner) values(other_workspace,'Disposable unrelated workspace',owner_id);
  insert into public.st_v2_members(workspace_id,user_id,role) values(other_workspace,reviewer_id,'admin');
  insert into sectalk_private.st_v6_impersonation_watch(workspace_id,member_id,tier)
    values(other_workspace,reviewer_id,'executive');
  set local role authenticated;
  current_review:=public.st_v8_offboarding_reconciliation(workspace_id);
  if current_review->>'current' is distinct from 'true'
    or current_review#>>'{summary,nativeRows,impersonationWatchEntries}' is distinct from '1' then
    raise exception 'An unrelated impersonation watch entry changed the workspace review';
  end if;
  reset role;
  update sectalk_private.st_v6_impersonation_watch w set tier='executive'
    where (w.workspace_id,w.member_id)=(fixture.workspace_id,reviewer_id);
  set local role authenticated;
  current_review:=public.st_v8_offboarding_reconciliation(workspace_id);
  if current_review->>'current' is distinct from 'false'
    or current_review#>>'{summary,nativeRows,impersonationWatchEntries}' is distinct from '1'
    or current_review::text like '%"tier"%'
    or current_review::text like '%"executive"%' then
    raise exception 'A watch tier change must stale the review and return only the count';
  end if;
  begin
    perform public.st_v8_offboarding_reconciliation(workspace_id,'confirm',workspace_id::text,
      (first_review->>'plan')::uuid,first_review->>'sha256');
    raise exception 'Reviewer confirmed stale impersonation watch evidence';
  exception when sqlstate 'PT409' then null; end;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  first_review:=public.st_v8_offboarding_reconciliation(workspace_id,'capture',workspace_id::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  current_review:=public.st_v8_offboarding_reconciliation(workspace_id,'confirm',workspace_id::text,
    (first_review->>'plan')::uuid,first_review->>'sha256');
  if current_review->>'current' is distinct from 'true' or current_review->>'reviewedAt' is null then
    raise exception 'Independent review did not accept the updated watch snapshot';
  end if;
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
  insert into sectalk_private.st_v8_residency_write_handoffs(workspace,approval,handoff,source_project,destination_project,phase)
    values(other_workspace,gen_random_uuid(),other_handoff,'fixture-source','fixture-destination','restored');
  insert into sectalk_private.st_v8_residency_rollback_manifest_admissions(handoff,vault_id,plan_sha256,expires_at)
    values(residency_handoff,recovery_vault_id,file_sha,now()+interval '1 hour');
  insert into sectalk_private.st_v8_residency_rollback_manifests
    (handoff,workspace,review,review_sha256,packet_sha256,plan_sha256,changes) values
    (residency_handoff,workspace_id,residency_review,file_sha,file_sha,file_sha,'[]'),
    (other_handoff,other_workspace,gen_random_uuid(),file_sha,file_sha,file_sha,'[]');
  insert into sectalk_private.st_v8_residency_rollback_baselines(handoff,snapshot) values
    (residency_handoff,'{"content":"synthetic private recovery content"}'),
    (other_handoff,'{}');
  insert into sectalk_private.st_v8_residency_rollback_reviews(id,handoff,requester,digest,changes)
    values(residency_review,residency_handoff,owner_id,file_sha,'[]');
  insert into sectalk_private.st_v8_residency_source_evidence(handoff,digest,requester)
    values(residency_handoff,file_sha,owner_id);
  insert into sectalk_private.st_v8_residency_board_author_consents(handoff,actor,email_tag,local_identity)
    values(residency_handoff,owner_id,file_sha,file_sha),(other_handoff,owner_id,file_sha,file_sha);
  insert into sectalk_private.st_v8_residency_channel_author_consents(handoff,actor,email_tag,local_identity)
    values(residency_handoff,owner_id,file_sha,file_sha);
  insert into sectalk_private.st_v8_residency_rollback_board_batches(handoff,packet_sha256,tasks,staged_by) values
    (residency_handoff,file_sha,'[{"title":"synthetic private recovery content"}]',owner_id),
    (other_handoff,file_sha,'[]',owner_id);
  insert into sectalk_private.st_v8_residency_rollback_channel_batches(handoff,packet_sha256,records,staged_by) values
    (residency_handoff,file_sha,'[{"body":"synthetic private recovery content"}]',owner_id),
    (other_handoff,file_sha,'[]',owner_id);
  insert into sectalk_private.st_v8_residency_cells(id,region,project_reference,label,environment)
    values(destination_cell,'eu','offboard-fixture-destination','Disposable destination','fixture');
  insert into sectalk_private.st_v8_residency_content_admissions
    (cell,workspace,source_project,approval,manifest_sha256,record_count,expires_at) values
    (destination_cell,workspace_id,'fixture-source',transfer_approval,file_sha,1,now()+interval '1 hour'),
    (destination_cell,other_workspace,'fixture-source',transfer_approval,file_sha,1,now()+interval '1 hour');
  insert into sectalk_private.st_v8_residency_staged_content(cell,workspace,source_project,approval,records) values
    (destination_cell,workspace_id,'fixture-source',transfer_approval,'[{"body":"synthetic private recovery content"}]'),
    (destination_cell,other_workspace,'fixture-source',transfer_approval,'[]');
  insert into sectalk_private.st_v8_residency_workspace_claims
    (cell,workspace,source_project,approval,owner_id,name,manifest_sha256,installation_nonce,expires_at)
    values(destination_cell,workspace_id,'fixture-source',transfer_approval,owner_id,'Unclaimed regional workspace',
      file_sha,claim_nonce,now()+interval '1 hour');
  insert into sectalk_private.st_v8_residency_room_imports
    (cell,workspace,source_project,approval,room,room_name,actor,evidence_count)
    values(destination_cell,workspace_id,'fixture-source',transfer_approval,room_id,'Imported room',owner_id,1);
  insert into sectalk_private.st_v8_residency_room_file_imports
    (cell,workspace,source_project,approval,room,file,actor)
    values(destination_cell,workspace_id,'fixture-source',transfer_approval,room_id,room_file,owner_id);
  insert into sectalk_private.st_v8_residency_room_task_imports
    (cell,workspace,source_project,approval,room,actor,task_count)
    values(destination_cell,workspace_id,'fixture-source',transfer_approval,room_id,owner_id,1);
  insert into sectalk_private.st_v8_residency_room_member_invites
    (cell,workspace,source_project,approval,room,member,challenge,identity,expires_at)
    values(destination_cell,workspace_id,'fixture-source',transfer_approval,room_id,reviewer_id,file_sha,file_sha,now()+interval '1 hour');
  select sectalk_private.st_v8_offboarding_reconcile_workspace_root(r)->>'revision' into staged_revision
    from sectalk_private.st_v8_offboarding_requests r where r.id=request_id;
  update sectalk_private.st_v8_residency_room_file_imports f set published_at=now()
    where f.workspace=workspace_id and f.file=room_file;
  if staged_revision is not distinct from (select sectalk_private.st_v8_offboarding_reconcile_workspace_root(r)->>'revision'
    from sectalk_private.st_v8_offboarding_requests r where r.id=request_id) then
    raise exception 'Publishing a staged regional file did not change the offboarding digest';
  end if;
  insert into sectalk_private.st_v8_residency_history_links
    (workspace,approval,source_project,destination_project,side,vault_id,expires_at)
  values (workspace_id,transfer_approval,'fixture-source','fixture-dest','source',history_vault_id,now()+interval '1 hour'),
    (other_workspace,transfer_approval,'fixture-source','fixture-dest','destination',other_history_vault_id,now()+interval '1 hour');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  first_review:=public.st_v8_offboarding_reconciliation(workspace_id,'capture',workspace_id::text);
  if first_review#>>'{summary,nativeRows,residencyRecoveryFileReceipts}'<>'1'
    or first_review#>>'{summary,nativeRows,residencyDestinationRetirements}'<>'1'
    or first_review#>>'{summary,nativeRows,residencySourceReactivations}'<>'1'
    or first_review#>>'{summary,nativeRows,residencyRollbackAdmissions}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencyRollbackManifests}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencyRollbackBaselines}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencyRollbackReviews}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencySourceEvidence}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencyBoardAuthorConsents}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencyChannelAuthorConsents}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencyRecoveryBoardBatches}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencyRecoveryChannelBatches}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencyContentAdmissions}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencyStagedContent}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencyWorkspaceClaims}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencyHistoryLinks}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencyRoomFileImports}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencyRoomTaskImports}' is distinct from '1'
    or first_review#>>'{summary,nativeRows,residencyRoomMemberInvites}' is distinct from '1'
    or first_review#>>'{summary,workspaceRootDependencies,unclassifiedConstraints}'<>'0'
    or first_review::text like '%'||residency_receipt::text||'%'
    or first_review::text like '%'||recovery_vault_id::text||'%'
    or first_review::text like '%'||claim_nonce::text||'%'
    or first_review::text like '%'||history_vault_id::text||'%'
    or first_review::text like '%'||other_history_vault_id::text||'%'
    or first_review::text like '%synthetic private recovery content%' then
    raise exception 'The residency receipt census is missing, unclassified or exposed'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  current_review:=public.st_v8_offboarding_reconciliation(workspace_id,'confirm',workspace_id::text,
    (first_review->>'plan')::uuid,first_review->>'sha256');
  if current_review->>'current' is distinct from 'true' or current_review->>'reviewedAt' is null then
    raise exception 'Regional recovery census was not independently confirmed'; end if;
  reset role;
  update sectalk_private.st_v8_residency_rollback_channel_batches
    set applied_by=reviewer_id,applied_at=now() where handoff=other_handoff;
  update sectalk_private.st_v8_residency_board_author_consents
    set revoked_at=now() where handoff=other_handoff;
  update sectalk_private.st_v8_residency_staged_content b set records='[{"value":"other workspace"}]'
    where b.workspace=other_workspace;
  update sectalk_private.st_v8_residency_history_links h set expires_at=now()
    where h.workspace=other_workspace;
  set local role authenticated;
  current_review:=public.st_v8_offboarding_reconciliation(workspace_id);
  if current_review->>'current' is distinct from 'true' then
    raise exception 'Another workspace changed this regional recovery review'; end if;
  reset role;
  select sectalk_private.st_v8_offboarding_reconcile_workspace_root(r)->>'revision' into staged_revision
    from sectalk_private.st_v8_offboarding_requests r where r.id=request_id;
  update sectalk_private.st_v8_residency_history_links h set expires_at=now()
    where h.workspace=workspace_id;
  select sectalk_private.st_v8_offboarding_reconcile_workspace_root(r) into current_review
    from sectalk_private.st_v8_offboarding_requests r where r.id=request_id;
  if current_review->>'revision' is not distinct from staged_revision
    or current_review#>>'{summary,nativeRows,residencyHistoryLinks}' is distinct from '1' then
    raise exception 'Regional history link expiration must change the digest without changing its count'; end if;
  update sectalk_private.st_v8_residency_history_links h set expires_at=now()+interval '1 hour'
    where h.workspace=workspace_id;
  update sectalk_private.st_v8_residency_board_author_consents
    set revoked_at=now() where handoff=residency_handoff;
  set local role authenticated;
  current_review:=public.st_v8_offboarding_reconciliation(workspace_id);
  if current_review->>'current' is distinct from 'false'
    or current_review#>>'{summary,nativeRows,residencyBoardAuthorConsents}' is distinct from '1' then
    raise exception 'Author approval revocation must stale a review even when the row count is unchanged'; end if;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  first_review:=public.st_v8_offboarding_reconciliation(workspace_id,'capture',workspace_id::text);
  if first_review->>'current' is distinct from 'true' then
    raise exception 'Owner could not recapture the updated offboarding census'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  reset role;
  update sectalk_private.st_v8_residency_rollback_channel_batches
    set applied_by=reviewer_id,applied_at=now() where handoff=residency_handoff;
  set local role authenticated;
  current_review:=public.st_v8_offboarding_reconciliation(workspace_id);
  if current_review->>'current' is distinct from 'false'
    or current_review#>>'{summary,nativeRows,residencyRecoveryChannelBatches}' is distinct from '1' then
    raise exception 'Applying a regional recovery batch must stale the review even when the count is unchanged'; end if;
  begin
    perform public.st_v8_offboarding_reconciliation(workspace_id,'confirm',workspace_id::text,
      (first_review->>'plan')::uuid,first_review->>'sha256');
    raise exception 'Reviewer confirmed stale regional recovery evidence';
  exception when sqlstate 'PT409' then null; end;
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
  insert into sectalk_private.st_v8_residency_history_links
    (workspace,approval,source_project,destination_project,side,vault_id,expires_at)
  select workspace_id,gen_random_uuid(),'fixture-source','fixture-dest','source',gen_random_uuid(),now()+interval '1 hour'
    from generate_series(1,500);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  current_review:=public.st_v8_offboarding_reconciliation(workspace_id);
  if not (current_review#>'{summary,overflow}') @> '["roomThreadReceipts","residencyHistoryLinks"]'::jsonb
    or current_review#>>'{summary,nativeRows,residencyHistoryLinks}' is distinct from '501'
    or current_review->>'current'<>'false' then
    raise exception 'New receipt family cap was not enforced'; end if;
  begin
    perform public.st_v8_offboarding_reconciliation(workspace_id,'capture',workspace_id::text);
    raise exception 'Overflowing receipt family could be certified';
  exception when sqlstate 'PT409' then null; end;
end $$;

select 'passed: recovery receipts, member dependencies and regional rollback records, same-count drift and tenant isolation';
rollback;
