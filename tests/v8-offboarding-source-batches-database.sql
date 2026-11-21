begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; workspace_id uuid; outsider_scope uuid:=gen_random_uuid();
  channel_id uuid:=gen_random_uuid(); room_id uuid:=gen_random_uuid(); request_id uuid:=gen_random_uuid(); export_id uuid:=gen_random_uuid();
  inventory_id uuid; channel_success uuid:=gen_random_uuid(); room_success uuid:=gen_random_uuid();
  room_task uuid:=gen_random_uuid(); workspace_task uuid:=gen_random_uuid(); channel_doomed uuid:=gen_random_uuid(); room_doomed uuid:=gen_random_uuid();
  hold_id uuid:=gen_random_uuid();
  done jsonb; doomed jsonb; receipt jsonb; report_id uuid; control_plan jsonb; source jsonb;
  ordered_sources jsonb; doomed_sources jsonb;
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
  perform public.st_v8_offboarding_post_copy(workspace_id,channel_id,channel_success,workspace_id::text);
  perform public.st_v8_offboarding_post_copy(workspace_id,channel_id,channel_doomed,workspace_id::text);
  perform public.st_v8_offboarding_room_post_copy(workspace_id,room_id,room_success,workspace_id::text);
  perform public.st_v8_offboarding_room_post_copy(workspace_id,room_id,room_doomed,workspace_id::text);
  perform public.st_v8_offboarding_room_task_copy(workspace_id,room_id,room_task,workspace_id::text);
  perform public.st_v8_offboarding_task_copy(workspace_id,workspace_task,workspace_id::text);

  ordered_sources:=jsonb_build_array(jsonb_build_object('kind','workspace_task','scope',workspace_id,'id',workspace_task),
    jsonb_build_object('kind','room_task','scope',room_id,'id',room_task),
    jsonb_build_object('kind','room_message','scope',room_id,'id',room_success),
    jsonb_build_object('kind','channel_message','scope',channel_id,'id',channel_success));
  doomed_sources:=jsonb_build_array(jsonb_build_object('kind','room_message','scope',room_id,'id',room_doomed),
    jsonb_build_object('kind','channel_message','scope',channel_id,'id',channel_doomed));
  if jsonb_array_length(public.st_v8_offboarding_source_batch_status(workspace_id)->'candidates')<>6 then
    raise exception 'Copied native sources are missing from the batch selector'; end if;
  begin
    perform public.st_v8_offboarding_source_batch(workspace_id,'capture',workspace_id::text,jsonb_build_array(ordered_sources->0,ordered_sources->0));
    raise exception 'Batch accepted a duplicate item';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_v8_offboarding_source_batch(workspace_id,'capture',workspace_id::text,
      jsonb_set(ordered_sources,'{0,scope}',to_jsonb(outsider_scope)));
    raise exception 'Batch accepted a foreign workspace task scope';
  exception when invalid_parameter_value then null; end;
  done:=public.st_v8_offboarding_source_batch(workspace_id,'capture',workspace_id::text,ordered_sources);
  doomed:=public.st_v8_offboarding_source_batch(workspace_id,'capture',workspace_id::text,doomed_sources);
  if done#>>'{manifest,0,kind}'<>'channel_message' or doomed#>>'{manifest,0,id}'<>channel_doomed::text
    or jsonb_array_length(done->'manifest')<>4
    or done->>'sha256' is distinct from encode(sha256(convert_to(jsonb_build_array('sectalk-offboarding-source-batch-v1',
      workspace_id,request_id,owner_id,reviewer_id,done->'manifest')::text,'UTF8')),'hex')
    then raise exception 'Batch manifest order, scope or digest differs'; end if;
  begin
    perform public.st_v8_offboarding_source_batch(workspace_id,'approve',workspace_id::text,null,(done->>'batch')::uuid,done->>'sha256');
    raise exception 'Owner approved their own batch';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_offboarding_source_batch(workspace_id,'delete',workspace_id::text,null,(done->>'batch')::uuid,done->>'sha256');
    raise exception 'Owner deleted before independent batch approval';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  if jsonb_array_length(public.st_v8_offboarding_source_batch_status(workspace_id)->'candidates')<>0
    or jsonb_array_length(public.st_v8_offboarding_source_batch_status(workspace_id)->'batches')<>2 then
    raise exception 'Reviewer should see only the prepared batches'; end if;
  begin
    perform public.st_v8_offboarding_source_batch(workspace_id,'approve',workspace_id::text,null,(done->>'batch')::uuid,repeat('0',64));
    raise exception 'Reviewer approved a different digest';
  exception when sqlstate 'PT409' then null; end;
  perform public.st_v8_offboarding_source_batch(workspace_id,'approve',workspace_id::text,null,(done->>'batch')::uuid,done->>'sha256');
  perform public.st_v8_offboarding_source_batch(workspace_id,'approve',workspace_id::text,null,(doomed->>'batch')::uuid,doomed->>'sha256');
  report_id:=public.st_v6_submit_room_report(room_id,room_doomed,'spam','A late synthetic report must block the batch.',true);

  reset role;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,workspace_id,owner_id,'Preserve disposable batch source while this hold is active.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_source_batch(workspace_id,'delete',workspace_id::text,null,(done->>'batch')::uuid,done->>'sha256');
    raise exception 'Batch deletion proceeded during a preservation hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release synthetic hold for the fixture.' where h.id=hold_id;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_source_batch(workspace_id,'delete',workspace_id::text,null,(doomed->>'batch')::uuid,doomed->>'sha256');
    raise exception 'Batch ignored a late native report';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  control_plan:=doomed#>'{manifest,0}';
  if not exists(select 1 from public.st_v2_posts where id=channel_doomed)
    or exists(select 1 from sectalk_private.st_v8_offboarding_post_decisions d
      where (d.deletion,d.action)=((control_plan->>'plan')::uuid,'deleted'))
    or exists(select 1 from sectalk_private.st_v8_offboarding_source_batch_decisions d
      where (d.batch,d.action)=((doomed->>'batch')::uuid,'deleted')) then
    raise exception 'Failed batch did not roll back its earlier native deletion'; end if;
  set local role authenticated;
  perform public.st_v8_offboarding_post_delete(workspace_id,channel_id,channel_doomed,'delete',workspace_id::text,
    (control_plan->>'plan')::uuid,control_plan->>'sha256');
  begin
    perform public.st_v8_offboarding_source_batch(workspace_id,'delete',workspace_id::text,null,(doomed->>'batch')::uuid,doomed->>'sha256');
    raise exception 'Batch counted an independently removed item';
  exception when sqlstate 'PT409' then
    if sqlerrm is distinct from 'A source was already removed outside this batch' then raise; end if;
  end;

  receipt:=public.st_v8_offboarding_source_batch(workspace_id,'delete',workspace_id::text,null,(done->>'batch')::uuid,done->>'sha256');
  if receipt->>'deletedAt' is null or receipt is distinct from public.st_v8_offboarding_source_batch(
    workspace_id,'delete',workspace_id::text,null,(done->>'batch')::uuid,done->>'sha256') then
    raise exception 'Missing/non-idempotent successful batch receipt'; end if;
  reset role;

  if exists(select 1 from public.st_v2_posts where id=channel_success)
    or exists(select 1 from public.st_v6_room_posts where id=room_success)
    or exists(select 1 from public.st_v6_tasks where id=room_task)
    or exists(select 1 from public.st_v2_items where id=workspace_task)
    or not exists(select 1 from public.st_v6_room_posts where id=room_doomed)
    or not exists(select 1 from sectalk_private.st_v6_room_reports where id=report_id)
    or (select count(*) from sectalk_private.st_v8_offboarding_source_batch_decisions d
      where d.batch=(done->>'batch')::uuid)<>2 then raise exception 'Batch source state or immutable receipt is incorrect'; end if;
  for source in select value from jsonb_array_elements(done->'manifest') loop
    if not sectalk_private.st_v8_offboarding_source_batch_item_deleted(source->>'kind',(source->>'plan')::uuid) then
      raise exception 'Per-source deletion receipt is missing'; end if;
  end loop;
  if has_function_privilege('service_role','public.st_v8_offboarding_source_batch(uuid,text,text,jsonb,uuid,text)','EXECUTE')
    or has_function_privilege('anon','public.st_v8_offboarding_source_batch(uuid,text,text,jsonb,uuid,text)','EXECUTE')
    then raise exception 'Unsafe batch action grants'; end if;
end $$;

select 'passed: mixed source deletion, independent manifest, rollback after late report, rejection of unrelated receipt, and idempotency';
rollback;
