begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; workspace_id uuid; room_id uuid:=gen_random_uuid();
  request_id uuid:=gen_random_uuid(); export_id uuid:=gen_random_uuid(); hold_id uuid:=gen_random_uuid(); case_id uuid;
  root_id uuid:=gen_random_uuid(); reply_a uuid:=gen_random_uuid(); reply_b uuid:=gen_random_uuid();
  protected_root uuid:=gen_random_uuid(); protected_reply uuid:=gen_random_uuid();
  changed_root uuid:=gen_random_uuid(); changed_reply uuid:=gen_random_uuid(); unapproved_reply uuid:=gen_random_uuid();
  control_post uuid:=gen_random_uuid(); report_id uuid;
  copy jsonb; part jsonb; plan jsonb; protected_plan jsonb; receipt jsonb; status jsonb;
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
  insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator)
    values(room_id,workspace_id,'Disposable thread room','public','blank',owner_id);
  insert into public.st_v6_room_members(room_id,user_id,role) values(room_id,owner_id,'owner'),(room_id,reviewer_id,'moderator');
  insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values(workspace_id,1);
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,wrapped) values(workspace_id,1,'managed',repeat('a',80));
  set local role authenticated;
  perform public.st_v6_room_post(room_id,root_id,'Disposable root');
  perform public.st_v6_room_post(room_id,reply_a,'Approved first reply','message',root_id);
  perform public.st_v6_room_post(room_id,reply_b,'Approved second reply','message',root_id);
  perform public.st_v6_room_post(room_id,protected_root,'Root protected by the late report');
  perform public.st_v6_room_post(room_id,protected_reply,'Reply later reported','message',protected_root);
  perform public.st_v6_room_post(room_id,changed_root,'Thread later receives an uncopied reply');
  perform public.st_v6_room_post(room_id,changed_reply,'Approved early reply','message',changed_root);
  perform public.st_v6_room_post(room_id,control_post,'Unrelated root without replies');
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'requested',workspace_id::text,'Disposable batch approval');
  perform public.st_v8_offboarding_content(workspace_id,'export_content',export_id,workspace_id::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'approved',workspace_id::text);
  perform public.st_v8_offboarding_content(workspace_id,'approve',export_id,workspace_id::text);

  case_id:=(public.st_v8_workspace_offboarding(workspace_id)#>>'{request,case}')::uuid;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v6_room_post(room_id,unapproved_reply,'Reply added after approval','message',changed_root);
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action)
    values(case_id,workspace_id,owner_id,'downloaded');
  insert into sectalk_private.st_v7_search_document(kind,object_id,fingerprint,first_terms,second_terms)
    select 'room',message_id,decode(repeat('0',64),'hex'),to_tsvector('synthetic'),to_tsvector('thread')
    from unnest(array[root_id,reply_a,reply_b,protected_root,protected_reply,control_post]) message_id;
  set local role authenticated;
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'read_only',workspace_id::text);
  begin
    perform public.st_v8_offboarding_room_thread_delete(workspace_id,room_id,root_id,'capture',workspace_id::text);
    raise exception 'Accepted thread before its exact copy was issued';
  exception when sqlstate 'PT409' then null; end;
  foreach actor in array array[reply_a,changed_root,control_post] loop
    begin
      perform public.st_v8_offboarding_room_thread_copy(workspace_id,room_id,actor,workspace_id::text);
      raise exception 'Accepted a reply-only, partial, or single-record thread';
    exception when insufficient_privilege then null; end;
  end loop;
  copy:=public.st_v8_offboarding_room_thread_copy(workspace_id,room_id,root_id,workspace_id::text);
  if copy->>'sha256'<>encode(sha256(convert_to(copy->>'manifestJson','UTF8')),'hex')
    or jsonb_array_length(copy->'records')<>3 or copy#>>'{records,0,id}'<>root_id::text then
    raise exception 'The exact thread copy was incomplete'; end if;
  for part in select value from jsonb_array_elements(copy->'records') loop
    if part->>'sha256'<>encode(sha256(convert_to(part->>'json','UTF8')),'hex') then
      raise exception 'An approved message digest did not match the issued bytes'; end if;
  end loop;
  if not exists(select 1 from jsonb_array_elements(public.st_v8_offboarding_room_thread_status(workspace_id)->'threads') q
      where q->>'id'=root_id::text and q->>'copied'='true' and q->>'messageCount'='3') then
    raise exception 'Exact copied thread is missing from the owner view'; end if;
  perform public.st_v8_offboarding_room_thread_copy(workspace_id,room_id,protected_root,workspace_id::text);
  plan:=public.st_v8_offboarding_room_thread_delete(workspace_id,room_id,root_id,'capture',workspace_id::text);
  protected_plan:=public.st_v8_offboarding_room_thread_delete(workspace_id,room_id,protected_root,'capture',workspace_id::text);
  begin
    perform public.st_v8_offboarding_room_thread_delete(workspace_id,room_id,root_id,'approve',workspace_id::text,
      (plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Owner approved their own deletion plan';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_offboarding_room_thread_delete(workspace_id,room_id,root_id,'delete',workspace_id::text,
      (plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Owner deleted before independent approval';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  status:=public.st_v8_offboarding_room_thread_status(workspace_id);
  if jsonb_array_length(status->'threads')<>0 or not exists(select 1 from jsonb_array_elements(status->'plans') q
    where q->>'plan'=plan->>'plan' and q->'manifest'=(copy->>'manifestJson')::jsonb and q->>'messageCount'='3') then
    raise exception 'Exact manifest missing from the independent reviewer view'; end if;
  begin
    perform public.st_v8_offboarding_room_thread_delete(workspace_id,room_id,root_id,'approve',workspace_id::text,
      (plan->>'plan')::uuid,repeat('f',64));
    raise exception 'Accepted a different deletion digest';
  exception when sqlstate 'PT409' then null; end;
  perform public.st_v8_offboarding_room_thread_delete(workspace_id,room_id,root_id,'approve',workspace_id::text,
    (plan->>'plan')::uuid,plan->>'sha256');
  perform public.st_v8_offboarding_room_thread_delete(workspace_id,room_id,protected_root,'approve',workspace_id::text,
    (protected_plan->>'plan')::uuid,protected_plan->>'sha256');
  report_id:=public.st_v6_submit_room_report(room_id,protected_reply,'spam','Synthetic late reply report.',true);
  reset role;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,workspace_id,owner_id,'Preserve disposable thread during this test.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_room_thread_delete(workspace_id,room_id,root_id,'delete',workspace_id::text,
      (plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Deletion proceeded during the active hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release the disposable thread hold.' where h.id=hold_id;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_room_thread_delete(workspace_id,room_id,protected_root,'delete',workspace_id::text,
      (protected_plan->>'plan')::uuid,protected_plan->>'sha256');
    raise exception 'Deletion accepted a reported reply in an approved thread';
  exception when sqlstate 'PT409' then null; end;
  receipt:=public.st_v8_offboarding_room_thread_delete(workspace_id,room_id,root_id,'delete',workspace_id::text,
    (plan->>'plan')::uuid,plan->>'sha256');
  if receipt->>'deletedAt' is null or receipt->>'messageCount'<>'3'
    or receipt is distinct from public.st_v8_offboarding_room_thread_delete(workspace_id,room_id,root_id,'delete',
      workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256') then
    raise exception 'Missing or non-idempotent exact thread receipt'; end if;
  reset role;
  if exists(select 1 from public.st_v6_room_posts where id in (root_id,reply_a,reply_b))
    or exists(select 1 from sectalk_private.st_v7_search_document q where q.kind='room' and q.object_id in (root_id,reply_a,reply_b))
    or (select count(*) from public.st_v6_room_posts where id in (protected_root,protected_reply,changed_root,changed_reply,unapproved_reply,control_post))<>6
    or (select count(*) from sectalk_private.st_v7_search_document q where q.kind='room'
      and q.object_id in (protected_root,protected_reply,control_post))<>3
    or not exists(select 1 from sectalk_private.st_v6_room_reports where id=report_id)
    or (select count(*) from sectalk_private.st_v8_offboarding_room_thread_decisions q where q.deletion=(plan->>'plan')::uuid)<>2
    or exists(select 1 from sectalk_private.st_v8_offboarding_room_thread_decisions q
      where (q.deletion,q.action)=((protected_plan->>'plan')::uuid,'deleted')) then
    raise exception 'Incomplete physical removal, protected data lost or incorrect audit receipt'; end if;
  if has_function_privilege('service_role','public.st_v8_offboarding_room_thread_delete(uuid,uuid,uuid,text,text,uuid,text)','EXECUTE')
    or has_function_privilege('anon','public.st_v8_offboarding_room_thread_delete(uuid,uuid,uuid,text,text,uuid,text)','EXECUTE')
    then raise exception 'Unsafe thread deletion grants'; end if;
end $$;

select 'passed: exact complete room thread and search removal, holds and late reports, partial thread denial, independent immutable receipt';
rollback;
