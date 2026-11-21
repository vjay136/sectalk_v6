begin;

do $$
<<fixture>>
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); stranger uuid:=gen_random_uuid(); actor uuid;
  session_id uuid; factor_id uuid; claims jsonb:='{}'; workspace_id uuid; other_workspace uuid;
  request_id uuid:=gen_random_uuid(); export_id uuid:=gen_random_uuid(); case_id uuid; hold_id uuid:=gen_random_uuid();
  task_id uuid:=gen_random_uuid(); assigned_task uuid:=gen_random_uuid(); drift_task uuid:=gen_random_uuid();
  unapproved_task uuid:=gen_random_uuid(); other_task uuid:=gen_random_uuid(); pending_case uuid;
  room_id uuid:=gen_random_uuid(); other_room uuid:=gen_random_uuid(); linked_task uuid:=gen_random_uuid();
  late_task uuid:=gen_random_uuid(); late_plan jsonb; source_post uuid:=gen_random_uuid(); audited_event bigint;
  plan jsonb; approved jsonb; receipt jsonb; task_copy jsonb; baseline_audit_intact boolean:=true;
begin
  begin
    perform sectalk_private.st_v6_audit_verify();
  exception when raise_exception then
    if sqlerrm is distinct from 'SecTalk audit source rows do not match the journal' then raise; end if;
    baseline_audit_intact:=false;
    raise notice 'Unrelated global audit source drift predates this fixture. Verifying the fixture receipt and exact chain entry.';
  end;
  foreach actor in array array[owner_id,reviewer_id,stranger] loop
    session_id:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'st_task_'||left(actor::text,8),'Offboarding task fixture');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',session_id,'aal','aal2'));
  end loop;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  workspace_id:=public.st_v2_create_workspace('Disposable offboarding source');
  perform set_config('request.jwt.claims',claims->>stranger::text,true);
  other_workspace:=public.st_v2_create_workspace('Other disposable workspace');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace_id,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(workspace_id,reviewer_id);
  insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator) values
    (room_id,workspace_id,'disposable-source','public','blank',owner_id),
    (other_room,other_workspace,'unrelated-source','public','blank',stranger);
  insert into public.st_v6_room_members(room_id,user_id,role) values
    (room_id,owner_id,'owner'),(room_id,reviewer_id,'moderator'),(other_room,stranger,'owner');
  insert into public.st_v6_room_posts(id,room_id,sender,body,kind)
    values(source_post,room_id,owner_id,'Preserve the linked source.','message');
  insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values(workspace_id,1);
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,wrapped)
    values(workspace_id,1,'managed',repeat('a',80));

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v6_task_create(task_id,room_id,null,'Exact room task');
  perform public.st_v6_task_create(assigned_task,room_id,null,'Task with assignment');
  perform public.st_v6_task_create(drift_task,room_id,null,'Changing room task');
  perform public.st_v6_task_create(linked_task,room_id,null,'Task with linked source',source_post);
  perform public.st_v6_task_create(late_task,room_id,null,'Task with a later event');
  perform set_config('request.jwt.claims',claims->>stranger::text,true);
  perform public.st_v6_task_create(other_task,other_room,null,'Other workspace task');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  reset role;
  insert into public.st_v6_task_people(task_id,user_id,kind) values(assigned_task,reviewer_id,'assignee');
  select a.id into audited_event from public.st_v6_task_audit a where a.task_id=fixture.task_id and a.action='created';
  insert into sectalk_private.st_v7_search_document(kind,object_id,fingerprint,first_terms,second_terms)
    values('task',task_id,decode(repeat('0',64),'hex'),to_tsvector('synthetic'),to_tsvector('source terms'));
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'capture',workspace_id::text);
    raise exception 'Accepted source before staging';
  exception when insufficient_privilege then null; end;
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'requested',workspace_id::text,'Disposable source deletion approval');
  perform public.st_v8_offboarding_content(workspace_id,'export_content',export_id,workspace_id::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'approved',workspace_id::text);
  perform public.st_v8_offboarding_content(workspace_id,'approve',export_id,workspace_id::text);
  case_id:=(public.st_v8_workspace_offboarding(workspace_id)#>>'{request,case}')::uuid;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  if not exists(select 1 from jsonb_array_elements(public.st_v8_offboarding_content(workspace_id,'page',export_id,workspace_id::text)->'records') x
    where x->>'id'=task_id::text and x->>'json' like '%Exact room task%') then
    raise exception 'Owner could not obtain exact approved source bytes'; end if;
  reset role;
  update public.st_v6_tasks set title='Changed after archive approval.' where id=drift_task;
  insert into public.st_v6_tasks(id,room_id,author_id,title) values(unapproved_task,room_id,owner_id,'Unapproved source');
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(case_id,workspace_id,owner_id,'downloaded');

  set local role authenticated;
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'read_only',workspace_id::text);
  begin
    perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'capture',workspace_id::text);
    raise exception 'Accepted source before the exact approved copy was issued';
  exception when sqlstate 'PT409' then null; end;
  begin
    perform public.st_v8_offboarding_room_task_copy(workspace_id,room_id,drift_task,workspace_id::text);
    raise exception 'Issued a copy for a changed approved task';
  exception when insufficient_privilege then null; end;
  task_copy:=public.st_v8_offboarding_room_task_copy(workspace_id,room_id,task_id,workspace_id::text);
  if task_copy->>'sha256'<>encode(sha256(convert_to(task_copy->>'json','UTF8')),'hex')
    or task_copy->>'id' is distinct from task_id::text
    or task_copy->>'sourceSha256'<>encode(sha256(convert_to(task_copy->>'sourceJson','UTF8')),'hex')
    or task_copy->>'creationAuditSha256'<>encode(sha256(convert_to(task_copy->>'creationAuditJson','UTF8')),'hex')
    or task_copy->>'creationAuditJson' is null then raise exception 'Issued copy did not match the approved task'; end if;
  foreach actor in array array[other_task,assigned_task,drift_task,unapproved_task,linked_task] loop
    begin
      perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,actor,'capture',workspace_id::text);
      raise exception 'Changed, dependent, unrelated or unapproved task was accepted';
    exception when sqlstate 'PT409' then null; end;
  end loop;
  perform public.st_v8_offboarding_room_task_copy(workspace_id,room_id,late_task,workspace_id::text);
  late_plan:=public.st_v8_offboarding_room_task_delete(workspace_id,room_id,late_task,'capture',workspace_id::text);
  plan:=public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'capture',workspace_id::text);
  if plan->>'plan' is null or plan->>'approvedAt' is not null or plan ? 'task' then raise exception 'Unexpected plan %',plan; end if;
  begin
    perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Owner executed without a separate approval';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'approve',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Owner approved their own deletion';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  if jsonb_array_length(public.st_v8_offboarding_room_task_status(workspace_id)->'tasks')<>0
    or not exists(select 1 from jsonb_array_elements(public.st_v8_offboarding_room_task_status(workspace_id)->'plans') q
      where q->>'plan'=plan->>'plan' and q->>'sha256'=plan->>'sha256') then
    raise exception 'Reviewer did not receive only the bound deletion plan'; end if;
  begin
    perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'approve',workspace_id::text,(plan->>'plan')::uuid,repeat('0',64));
    raise exception 'Reviewer confirmed a different manifest digest';
  exception when sqlstate 'PT409' then null; end;
  approved:=public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'approve',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
  if approved->>'approvedAt' is null then raise exception 'Reviewer approval missing'; end if;
  perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,late_task,'approve',workspace_id::text,
    (late_plan->>'plan')::uuid,late_plan->>'sha256');
  begin
    perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Reviewer executed the deletion';
  exception when insufficient_privilege then null; end;
  reset role;

  insert into public.st_v6_task_audit(task_id,actor_id,action,detail)
    values(late_task,owner_id,'update',jsonb_build_object('status','todo'));
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,late_task,'delete',workspace_id::text,
      (late_plan->>'plan')::uuid,late_plan->>'sha256');
    raise exception 'Deletion proceeded despite a later audit event';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,workspace_id,owner_id,'Retain disposable source history during test.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Deletion during active hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release the disposable fixture hold.' where h.id=hold_id;
  insert into sectalk_private.st_v7_compliance_cases(workspace_id,requester,case_reference,reason,sources)
    values(workspace_id,owner_id,'Unresolved retention review','Disposable retention blocker','[{"kind":"audit"}]')
    returning id into pending_case;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Deletion cut across open evidence retention';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  update sectalk_private.st_v7_compliance_cases set state='withdrawn' where id=pending_case;
  insert into sectalk_private.st_v8_workspace_standard_room_sso(workspace,protocol,provider)
    values(workspace_id,'saml',gen_random_uuid()::text);
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'delete',workspace_id::text,
      (plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Deletion accepted without required native room SSO';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  delete from sectalk_private.st_v8_workspace_standard_room_sso s where s.workspace=workspace_id;
  update sectalk_private.st_v7_tenant_key_versions k set wrapped=repeat('b',80) where k.workspace=workspace_id;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Deletion proceeded after key revision changed';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  update sectalk_private.st_v7_tenant_key_versions k set wrapped=repeat('a',80) where k.workspace=workspace_id;
  update auth.mfa_amr_claims a set updated_at=now()-interval '6 minutes'
    where a.session_id=(claims->owner_id::text->>'session_id')::uuid;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Deletion accepted stale owner assurance';
  exception when insufficient_privilege then null; end;
  reset role;
  update auth.mfa_amr_claims a set updated_at=now()
    where a.session_id=(claims->owner_id::text->>'session_id')::uuid;
  delete from sectalk_private.st_v8_offboarding_reviewers q where q.workspace=workspace_id and q.actor=reviewer_id;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Deletion accepted after independent reviewer lost assignment';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into sectalk_private.st_v8_offboarding_reviewers values(workspace_id,reviewer_id);

  set local role authenticated;
  receipt:=public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
  if receipt->>'deletedAt' is null or receipt is distinct from public.st_v8_offboarding_room_task_delete(workspace_id,room_id,task_id,'delete',workspace_id::text,
    (plan->>'plan')::uuid,plan->>'sha256') then raise exception 'Missing or non-idempotent deletion receipt'; end if;
  reset role;
  if exists(select 1 from public.st_v6_tasks i where i.id=task_id)
    or exists(select 1 from sectalk_private.st_v7_search_document d where d.kind='task' and d.object_id=task_id)
    or (select count(*) from public.st_v6_tasks i where i.id in (other_task,assigned_task,drift_task,unapproved_task,linked_task,late_task))<>6
    or not exists(select 1 from public.st_v6_task_people x where x.task_id=assigned_task and x.user_id=reviewer_id)
    or not exists(select 1 from sectalk_private.st_v6_task_sources x where x.task_id=linked_task and x.message_id=source_post)
    or exists(select 1 from public.st_v6_task_audit x where x.id=audited_event)
    or not exists(select 1 from sectalk_private.st_v8_offboarding_retained_task_creation x
      where (x.deletion,x.audit_id)=((plan->>'plan')::uuid,audited_event)
        and x.audit_row=(task_copy->>'creationAuditJson')::jsonb and x.sha256=task_copy->>'creationAuditSha256')
    or not exists(select 1 from sectalk_private.st_v6_audit_chain x where x.source='public.st_v6_task_audit'
      and x.source_id=audited_event and x.operation='DELETE' and encode(x.row_hash,'hex')=task_copy->>'creationAuditSha256'
      and x.entry_hash=sectalk_private.st_v6_audit_entry_hash(coalesce((select prior.entry_hash
        from sectalk_private.st_v6_audit_chain prior where prior.entry_no=x.entry_no-1),decode(repeat('0',64),'hex')),
        x.entry_no,x.source,x.source_id,x.operation,x.row_hash)) then
    raise exception 'Physical deletion or exact isolation failed'; end if;
  if (select count(*) from sectalk_private.st_v8_offboarding_room_task_decisions d where d.deletion=(plan->>'plan')::uuid)<>2
    or has_function_privilege('service_role','public.st_v8_offboarding_room_task_delete(uuid,uuid,uuid,text,text,uuid,text)','EXECUTE')
    or has_function_privilege('anon','public.st_v8_offboarding_room_task_delete(uuid,uuid,uuid,text,text,uuid,text)','EXECUTE') then raise exception 'Invalid audit or grants'; end if;
  if has_table_privilege('authenticated','sectalk_private.st_v8_offboarding_retained_task_creation','SELECT')
    or has_table_privilege('service_role','sectalk_private.st_v8_offboarding_retained_task_creation','SELECT')
    then raise exception 'Retained audit grants expose custody'; end if;
  begin
    delete from sectalk_private.st_v8_offboarding_retained_task_creation x where x.audit_id=audited_event;
    raise exception 'Retained creation evidence was mutable';
  exception when insufficient_privilege then null; end;
  if baseline_audit_intact then perform sectalk_private.st_v6_audit_verify(); end if;
end $$;

select 'passed: exact dual-party room task deletion with retained original audit, retention, key and hold checks, source and search removal';
rollback;
