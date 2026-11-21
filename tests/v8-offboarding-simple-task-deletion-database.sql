begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); stranger uuid:=gen_random_uuid(); actor uuid;
  session_id uuid; factor_id uuid; claims jsonb:='{}'; workspace_id uuid; other_workspace uuid;
  request_id uuid:=gen_random_uuid(); export_id uuid:=gen_random_uuid(); case_id uuid; hold_id uuid:=gen_random_uuid();
  task_id uuid:=gen_random_uuid(); checklist_task uuid:=gen_random_uuid(); drift_task uuid:=gen_random_uuid();
  unapproved_task uuid:=gen_random_uuid(); other_task uuid:=gen_random_uuid(); pending_case uuid;
  plan jsonb; approved jsonb; receipt jsonb; task_copy jsonb;
begin
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
  insert into public.st_v2_items(id,workspace_id,kind,created_by,title,details) values
    (task_id,workspace_id,'task',owner_id,'Exact task','Synthetic scope test.'),
    (checklist_task,workspace_id,'task',owner_id,'Task with checklist','Protected dependency.'),
    (drift_task,workspace_id,'task',owner_id,'Changed task','Initial approved revision.'),
    (other_task,other_workspace,'task',stranger,'Other workspace task','Other tenant source.');
  insert into public.st_v4_checklist(task_id,label) values(checklist_task,'Preserve dependent user data');
  insert into sectalk_private.st_v7_search_document(kind,object_id,fingerprint,first_terms,second_terms)
    values('board',task_id,decode(repeat('0',64),'hex'),to_tsvector('synthetic'),to_tsvector('source terms'));
  insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values(workspace_id,1);
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,wrapped)
    values(workspace_id,1,'managed',repeat('a',80));

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_task_delete(workspace_id,task_id,'capture',workspace_id::text);
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
    where x->>'id'=task_id::text and x->>'json' like '%Synthetic scope test.%') then
    raise exception 'Owner could not obtain exact approved source bytes'; end if;
  reset role;
  update public.st_v2_items set details='Changed after archive approval.' where id=drift_task;
  insert into public.st_v2_items(id,workspace_id,kind,created_by,title) values(unapproved_task,workspace_id,'task',owner_id,'Unapproved source');
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(case_id,workspace_id,owner_id,'downloaded');

  set local role authenticated;
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'read_only',workspace_id::text);
  begin
    perform public.st_v8_offboarding_task_delete(workspace_id,task_id,'capture',workspace_id::text);
    raise exception 'Accepted source before the exact approved copy was issued';
  exception when sqlstate 'PT409' then null; end;
  begin
    perform public.st_v8_offboarding_task_copy(workspace_id,drift_task,workspace_id::text);
    raise exception 'Issued a copy for a changed approved task';
  exception when insufficient_privilege then null; end;
  task_copy:=public.st_v8_offboarding_task_copy(workspace_id,task_id,workspace_id::text);
  if task_copy->>'sha256'<>encode(sha256(convert_to(task_copy->>'json','UTF8')),'hex')
    or task_copy->>'id' is distinct from task_id::text then raise exception 'Issued copy did not match the approved task'; end if;
  foreach actor in array array[other_task,checklist_task,drift_task,unapproved_task] loop
    begin
      perform public.st_v8_offboarding_task_delete(workspace_id,actor,'capture',workspace_id::text);
      raise exception 'Changed, dependent, unrelated or unapproved task was accepted';
    exception when sqlstate 'PT409' then null; end;
  end loop;
  plan:=public.st_v8_offboarding_task_delete(workspace_id,task_id,'capture',workspace_id::text);
  if plan->>'plan' is null or plan->>'approvedAt' is not null or plan ? 'task' then raise exception 'Unexpected plan %',plan; end if;
  begin
    perform public.st_v8_offboarding_task_delete(workspace_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Owner executed without a separate approval';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_offboarding_task_delete(workspace_id,task_id,'approve',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Owner approved their own deletion';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  if jsonb_array_length(public.st_v8_offboarding_task_status(workspace_id)->'tasks')<>0
    or not exists(select 1 from jsonb_array_elements(public.st_v8_offboarding_task_status(workspace_id)->'plans') q
      where q->>'plan'=plan->>'plan' and q->>'sha256'=plan->>'sha256') then
    raise exception 'Reviewer did not receive only the bound deletion plan'; end if;
  begin
    perform public.st_v8_offboarding_task_delete(workspace_id,task_id,'approve',workspace_id::text,(plan->>'plan')::uuid,repeat('0',64));
    raise exception 'Reviewer confirmed a different manifest digest';
  exception when sqlstate 'PT409' then null; end;
  approved:=public.st_v8_offboarding_task_delete(workspace_id,task_id,'approve',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
  if approved->>'approvedAt' is null then raise exception 'Reviewer approval missing'; end if;
  begin
    perform public.st_v8_offboarding_task_delete(workspace_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Reviewer executed the deletion';
  exception when insufficient_privilege then null; end;
  reset role;

  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,workspace_id,owner_id,'Retain disposable source history during test.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_task_delete(workspace_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
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
    perform public.st_v8_offboarding_task_delete(workspace_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Deletion cut across open evidence retention';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  update sectalk_private.st_v7_compliance_cases set state='withdrawn' where id=pending_case;
  update sectalk_private.st_v7_tenant_key_versions k set wrapped=repeat('b',80) where k.workspace=workspace_id;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_task_delete(workspace_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Deletion proceeded after key revision changed';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  update sectalk_private.st_v7_tenant_key_versions k set wrapped=repeat('a',80) where k.workspace=workspace_id;
  update auth.mfa_amr_claims a set updated_at=now()-interval '6 minutes'
    where a.session_id=(claims->owner_id::text->>'session_id')::uuid;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_task_delete(workspace_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Deletion accepted stale owner assurance';
  exception when insufficient_privilege then null; end;
  reset role;
  update auth.mfa_amr_claims a set updated_at=now()
    where a.session_id=(claims->owner_id::text->>'session_id')::uuid;
  delete from sectalk_private.st_v8_offboarding_reviewers q where q.workspace=workspace_id and q.actor=reviewer_id;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_task_delete(workspace_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Deletion accepted after independent reviewer lost assignment';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into sectalk_private.st_v8_offboarding_reviewers values(workspace_id,reviewer_id);

  set local role authenticated;
  receipt:=public.st_v8_offboarding_task_delete(workspace_id,task_id,'delete',workspace_id::text,(plan->>'plan')::uuid,plan->>'sha256');
  if receipt->>'deletedAt' is null or receipt is distinct from public.st_v8_offboarding_task_delete(workspace_id,task_id,'delete',workspace_id::text,
    (plan->>'plan')::uuid,plan->>'sha256') then raise exception 'Missing or non-idempotent deletion receipt'; end if;
  reset role;
  if exists(select 1 from public.st_v2_items i where i.id=task_id)
    or exists(select 1 from sectalk_private.st_v7_search_document d where d.kind='board' and d.object_id=task_id)
    or (select count(*) from public.st_v2_items i where i.id in (other_task,checklist_task,drift_task,unapproved_task))<>4
    or not exists(select 1 from public.st_v4_checklist x where x.task_id=checklist_task) then
    raise exception 'Physical deletion or exact isolation failed'; end if;
  if (select count(*) from sectalk_private.st_v8_offboarding_task_decisions d where d.deletion=(plan->>'plan')::uuid)<>2
    or has_function_privilege('service_role','public.st_v8_offboarding_task_delete(uuid,uuid,text,text,uuid,text)','EXECUTE')
    or has_function_privilege('anon','public.st_v8_offboarding_task_delete(uuid,uuid,text,text,uuid,text)','EXECUTE') then raise exception 'Invalid audit or grants'; end if;
end $$;

select 'passed: exact dual-party task deletion, retention, key and hold checks, source and search removal';
rollback;
