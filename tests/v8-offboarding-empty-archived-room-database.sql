begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; w uuid; workspace_id uuid; another_workspace uuid;
  request_id uuid:=gen_random_uuid(); hold_id uuid:=gen_random_uuid(); report_id uuid:=gen_random_uuid(); case_id uuid;
  eligible uuid:=gen_random_uuid(); nonempty uuid:=gen_random_uuid(); changed uuid:=gen_random_uuid();
  control uuid:=gen_random_uuid(); storage_only uuid:=gen_random_uuid(); foreign_key_room uuid:=gen_random_uuid(); expected_archive_sha text;
  copy jsonb; original jsonb; selected_plan jsonb; changed_plan jsonb; receipt jsonb; status jsonb;
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
  workspace_id:=public.st_v2_create_workspace('Disposable archived room source');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  another_workspace:=public.st_v2_create_workspace('Disposable active room workspace');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace_id,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(workspace_id,reviewer_id);
  w:=workspace_id;
  insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values(w,1);
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,wrapped) values(w,1,'managed',repeat('a',80));
  set local role authenticated;
  perform public.st_v6_room_create(eligible,w,'archive-candidate','public','blank');
  perform public.st_v6_room_create(nonempty,w,'archive-with-one-post','public','blank');
  perform public.st_v6_room_create(changed,w,'archive-with-late-evidence','public','blank');
  perform public.st_v6_room_create(control,w,'live-control','public','blank');
  perform public.st_v6_room_create(storage_only,w,'archive-with-storage','public','blank');
  perform public.st_v6_room_create(foreign_key_room,w,'archive-with-dependency','public','blank');
  reset role;
  insert into public.st_v6_room_posts(id,room_id,sender,body,kind) values(gen_random_uuid(),nonempty,owner_id,'Keep this archived post.','message');
  set local role authenticated;
  perform public.st_v6_manage_room(eligible,'archive');
  perform public.st_v6_manage_room(nonempty,'archive');
  perform public.st_v6_manage_room(changed,'archive');
  perform public.st_v6_manage_room(storage_only,'archive');
  perform public.st_v6_manage_room(foreign_key_room,'archive');
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Keep the remaining workspace data.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  case_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  create table sectalk_private.disposable_room_dependency(room uuid references public.st_v6_rooms on delete cascade);
  insert into sectalk_private.disposable_room_dependency values(foreign_key_room);
  insert into storage.objects(bucket_id,name) values('sectalk-workspace-files',w||'/rooms/'||storage_only||'/'||gen_random_uuid());
  select jsonb_build_object('creatorMembership',(select to_jsonb(m) from public.st_v6_room_members m where m.room_id=eligible),
    'auditEvents',(select jsonb_agg(to_jsonb(a) order by a.id) from public.st_v6_room_audit a where a.room_id=eligible))
    into original;
  expected_archive_sha:=encode(sha256(convert_to(original::text,'UTF8')),'hex');
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action)
    values(case_id,w,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  begin
    perform public.st_v8_offboarding_archived_room(w,eligible,'capture',w::text);
    raise exception 'Captured a plan before the exact copy';
  exception when sqlstate 'PT409' then null; end;
  if exists(select 1 from jsonb_array_elements(public.st_v8_offboarding_archived_room_status(w)->'rooms') c
    where c->>'id' in (nonempty::text,control::text,storage_only::text,foreign_key_room::text))
    then raise exception 'Archived history or a live room was offered for removal'; end if;
  copy:=public.st_v8_offboarding_archived_room(w,eligible,'copy',w::text);
  if copy->>'sha256'<>encode(sha256(convert_to(copy->>'json','UTF8')),'hex')
    or (copy->>'json')::jsonb->'retainedProof' is distinct from original
    or (copy->>'json')::jsonb#>>'{room,id}' is distinct from eligible::text
    then raise exception 'Issued copy does not match original native bytes'; end if;
  selected_plan:=public.st_v8_offboarding_archived_room(w,eligible,'capture',w::text);
  perform public.st_v8_offboarding_archived_room(w,changed,'copy',w::text);
  changed_plan:=public.st_v8_offboarding_archived_room(w,changed,'capture',w::text);
  begin
    perform public.st_v8_offboarding_archived_room(w,eligible,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner self-approved';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_offboarding_archived_room(w,eligible,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner removed room before review';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  status:=public.st_v8_offboarding_archived_room_status(w);
  if jsonb_array_length(status->'rooms')<>0 or not exists(select 1 from jsonb_array_elements(status->'plans') p
    where p->>'plan'=selected_plan->>'plan' and p->>'copySha256'=copy->>'sha256'
    and p->>'archiveSha256'=expected_archive_sha)
    then raise exception 'Reviewer lacks exact archive digests or sees owner-only contents'; end if;
  begin
    perform public.st_v8_offboarding_archived_room(w,control,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Approval was reused for another room';
  exception when sqlstate 'PT409' then null; end;
  perform public.st_v8_offboarding_archived_room(w,eligible,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  perform public.st_v8_offboarding_archived_room(w,changed,'approve',w::text,(changed_plan->>'plan')::uuid,changed_plan->>'sha256');
  reset role;
  insert into sectalk_private.st_v6_room_reports(id,workspace_id,room_id,post_id,reporter,subject,category,details,share_with_workspace)
    values(report_id,w,changed,gen_random_uuid(),reviewer_id,owner_id,'spam','Disposable late report of a missing source post.',true);
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,w,owner_id,'Preserve room during disposable testing.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_archived_room(w,eligible,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Removed room with an active hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release this disposable hold.' where h.id=hold_id;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_archived_room(w,changed,'delete',w::text,(changed_plan->>'plan')::uuid,changed_plan->>'sha256');
    raise exception 'Removed approved room despite a new report on an earlier post';
  exception when sqlstate 'PT409' then null; end;
  receipt:=public.st_v8_offboarding_archived_room(w,eligible,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  if receipt->>'deletedAt' is null or receipt is distinct from
    public.st_v8_offboarding_archived_room(w,eligible,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256')
    then raise exception 'Missing or irreproducible immutable removal receipt'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform public.st_v6_room_create(eligible,another_workspace,'retired-room-id','public','blank');
    raise exception 'Reused a retired room identifier';
  exception when sqlstate 'PT409' then
    if sqlerrm<>'This room identifier is permanently retired' then raise; end if;
  end;
  reset role;
  if exists(select 1 from public.st_v6_rooms c where c.id=eligible)
    or (select count(*) from public.st_v6_rooms c where c.id in (nonempty,changed,control,storage_only,foreign_key_room))<>5
    or not exists(select 1 from public.st_v6_room_posts p where p.room_id=nonempty)
    or not exists(select 1 from sectalk_private.st_v6_room_reports r where r.id=report_id and r.room_id=changed)
    or not exists(select 1 from storage.objects y where y.bucket_id='sectalk-workspace-files'
      and y.name like (w||'/rooms/'||storage_only||'/%'))
    or not exists(select 1 from sectalk_private.disposable_room_dependency p where p.room=foreign_key_room)
    or exists(select 1 from public.st_v6_room_audit a where a.room_id=eligible)
    or exists(select 1 from public.st_v6_room_members m where m.room_id=eligible)
    or not exists(select 1 from sectalk_private.st_v8_offboarding_retained_room_proof e
      where (e.plan,e.proof,e.sha256)=((selected_plan->>'plan')::uuid,original,expected_archive_sha))
    or (select count(*) from sectalk_private.st_v6_audit_chain j
      join jsonb_array_elements(original->'auditEvents') a on j.source_id=(a->>'id')::bigint
      where j.source='public.st_v6_room_audit' and j.operation='DELETE'
        and j.row_hash=sectalk_private.st_v6_audit_row_hash(a))<>2
    then raise exception 'Physical removal did not retain native creation, membership or archive evidence or touched protected records'; end if;
  if has_function_privilege('service_role','public.st_v8_offboarding_archived_room(uuid,uuid,text,text,uuid,text)','EXECUTE')
    or has_function_privilege('anon','public.st_v8_offboarding_archived_room(uuid,uuid,text,text,uuid,text)','EXECUTE')
    then raise exception 'Unsafe archive action grants'; end if;
end $$;

select 'passed: exact archived empty room removal, retained creator membership, native creation and archive events and chain, protected history and legal holds';
rollback;
