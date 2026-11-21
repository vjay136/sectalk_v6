begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; w uuid; workspace_id uuid; request_id uuid:=gen_random_uuid(); hold_id uuid:=gen_random_uuid(); case_id uuid;
  eligible uuid; nonempty uuid; changed uuid; control uuid; expected_audit_id bigint; expected_archive_sha text;
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
  workspace_id:=public.st_v2_create_workspace('Disposable archived channel source');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace_id,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(workspace_id,reviewer_id);
  w:=workspace_id;
  insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values(w,1);
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,wrapped) values(w,1,'managed',repeat('a',80));
  set local role authenticated;
  eligible:=public.st_v2_create_channel(w,'archive-candidate');
  nonempty:=public.st_v2_create_channel(w,'archive-with-one-post');
  changed:=public.st_v2_create_channel(w,'archive-with-late-evidence');
  control:=public.st_v2_create_channel(w,'live-control');
  reset role;
  insert into public.st_v2_posts(id,channel_id,sender,body) values(gen_random_uuid(),nonempty,reviewer_id,'Keep this archived post.');
  set local role authenticated;
  perform public.st_v6_manage_channel(eligible,'archive');
  perform public.st_v6_manage_channel(nonempty,'archive');
  perform public.st_v6_manage_channel(changed,'archive');
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Keep the remaining workspace data.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  case_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  select a.id,to_jsonb(a),encode(sectalk_private.st_v6_audit_row_hash(to_jsonb(a)),'hex') into expected_audit_id,original,expected_archive_sha from sectalk_private.st_v6_channel_audit a where a.channel_id=eligible;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action)
    values(case_id,w,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  begin
    perform public.st_v8_offboarding_archived_channel(w,eligible,'capture',w::text);
    raise exception 'Captured a plan before the exact copy';
  exception when sqlstate 'PT409' then null; end;
  if exists(select 1 from jsonb_array_elements(public.st_v8_offboarding_archived_channel_status(w)->'channels') c
    where c->>'id' in (nonempty::text,control::text))
    then raise exception 'Archived history or a live channel was offered for removal'; end if;
  copy:=public.st_v8_offboarding_archived_channel(w,eligible,'copy',w::text);
  if copy->>'sha256'<>encode(sha256(convert_to(copy->>'json','UTF8')),'hex')
    or (copy->>'json')::jsonb->'archiveAudit' is distinct from original
    or (copy->>'json')::jsonb#>>'{channel,id}' is distinct from eligible::text
    then raise exception 'Issued copy does not match original native bytes'; end if;
  selected_plan:=public.st_v8_offboarding_archived_channel(w,eligible,'capture',w::text);
  perform public.st_v8_offboarding_archived_channel(w,changed,'copy',w::text);
  changed_plan:=public.st_v8_offboarding_archived_channel(w,changed,'capture',w::text);
  begin
    perform public.st_v8_offboarding_archived_channel(w,eligible,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner self-approved';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_offboarding_archived_channel(w,eligible,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner removed channel before review';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  status:=public.st_v8_offboarding_archived_channel_status(w);
  if jsonb_array_length(status->'channels')<>0 or not exists(select 1 from jsonb_array_elements(status->'plans') p
    where p->>'plan'=selected_plan->>'plan' and p->>'copySha256'=copy->>'sha256'
    and p->>'archiveSha256'=expected_archive_sha)
    then raise exception 'Reviewer lacks exact archive digests or sees owner-only contents'; end if;
  begin
    perform public.st_v8_offboarding_archived_channel(w,control,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Approval was reused for another channel';
  exception when sqlstate 'PT409' then null; end;
  perform public.st_v8_offboarding_archived_channel(w,eligible,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  perform public.st_v8_offboarding_archived_channel(w,changed,'approve',w::text,(changed_plan->>'plan')::uuid,changed_plan->>'sha256');
  reset role;
  insert into sectalk_private.st_v6_channel_audit(channel_id,actor,action) values(changed,reviewer_id,'restore');
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,w,owner_id,'Preserve channel during disposable testing.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_archived_channel(w,eligible,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Removed channel with an active hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release this disposable hold.' where h.id=hold_id;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_archived_channel(w,changed,'delete',w::text,(changed_plan->>'plan')::uuid,changed_plan->>'sha256');
    raise exception 'Removed approved channel despite additional native archive history';
  exception when sqlstate 'PT409' then null; end;
  receipt:=public.st_v8_offboarding_archived_channel(w,eligible,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  if receipt->>'deletedAt' is null or receipt is distinct from
    public.st_v8_offboarding_archived_channel(w,eligible,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256')
    then raise exception 'Missing or irreproducible immutable removal receipt'; end if;
  reset role;
  if exists(select 1 from public.st_v2_channels c where c.id=eligible)
    or (select count(*) from public.st_v2_channels c where c.id in (nonempty,changed,control))<>3
    or not exists(select 1 from public.st_v2_posts p where p.channel_id=nonempty)
    or exists(select 1 from sectalk_private.st_v6_channel_audit a where a.channel_id=eligible)
    or not exists(select 1 from sectalk_private.st_v8_offboarding_retained_channel_archive e
      where (e.plan,e.audit_id,e.audit_row,e.sha256)=((selected_plan->>'plan')::uuid,expected_audit_id,original,
        encode(sectalk_private.st_v6_audit_row_hash(original),'hex')))
    or not exists(select 1 from sectalk_private.st_v6_audit_chain j
      where (j.source,j.source_id,j.operation,j.row_hash)=('sectalk_private.st_v6_channel_audit',expected_audit_id,
        'DELETE',sectalk_private.st_v6_audit_row_hash(original)))
    or not exists(select 1 from public.st_v2_workspace_audit a
      where (a.workspace_id,a.event,a.target)=(w,'channel.created',eligible))
    then raise exception 'Physical removal did not retain native archive and workspace evidence or touched protected records'; end if;
  if has_function_privilege('service_role','public.st_v8_offboarding_archived_channel(uuid,uuid,text,text,uuid,text)','EXECUTE')
    or has_function_privilege('anon','public.st_v8_offboarding_archived_channel(uuid,uuid,text,text,uuid,text)','EXECUTE')
    then raise exception 'Unsafe archive action grants'; end if;
end $$;

select 'passed: exact archived empty channel removal, retained native archive event and chain, protected history and legal holds';
rollback;