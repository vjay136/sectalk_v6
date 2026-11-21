begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; w uuid; workspace_id uuid; request_id uuid:=gen_random_uuid(); hold_id uuid:=gen_random_uuid(); case_id uuid;
  eligible uuid; nonempty uuid; changed uuid; control uuid; too_many uuid; active_channel uuid; drifted uuid;
  expected_audit_id bigint; expected_archive_sha text;
  post_ids uuid[]:=array[gen_random_uuid(),gen_random_uuid()]; protected_post uuid:=gen_random_uuid(); late_post uuid:=gen_random_uuid();
  drifted_post uuid:=gen_random_uuid(); drifted_plan jsonb;
  copy jsonb; original jsonb; model_manifest jsonb; selected_plan jsonb; changed_plan jsonb; receipt jsonb; status jsonb;
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
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  active_channel:=public.st_v2_create_channel(public.st_v2_create_workspace('Disposable active channel workspace'),'reuse-control');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
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
  too_many:=public.st_v2_create_channel(w,'archive-with-large-history');
  drifted:=public.st_v2_create_channel(w,'archive-with-version-change');
  reset role;
  insert into public.st_v2_posts(id,channel_id,sender,body)
    select id,eligible,owner_id,'Approved owner-written history '||id from unnest(post_ids) id;
  insert into public.st_v2_posts(id,channel_id,sender,body)
    values(protected_post,nonempty,reviewer_id,'Keep this author-shared archived post.'),
      (late_post,changed,owner_id,'Later reported archived post.'),
      (drifted_post,drifted,owner_id,'Original approved message version.');
  insert into public.st_v2_posts(id,channel_id,sender,body)
    select gen_random_uuid(),too_many,owner_id,'Keep history above the cap.' from generate_series(1,17);
  insert into sectalk_private.st_v7_search_document(kind,object_id,fingerprint,first_terms,second_terms)
    select 'channel',id,decode(repeat('0',64),'hex'),to_tsvector('synthetic'),to_tsvector('archive')
    from unnest(post_ids||protected_post) id;
  set local role authenticated;
  perform public.st_v6_manage_channel(eligible,'archive');
  perform public.st_v6_manage_channel(nonempty,'archive');
  perform public.st_v6_manage_channel(changed,'archive');
  perform public.st_v6_manage_channel(too_many,'archive');
  perform public.st_v6_manage_channel(drifted,'archive');
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Keep the remaining workspace data.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  case_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  select a.id,to_jsonb(a),encode(sectalk_private.st_v6_audit_row_hash(to_jsonb(a)),'hex') into expected_audit_id,original,expected_archive_sha
    from sectalk_private.st_v6_channel_audit a where a.channel_id=eligible;
  select jsonb_agg(jsonb_build_object('id',p.id,'sha256',encode(sha256(convert_to(to_jsonb(p)::text,'UTF8')),'hex')) order by p.id)
    into model_manifest from public.st_v2_posts p where p.channel_id=eligible;
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
    where c->>'id' in (nonempty::text,control::text,too_many::text))
    then raise exception 'Archived history or a live channel was offered for removal'; end if;
  copy:=public.st_v8_offboarding_archived_channel(w,eligible,'copy',w::text);
  if copy->>'sha256'<>encode(sha256(convert_to(copy->>'json','UTF8')),'hex')
    or (copy->>'json')::jsonb->'archiveAudit' is distinct from original
    or (copy->>'json')::jsonb#>>'{channel,id}' is distinct from eligible::text
    or copy->>'format' is distinct from 'sectalk-offboarding-archived-channel-history-copy-v1'
    or jsonb_array_length((copy->>'json')::jsonb->'messages')<>2
    or (select jsonb_agg(jsonb_build_object('id',p->>'id','sha256',encode(sha256(convert_to(p::text,'UTF8')),'hex')) order by p->>'id')
      from jsonb_array_elements((copy->>'json')::jsonb->'messages') p) is distinct from model_manifest
    then raise exception 'Issued copy does not match original native bytes'; end if;
  selected_plan:=public.st_v8_offboarding_archived_channel(w,eligible,'capture',w::text);
  perform public.st_v8_offboarding_archived_channel(w,changed,'copy',w::text);
  changed_plan:=public.st_v8_offboarding_archived_channel(w,changed,'capture',w::text);
  perform public.st_v8_offboarding_archived_channel(w,drifted,'copy',w::text);
  drifted_plan:=public.st_v8_offboarding_archived_channel(w,drifted,'capture',w::text);
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
    and p->>'archiveSha256'=expected_archive_sha and p->'messages'=model_manifest)
    then raise exception 'Reviewer lacks exact archive digests or sees owner-only contents'; end if;
  begin
    perform public.st_v8_offboarding_archived_channel(w,control,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Approval was reused for another channel';
  exception when sqlstate 'PT409' then null; end;
  perform public.st_v8_offboarding_archived_channel(w,eligible,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  perform public.st_v8_offboarding_archived_channel(w,changed,'approve',w::text,(changed_plan->>'plan')::uuid,changed_plan->>'sha256');
  perform public.st_v8_offboarding_archived_channel(w,drifted,'approve',w::text,(drifted_plan->>'plan')::uuid,drifted_plan->>'sha256');
  reset role;
  set local role authenticated;
  perform public.st_v7_submit_channel_report(changed,late_post,'spam','Synthetic report after exact approval.',true,true);
  reset role;
  begin
    update public.st_v2_posts p set body='New unapproved message version.' where p.id=drifted_post;
    raise exception 'A read-only archive accepted an edited message';
  exception when sqlstate 'PT423' then
    if sqlerrm<>'This workspace is read-only for offboarding.' then raise; end if;
  end;
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
    raise exception 'Removed approved channel despite a new report on an approved message';
  exception when sqlstate 'PT409' then null; end;
  begin
    perform public.st_v8_offboarding_archived_channel(w,drifted,'delete',w::text,(drifted_plan->>'plan')::uuid,repeat('f',64));
    raise exception 'Removed messages using a different plan digest';
  exception when sqlstate 'PT409' then null; end;
  receipt:=public.st_v8_offboarding_archived_channel(w,eligible,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  if receipt->>'deletedAt' is null or receipt is distinct from
    public.st_v8_offboarding_archived_channel(w,eligible,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256')
    then raise exception 'Missing or irreproducible immutable removal receipt'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform public.st_v2_post(active_channel,post_ids[1],'Attempt archived message ID reuse in an active workspace.');
    raise exception 'Reused a retired archived message identifier';
  exception when sqlstate 'PT409' then
    if sqlerrm<>'This archived message identifier is permanently retired' then raise; end if;
  end;
  reset role;
  if exists(select 1 from public.st_v2_channels c where c.id=eligible)
    or (select count(*) from public.st_v2_channels c where c.id in (nonempty,changed,control))<>3
    or not exists(select 1 from public.st_v2_posts p where (p.channel_id,p.id)=(nonempty,protected_post))
    or exists(select 1 from public.st_v2_posts p where p.id=any(post_ids))
    or (select count(*) from sectalk_private.st_v8_offboarding_retired_channel_posts t
      where (t.channel,t.plan)=(eligible,(selected_plan->>'plan')::uuid) and t.post=any(post_ids))<>2
    or exists(select 1 from sectalk_private.st_v7_search_document d where d.kind='channel' and d.object_id=any(post_ids))
    or not exists(select 1 from sectalk_private.st_v7_search_document d where (d.kind,d.object_id)=('channel',protected_post))
    or not exists(select 1 from sectalk_private.st_v7_channel_reports r where (r.channel_id,r.post_id)=(changed,late_post))
    or not exists(select 1 from public.st_v2_posts p where p.id=drifted_post and p.body='Original approved message version.')
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

select 'passed: exact archived channel and two message removals, retained archive and searchable controls, legal hold, late report, limit';
rollback;
