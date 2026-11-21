begin;

create or replace function public.st_v8_residency_compare_destination(p_workspace uuid,p_approval uuid)
returns jsonb language plpgsql stable security definer set search_path='' set timezone='UTC' as $$
declare actor_id uuid:=auth.uid(); admitted record; fingerprint text; findings jsonb;
begin
  if p_workspace is null or p_approval is null
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
    or sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'owner'
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    then raise insufficient_privilege; end if;
  select c.cell,c.source_project,c.manifest_sha256,a.record_count,s.records,least(c.expires_at,a.expires_at) expires_at
    into admitted from sectalk_private.st_v8_residency_workspace_claims c
    join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
    join sectalk_private.st_v8_residency_cells t on t.id=c.cell and t.retired_at is null and t.project_reference<>c.source_project
    join sectalk_private.st_v8_residency_content_admissions a on (a.cell,a.workspace,a.source_project,a.approval)=
      (c.cell,c.workspace,c.source_project,c.approval)
    join sectalk_private.st_v8_residency_staged_content s on (s.cell,s.workspace,s.source_project,s.approval)=
      (c.cell,c.workspace,c.source_project,c.approval)
    where (c.workspace,c.approval,c.owner_id)=(p_workspace,p_approval,actor_id)
      and c.claimed_at is not null and c.manifest_sha256=a.manifest_sha256;
  if not found then raise insufficient_privilege; end if;

  select encode(sha256(convert_to(jsonb_build_object('format','sectalk-workspace-content-v1','workspace',p_workspace,
    'approval',p_approval,'entries',jsonb_agg(jsonb_build_array(position,x->>'kind',x->>'scope',x->>'id',x->>'sha256')
      order by position))::text,'UTF8')),'hex') into fingerprint
  from jsonb_array_elements(admitted.records) with ordinality as entry(x,position);
  if fingerprint is distinct from admitted.manifest_sha256 or jsonb_array_length(admitted.records)<>admitted.record_count
    or exists(select 1 from jsonb_array_elements(admitted.records) item where
      encode(sha256(convert_to(item->>'json','UTF8')),'hex') is distinct from item->>'sha256')
    then raise exception 'The approved destination manifest changed' using errcode='PT409'; end if;

  with entries as materialized (
    select position,x->>'kind' kind,(x->>'scope')::uuid scope,(x->>'id')::uuid id,x->>'sha256' digest,(x->>'json')::jsonb payload
    from jsonb_array_elements(admitted.records) with ordinality as entry(x,position)
  ), compared as (
    select e.position,e.kind,e.scope,e.id,
    case e.kind
      when 'workspace_task' then case
        when tw.imported_at is null and w.id is null then 'missing'
        when tw.imported_at is not null and (w.workspace_id,w.kind,w.created_by,w.title,w.details,w.due_at,w.completed,w.created_at)
          is not distinct from (p_workspace,'task',tw.actor,e.payload->>'title',e.payload->>'details',
            (e.payload->>'dueAt')::timestamptz,(e.payload->>'completed')::boolean,(e.payload->>'createdAt')::timestamptz) then 'matched'
        else 'changed' end
      when 'room_task' then case
        when tr.imported_at is null and rt.id is null then 'missing'
        when tr.imported_at is not null and (rm.kind,rm.classification,rm.encryption_mode,rm.archived)=('private','confidential','standard',false)
          and (rt.room_id,rt.author_id,rt.title,rt.status,rt.priority,to_jsonb(rt.labels),rt.due_at,rt.created_at,rt.updated_at)
            is not distinct from (e.scope,tr.actor,e.payload->>'title',e.payload->>'status',e.payload->>'priority',e.payload->'labels',
              (e.payload->>'dueAt')::timestamptz,(e.payload->>'createdAt')::timestamptz,(e.payload->>'updatedAt')::timestamptz)
          and exists(select 1 from public.st_v6_task_audit v where v.task_id=e.id and v.actor_id=tr.actor
            and v.action='residency_restored' and (v.detail->>'approval',v.detail->>'sourceRecordSha256')=(p_approval::text,e.digest)) then 'matched'
        else 'changed' end
      when 'channel_message' then case
        when th.post is null and cp.id is null then 'missing'
        when th.post is not null and th.record_digest=e.digest and (ch.name,ch.visibility,ch.encryption_mode,ch.archived)=
            (e.payload->>'name','workspace','standard',false)
          and (cp.sender,cp.body,cp.created_at,cp.quarantined_at) is not distinct from
            (th.actor,e.payload->>'body',(e.payload->>'createdAt')::timestamptz,null::timestamptz) then 'matched'
        else 'changed' end
      when 'room_message' then case
        when e.payload->>'kind' is distinct from 'message' then 'unsupported'
        when rh.post is null and rp.id is null then 'missing'
        when rh.post is not null and ri.room is not null and rh.record_digest=e.digest
          and (rm.name,rm.kind,rm.classification,rm.encryption_mode,rm.archived)=
            (e.payload->>'name','private','confidential','standard',false)
          and (rp.sender,rp.kind,rp.body,rp.parent_id,rp.created_at,rp.edited_at,rp.removed_at,rp.forwarded)
            is not distinct from (rh.actor,'message',e.payload->>'body',(e.payload->>'parent')::uuid,
              (e.payload->>'createdAt')::timestamptz,(e.payload->>'editedAt')::timestamptz,null::timestamptz,false) then 'matched'
        else 'changed' end
      when 'workspace_file' then case
        when wf.id is null then 'missing'
        when wf.published_at is not null and wf.deleted_at is null
          and (wf.filename,wf.size_bytes,encode(wf.fingerprint,'hex'),wo.metadata->>'size')=
            (e.payload->>'filename',(e.payload->>'bytes')::integer,e.payload->>'fingerprint',e.payload->>'bytes') then 'check_bytes'
        else 'changed' end
      when 'room_file' then case
        when rf.id is null and tf.file is null then 'missing'
        when tf.published_at is not null and (rm.kind,rm.classification,rm.encryption_mode,rm.archived)=('private','confidential','standard',false)
          and rf.published_at is not null and rf.deleted_at is null
          and (rf.filename,rf.size_bytes,rf.sha256,ro.metadata->>'size')=
            (e.payload->>'filename',(e.payload->>'bytes')::integer,e.payload->>'sha256',e.payload->>'bytes') then 'check_bytes'
        else 'changed' end
      else 'unsupported' end status
    from entries e
    left join sectalk_private.st_v8_residency_task_imports tw on e.kind='workspace_task' and
      (tw.cell,tw.workspace,tw.source_project,tw.approval)=(admitted.cell,p_workspace,admitted.source_project,p_approval)
    left join public.st_v2_items w on e.kind='workspace_task' and (w.workspace_id,w.id)=(p_workspace,e.id)
    left join public.st_v6_rooms rm on e.kind in ('room_task','room_file','room_message') and (rm.workspace_id,rm.id)=(p_workspace,e.scope)
    left join sectalk_private.st_v8_residency_room_imports ri on e.kind='room_message' and
      (ri.cell,ri.workspace,ri.source_project,ri.approval,ri.room)=(admitted.cell,p_workspace,admitted.source_project,p_approval,rm.id)
    left join sectalk_private.st_v8_residency_room_history rh on e.kind='room_message' and
      (rh.workspace,rh.approval,rh.room,rh.post)=(p_workspace,p_approval,e.scope,e.id)
    left join public.st_v6_room_posts rp on e.kind='room_message' and (rp.room_id,rp.id)=(rm.id,e.id)
    left join sectalk_private.st_v8_residency_room_task_imports tr on e.kind='room_task' and
      (tr.cell,tr.workspace,tr.source_project,tr.approval,tr.room)=(admitted.cell,p_workspace,admitted.source_project,p_approval,rm.id)
    left join public.st_v6_tasks rt on e.kind='room_task' and (rt.room_id,rt.id)=(rm.id,e.id)
    left join public.st_v2_channels ch on e.kind='channel_message' and (ch.workspace_id,ch.id)=(p_workspace,e.scope)
    left join sectalk_private.st_v8_residency_channel_history th on e.kind='channel_message' and
      (th.workspace,th.approval,th.channel,th.post)=(p_workspace,p_approval,e.scope,e.id)
    left join public.st_v2_posts cp on e.kind='channel_message' and (cp.channel_id,cp.id)=(ch.id,e.id)
    left join sectalk_private.st_v6_workspace_files wf on e.kind='workspace_file' and (wf.workspace,wf.id)=(p_workspace,e.id)
    left join storage.objects wo on wf.id is not null and wo.bucket_id='sectalk-workspace-files'
      and wo.name=p_workspace::text||'/'||e.id::text
    left join sectalk_private.st_v8_residency_room_file_imports tf on e.kind='room_file' and
      (tf.cell,tf.workspace,tf.source_project,tf.approval,tf.room,tf.file)=(admitted.cell,p_workspace,admitted.source_project,p_approval,e.scope,e.id)
    left join sectalk_private.st_v6_room_files rf on e.kind='room_file' and (rf.workspace,rf.room,rf.id)=(p_workspace,rm.id,e.id)
    left join storage.objects ro on rf.id is not null and ro.bucket_id='sectalk-workspace-files'
      and ro.name=p_workspace::text||'/rooms/'||e.scope::text||'/'||e.id::text
  )
  select jsonb_agg(jsonb_build_object('kind',kind,'scope',scope,'id',id,'status',status) order by position) into findings from compared;

  return jsonb_build_object('checkedAt',statement_timestamp(),'approvalCurrent',admitted.expires_at>statement_timestamp(),
    'manifestSha256',admitted.manifest_sha256,'records',findings);
end $$;

revoke all on function public.st_v8_residency_compare_destination(uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_compare_destination(uuid,uuid) to authenticated;
notify pgrst,'reload schema';
commit;
