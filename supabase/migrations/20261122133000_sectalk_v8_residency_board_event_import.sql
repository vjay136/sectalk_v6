begin;

alter table sectalk_private.st_v8_residency_task_imports
  drop constraint st_v8_residency_task_imports_task_count_check,
  add column event_count integer not null default 0,
  add constraint st_v8_residency_board_import_counts
    check(task_count>=0 and event_count>=0 and task_count+event_count between 1 and 500);

create or replace function sectalk_private.st_v8_content_export_records(p_workspace uuid,p_owner uuid,p_reviewer uuid,
  p_kind text default null,p_scope uuid default null,p_record uuid default null)
returns table(kind text,scope_id uuid,record_id uuid,item jsonb)
language sql stable security definer set search_path='' set timezone='UTC' as $$
  select 'room_message',r.id,p.id,jsonb_build_object('room',r.id,'name',r.name,'message',p.id,'parent',p.parent_id,
    'body',p.body,'kind',p.kind,'createdAt',p.created_at,'editedAt',p.edited_at)
  from public.st_v6_rooms r join public.st_v6_room_posts p on p.room_id=r.id
  where (p_kind is null or p_kind='room_message') and (p_scope is null or r.id=p_scope) and (p_record is null or p.id=p_record)
    and r.workspace_id=p_workspace and r.kind='public' and r.classification in ('public','internal') and not r.archived
    and p.removed_at is null and not p.forwarded
    and (p.parent_id is null or exists(select 1 from public.st_v6_room_posts root
      where (root.room_id,root.id)=(p.room_id,p.parent_id) and root.parent_id is null
        and root.removed_at is null and not root.forwarded
        and (root.sender=p_owner or sectalk_private.open_pair(root.sender,p_owner))
        and (root.sender=p_reviewer or sectalk_private.open_pair(root.sender,p_reviewer))))
    and sectalk_private.st_v6_room_role(r.id,p_owner) is not null
    and sectalk_private.st_v6_room_role(r.id,p_reviewer) is not null
    and (p.sender=p_owner or sectalk_private.open_pair(p.sender,p_owner))
    and (p.sender=p_reviewer or sectalk_private.open_pair(p.sender,p_reviewer))
  union all
  select 'channel_message',c.id,p.id,jsonb_build_object('channel',c.id,'name',c.name,'message',p.id,
    'body',p.body,'createdAt',p.created_at)
  from public.st_v2_channels c join public.st_v2_posts p on p.channel_id=c.id
  where (p_kind is null or p_kind='channel_message') and (p_scope is null or c.id=p_scope) and (p_record is null or p.id=p_record)
    and c.workspace_id=p_workspace and c.visibility='workspace' and c.encryption_mode='standard' and not c.archived
    and p.quarantined_at is null
    and sectalk_private.st_v2_post_read(c.id,p.sender,p_owner)
    and sectalk_private.st_v2_post_read(c.id,p.sender,p_reviewer)
  union all
  select 'workspace_task',i.workspace_id,i.id,jsonb_build_object('task',i.id,'title',i.title,'details',i.details,
    'dueAt',i.due_at,'completed',i.completed,'createdAt',i.created_at)
  from public.st_v2_items i
  where (p_kind is null or p_kind='workspace_task') and (p_scope is null or i.workspace_id=p_scope) and (p_record is null or i.id=p_record)
    and i.workspace_id=p_workspace and i.kind='task'
    and (i.created_by=p_owner or sectalk_private.open_pair(i.created_by,p_owner))
    and (i.created_by=p_reviewer or sectalk_private.open_pair(i.created_by,p_reviewer))
  union all
  select 'workspace_event',i.workspace_id,i.id,jsonb_build_object('event',i.id,'title',i.title,'details',i.details,
    'dueAt',i.due_at,'createdAt',i.created_at)
  from public.st_v2_items i
  where (p_kind is null or p_kind='workspace_event') and (p_scope is null or i.workspace_id=p_scope)
    and (p_record is null or i.id=p_record) and i.workspace_id=p_workspace and i.kind='event'
    and (i.created_by=p_owner or sectalk_private.open_pair(i.created_by,p_owner))
    and (i.created_by=p_reviewer or sectalk_private.open_pair(i.created_by,p_reviewer))
  union all
  select 'room_task',r.id,t.id,jsonb_build_object('room',r.id,'task',t.id,'title',t.title,'status',t.status,
    'priority',t.priority,'labels',t.labels,'dueAt',t.due_at,'createdAt',t.created_at,'updatedAt',t.updated_at)
  from public.st_v6_rooms r join public.st_v6_tasks t on t.room_id=r.id
  where (p_kind is null or p_kind='room_task') and (p_scope is null or r.id=p_scope) and (p_record is null or t.id=p_record)
    and r.workspace_id=p_workspace and r.kind='public' and r.classification in ('public','internal') and not r.archived
    and not exists(select 1 from sectalk_private.st_v6_task_sources x where x.task_id=t.id)
    and sectalk_private.st_v6_room_role(r.id,p_owner) is not null
    and sectalk_private.st_v6_room_role(r.id,p_reviewer) is not null
    and sectalk_private.st_v6_task_audience(r.id,null,p_owner)
    and sectalk_private.st_v6_task_audience(r.id,null,p_reviewer)
    and (t.author_id=p_owner or sectalk_private.open_pair(t.author_id,p_owner))
    and (t.author_id=p_reviewer or sectalk_private.open_pair(t.author_id,p_reviewer));
$$;

create or replace function public.st_v8_stage_residency_content(p_cell uuid, p_nonce uuid, p_source text,
  p_workspace uuid, p_approval uuid, p_records jsonb)
returns jsonb language plpgsql security definer set search_path='' as $$
declare admission sectalk_private.st_v8_residency_content_admissions;
  fingerprint text; seen integer; valid integer; distinct_records integer; canonical jsonb; wrote boolean;
begin
  select a.* into admission from sectalk_private.st_v8_residency_content_admissions a
    join sectalk_private.st_v8_residency_installation i on i.cell=a.cell and i.installation_nonce=p_nonce
    join sectalk_private.st_v8_residency_cells c on c.id=a.cell and c.retired_at is null
    where (a.cell,a.workspace,a.source_project,a.approval)=(p_cell,p_workspace,p_source,p_approval)
      and c.project_reference<>p_source and a.expires_at>statement_timestamp()
    for update of a;
  if not found then raise exception 'Target transfer approval unavailable' using errcode='42501'; end if;
  if jsonb_typeof(p_records) is distinct from 'array' or octet_length(p_records::text)>8388608
    or jsonb_array_length(p_records)<>admission.record_count then
    raise exception 'Invalid approved transfer size' using errcode='22023'; end if;

  with checked as (
    select entry, position, entry->>'kind' as kind, entry->>'scope' as scope,
      entry->>'id' as record, entry->>'sha256' as digest
    from jsonb_array_elements(p_records) with ordinality as item(entry,position)
  )
  select count(*), count(*) filter (where jsonb_typeof(entry)='object'
      and entry ?& array['position','kind','scope','id','sha256','json']
      and entry - array['position','kind','scope','id','sha256','json']='{}'::jsonb
      and entry->'position'=to_jsonb(position)
      and kind in ('channel_message','room_message','workspace_task','workspace_event','room_task','workspace_file','room_file')
      and scope~'^[0-9a-f-]{36}$' and record~'^[0-9a-f-]{36}$'
      and jsonb_typeof(entry->'json')='string'
      and encode(sha256(convert_to(entry->>'json','UTF8')),'hex')=digest),
    count(distinct (kind,scope,record)),
    jsonb_agg(jsonb_build_array(position,kind,scope,record,digest) order by position)
    into seen,valid,distinct_records,canonical from checked;
  if seen<>valid or seen<>distinct_records then
    raise exception 'Approved content is incomplete or changed' using errcode='22023'; end if;

  fingerprint:=encode(sha256(convert_to(jsonb_build_object('format','sectalk-workspace-content-v1',
    'workspace',p_workspace,'approval',p_approval,'entries',canonical)::text,'UTF8')),'hex');
  if fingerprint<>admission.manifest_sha256 then
    raise exception 'Approved manifest differs' using errcode='42501'; end if;
  insert into sectalk_private.st_v8_residency_staged_content (cell,workspace,source_project,approval,records)
    values(p_cell,p_workspace,p_source,p_approval,p_records) on conflict do nothing;
  wrote:=found;
  if not exists(select 1 from sectalk_private.st_v8_residency_staged_content s
    where (s.cell,s.workspace,s.source_project,s.approval)=(p_cell,p_workspace,p_source,p_approval)
      and s.records=p_records) then
    raise exception 'Target transfer differs from existing archive' using errcode='PT409'; end if;
  return jsonb_build_object('staged',wrote,'count',seen,'manifestSha256',fingerprint);
end $$;

create or replace function public.st_v8_residency_task_import(p_workspace uuid, p_approval uuid default null,
  p_confirmation text default null)
returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' as $$
declare actor_id uuid:=auth.uid(); admitted record; saved record; task_count integer; event_count integer; wrote integer; fingerprint text;
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false) then raise insufficient_privilege; end if;
  if p_approval is not null then
    if p_confirmation is distinct from p_workspace::text or sectalk_private.st_v7_admin_fresh() is not true then
      raise insufficient_privilege; end if;
    perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
  end if;
  if sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) <> 'owner'
    or sectalk_private.st_v8_planner_sso_allows(p_workspace) is not true
    or sectalk_private.st_v8_organization_sso_allows(p_workspace) is not true then raise insufficient_privilege; end if;

  select a.*,s.records,r.task_count as imported_count,r.imported_at into admitted
    from sectalk_private.st_v8_residency_workspace_claims c
    join sectalk_private.st_v8_residency_installation i
      on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
    join sectalk_private.st_v8_residency_cells t
      on t.id=c.cell and t.retired_at is null and t.project_reference<>c.source_project
    join sectalk_private.st_v8_residency_content_admissions a
      on (a.cell,a.workspace,a.source_project,a.approval)=(c.cell,c.workspace,c.source_project,c.approval)
    join sectalk_private.st_v8_residency_staged_content s
      on (s.cell,s.workspace,s.source_project,s.approval)=(a.cell,a.workspace,a.source_project,a.approval)
    left join sectalk_private.st_v8_residency_task_imports r
      on (r.cell,r.workspace,r.source_project,r.approval)=(a.cell,a.workspace,a.source_project,a.approval)
    where (c.workspace,c.owner_id)=(p_workspace,actor_id) and c.claimed_at is not null
      and c.manifest_sha256=a.manifest_sha256 and (p_approval is null or c.approval=p_approval)
      and (least(c.expires_at,a.expires_at)>statement_timestamp() or r.imported_at is not null)
    for share of c,i,t,a,s;
  if not found then
    if p_approval is not null then raise insufficient_privilege; end if;
    return null;
  end if;
  if p_approval is not null and exists(select 1 from sectalk_private.st_v8_residency_staged_content s
      where (s.cell,s.workspace,s.approval)=(admitted.cell,p_workspace,p_approval)
        and s.source_project<>admitted.source_project) then
    raise exception 'Multiple source bindings for the same approval' using errcode='PT409'; end if;
  select count(*) filter(where x->>'kind'='workspace_task'),count(*) filter(where x->>'kind'='workspace_event')
    into task_count,event_count from jsonb_array_elements(admitted.records) x;
  if p_approval is null or admitted.imported_at is not null then
    return jsonb_build_object('approval',admitted.approval,'manifestSha256',admitted.manifest_sha256,
      'taskCount',task_count,'eventCount',event_count,'importedAt',admitted.imported_at);
  end if;
  if task_count+event_count=0 then raise exception 'This manifest contains no workspace tasks or events' using errcode='PT409'; end if;
  perform sectalk_private.st_v7_require_workspace_write(p_workspace);

  select encode(sha256(convert_to(jsonb_build_object('format','sectalk-workspace-content-v1',
    'workspace',p_workspace,'approval',p_approval,'entries',jsonb_agg(jsonb_build_array(
      position,entry->>'kind',entry->>'scope',entry->>'id',entry->>'sha256') order by position))::text,'UTF8')),'hex')
    into fingerprint from jsonb_array_elements(admitted.records) with ordinality as items(entry,position);
  if fingerprint is distinct from admitted.manifest_sha256 or jsonb_array_length(admitted.records)<>admitted.record_count then
    raise exception 'The approved destination manifest changed' using errcode='PT409'; end if;

  for saved in select (x->>'id')::uuid as id,(x->>'scope')::uuid as scope,(x->>'json')::jsonb as payload,
      x->>'sha256' as digest,x->>'json' as content,x->>'kind' as family
    from jsonb_array_elements(admitted.records) x where x->>'kind' in ('workspace_task','workspace_event')
  loop
    if saved.scope is distinct from p_workspace
      or saved.payload->>(case saved.family when 'workspace_task' then 'task' else 'event' end) is distinct from saved.id::text
      or encode(sha256(convert_to(saved.content,'UTF8')),'hex') is distinct from saved.digest
      or jsonb_typeof(saved.payload->'title') is distinct from 'string'
      or jsonb_typeof(saved.payload->'details') is distinct from 'string'
      or (saved.family='workspace_task' and jsonb_typeof(saved.payload->'completed') is distinct from 'boolean')
      or (saved.family='workspace_event' and (jsonb_typeof(saved.payload->'dueAt') is distinct from 'string'
        or saved.payload ? 'completed'))
      or jsonb_typeof(saved.payload->'createdAt') is distinct from 'string' then
      raise exception 'Malformed approved workspace Board record' using errcode='22023'; end if;
  end loop;

  with items as (
    select (x->>'id')::uuid as id,(x->>'json')::jsonb as payload,
      case x->>'kind' when 'workspace_task' then 'task' else 'event' end as kind
    from jsonb_array_elements(admitted.records) x where x->>'kind' in ('workspace_task','workspace_event')
  )
  insert into public.st_v2_items(id,workspace_id,kind,title,details,due_at,completed,created_by,created_at)
    select id,p_workspace,kind,payload->>'title',payload->>'details',(payload->>'dueAt')::timestamptz,
      case kind when 'task' then (payload->>'completed')::boolean else false end,
      actor_id,(payload->>'createdAt')::timestamptz
    from items order by id on conflict(id) do nothing;
  get diagnostics wrote=row_count;
  if wrote<>task_count+event_count then
    raise exception 'An imported Board record ID already exists. No Board records were changed.' using errcode='PT409'; end if;
  insert into sectalk_private.st_v8_residency_task_imports(cell,workspace,source_project,approval,actor,task_count,event_count)
    values(admitted.cell,p_workspace,admitted.source_project,p_approval,actor_id,task_count,event_count)
    returning imported_at into admitted.imported_at;
  return jsonb_build_object('approval',p_approval,'manifestSha256',admitted.manifest_sha256,
    'taskCount',task_count,'eventCount',event_count,'importedAt',admitted.imported_at);
end $$;

create or replace function sectalk_private.st_v8_residency_compare_destination(p_workspace uuid,p_approval uuid)
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
      when 'workspace_event' then case
        when tw.imported_at is null and w.id is null then 'missing'
        when tw.imported_at is not null and tw.event_count>0
          and (w.workspace_id,w.kind,w.created_by,w.title,w.details,w.due_at,w.completed,w.created_at)
          is not distinct from (p_workspace,'event',tw.actor,e.payload->>'title',e.payload->>'details',
            (e.payload->>'dueAt')::timestamptz,false,(e.payload->>'createdAt')::timestamptz) then 'matched'
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
    left join sectalk_private.st_v8_residency_task_imports tw on e.kind in ('workspace_task','workspace_event') and
      (tw.cell,tw.workspace,tw.source_project,tw.approval)=(admitted.cell,p_workspace,admitted.source_project,p_approval)
    left join public.st_v2_items w on e.kind in ('workspace_task','workspace_event') and (w.workspace_id,w.id)=(p_workspace,e.id)
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

create or replace function sectalk_private.st_v8_residency_source_coverage(p_workspace uuid,p_approval uuid)
returns jsonb language plpgsql stable security definer set search_path='' set timezone='UTC' as $$
declare actor uuid:=auth.uid(); approval sectalk_private.st_v8_content_exports; totals jsonb; fingerprint text; pinned integer;
begin
  if p_workspace is null or p_approval is null or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false) then raise insufficient_privilege; end if;

  select * into approval from sectalk_private.st_v8_content_exports c
    where (c.workspace,c.id)=(p_workspace,p_approval) and c.approved_at is not null and c.withdrawn_at is null
      and c.expires_at>statement_timestamp() and actor in (c.requester,c.reviewer)
      and sectalk_private.st_v8_offboarding_role(c.workspace,c.requester)='owner'
      and sectalk_private.st_v8_offboarding_role(c.workspace,c.reviewer)='reviewer';
  if not found then raise insufficient_privilege; end if;

  with pinned_entries as materialized (
    select e.* from sectalk_private.st_v8_content_export_entries e where e.export_id=p_approval
  ), pinned_revisions as (
    select e.kind,e.scope_id,e.record_id, exists(
      select 1 from (
        select s.item from sectalk_private.st_v8_content_export_records(p_workspace,approval.requester,
          approval.reviewer,e.kind,e.scope_id,e.record_id) s where e.kind not in ('workspace_file','room_file')
        union all select s.item from sectalk_private.st_v8_offboarding_file_records(p_workspace,approval.requester,
          approval.reviewer,e.record_id) s where e.kind='workspace_file' and approval.include_workspace_files
        union all select s.item from sectalk_private.st_v8_offboarding_room_file_records(p_workspace,approval.requester,
          approval.reviewer,e.scope_id,e.record_id) s where e.kind='room_file' and approval.include_room_files
      ) revision where encode(sha256(convert_to(revision.item::text,'UTF8')),'hex')=e.sha256
    ) as current
    from pinned_entries e
  ), live_records as (
    (select 'workspace_task' as kind,i.workspace_id as scope_id,i.id as record_id from public.st_v2_items i
      where i.workspace_id=p_workspace and i.kind='task' limit 501)
    union all (select 'workspace_event',i.workspace_id,i.id from public.st_v2_items i
      where i.workspace_id=p_workspace and i.kind='event' limit 501)
    union all (select 'channel_message',c.id,p.id from public.st_v2_channels c join public.st_v2_posts p on p.channel_id=c.id
      where c.workspace_id=p_workspace limit 501)
    union all (select 'room_message',r.id,p.id from public.st_v6_rooms r join public.st_v6_room_posts p on p.room_id=r.id
      where r.workspace_id=p_workspace and p.removed_at is null limit 501)
    union all (select 'room_task',r.id,t.id from public.st_v6_rooms r join public.st_v6_tasks t on t.room_id=r.id
      where r.workspace_id=p_workspace limit 501)
    union all (select 'workspace_file',f.workspace,f.id from sectalk_private.st_v6_workspace_files f
      where f.workspace=p_workspace and f.deleted_at is null limit 501)
    union all (select 'room_file',f.room,f.id from sectalk_private.st_v6_room_files f
      where f.workspace=p_workspace and f.deleted_at is null limit 501)
  ), source_counts as (
    select live.kind,count(*) as observed,count(*) filter(where e.record_id is null) as unapproved
    from live_records live left join pinned_entries e using(kind,scope_id,record_id) group by live.kind
  ), pinned_counts as (
    select p.kind,count(*) as approved,count(*) filter(where p.current) as current from pinned_revisions p group by p.kind
  ), families as (
    select k.kind,coalesce(s.observed,0) as observed,coalesce(s.unapproved,0) as unapproved,
      coalesce(s.observed,0)=501 as capped,coalesce(p.approved,0) as approved,coalesce(p.current,0) as current
    from unnest(array['workspace_task','workspace_event','room_task','channel_message','room_message','workspace_file','room_file']) k(kind)
    left join source_counts s on s.kind=k.kind left join pinned_counts p on p.kind=k.kind
  )
  select (select jsonb_agg(jsonb_build_object('kind',f.kind,'observed',f.observed,'unapproved',f.unapproved,
      'capped',f.capped,'approved',f.approved,'current',f.current,'drifted',f.approved-f.current) order by f.kind) from families f),
    count(*),encode(sha256(convert_to(jsonb_build_object('format','sectalk-workspace-content-v1','workspace',p_workspace,
      'approval',p_approval,'entries',coalesce(jsonb_agg(jsonb_build_array(e.position,e.kind,e.scope_id,e.record_id,e.sha256)
      order by e.position),'[]'))::text,'UTF8')),'hex') into totals,pinned,fingerprint from pinned_entries e;

  if pinned is distinct from approval.record_count or fingerprint is distinct from approval.manifest_sha256
    then raise exception 'The approved source manifest changed' using errcode='PT409'; end if;
  return jsonb_build_object('measuredAt',statement_timestamp(),'approvedRecords',pinned,'families',totals);
end $$;

create or replace function public.st_v8_residency_source_coverage(p_workspace uuid,p_approval uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare coverage jsonb;
begin
  coverage:=sectalk_private.st_v8_residency_source_coverage(p_workspace,p_approval);

  return coverage||jsonb_build_object('unsupportedBoardItems',(
    select jsonb_agg(jsonb_build_object('kind',board.kind,'observed',board.observed,
      'capped',board.observed=501) order by board.kind)
    from (
      select kinds.kind,(select count(*) from (
        select 1 from public.st_v2_items item
        where item.workspace_id=p_workspace and item.kind=kinds.kind limit 501
      ) sample) as observed
      from unnest(array['note','announcement']) kinds(kind)
    ) board
  ));
end $$;

notify pgrst,'reload schema';
commit;
