begin;

create table sectalk_private.st_v8_residency_room_task_imports (
  cell uuid not null,
  workspace uuid not null,
  source_project text not null,
  approval uuid not null,
  room uuid not null,
  actor uuid not null,
  task_count integer not null check(task_count between 1 and 500),
  imported_at timestamptz not null default clock_timestamp(),
  primary key(cell,workspace,source_project,approval,room),
  foreign key(cell,workspace,source_project,approval,room)
    references sectalk_private.st_v8_residency_room_imports on delete cascade
);
alter table sectalk_private.st_v8_residency_room_task_imports enable row level security;
revoke all on sectalk_private.st_v8_residency_room_task_imports from public,anon,authenticated,service_role;

create function public.st_v8_residency_room_task_import(p_workspace uuid,p_approval uuid default null,
  p_room uuid default null,p_confirmation text default null)
returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' as $$
declare actor_id uuid:=auth.uid(); admitted record; receipt sectalk_private.st_v8_residency_room_task_imports;
  fingerprint text; room_name text; options jsonb; saved record; payload jsonb; labels text[];
  count_tasks integer; inserted integer;
begin
  if p_workspace is null or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or (p_approval is null)<>(p_room is null) then raise insufficient_privilege; end if;
  if p_room is not null then
    if p_confirmation is distinct from p_workspace::text or sectalk_private.st_v7_admin_fresh() is not true
      then raise insufficient_privilege; end if;
    perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
    if not found then raise insufficient_privilege; end if;
  end if;
  if sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'owner'
    or sectalk_private.st_v8_organization_sso_allows(p_workspace) is not true
    or sectalk_private.st_v8_planner_sso_allows(p_workspace) is not true then raise insufficient_privilege; end if;
  select c.cell,c.source_project,c.approval,c.manifest_sha256,least(c.expires_at,a.expires_at) expires_at,s.records
    into admitted from sectalk_private.st_v8_residency_workspace_claims c
    join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
    join sectalk_private.st_v8_residency_cells t on t.id=c.cell and t.retired_at is null and t.project_reference<>c.source_project
    join sectalk_private.st_v8_residency_content_admissions a on (a.cell,a.workspace,a.source_project,a.approval)=
      (c.cell,c.workspace,c.source_project,c.approval)
    join sectalk_private.st_v8_residency_staged_content s on (s.cell,s.workspace,s.source_project,s.approval)=
      (c.cell,c.workspace,c.source_project,c.approval)
    where (c.workspace,c.owner_id)=(p_workspace,actor_id) and c.claimed_at is not null
      and c.manifest_sha256=a.manifest_sha256 and (p_approval is null or c.approval=p_approval)
    for share of c,i,t,a,s;
  if not found then
    if p_room is not null then raise insufficient_privilege; end if;
    return null;
  end if;

  if p_room is null then
    select coalesce(jsonb_agg(jsonb_build_object('id',r.id,'name',r.name,'taskCount',tasks.total,
      'importedAt',done.imported_at) order by r.name,r.id),'[]'::jsonb) into options
    from sectalk_private.st_v8_residency_room_imports j
    join public.st_v6_rooms r on (r.id,r.workspace_id)=(j.room,j.workspace)
    left join sectalk_private.st_v8_residency_room_task_imports done
      on (done.cell,done.workspace,done.source_project,done.approval,done.room)=(j.cell,j.workspace,j.source_project,j.approval,j.room)
    cross join lateral (select count(*)::integer as total from jsonb_array_elements(admitted.records) x
      where (x->>'kind',x->>'scope')=('room_task',r.id::text)) tasks
    where (j.cell,j.workspace,j.source_project,j.approval,j.actor)=(admitted.cell,p_workspace,admitted.source_project,admitted.approval,actor_id)
      and (r.kind,r.classification,r.encryption_mode,r.creator)=('private','confidential','standard',actor_id)
      and not r.archived and not r.locked and tasks.total>0
      and sectalk_private.st_v6_room_role(r.id,actor_id)='owner'
      and (admitted.expires_at>statement_timestamp() or done.imported_at is not null);
    return jsonb_build_object('approval',admitted.approval,'manifestSha256',admitted.manifest_sha256,'rooms',options);
  end if;

  select r.name into room_name
    from sectalk_private.st_v8_residency_room_imports j
    join public.st_v6_rooms r on (r.id,r.workspace_id)=(j.room,j.workspace)
    where (j.cell,j.workspace,j.source_project,j.approval,j.room,j.actor)=
      (admitted.cell,p_workspace,admitted.source_project,p_approval,p_room,actor_id)
      and (r.kind,r.classification,r.encryption_mode,r.creator)=('private','confidential','standard',actor_id)
      and not r.archived and not r.locked for share of j,r;
  if not found or sectalk_private.st_v6_room_role(p_room,actor_id) is distinct from 'owner'
    or not sectalk_private.st_v6_task_scope_write(p_room,null) then raise insufficient_privilege; end if;
  select * into receipt from sectalk_private.st_v8_residency_room_task_imports j
    where (j.cell,j.workspace,j.source_project,j.approval,j.room)=
      (admitted.cell,p_workspace,admitted.source_project,p_approval,p_room);
  if found then return jsonb_build_object('room',receipt.room,'name',room_name,'taskCount',receipt.task_count,'importedAt',receipt.imported_at); end if;

  if admitted.expires_at<=statement_timestamp() or sectalk_private.st_v8_offboarding_holds(p_workspace)
    then raise insufficient_privilege; end if;
  perform sectalk_private.st_v7_require_workspace_write(p_workspace);
  select encode(sha256(convert_to(jsonb_build_object('format','sectalk-workspace-content-v1','workspace',p_workspace,
    'approval',p_approval,'entries',jsonb_agg(jsonb_build_array(position,x->>'kind',x->>'scope',x->>'id',x->>'sha256')
      order by position))::text,'UTF8')),'hex') into fingerprint
  from jsonb_array_elements(admitted.records) with ordinality as item(x,position);
  if fingerprint is distinct from admitted.manifest_sha256 then
    raise exception 'The approved destination manifest changed' using errcode='PT409'; end if;

  count_tasks:=0;
  for saved in select x->>'id' id,x->>'json' raw,x->>'sha256' sha from jsonb_array_elements(admitted.records) x
    where (x->>'kind',x->>'scope')=('room_task',p_room::text) order by x->>'id'
  loop
    payload:=saved.raw::jsonb;
    if encode(sha256(convert_to(saved.raw,'UTF8')),'hex') is distinct from saved.sha
      or not coalesce(jsonb_typeof(payload)='object' and
        payload ?& array['room','task','title','status','priority','labels','dueAt','createdAt','updatedAt']
        and payload-array['room','task','title','status','priority','labels','dueAt','createdAt','updatedAt']='{}'::jsonb
        and (payload->>'room',payload->>'task')=(p_room::text,saved.id)
        and jsonb_typeof(payload->'title')='string' and char_length(payload->>'title') between 1 and 120
        and payload->>'status' in ('todo','in_progress','blocked','done','cancelled')
        and payload->>'priority' in ('low','normal','high','urgent')
        and jsonb_typeof(payload->'labels')='array' and jsonb_typeof(payload->'dueAt') in ('string','null')
        and jsonb_typeof(payload->'createdAt')='string' and jsonb_typeof(payload->'updatedAt')='string',false)
      then raise exception 'Malformed approved room task' using errcode='22023'; end if;
    if exists(select 1 from jsonb_array_elements(payload->'labels') item where jsonb_typeof(item) not in ('string'))
      then raise exception 'Malformed approved room task labels' using errcode='22023'; end if;
    labels:=array(select item from jsonb_array_elements_text(payload->'labels') item);
    if labels is distinct from sectalk_private.st_v6_task_labels(labels) then
      raise exception 'Malformed approved room task labels' using errcode='22023'; end if;
    insert into public.st_v6_tasks(id,room_id,author_id,title,status,priority,labels,due_at,created_at,updated_at)
      values(saved.id::uuid,p_room,actor_id,payload->>'title',payload->>'status',payload->>'priority',labels,
        (payload->>'dueAt')::timestamptz,(payload->>'createdAt')::timestamptz,(payload->>'updatedAt')::timestamptz)
      on conflict(id) do nothing;
    get diagnostics inserted=row_count;
    if inserted<>1 then raise exception 'An approved room task ID is already in use. No tasks were changed.' using errcode='PT409'; end if;
    insert into public.st_v6_task_audit(task_id,actor_id,action,detail)
      values(saved.id::uuid,actor_id,'residency_restored',jsonb_build_object('approval',p_approval,'sourceRecordSha256',saved.sha));
    count_tasks:=count_tasks+1;
  end loop;
  if count_tasks=0 then raise exception 'There are no approved tasks for this room' using errcode='PT409'; end if;
  insert into sectalk_private.st_v8_residency_room_task_imports(cell,workspace,source_project,approval,room,actor,task_count)
    values(admitted.cell,p_workspace,admitted.source_project,p_approval,p_room,actor_id,count_tasks)
    returning * into receipt;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor_id,'room.tasks_residency_imported',p_room);
  return jsonb_build_object('room',receipt.room,'name',room_name,'taskCount',receipt.task_count,'importedAt',receipt.imported_at);
end $$;

revoke all on function public.st_v8_residency_room_task_import(uuid,uuid,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_room_task_import(uuid,uuid,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
