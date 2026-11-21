begin;

create or replace function public.st_v8_residency_task_import(p_workspace uuid, p_approval uuid default null,
  p_confirmation text default null)
returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' as $$
declare actor_id uuid:=auth.uid(); admitted record; saved record; task_count integer; wrote integer; fingerprint text;
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
  select count(*) into task_count from jsonb_array_elements(admitted.records) x
    where x->>'kind'='workspace_task';
  if p_approval is null or admitted.imported_at is not null then
    return jsonb_build_object('approval',admitted.approval,'manifestSha256',admitted.manifest_sha256,
      'taskCount',task_count,'importedAt',admitted.imported_at);
  end if;
  if task_count=0 then raise exception 'This manifest contains no workspace tasks' using errcode='PT409'; end if;
  perform sectalk_private.st_v7_require_workspace_write(p_workspace);

  select encode(sha256(convert_to(jsonb_build_object('format','sectalk-workspace-content-v1',
    'workspace',p_workspace,'approval',p_approval,'entries',jsonb_agg(jsonb_build_array(
      position,entry->>'kind',entry->>'scope',entry->>'id',entry->>'sha256') order by position))::text,'UTF8')),'hex')
    into fingerprint from jsonb_array_elements(admitted.records) with ordinality as items(entry,position);
  if fingerprint is distinct from admitted.manifest_sha256 or jsonb_array_length(admitted.records)<>admitted.record_count then
    raise exception 'The approved destination manifest changed' using errcode='PT409'; end if;

  for saved in select (x->>'id')::uuid as id,(x->>'scope')::uuid as scope,(x->>'json')::jsonb as payload,
      x->>'sha256' as digest,x->>'json' as content
    from jsonb_array_elements(admitted.records) x where x->>'kind'='workspace_task'
  loop
    if saved.scope is distinct from p_workspace or saved.payload->>'task' is distinct from saved.id::text
      or encode(sha256(convert_to(saved.content,'UTF8')),'hex') is distinct from saved.digest
      or jsonb_typeof(saved.payload->'title') is distinct from 'string'
      or jsonb_typeof(saved.payload->'details') is distinct from 'string'
      or jsonb_typeof(saved.payload->'completed') is distinct from 'boolean'
      or jsonb_typeof(saved.payload->'createdAt') is distinct from 'string' then
      raise exception 'Malformed approved workspace task' using errcode='22023'; end if;
  end loop;

  with tasks as (
    select (x->>'id')::uuid as id,(x->>'json')::jsonb as payload from jsonb_array_elements(admitted.records) x
    where x->>'kind'='workspace_task'
  )
  insert into public.st_v2_items(id,workspace_id,kind,title,details,due_at,completed,created_by,created_at)
    select id,p_workspace,'task',payload->>'title',payload->>'details',(payload->>'dueAt')::timestamptz,
      (payload->>'completed')::boolean,actor_id,(payload->>'createdAt')::timestamptz
    from tasks order by id on conflict(id) do nothing;
  get diagnostics wrote=row_count;
  if wrote<>task_count then
    raise exception 'An imported task ID already exists. No tasks were changed.' using errcode='PT409'; end if;
  insert into sectalk_private.st_v8_residency_task_imports(cell,workspace,source_project,approval,actor,task_count)
    values(admitted.cell,p_workspace,admitted.source_project,p_approval,actor_id,task_count)
    returning imported_at into admitted.imported_at;
  return jsonb_build_object('approval',p_approval,'manifestSha256',admitted.manifest_sha256,
    'taskCount',task_count,'importedAt',admitted.imported_at);
end $$;

revoke all on function public.st_v8_residency_task_import(uuid,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_task_import(uuid,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
