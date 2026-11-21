begin;

create table sectalk_private.st_v8_offboarding_room_task_deletions (
  id uuid primary key default gen_random_uuid(),
  request uuid not null,
  workspace uuid not null,
  room uuid not null,
  task uuid not null,
  owner_id uuid not null,
  reviewer uuid not null check(reviewer<>owner_id),
  export_id uuid not null,
  manifest_sha256 text not null check(manifest_sha256~'^[0-9a-f]{64}$'),
  task_sha256 text not null check(task_sha256~'^[0-9a-f]{64}$'),
  key_sha256 text not null check(key_sha256~'^[0-9a-f]{64}$'),
  sha256 text not null check(sha256~'^[0-9a-f]{64}$'),
  requested_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null
);
create table sectalk_private.st_v8_offboarding_room_task_decisions (
  deletion uuid not null references sectalk_private.st_v8_offboarding_room_task_deletions(id),
  action text not null check(action in ('approved','deleted')),
  actor uuid not null,
  happened_at timestamptz not null default clock_timestamp(),
  primary key(deletion,action)
);
create table sectalk_private.st_v8_offboarding_room_task_copies (
  request uuid not null,
  export_id uuid not null,
  room uuid not null,
  task uuid not null,
  owner_id uuid not null,
  task_sha256 text not null check(task_sha256~'^[0-9a-f]{64}$'),
  source_sha256 text not null check(source_sha256~'^[0-9a-f]{64}$'),
  audit_sha256 text not null check(audit_sha256~'^[0-9a-f]{64}$'),
  issued_at timestamptz not null default clock_timestamp(),
  primary key(request,export_id,room,task)
);
-- Original audit event data remains verifiable after the live task and its foreign-key children are removed.
create table sectalk_private.st_v8_offboarding_retained_task_creation (
  deletion uuid primary key references sectalk_private.st_v8_offboarding_room_task_deletions,
  audit_id bigint not null unique,
  audit_row jsonb not null,
  sha256 text not null check(sha256=encode(sectalk_private.st_v6_audit_row_hash(audit_row),'hex')),
  check((audit_row->>'id')::bigint=audit_id)
);
create trigger st_v8_offboarding_task_creation_immutable before update or delete
  on sectalk_private.st_v8_offboarding_retained_task_creation
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_retained_task_creation enable row level security;
revoke all on sectalk_private.st_v8_offboarding_retained_task_creation from public,anon,authenticated,service_role;

create index st_v8_offboarding_room_task_lookup on sectalk_private.st_v8_offboarding_room_task_deletions(request,room,task,requested_at desc);
create trigger st_v8_offboarding_room_task_plan_immutable before update or delete on sectalk_private.st_v8_offboarding_room_task_deletions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_offboarding_room_task_decision_immutable before update or delete on sectalk_private.st_v8_offboarding_room_task_decisions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_offboarding_room_task_copy_immutable before update or delete on sectalk_private.st_v8_offboarding_room_task_copies
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_room_task_deletions enable row level security;
alter table sectalk_private.st_v8_offboarding_room_task_decisions enable row level security;
alter table sectalk_private.st_v8_offboarding_room_task_copies enable row level security;
revoke all on sectalk_private.st_v8_offboarding_room_task_deletions,sectalk_private.st_v8_offboarding_room_task_decisions,
  sectalk_private.st_v8_offboarding_room_task_copies
  from public,anon,authenticated,service_role;

-- Only source-independent open tasks with the original creation event qualify.
create function sectalk_private.st_v8_offboarding_room_task_eligible(
  p_workspace uuid,p_room uuid,p_task uuid,p_owner uuid,p_reviewer uuid
) returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from public.st_v6_tasks t
    join public.st_v6_rooms r on r.id=t.room_id
    where (r.workspace_id,r.id,t.id)=(p_workspace,p_room,p_task)
      and r.kind='public' and r.encryption_mode='standard' and r.classification in ('public','internal') and not r.archived
      and t.chat_id is null and t.status='todo'
      and sectalk_private.st_v8_standard_room_session_allowed(r.id)
      and sectalk_private.st_v6_room_role(r.id,p_owner) is not null
      and sectalk_private.st_v6_room_role(r.id,p_reviewer) is not null
      and sectalk_private.st_v6_task_audience(r.id,null,p_owner)
      and sectalk_private.st_v6_task_audience(r.id,null,p_reviewer)
      and not exists(select 1 from sectalk_private.st_v6_task_sources x where x.task_id=t.id)
      and not exists(select 1 from public.st_v6_task_people x where x.task_id=t.id)
      and not exists(select 1 from public.st_v6_task_notices x where x.task_id=t.id)
      and (select count(*) from public.st_v6_task_audit a where a.task_id=t.id)=1
      and exists(select 1 from public.st_v6_task_audit a where a.task_id=t.id and a.actor_id=t.author_id
        and a.action='created' and a.detail=jsonb_build_object('status','todo','priority',t.priority)))
$$;

create function public.st_v8_offboarding_room_task_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
begin
  return jsonb_build_object('held',sectalk_private.st_v8_offboarding_holds(p_workspace),
    'tasks',case when r.requester=auth.uid() then coalesce((select jsonb_agg(to_jsonb(q) order by q.title,q.id) from (
      select p.id,p.room_id as room,p.title,exists(select 1 from sectalk_private.st_v8_offboarding_room_task_copies a
        where (a.request,a.export_id,a.room,a.task)=(r.id,c.id,k.id,p.id)) as copied
      from sectalk_private.st_v8_content_exports c join sectalk_private.st_v8_content_export_entries e on e.export_id=c.id
      join public.st_v6_tasks p on (p.room_id,p.id)=(e.scope_id,e.record_id)
      join public.st_v6_rooms k on (k.workspace_id,k.id)=(p_workspace,p.room_id)
      where c.workspace=p_workspace and c.requester=r.requester and c.reviewer=r.reviewer and c.withdrawn_at is null
        and c.expires_at>statement_timestamp() and e.kind='room_task'
        and sectalk_private.st_v8_offboarding_room_task_eligible(p_workspace,k.id,p.id,r.requester,r.reviewer)
      order by p.title,p.id limit 500
    ) q),'[]') else '[]'::jsonb end,
    'plans',coalesce((select jsonb_agg(to_jsonb(q) order by q."requestedAt" desc,q.plan) from (
      select d.id as plan,d.room,d.task,d.sha256,d.requested_at as "requestedAt",d.expires_at as "expiresAt",
        a.happened_at as "approvedAt",x.happened_at as "deletedAt"
      from sectalk_private.st_v8_offboarding_room_task_deletions d
      left join sectalk_private.st_v8_offboarding_room_task_decisions a on (a.deletion,a.action)=(d.id,'approved')
      left join sectalk_private.st_v8_offboarding_room_task_decisions x on (x.deletion,x.action)=(d.id,'deleted')
      where d.request=r.id and d.workspace=p_workspace and (d.expires_at>statement_timestamp() or x.happened_at is not null)
      order by d.requested_at desc,d.id limit 50
    ) q),'[]'));
end $$;

create function public.st_v8_offboarding_room_task_copy(p_workspace uuid,p_room uuid,p_task uuid,p_confirmation text)
returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  entry sectalk_private.st_v8_content_export_entries; payload jsonb; source_hash text; audit_hash text;
  audit_row jsonb; source_json text; approved_json text;
begin
  if r.requester is distinct from auth.uid() or p_task is null or p_confirmation is distinct from p_workspace::text
    then raise insufficient_privilege; end if;
  select e.* into entry from sectalk_private.st_v8_content_export_entries e
    join sectalk_private.st_v8_content_exports c on c.id=e.export_id
    where c.workspace=p_workspace and c.requester=r.requester and c.reviewer=r.reviewer and c.withdrawn_at is null
      and c.expires_at>statement_timestamp() and (e.scope_id,e.record_id,e.kind)=(p_room,p_task,'room_task') for share of c;
  if entry.export_id is null or not sectalk_private.st_v8_offboarding_room_task_eligible(p_workspace,p_room,p_task,r.requester,r.reviewer)
    then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_offboarding_room_task_copy',20);
  select to_jsonb(a),encode(sectalk_private.st_v6_audit_row_hash(to_jsonb(a)),'hex') into audit_row,audit_hash
    from public.st_v6_task_audit a where a.task_id=p_task and a.action='created';
  if audit_hash is null then raise insufficient_privilege; end if;
  select s.item::text,to_jsonb(p)::text into approved_json,source_json
  from sectalk_private.st_v8_content_export_records(p_workspace,r.requester,r.reviewer,'room_task',p_room,p_task) s
  join public.st_v6_tasks p on (p.room_id,p.id)=(s.scope_id,s.record_id)
  where encode(sha256(convert_to(s.item::text,'UTF8')),'hex')=entry.sha256;
  if source_json is null then raise insufficient_privilege; end if;
  source_hash:=encode(sha256(convert_to(source_json,'UTF8')),'hex');
  payload:=jsonb_build_object('format','sectalk-offboarding-room-task-copy-v1','scope',p_room,'id',p_task,
    'approval',entry.export_id,'sha256',entry.sha256,'json',approved_json,'sourceJson',source_json,'sourceSha256',source_hash,
    'creationAuditJson',audit_row::text,'creationAuditSha256',audit_hash);
  insert into sectalk_private.st_v8_offboarding_room_task_copies(request,export_id,room,task,owner_id,task_sha256,source_sha256,audit_sha256)
    values(r.id,entry.export_id,p_room,p_task,r.requester,entry.sha256,source_hash,audit_hash) on conflict do nothing;
  return payload;
end $$;

create function public.st_v8_offboarding_room_task_delete(p_workspace uuid,p_room uuid,p_task uuid,p_action text,
  p_confirmation text,p_plan uuid default null,p_sha256 text default null)
returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  actor uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_room_task_deletions; c sectalk_private.st_v8_content_exports;
  item public.st_v6_tasks; current_task_hash text; approved_task_hash text; current_key_hash text;
  source_hash text; fingerprint text; creation public.st_v6_task_audit; audit_hash text; inventory_until timestamptz; approved_at timestamptz; deleted_at timestamptz;
begin
  if p_workspace is null or p_room is null or p_task is null or p_action is null or p_action not in ('capture','approve','delete')
    or p_confirmation is distinct from p_workspace::text
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
    or not coalesce(sectalk_private.st_v8_planner_sso_allows(p_workspace),false) then raise insufficient_privilege; end if;
  -- Use the established key-before-hold lock order. Native hold and custody changes use these same locks.
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
  select x.* into r from sectalk_private.st_v8_offboarding_requests x
    where x.workspace=p_workspace and x.state='read_only' and x.integration_shutdown is not null for update;
  if r.id is null or actor is distinct from (case when p_action='approve' then r.reviewer else r.requester end)
    then raise insufficient_privilege; end if;
  perform 1 from sectalk_private.st_v8_offboarding_reviewers q where (q.workspace,q.actor)=(p_workspace,r.reviewer) for share;
  if not found then raise insufficient_privilege; end if;
  perform 1 from public.st_v2_members m where m.workspace_id=p_workspace and m.user_id in (r.requester,r.reviewer)
    order by m.user_id for share;
  if sectalk_private.st_v8_offboarding_role(p_workspace,r.requester) is distinct from 'owner'
    or sectalk_private.st_v8_offboarding_role(p_workspace,r.reviewer) is distinct from 'reviewer'
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_offboarding_room_task_delete',12);

  if p_action<>'capture' then
    select d.* into plan from sectalk_private.st_v8_offboarding_room_task_deletions d
      where (d.id,d.request,d.workspace,d.room,d.task,d.sha256)=(p_plan,r.id,p_workspace,p_room,p_task,p_sha256);
    if plan.id is null then raise exception 'Confirm the exact room task deletion plan and digest' using errcode='PT409'; end if;
    select d.happened_at into approved_at from sectalk_private.st_v8_offboarding_room_task_decisions d
      where d.deletion=plan.id and d.action='approved' and d.actor=r.reviewer;
    select d.happened_at into deleted_at from sectalk_private.st_v8_offboarding_room_task_decisions d
      where d.deletion=plan.id and d.action='deleted' and d.actor=r.requester;
    if deleted_at is not null then
      return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'approvedAt',approved_at,'deletedAt',deleted_at);
    end if;
  end if;

  -- Keep current approved access to the staged inventory and do not cut across other preservation work.
  select q.expires_at into inventory_until from sectalk_private.st_v7_compliance_cases q
    where q.id=r.case_id and q.workspace_id=p_workspace and q.requester=r.requester and q.reviewer=r.reviewer
      and q.state='approved' and q.expires_at>clock_timestamp() and q.manifest_sha256~'^[0-9a-f]{64}$'
      and q.ticket is null for share;
  if inventory_until is null or not exists(select 1 from sectalk_private.st_v7_compliance_audit a
      where (a.case_id,a.workspace_id,a.actor,a.action)=(r.case_id,p_workspace,r.requester,'downloaded'))
    or exists(select 1 from sectalk_private.st_v7_compliance_cases q where q.workspace_id=p_workspace
      and q.id<>r.case_id and q.state in ('pending','approved') and q.expires_at>clock_timestamp())
    or exists(select 1 from sectalk_private.st_v7_evidence_operations o join sectalk_private.st_v7_compliance_cases q on q.id=o.case_id
      where q.workspace_id=p_workspace and o.expires_at>clock_timestamp()) then
    raise exception 'Live inventory and clear evidence retention are required' using errcode='PT409'; end if;

  select x.* into c from sectalk_private.st_v8_content_exports x
    where x.workspace=p_workspace and x.requester=r.requester and x.reviewer=r.reviewer
      and x.withdrawn_at is null and x.approved_at is not null and x.expires_at>clock_timestamp()
      and x.manifest_sha256~'^[0-9a-f]{64}$' for share;
  if c.id is null then raise exception 'A current separate content approval is required' using errcode='PT409'; end if;
  select e.sha256 into approved_task_hash from sectalk_private.st_v8_content_export_entries e
    where (e.export_id,e.kind,e.scope_id,e.record_id)=(c.id,'room_task',p_room,p_task);

  -- Retry a busy source while holding workspace preservation locks.
  perform 1 from public.st_v6_rooms where (workspace_id,id)=(p_workspace,p_room) for no key update nowait;
  if not found then raise insufficient_privilege; end if;
  select i.* into item from public.st_v6_tasks i where (i.room_id,i.id)=(p_room,p_task) for update nowait;
  if item.id is null or approved_task_hash is null
    or not sectalk_private.st_v8_offboarding_room_task_eligible(p_workspace,p_room,p_task,r.requester,r.reviewer)
    then raise exception 'Only exact approved standard public room tasks without evidence or dependencies are eligible'
      using errcode='PT409'; end if;
  select a.* into creation from public.st_v6_task_audit a where a.task_id=p_task and a.action='created' for update nowait;
  if creation.id is null then raise insufficient_privilege; end if;
  audit_hash:=encode(sectalk_private.st_v6_audit_row_hash(to_jsonb(creation)),'hex');
  if not exists(select 1 from sectalk_private.st_v6_audit_chain a
      where (a.source,a.source_id,a.operation)=('public.st_v6_task_audit',creation.id,'INSERT') and encode(a.row_hash,'hex')=audit_hash)
    or exists(select 1 from sectalk_private.st_v6_audit_chain a
      where (a.source,a.source_id)=('public.st_v6_task_audit',creation.id) and a.operation<>'INSERT')
    then raise exception 'The original task creation event no longer matches audit custody' using errcode='PT409'; end if;
  source_hash:=encode(sha256(convert_to(to_jsonb(item)::text,'UTF8')),'hex');
  if not exists(select 1 from sectalk_private.st_v8_offboarding_room_task_copies x
    where (x.request,x.export_id,x.room,x.task,x.owner_id,x.task_sha256)=(r.id,c.id,p_room,item.id,r.requester,approved_task_hash)
      and x.source_sha256=source_hash and x.audit_sha256=audit_hash) then
    raise exception 'Download the exact approved room task copy before creating its deletion plan' using errcode='PT409'; end if;
  select encode(sha256(convert_to(s.item::text,'UTF8')),'hex') into current_task_hash
    from sectalk_private.st_v8_content_export_records(p_workspace,r.requester,r.reviewer,'room_task',p_room,p_task) s;
  if current_task_hash is distinct from approved_task_hash then
    raise exception 'The room task or its approved source access changed' using errcode='PT409'; end if;

  select encode(sha256(convert_to(jsonb_build_array(s.current_version,
    coalesce((select jsonb_agg(jsonb_build_array(k.version,k.custody,k.provider_ref,k.wrapped) order by k.version)
      from sectalk_private.st_v7_tenant_key_versions k where k.workspace=s.workspace),'[]'))::text,'UTF8')),'hex')
    into current_key_hash from sectalk_private.st_v7_tenant_key_state s where s.workspace=p_workspace and s.destroyed_at is null
      and exists(select 1 from sectalk_private.st_v7_tenant_key_versions k where (k.workspace,k.version)=(s.workspace,s.current_version));
  if current_key_hash is null
    or exists(select 1 from sectalk_private.st_v7_tenant_key_destroy k where k.workspace=p_workspace and k.result is null)
    or exists(select 1 from sectalk_private.st_v7_tenant_rotation_tickets k where k.workspace=p_workspace and k.expires_at>clock_timestamp())
    then raise exception 'A live stable custody state is required to preserve recoverability' using errcode='PT409'; end if;

  fingerprint:=encode(sha256(convert_to(jsonb_build_array('sectalk-offboarding-standard-room-task-v1',p_workspace,r.id,
    r.snapshot_sha256,c.id,c.manifest_sha256,p_room,p_task,approved_task_hash,
    source_hash,audit_hash,current_key_hash)::text,'UTF8')),'hex');
  if p_action='capture' then
    select d.* into plan from sectalk_private.st_v8_offboarding_room_task_deletions d where d.request=r.id and d.room=p_room and d.task=p_task
      and d.sha256=fingerprint and d.expires_at>clock_timestamp() order by d.requested_at desc,d.id desc limit 1;
    if plan.id is null then
      insert into sectalk_private.st_v8_offboarding_room_task_deletions(request,workspace,room,task,owner_id,reviewer,export_id,
        manifest_sha256,task_sha256,key_sha256,sha256,expires_at)
        values(r.id,p_workspace,p_room,p_task,r.requester,r.reviewer,c.id,c.manifest_sha256,approved_task_hash,current_key_hash,
          fingerprint,least(inventory_until,c.expires_at)) returning * into plan;
    end if;
  elsif plan.sha256 is distinct from fingerprint or plan.expires_at<=clock_timestamp() then
    raise exception 'The approved source or custody changed, or the approval expired' using errcode='PT409';
  elsif p_action='approve' then
    if approved_at is null then
      insert into sectalk_private.st_v8_offboarding_room_task_decisions(deletion,action,actor)
        values(plan.id,'approved',actor) returning happened_at into approved_at;
    end if;
  else
    if approved_at is null then raise insufficient_privilege; end if;
    -- Leave triggers active and wait for an in-flight search refresh before removing source and indexed text.
    loop
      insert into sectalk_private.st_v7_search_pending(kind,object_id) values('task',p_task) on conflict do nothing;
      perform 1 from sectalk_private.st_v7_search_pending where kind='task' and object_id=p_task for update;
      exit when found;
    end loop;
    if not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
      or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
      or not coalesce(sectalk_private.st_v8_planner_sso_allows(p_workspace),false)
      or sectalk_private.st_v8_offboarding_role(p_workspace,r.requester) is distinct from 'owner'
      or sectalk_private.st_v8_offboarding_role(p_workspace,r.reviewer) is distinct from 'reviewer'
      or not sectalk_private.st_v8_offboarding_room_task_eligible(p_workspace,p_room,p_task,r.requester,r.reviewer)
      or least(inventory_until,c.expires_at,plan.expires_at)<=clock_timestamp() then raise insufficient_privilege; end if;
    perform 1 from auth.sessions n
      join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
      join auth.mfa_amr_claims proof on proof.session_id=n.id and proof.authentication_method='totp'
      where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',actor) and n.aal='aal2'
        and f.status='verified' and f.factor_type='totp' and proof.updated_at>clock_timestamp()-interval '5 minutes'
        and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp()
      for share of n,f,proof;
    if not found then raise insufficient_privilege; end if;
    insert into sectalk_private.st_v8_offboarding_retained_task_creation(deletion,audit_id,audit_row,sha256)
      values(plan.id,creation.id,to_jsonb(creation),audit_hash);
    -- Allow the existing FK cascade and audit-chain capture to journal the removal.
    delete from public.st_v6_tasks i where (i.room_id,i.id)=(p_room,p_task) and i.chat_id is null;
    if not found then raise exception 'The scoped room task could not be removed' using errcode='PT409'; end if;
    delete from sectalk_private.st_v7_search_document d where (d.kind,d.object_id)=('task',p_task);
    insert into sectalk_private.st_v8_offboarding_room_task_decisions(deletion,action,actor)
      values(plan.id,'deleted',actor) returning happened_at into deleted_at;
  end if;
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'approvedAt',approved_at,'deletedAt',deleted_at);
end $$;

revoke all on function sectalk_private.st_v8_offboarding_room_task_eligible(uuid,uuid,uuid,uuid,uuid),public.st_v8_offboarding_room_task_status(uuid),
  public.st_v8_offboarding_room_task_copy(uuid,uuid,uuid,text),public.st_v8_offboarding_room_task_delete(uuid,uuid,uuid,text,text,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_room_task_status(uuid),public.st_v8_offboarding_room_task_copy(uuid,uuid,uuid,text),
  public.st_v8_offboarding_room_task_delete(uuid,uuid,uuid,text,text,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
