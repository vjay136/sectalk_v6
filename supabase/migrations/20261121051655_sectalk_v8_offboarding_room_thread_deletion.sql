begin;

create table sectalk_private.st_v8_offboarding_room_thread_deletions (
  id uuid primary key default gen_random_uuid(),
  request uuid not null,
  workspace uuid not null,
  room uuid not null,
  root uuid not null,
  owner_id uuid not null,
  reviewer uuid not null check(reviewer<>owner_id),
  export_id uuid not null,
  manifest_sha256 text not null check(manifest_sha256~'^[0-9a-f]{64}$'),
  thread_sha256 text not null check(thread_sha256~'^[0-9a-f]{64}$'),
  manifest jsonb not null check(jsonb_typeof(manifest)='array'),
  message_count integer not null check(message_count between 2 and 16),
  key_sha256 text not null check(key_sha256~'^[0-9a-f]{64}$'),
  sha256 text not null check(sha256~'^[0-9a-f]{64}$'),
  requested_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  check(message_count=jsonb_array_length(manifest))
);
create table sectalk_private.st_v8_offboarding_room_thread_decisions (
  deletion uuid not null references sectalk_private.st_v8_offboarding_room_thread_deletions(id),
  action text not null check(action in ('approved','deleted')),
  actor uuid not null,
  happened_at timestamptz not null default clock_timestamp(),
  primary key(deletion,action)
);
create table sectalk_private.st_v8_offboarding_room_thread_copies (
  request uuid not null,
  export_id uuid not null,
  room uuid not null,
  root uuid not null,
  owner_id uuid not null,
  thread_sha256 text not null check(thread_sha256~'^[0-9a-f]{64}$'),
  issued_at timestamptz not null default clock_timestamp(),
  primary key(request,export_id,room,root)
);
create index st_v8_offboarding_room_thread_lookup on sectalk_private.st_v8_offboarding_room_thread_deletions(request,room,root,requested_at desc);
create trigger st_v8_offboarding_room_thread_plan_immutable before update or delete on sectalk_private.st_v8_offboarding_room_thread_deletions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_offboarding_room_thread_decision_immutable before update or delete on sectalk_private.st_v8_offboarding_room_thread_decisions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_offboarding_room_thread_copy_immutable before update or delete on sectalk_private.st_v8_offboarding_room_thread_copies
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_room_thread_deletions enable row level security;
alter table sectalk_private.st_v8_offboarding_room_thread_decisions enable row level security;
alter table sectalk_private.st_v8_offboarding_room_thread_copies enable row level security;
revoke all on sectalk_private.st_v8_offboarding_room_thread_deletions,sectalk_private.st_v8_offboarding_room_thread_decisions,
  sectalk_private.st_v8_offboarding_room_thread_copies
  from public,anon,authenticated,service_role;

-- Only the complete live root/reply set qualifies. Unrelated FK dependents stay protected.
create function sectalk_private.st_v8_offboarding_room_thread_source(
  p_workspace uuid,p_room uuid,p_root uuid,p_owner uuid,p_reviewer uuid,p_export uuid
) returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  with selected as materialized (
    select p.* from public.st_v6_room_posts p
    where p.room_id=p_room and (p.id=p_root or p.parent_id=p_root)
    order by p.id limit 17
  ), allowed as materialized (
    select p.id,p.parent_id,
      approved.sha256 as export_sha,raw.source_sha,s.item::text as item
    from selected p
    cross join lateral (select encode(sha256(convert_to(to_jsonb(p)::text,'UTF8')),'hex') as source_sha) raw
    join sectalk_private.st_v8_content_export_entries approved
      on (approved.export_id,approved.kind,approved.scope_id,approved.record_id)=(p_export,'room_message',p_room,p.id)
    cross join lateral sectalk_private.st_v8_content_export_records(p_workspace,p_owner,p_reviewer,'room_message',p_room,p.id) s
    where p.kind='message' and not p.forwarded and p.removed_at is null and p.edited_at is null
      and (p.sender=p_owner or sectalk_private.open_pair(p.sender,p_owner))
      and (p.sender=p_reviewer or sectalk_private.open_pair(p.sender,p_reviewer))
      and approved.sha256=encode(sha256(convert_to(s.item::text,'UTF8')),'hex')
      -- The shared search document currently uses only the post ID.
      and not exists(select 1 from public.st_v6_room_posts other where other.id=p.id and other.room_id<>p.room_id)
      and (p.parent_id is null or not exists(select 1 from public.st_v6_room_posts nested
        where (nested.room_id,nested.parent_id)=(p.room_id,p.id)))
      and not exists(select 1 from public.st_v6_room_pins pin where (pin.room_id,pin.post_id)=(p.room_id,p.id))
      and not exists(select 1 from public.st_v6_thread_follows f where (f.room_id,f.post_id)=(p.room_id,p.id))
      and not exists(select 1 from sectalk_private.st_v6_room_reactions x where (x.room_id,x.post_id)=(p.room_id,p.id))
      and not exists(select 1 from sectalk_private.room_read_receipts x where (x.room_id,x.post_id)=(p.room_id,p.id))
      and not exists(select 1 from public.st_v3_notifications n where (n.room_id,n.room_post_id)=(p.room_id,p.id))
      and not exists(select 1 from sectalk_private.st_v6_admin_notification_runs x where (x.room_id,x.post_id)=(p.room_id,p.id))
      and not exists(select 1 from sectalk_private.st_v6_thread_summary_consent x where (x.room,x.root)=(p.room_id,p.id))
      and not exists(select 1 from public.st_v6_room_audit x where (x.room_id,x.target)=(p.room_id,p.id))
      and not exists(select 1 from sectalk_private.st_v6_task_sources x join public.st_v6_tasks t on t.id=x.task_id
        where (t.room_id,x.message_id)=(p.room_id,p.id))
      and not exists(select 1 from sectalk_private.st_v6_room_reports x where (x.room_id,x.post_id)=(p.room_id,p.id))
      and not exists(select 1 from sectalk_private.st_v8_managed_room_posts x where (x.room,x.id)=(p.room_id,p.id))
      and not exists(select 1 from sectalk_private.st_v6_preserved_post_versions v
        where (v.source,v.scope_id,v.post_id)=('room',p.room_id,p.id))
      and not exists(select 1 from sectalk_private.st_v7_dlp_delivery_receipts d
        where (d.scope_type,d.scope_id,d.message_id)=('room',p.room_id,p.id))
  )
  select jsonb_build_object('manifest',jsonb_agg(jsonb_build_object('id',a.id,'parent',a.parent_id,
      'sha256',a.export_sha,'sourceSha256',a.source_sha) order by a.parent_id nulls first,a.id),
    'records',jsonb_agg(jsonb_build_object('id',a.id,'sha256',a.export_sha,'json',a.item)
      order by a.parent_id nulls first,a.id))
  from allowed a
  having count(*) between 2 and 16 and count(*)=(select count(*) from selected)
    and count(*) filter(where a.id=p_root and a.parent_id is null)=1
    and exists(select 1 from public.st_v6_rooms r where (r.workspace_id,r.id)=(p_workspace,p_room)
      and r.kind='public' and r.encryption_mode='standard' and r.classification in ('public','internal') and not r.archived)
    and sectalk_private.st_v8_standard_room_session_allowed(p_room)
    and sectalk_private.st_v6_room_role(p_room,p_owner) is not null
    and sectalk_private.st_v6_room_role(p_room,p_reviewer) is not null;
$$;

create function public.st_v8_offboarding_room_thread_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
begin
  return jsonb_build_object('held',sectalk_private.st_v8_offboarding_holds(p_workspace),
    'threads',case when r.requester=auth.uid() then coalesce((select jsonb_agg(to_jsonb(q) order by q.name,q.id) from (
      select p.id,p.room_id as room,k.name,jsonb_array_length(content.item->'manifest') as "messageCount",
        exists(select 1 from sectalk_private.st_v8_offboarding_room_thread_copies a
          where (a.request,a.export_id,a.room,a.root)=(r.id,c.id,k.id,p.id)
            and a.thread_sha256=encode(sha256(convert_to((content.item->'manifest')::text,'UTF8')),'hex')) as copied
      from sectalk_private.st_v8_content_exports c join sectalk_private.st_v8_content_export_entries e on e.export_id=c.id
      join public.st_v6_room_posts p on (p.room_id,p.id)=(e.scope_id,e.record_id) and p.parent_id is null
      join public.st_v6_rooms k on (k.workspace_id,k.id)=(p_workspace,p.room_id)
      cross join lateral (select sectalk_private.st_v8_offboarding_room_thread_source(
        p_workspace,k.id,p.id,r.requester,r.reviewer,c.id) as item offset 0) content
      where c.workspace=p_workspace and c.requester=r.requester and c.reviewer=r.reviewer and c.withdrawn_at is null
        and c.expires_at>statement_timestamp() and e.kind='room_message' and content.item is not null
      order by k.name,p.id limit 100
    ) q),'[]') else '[]'::jsonb end,
    'plans',coalesce((select jsonb_agg(to_jsonb(q) order by q."requestedAt" desc,q.plan) from (
      select d.id as plan,d.room,d.root,d.sha256,d.manifest,d.message_count as "messageCount",
        d.requested_at as "requestedAt",d.expires_at as "expiresAt",
        a.happened_at as "approvedAt",x.happened_at as "deletedAt"
      from sectalk_private.st_v8_offboarding_room_thread_deletions d
      left join sectalk_private.st_v8_offboarding_room_thread_decisions a on (a.deletion,a.action)=(d.id,'approved')
      left join sectalk_private.st_v8_offboarding_room_thread_decisions x on (x.deletion,x.action)=(d.id,'deleted')
      where d.request=r.id and d.workspace=p_workspace and (d.expires_at>statement_timestamp() or x.happened_at is not null)
      order by d.requested_at desc,d.id limit 50
    ) q),'[]'));
end $$;

create function public.st_v8_offboarding_room_thread_copy(p_workspace uuid,p_room uuid,p_root uuid,p_confirmation text)
returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  approval uuid; thread jsonb; thread_hash text;
begin
  if r.requester is distinct from auth.uid() or p_room is null or p_root is null
    or p_confirmation is distinct from p_workspace::text then raise insufficient_privilege; end if;
  select c.id into approval from sectalk_private.st_v8_content_exports c
    where c.workspace=p_workspace and c.requester=r.requester and c.reviewer=r.reviewer and c.withdrawn_at is null
      and c.approved_at is not null and c.expires_at>statement_timestamp() for share;
  if approval is null then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_offboarding_room_thread_copy',10);
  thread:=sectalk_private.st_v8_offboarding_room_thread_source(p_workspace,p_room,p_root,r.requester,r.reviewer,approval);
  if thread is null then raise insufficient_privilege; end if;
  thread_hash:=encode(sha256(convert_to((thread->'manifest')::text,'UTF8')),'hex');
  insert into sectalk_private.st_v8_offboarding_room_thread_copies(request,export_id,room,root,owner_id,thread_sha256)
    values(r.id,approval,p_room,p_root,r.requester,thread_hash) on conflict do nothing;
  return jsonb_build_object('format','sectalk-offboarding-room-thread-copy-v1','scope',p_room,'root',p_root,
    'approval',approval,'sha256',thread_hash,'manifestJson',(thread->'manifest')::text,'records',thread->'records');
end $$;

create function public.st_v8_offboarding_room_thread_delete(p_workspace uuid,p_room uuid,p_root uuid,p_action text,
  p_confirmation text,p_plan uuid default null,p_sha256 text default null)
returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  actor uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_room_thread_deletions; c sectalk_private.st_v8_content_exports;
  thread jsonb; thread_hash text; current_key_hash text; message_count integer; removed_count integer; message_id uuid;
  fingerprint text; inventory_until timestamptz; approved_at timestamptz; deleted_at timestamptz;
begin
  if p_workspace is null or p_room is null or p_root is null or p_action is null or p_action not in ('capture','approve','delete')
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
  perform sectalk_private.limit_action('v8_offboarding_room_thread_delete',12);

  if p_action<>'capture' then
    select d.* into plan from sectalk_private.st_v8_offboarding_room_thread_deletions d
      where (d.id,d.request,d.workspace,d.room,d.root,d.sha256)=(p_plan,r.id,p_workspace,p_room,p_root,p_sha256);
    if plan.id is null then raise exception 'Confirm the exact room thread deletion plan and digest' using errcode='PT409'; end if;
    select d.happened_at into approved_at from sectalk_private.st_v8_offboarding_room_thread_decisions d
      where d.deletion=plan.id and d.action='approved' and d.actor=r.reviewer;
    select d.happened_at into deleted_at from sectalk_private.st_v8_offboarding_room_thread_decisions d
      where d.deletion=plan.id and d.action='deleted' and d.actor=r.requester;
    if deleted_at is not null then
      return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'messageCount',plan.message_count,'approvedAt',approved_at,'deletedAt',deleted_at);
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
  -- Room writes take the same room lock. The exact post locks also serialize reports and FK insertions.
  perform 1 from public.st_v6_rooms where (workspace_id,id)=(p_workspace,p_room) for no key update nowait;
  if not found then raise insufficient_privilege; end if;
  perform 1 from public.st_v6_room_posts p where p.room_id=p_room and (p.id=p_root or p.parent_id=p_root)
    order by p.id limit 17 for update nowait;
  thread:=sectalk_private.st_v8_offboarding_room_thread_source(p_workspace,p_room,p_root,r.requester,r.reviewer,c.id);
  if thread is null then raise exception 'Only a complete approved standard room thread without preserved dependencies is eligible'
    using errcode='PT409'; end if;
  thread_hash:=encode(sha256(convert_to((thread->'manifest')::text,'UTF8')),'hex');
  message_count:=jsonb_array_length(thread->'manifest');
  if not exists(select 1 from sectalk_private.st_v8_offboarding_room_thread_copies x
    where (x.request,x.export_id,x.room,x.root,x.owner_id,x.thread_sha256)=(r.id,c.id,p_room,p_root,r.requester,thread_hash)) then
    raise exception 'Download the exact approved thread copy before preparing a deletion plan' using errcode='PT409'; end if;

  select encode(sha256(convert_to(jsonb_build_array(s.current_version,
    coalesce((select jsonb_agg(jsonb_build_array(k.version,k.custody,k.provider_ref,k.wrapped) order by k.version)
      from sectalk_private.st_v7_tenant_key_versions k where k.workspace=s.workspace),'[]'))::text,'UTF8')),'hex')
    into current_key_hash from sectalk_private.st_v7_tenant_key_state s where s.workspace=p_workspace and s.destroyed_at is null
      and exists(select 1 from sectalk_private.st_v7_tenant_key_versions k where (k.workspace,k.version)=(s.workspace,s.current_version));
  if current_key_hash is null
    or exists(select 1 from sectalk_private.st_v7_tenant_key_destroy k where k.workspace=p_workspace and k.result is null)
    or exists(select 1 from sectalk_private.st_v7_tenant_rotation_tickets k where k.workspace=p_workspace and k.expires_at>clock_timestamp())
    then raise exception 'A live stable custody state is required to preserve recoverability' using errcode='PT409'; end if;

  fingerprint:=encode(sha256(convert_to(jsonb_build_array('sectalk-offboarding-standard-room-thread-v1',p_workspace,r.id,
    r.snapshot_sha256,c.id,c.manifest_sha256,p_room,p_root,thread_hash,current_key_hash)::text,'UTF8')),'hex');
  if p_action='capture' then
    select d.* into plan from sectalk_private.st_v8_offboarding_room_thread_deletions d where d.request=r.id and d.room=p_room and d.root=p_root
      and d.sha256=fingerprint and d.expires_at>clock_timestamp() order by d.requested_at desc,d.id desc limit 1;
    if plan.id is null then
      insert into sectalk_private.st_v8_offboarding_room_thread_deletions(request,workspace,room,root,owner_id,reviewer,export_id,
        manifest_sha256,thread_sha256,manifest,message_count,key_sha256,sha256,expires_at)
        values(r.id,p_workspace,p_room,p_root,r.requester,r.reviewer,c.id,c.manifest_sha256,thread_hash,thread->'manifest',
          message_count,current_key_hash,fingerprint,least(inventory_until,c.expires_at)) returning * into plan;
    end if;
  elsif plan.sha256 is distinct from fingerprint or plan.expires_at<=clock_timestamp() then
    raise exception 'The approved source or custody changed, or the approval expired' using errcode='PT409';
  elsif p_action='approve' then
    if approved_at is null then
      insert into sectalk_private.st_v8_offboarding_room_thread_decisions(deletion,action,actor)
        values(plan.id,'approved',actor) returning happened_at into approved_at;
    end if;
  else
    if approved_at is null then raise insufficient_privilege; end if;
    -- Wait for in-flight search refreshes against the exact IDs in deterministic order.
    for message_id in select (x->>'id')::uuid from jsonb_array_elements(thread->'manifest') x order by 1 loop
      loop
        insert into sectalk_private.st_v7_search_pending(kind,object_id) values('room',message_id) on conflict do nothing;
        perform 1 from sectalk_private.st_v7_search_pending q where (q.kind,q.object_id)=('room',message_id) for update;
        exit when found;
      end loop;
    end loop;
    if not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
      or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
      or not coalesce(sectalk_private.st_v8_planner_sso_allows(p_workspace),false)
      or sectalk_private.st_v8_offboarding_role(p_workspace,r.requester) is distinct from 'owner'
      or sectalk_private.st_v8_offboarding_role(p_workspace,r.reviewer) is distinct from 'reviewer'
      or thread is distinct from sectalk_private.st_v8_offboarding_room_thread_source(p_workspace,p_room,p_root,r.requester,r.reviewer,c.id)
      or least(inventory_until,c.expires_at,plan.expires_at)<=clock_timestamp() then raise insufficient_privilege; end if;
    perform 1 from auth.sessions n
      join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
      join auth.mfa_amr_claims proof on proof.session_id=n.id and proof.authentication_method='totp'
      where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',actor) and n.aal='aal2'
        and f.status='verified' and f.factor_type='totp' and proof.updated_at>clock_timestamp()-interval '5 minutes'
        and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp()
      for share of n,f,proof;
    if not found then raise insufficient_privilege; end if;
    delete from public.st_v6_room_posts p where p.room_id=p_room
      and p.id in (select (x->>'id')::uuid from jsonb_array_elements(thread->'manifest') x);
    get diagnostics removed_count=row_count;
    if removed_count<>message_count then raise exception 'The complete thread could not be removed' using errcode='PT409'; end if;
    delete from sectalk_private.st_v7_search_document d where d.kind='room'
      and d.object_id in (select (x->>'id')::uuid from jsonb_array_elements(thread->'manifest') x)
      and not exists(select 1 from public.st_v6_room_posts other where other.id=d.object_id);
    insert into sectalk_private.st_v8_offboarding_room_thread_decisions(deletion,action,actor)
      values(plan.id,'deleted',actor) returning happened_at into deleted_at;
  end if;
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'messageCount',plan.message_count,'approvedAt',approved_at,'deletedAt',deleted_at);
end $$;

revoke all on function sectalk_private.st_v8_offboarding_room_thread_source(uuid,uuid,uuid,uuid,uuid,uuid),public.st_v8_offboarding_room_thread_status(uuid),
  public.st_v8_offboarding_room_thread_copy(uuid,uuid,uuid,text),public.st_v8_offboarding_room_thread_delete(uuid,uuid,uuid,text,text,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_room_thread_status(uuid),public.st_v8_offboarding_room_thread_copy(uuid,uuid,uuid,text),
  public.st_v8_offboarding_room_thread_delete(uuid,uuid,uuid,text,text,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
