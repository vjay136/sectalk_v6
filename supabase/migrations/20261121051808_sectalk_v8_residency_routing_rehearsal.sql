begin;

create table sectalk_private.st_v8_residency_routing_rehearsals (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  id uuid not null unique default gen_random_uuid(),
  request uuid not null references sectalk_private.st_v8_residency_requests on delete cascade,
  owner_id uuid not null,
  pause_started_at timestamptz not null,
  ends_at timestamptz not null,
  reviewer uuid,
  ended_at timestamptz,
  check(reviewer is distinct from owner_id)
);
alter table sectalk_private.st_v8_residency_routing_rehearsals enable row level security;
revoke all on sectalk_private.st_v8_residency_routing_rehearsals from public,anon,authenticated,service_role;

create function public.st_v8_residency_routing_rehearsal(p_workspace uuid,p_action text default 'status',
  p_rehearsal uuid default null,p_confirmation text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); actor_role text; owner_allowed boolean; reviewer_allowed boolean;
  placement record; rehearsal sectalk_private.st_v8_residency_routing_rehearsals; state text:='inactive';
begin
  if p_workspace is null or p_action is null or p_action not in ('status','request','approve','end')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false) then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if p_confirmation is distinct from p_workspace::text or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
      then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
  end if;
  select r.id,r.requester,c.project_reference,c.environment,c.region,l.started_at,l.ends_at,r.observed_at,
    r.observation_nonce,r.reviewed_by,i.installation_nonce,q.reviewer as provider_reviewer,q.verified_at
    into placement from sectalk_private.st_v8_residency_requests r
    join public.st_v2_workspaces w on (w.id,w.owner)=(r.workspace,r.requester)
    join sectalk_private.st_v8_residency_cells c on c.id=r.cell and c.retired_at is null
    join sectalk_private.st_v8_residency_cell_authorizations a on (a.workspace,a.cell)=(r.workspace,r.cell)
    join sectalk_private.st_v8_residency_source_pauses l on (l.workspace,l.request)=(r.workspace,r.id)
      and l.resumed_at is null and l.ends_at>clock_timestamp()
    left join sectalk_private.st_v8_residency_installation i on i.cell=c.id
    left join sectalk_private.st_v8_residency_provider_checks q on q.request=r.id
    where r.workspace=p_workspace and r.withdrawn_at is null
      and (sectalk_private.st_v7_workspace_entitlements(p_workspace)).plan='enterprise'
      and sectalk_private.st_v7_workspace_payment_mode(p_workspace)->>'reason'='residency';
  actor_role:=sectalk_private.st_v2_role(p_workspace,actor_id);
  owner_allowed:=coalesce(actor_role='owner' and sectalk_private.st_v8_residency_owner(p_workspace),false);
  reviewer_allowed:=exists(select 1 from sectalk_private.st_v8_residency_verifiers v
    where (v.workspace,v.actor)=(p_workspace,actor_id) and not owner_allowed);
  if actor_role is null and not reviewer_allowed then raise insufficient_privilege; end if;

  select * into rehearsal from sectalk_private.st_v8_residency_routing_rehearsals x where x.workspace=p_workspace;
  if p_action='end' then
    if p_rehearsal is null or rehearsal.id is distinct from p_rehearsal
      or not coalesce(owner_allowed or reviewer_allowed and rehearsal.reviewer=actor_id,false) then raise insufficient_privilege; end if;
    update sectalk_private.st_v8_residency_routing_rehearsals set ended_at=clock_timestamp()
      where workspace=p_workspace and ended_at is null;
    if found then insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor_id,'workspace.residency_route_ended',rehearsal.id); end if;
    return jsonb_build_object('status','inactive','role',case when owner_allowed then 'owner' else 'reviewer' end);
  end if;

  if placement.id is not null and ((placement.environment='fixture' and placement.reviewed_by is not null
      and placement.observed_at>statement_timestamp()-interval '1 day'
      and placement.observation_nonce=placement.installation_nonce
      and exists(select 1 from sectalk_private.st_v8_residency_verifiers v
        where (v.workspace,v.actor)=(p_workspace,placement.reviewed_by) and sectalk_private.st_v2_active(v.actor)))
    or (placement.environment='deployment' and placement.verified_at>statement_timestamp()-interval '1 day'
      and exists(select 1 from sectalk_private.st_v8_residency_provider_scope(placement.id,placement.provider_reviewer)))) then
    state:='ready';
    if (rehearsal.request,rehearsal.owner_id,rehearsal.pause_started_at)=(placement.id,placement.requester,placement.started_at)
      and rehearsal.ended_at is null and rehearsal.ends_at>clock_timestamp() and
      (rehearsal.reviewer is null or exists(select 1 from sectalk_private.st_v8_residency_verifiers v
        where (v.workspace,v.actor)=(p_workspace,rehearsal.reviewer) and sectalk_private.st_v2_active(v.actor))) then
      state:=case when rehearsal.reviewer is null then 'pending' else 'active' end;
    end if;
  end if;

  if p_action='request' then
    if not owner_allowed or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
      then raise insufficient_privilege; end if;
    if state='inactive' then raise exception 'An independently verified target and current write pause are required.' using errcode='PT409'; end if;
    if state='ready' then
      perform sectalk_private.limit_action('v8_residency_route',8);
      insert into sectalk_private.st_v8_residency_routing_rehearsals as x(workspace,request,owner_id,pause_started_at,ends_at)
        values(p_workspace,placement.id,actor_id,placement.started_at,least(placement.ends_at,clock_timestamp()+interval '10 minutes'))
        on conflict(workspace) do update set id=excluded.id,request=excluded.request,owner_id=excluded.owner_id,
          pause_started_at=excluded.pause_started_at,ends_at=excluded.ends_at,reviewer=null,ended_at=null
        returning x.* into rehearsal;
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(p_workspace,actor_id,'workspace.residency_route_requested',rehearsal.id);
      state:='pending';
    end if;
  elsif p_action='approve' then
    if not reviewer_allowed or actor_id=placement.requester or p_rehearsal is null
      or rehearsal.id is distinct from p_rehearsal then raise insufficient_privilege; end if;
    if state<>'pending' and not (state='active' and rehearsal.reviewer=actor_id) then
      raise exception 'This routing rehearsal is no longer awaiting review.' using errcode='PT409'; end if;
    if state='pending' then
      perform sectalk_private.limit_action('v8_residency_route',8);
      update sectalk_private.st_v8_residency_routing_rehearsals set reviewer=actor_id where workspace=p_workspace;
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(p_workspace,actor_id,'workspace.residency_route_approved',rehearsal.id);
      state:='active';
    end if;
  end if;

  return jsonb_build_object('status',case when actor_role is null and state='active' then 'inactive'
      when (owner_allowed or reviewer_allowed) or state='active' then state else 'inactive' end,
    'role',case when owner_allowed then 'owner' when reviewer_allowed then 'reviewer' end,
    'rehearsal',case when (owner_allowed or reviewer_allowed) and state in ('pending','active') then rehearsal.id end,
    'until',case when state='active' and actor_role is not null or state='pending' and (owner_allowed or reviewer_allowed) then rehearsal.ends_at end,
    'project',case when state='active' and actor_role is not null then placement.project_reference end,
    'fixture',case when state='active' and actor_role is not null then placement.environment='fixture' end);
end $$;

revoke all on function public.st_v8_residency_routing_rehearsal(uuid,text,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_routing_rehearsal(uuid,text,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
