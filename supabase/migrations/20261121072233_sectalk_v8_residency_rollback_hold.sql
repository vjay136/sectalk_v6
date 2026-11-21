begin;

create table sectalk_private.st_v8_residency_rollback_holds (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  approval uuid not null,
  handoff uuid not null,
  side text not null check (side in ('source','destination')),
  held_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v8_residency_rollback_holds enable row level security;
revoke all on table sectalk_private.st_v8_residency_rollback_holds from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_residency_rollback_side(p_workspace uuid)
returns text language sql stable set search_path='' as $$
  select x.side from sectalk_private.st_v8_residency_rollback_holds x
  join sectalk_private.st_v8_residency_write_handoffs f using(workspace,approval,handoff)
  where x.workspace=p_workspace
    and ((x.side='source' and f.phase='held') or (x.side='destination' and f.phase='activated'))
$$;
revoke all on function sectalk_private.st_v8_residency_rollback_side(uuid) from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v7_workspace_payment_mode(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select case when exists(select 1 from sectalk_private.st_v8_offboarding_requests r
    where r.workspace=p_workspace and r.state='read_only')
    then '{"mode":"read_only","reason":"offboarding"}'::jsonb
    when sectalk_private.st_v8_residency_rollback_side(p_workspace)='destination'
    then '{"mode":"read_only","reason":"residency","handoff":true,"rollback":true}'::jsonb
    when exists(select 1 from sectalk_private.st_v8_residency_write_handoffs h
      where h.workspace=p_workspace and h.phase in ('standby','cancelled','held'))
    then '{"mode":"read_only","reason":"residency","handoff":true}'::jsonb
    when exists(select 1 from sectalk_private.st_v8_residency_source_pauses p
      join sectalk_private.st_v8_residency_requests r on (r.id,r.workspace)=(p.request,p.workspace)
      where p.workspace=p_workspace and p.resumed_at is null and p.ends_at>statement_timestamp() and r.withdrawn_at is null)
    then '{"mode":"read_only","reason":"residency"}'::jsonb else coalesce((
    select jsonb_build_object('mode',case when g.deadline>statement_timestamp() then 'grace' else 'read_only' end,
      'grace_until',g.deadline)
    from public.st_v2_workspaces w join public.st_v2_subscriptions s on s.user_id=w.owner
    left join sectalk_private.st_v7_nonpayment_cancellations c on (c.subscription,c.account,c.customer)=(s.subscription_id,s.user_id,s.customer_id)
    cross join lateral (
      select case when s.status='past_due' then sectalk_private.st_v7_renewal_grace(s.user_id,s.subscription_id,s.period_end) else
        coalesce((select min(r.grace_until) from sectalk_private.st_v7_renewal_cases r
          where (r.recipient,r.customer,r.subscription)=(s.user_id,s.customer_id,s.subscription_id) and r.stage<>'paid'),
          s.period_end+make_interval(hours=>(select grace_hours from sectalk_private.st_v7_renewal_policy where singleton)),
          s.synced_at+make_interval(hours=>(select grace_hours from sectalk_private.st_v7_renewal_policy where singleton)))
      end deadline
    ) g
    where w.id=p_workspace and s.plan<>'free'
      and (s.status in ('past_due','unpaid') or (s.status='canceled' and c.subscription is not null))
      and g.deadline is not null
  ),'{"mode":"active"}') end
$$;

create function public.st_v8_residency_rollback_hold(p_workspace uuid,p_action text default 'status',
  p_approval uuid default null,p_confirmation text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); transfer sectalk_private.st_v8_residency_write_handoffs; transfer_side text;
begin
  if p_workspace is null or p_action is null or p_action not in ('status','hold_destination','suspend_source_route')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'owner'
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if p_approval is null or p_confirmation is distinct from p_workspace::text
      or not coalesce(sectalk_private.st_v7_admin_fresh(),false) then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces w where (w.id,w.owner)=(p_workspace,actor_id) for share;
    if not found then raise insufficient_privilege; end if;
  end if;
  select f.* into transfer from sectalk_private.st_v8_residency_write_handoffs f
    where f.workspace=p_workspace and (p_approval is null or f.approval=p_approval);
  if transfer.phase='held' then
    transfer_side:='source';
  elsif transfer.phase='activated' and exists(
    select 1 from sectalk_private.st_v8_residency_workspace_claims c
    join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
    join sectalk_private.st_v8_residency_cells t on (t.id,t.project_reference)=(c.cell,transfer.destination_project)
    where (c.workspace,c.approval,c.source_project)=(p_workspace,transfer.approval,transfer.source_project)
      and c.claimed_at is not null
    ) then
    transfer_side:='destination';
  end if;
  if p_action='status' then
    if transfer_side is null then return '{"state":"inactive"}'::jsonb; end if;
    return jsonb_build_object('state',case when sectalk_private.st_v8_residency_rollback_side(p_workspace)=transfer_side
      then 'held' else 'ready' end,'side',transfer_side,'approval',transfer.approval);
  end if;
  if transfer_side is distinct from (case when p_action='hold_destination' then 'destination' else 'source' end)
    then raise insufficient_privilege; end if;
  insert into sectalk_private.st_v8_residency_rollback_holds(workspace,approval,handoff,side)
    values(p_workspace,transfer.approval,transfer.handoff,transfer_side) on conflict(workspace) do nothing;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor_id,case when transfer_side='destination' then 'workspace.residency_rollback_destination_held'
        else 'workspace.residency_rollback_route_suspended' end,transfer.handoff);
  elsif sectalk_private.st_v8_residency_rollback_side(p_workspace) is distinct from transfer_side then
    raise exception 'A different rollback generation is already recorded for this workspace.' using errcode='PT409';
  end if;
  return jsonb_build_object('state','held','side',transfer_side,'approval',transfer.approval);
end $$;
revoke all on function public.st_v8_residency_rollback_hold(uuid,text,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_rollback_hold(uuid,text,uuid,text) to authenticated;

alter function public.st_v8_residency_active_route(uuid,text,uuid,text,jsonb) set schema sectalk_private;
revoke all on function sectalk_private.st_v8_residency_active_route(uuid,text,uuid,text,jsonb) from public,anon,authenticated,service_role;

create function public.st_v8_residency_active_route(p_workspace uuid,p_action text default 'status',
  p_approval uuid default null,p_confirmation text default null,p_proof jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare route jsonb; held_side text;
begin
  if p_action='status' then
    route:=sectalk_private.st_v8_residency_active_route(p_workspace,p_action,p_approval,p_confirmation,p_proof);
    held_side:=sectalk_private.st_v8_residency_rollback_side(p_workspace);
    if held_side='source' then return '{"status":"unavailable"}'::jsonb; end if;
    if held_side='destination' then return '{"status":"inactive"}'::jsonb; end if;
    return route;
  end if;
  if p_action is null or p_action not in ('issue','publish') or p_workspace is null or p_approval is null
    or p_confirmation is distinct from p_workspace::text
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or sectalk_private.st_v8_offboarding_role(p_workspace,auth.uid()) is distinct from 'owner'
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    or not coalesce(sectalk_private.st_v7_admin_fresh(),false) then raise insufficient_privilege; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
  if sectalk_private.st_v8_residency_rollback_side(p_workspace) is not null then
    raise exception 'Member routing is suspended for rollback review.' using errcode='PT409';
  end if;
  return sectalk_private.st_v8_residency_active_route(p_workspace,p_action,p_approval,p_confirmation,p_proof);
end $$;
revoke all on function public.st_v8_residency_active_route(uuid,text,uuid,text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_active_route(uuid,text,uuid,text,jsonb) to authenticated;

notify pgrst,'reload schema';
commit;
