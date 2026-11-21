begin;

create table sectalk_private.st_v8_residency_source_pauses (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  request uuid not null references sectalk_private.st_v8_residency_requests on delete cascade,
  paused_by uuid not null,
  started_at timestamptz not null,
  ends_at timestamptz not null check(ends_at>started_at),
  resumed_at timestamptz
);
alter table sectalk_private.st_v8_residency_source_pauses enable row level security;
revoke all on sectalk_private.st_v8_residency_source_pauses from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v7_workspace_payment_mode(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select case when exists(select 1 from sectalk_private.st_v8_offboarding_requests r
    where r.workspace=p_workspace and r.state='read_only')
    then '{"mode":"read_only","reason":"offboarding"}'::jsonb
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

create or replace function sectalk_private.st_v7_require_workspace_write(p_workspace uuid)
returns void language plpgsql security definer set search_path='' as $$
declare state jsonb;
begin
  if p_workspace is null then return; end if;
  perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
  perform 1 from public.st_v2_subscriptions s join public.st_v2_workspaces w on w.owner=s.user_id
    where w.id=p_workspace for share of s;
  state:=sectalk_private.st_v7_workspace_payment_mode(p_workspace);
  if state->>'reason'='offboarding' then
    raise exception 'This workspace is read-only for offboarding.' using errcode='PT423';
  end if;
  if state->>'reason'='residency' then
    raise exception 'Workspace writes are paused for migration.' using errcode='PT423';
  end if;
  if state->>'mode'='read_only' then
    raise exception 'This workspace is read-only until payment is restored.' using errcode='PT423';
  end if;
end $$;

create function public.st_v8_residency_source_pause(p_workspace uuid,p_request uuid,p_action text default 'status',p_confirmation text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); r sectalk_private.st_v8_residency_requests; lease sectalk_private.st_v8_residency_source_pauses;
  placement text; active boolean; captured timestamptz;
begin
  if p_workspace is null or p_request is null or p_action is null or p_action not in ('status','pause','resume')
    or not coalesce(sectalk_private.st_v8_residency_owner(p_workspace),false)
    or (p_action<>'resume' and not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false))
    then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if p_confirmation is distinct from p_workspace::text or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
      then raise insufficient_privilege; end if;
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace and w.owner=actor_id for key share;
    if not found then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    if not coalesce(sectalk_private.st_v8_residency_owner(p_workspace),false)
      or not coalesce(sectalk_private.st_v7_admin_fresh(),false) then raise insufficient_privilege; end if;
    perform sectalk_private.limit_action('v8_residency_source_pause',8);
  end if;
  select * into r from sectalk_private.st_v8_residency_requests q
    where (q.workspace,q.id,q.requester)=(p_workspace,p_request,actor_id) and q.withdrawn_at is null;
  if not found then raise insufficient_privilege; end if;
  select * into lease from sectalk_private.st_v8_residency_source_pauses p where p.workspace=p_workspace;
  active:=coalesce(lease.request=r.id and lease.resumed_at is null and lease.ends_at>clock_timestamp(),false);
  if p_action='pause' and not active then
    placement:=public.st_v8_workspace_residency(p_workspace)#>>'{request,state}';
    if placement not in ('fixture_target_verified','provider_target_verified') or placement is null
      or (placement='fixture_target_verified' and not exists(select 1 from sectalk_private.st_v8_residency_verifiers v
        where (v.workspace,v.actor)=(p_workspace,r.reviewed_by) and sectalk_private.st_v2_active(v.actor))) then
      raise exception 'The target needs a current independent residency review.' using errcode='PT409'; end if;
    if sectalk_private.st_v7_workspace_payment_mode(p_workspace)->>'mode'='read_only' then
      raise exception 'Resolve the current workspace restriction before pausing for migration.' using errcode='PT409'; end if;
    captured:=clock_timestamp();
    insert into sectalk_private.st_v8_residency_source_pauses(workspace,request,paused_by,started_at,ends_at)
      values(p_workspace,p_request,actor_id,captured,captured+interval '30 minutes')
      on conflict(workspace) do update set request=excluded.request,paused_by=excluded.paused_by,
        started_at=excluded.started_at,ends_at=excluded.ends_at,resumed_at=null
      returning * into lease;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor_id,'workspace.residency_writes_paused',p_request);
    active:=true;
  elsif p_action='resume' and active then
    update sectalk_private.st_v8_residency_source_pauses set resumed_at=clock_timestamp() where workspace=p_workspace;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor_id,'workspace.residency_writes_resumed',p_request);
    active:=false;
  end if;
  return jsonb_build_object('paused',active,'until',case when active then lease.ends_at end);
end $$;

revoke all on function public.st_v8_residency_source_pause(uuid,uuid,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_source_pause(uuid,uuid,text,text) to authenticated;
notify pgrst,'reload schema';
commit;
