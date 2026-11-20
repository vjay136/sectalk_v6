begin;
create table sectalk_private.st_v7_billing_admins (
  workspace uuid not null,
  account uuid not null,
  assigned_by uuid not null references auth.users on delete cascade,
  assigned_at timestamptz not null default statement_timestamp(),
  primary key(workspace,account),
  foreign key(workspace,account) references public.st_v2_members(workspace_id,user_id) on delete cascade,
  check(account<>assigned_by)
);
create index on sectalk_private.st_v7_billing_admins(account);
alter table sectalk_private.st_v7_billing_admins enable row level security;
revoke all on sectalk_private.st_v7_billing_admins from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_billing_admin_allowed(p_workspace uuid,p_actor uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v7_billing_admins g
    join public.st_v2_workspaces w on w.id=g.workspace and w.owner=g.assigned_by
    where g.workspace=p_workspace and g.account=p_actor and p_actor<>w.owner
      and sectalk_private.st_v2_role(w.id,p_actor) in ('admin','member')
      and sectalk_private.st_v2_active(p_actor) and sectalk_private.st_v2_active(w.owner))
$$;
create function sectalk_private.st_v7_billing_admin_session()
returns boolean language sql stable security definer set search_path='' as $$
  select auth.uid() is not null and public.st_v7_current_session_valid()
    and public.st_v7_login_risk_status()='clear' and not public.st_v7_account_under_lockdown()
    and sectalk_private.st_v2_active(auth.uid())
$$;

create function public.st_v7_billing_admin_manage(p_workspace uuid,p_account uuid default null,p_enabled boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if p_workspace is null or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not exists(select 1 from public.st_v2_workspaces w where w.id=p_workspace and w.owner=actor
      and sectalk_private.st_v2_role(w.id,actor)='owner') then
    raise exception 'Workspace owner required' using errcode='42501';
  end if;
  if public.st_v7_sensitive_action_status('billing') is distinct from 'verified' then
    return jsonb_build_object('access','mfa');
  end if;
  if p_enabled is not null then
    if p_account is null or p_account=actor then
      raise exception 'Choose an eligible workspace member' using errcode='22023';
    end if;
    perform sectalk_private.limit_action('v7_billing_admin_grant',20);
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace and w.owner=actor
      and sectalk_private.st_v2_role(w.id,actor)='owner' for no key update;
    if not found then raise exception 'Workspace owner required' using errcode='42501'; end if;
    if p_enabled then
      perform 1 from public.st_v2_members m where m.workspace_id=p_workspace and m.user_id=p_account
        and m.suspended_at is null and m.role in ('admin','member') and sectalk_private.st_v2_active(p_account) for update;
      if not found then raise exception 'Choose an eligible workspace member' using errcode='22023'; end if;
      insert into sectalk_private.st_v7_billing_admins as g(workspace,account,assigned_by) values(p_workspace,p_account,actor)
      on conflict(workspace,account) do update set assigned_by=excluded.assigned_by,assigned_at=excluded.assigned_at
      where g.assigned_by is distinct from excluded.assigned_by;
    else
      delete from sectalk_private.st_v7_billing_admins g where g.workspace=p_workspace and g.account=p_account;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,case when p_enabled then 'billing.access_granted' else 'billing.access_revoked' end,p_account);
    end if;
  end if;
  return jsonb_build_object('access','verified','members',coalesce((select jsonb_agg(to_jsonb(entry)) from (
    select p.id,p.handle,p.name,coalesce(g.assigned_by=actor,false) as granted,
      m.suspended_at is null and sectalk_private.st_v2_active(m.user_id) as eligible
    from public.st_v2_members m join public.st_profiles p on p.id=m.user_id
    left join sectalk_private.st_v7_billing_admins g on (g.workspace,g.account)=(m.workspace_id,m.user_id)
    where m.workspace_id=p_workspace and m.user_id<>actor
      and (g.account is not null or m.suspended_at is null and sectalk_private.st_v2_active(m.user_id))
    order by (g.account is not null) desc,p.handle,p.id limit 500
  ) entry),'[]'));
end $$;

create function public.st_v7_billing_admin_view(p_workspace uuid default null)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid(); plan sectalk_private.st_v7_plan_entitlements; totals jsonb; stored bigint; seats integer;
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false) then
    raise exception 'Current session required' using errcode='42501';
  end if;
  if p_workspace is null then
    return coalesce((select jsonb_agg(to_jsonb(entry)) from (
      select w.id,w.name,w.owner=actor as manages,w.owner<>actor as delegated
      from public.st_v2_workspaces w where (w.owner=actor and sectalk_private.st_v2_role(w.id,actor)='owner')
        or sectalk_private.st_v7_billing_admin_allowed(w.id,actor)
      order by w.name,w.id limit 100
    ) entry),'[]');
  end if;
  if not sectalk_private.st_v7_billing_admin_allowed(p_workspace,actor) then
    raise exception 'Explicit billing administrator grant required' using errcode='42501';
  end if;
  select * into plan from sectalk_private.st_v7_workspace_entitlements(p_workspace);
  select count(*) into seats from public.st_v2_members where workspace_id=p_workspace;
  select s.bytes into stored from sectalk_private.st_v7_workspace_storage() s where s.workspace=p_workspace;
  select jsonb_build_object('recording_ms',coalesce(sum(e.amount) filter(where e.metric='recording_ms'),0),
    'transcription_samples',coalesce(sum(e.amount) filter(where e.metric='transcription_samples'),0),
    'storage_byte_hours',coalesce(sum(e.amount) filter(where e.metric='storage_byte_hours'),0),
    'file_inspections',coalesce(sum(e.amount) filter(where e.metric='ai_scans'),0))
  into totals from sectalk_private.st_v7_usage_events e where e.workspace=p_workspace
    and e.occurred_at>=date_trunc('month',now(),'UTC');
  return totals||jsonb_build_object('plan',plan.plan,'plan_version',plan.version,'seats',seats,'seat_limit',plan.seat_limit,
    'storage_bytes',coalesce(stored,0),'storage_quota_bytes',plan.storage_bytes);
end $$;

create function public.st_v7_billing_admin_provider_scope(p_workspace uuid,p_actor uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('customer',s.customer_id,'subscription',s.subscription_id,'status',s.status)
  from public.st_v2_workspaces w join public.st_v2_subscriptions s on s.user_id=w.owner
  where w.id=p_workspace and sectalk_private.st_v7_billing_admin_allowed(w.id,p_actor)
    and s.customer_id ~ '^cus_[a-zA-Z0-9_]{1,100}$' and s.subscription_id ~ '^sub_[a-zA-Z0-9_]{1,100}$'
$$;

revoke all on function sectalk_private.st_v7_billing_admin_allowed(uuid,uuid),sectalk_private.st_v7_billing_admin_session(),
  public.st_v7_billing_admin_manage(uuid,uuid,boolean),public.st_v7_billing_admin_view(uuid),
  public.st_v7_billing_admin_provider_scope(uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_billing_admin_manage(uuid,uuid,boolean),public.st_v7_billing_admin_view(uuid) to authenticated;
grant execute on function public.st_v7_billing_admin_provider_scope(uuid,uuid) to service_role;
commit;
