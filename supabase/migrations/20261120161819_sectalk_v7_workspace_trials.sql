begin;

create table sectalk_private.st_v7_workspace_trials (
  workspace_id uuid primary key references public.st_v2_workspaces(id) on delete cascade,
  requested_by uuid not null,
  reservation uuid not null unique default gen_random_uuid(),
  plan text not null check(plan in ('professional','business')),
  version integer not null,
  reserved_until timestamptz,
  provider_session text unique,
  started_at timestamptz,
  expires_at timestamptz,
  foreign key(plan,version) references sectalk_private.st_v7_plan_entitlements,
  check ((started_at is null)=(expires_at is null)),
  check (expires_at is null or expires_at=started_at+interval '336 hours')
);
alter table sectalk_private.st_v7_workspace_trials enable row level security;
revoke all on sectalk_private.st_v7_workspace_trials from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v7_workspace_entitlements(p_workspace uuid)
returns sectalk_private.st_v7_plan_entitlements language sql stable security definer set search_path='' as $$
  select coalesce(trial.plan,account.plan),coalesce(trial.version,account.version),
    coalesce(trial.workspace_limit,account.workspace_limit),coalesce(trial.seat_limit,account.seat_limit),
    coalesce(trial.group_limit,account.group_limit),coalesce(trial.file_bytes,account.file_bytes),
    coalesce(trial.storage_bytes,account.storage_bytes),coalesce(trial.task_creation,account.task_creation),
    coalesce(trial.recurring_meetings,account.recurring_meetings),coalesce(trial.integration_api,account.integration_api)
  from public.st_v2_workspaces w
  cross join lateral sectalk_private.st_v7_account_entitlements(w.owner) account
  left join sectalk_private.st_v7_workspace_trials t on t.workspace_id=w.id and t.expires_at>now() and account.plan='free'
  left join sectalk_private.st_v7_plan_entitlements trial on (trial.plan,trial.version)=(t.plan,t.version)
  where w.id=p_workspace;
$$;

create function public.st_v7_workspace_trial_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare trial sectalk_private.st_v7_workspace_trials;
begin
  if not coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid())='owner',false)
     or sectalk_private.st_v2_active(auth.uid()) is not true then
    raise exception using errcode='42501',message='Workspace trial unavailable';
  end if;
  select * into trial from sectalk_private.st_v7_workspace_trials where workspace_id=p_workspace;
  return jsonb_build_object('state',case
    when trial.expires_at>now() then 'active'
    when trial.started_at is not null then 'used'
    when sectalk_private.st_v2_effective_plan(auth.uid())<>'free' then 'subscribed'
    when trial.reserved_until>now() then 'pending'
    else 'eligible' end,
    'plan',trial.plan,'expires_at',trial.expires_at,'reserved_until',trial.reserved_until);
end $$;

create function public.st_v7_start_workspace_trial(p_workspace uuid,p_owner uuid,p_plan text,p_card_required boolean)
returns jsonb language plpgsql security definer set search_path='' as $$
declare trial sectalk_private.st_v7_workspace_trials;
declare version integer;
begin
  if p_plan is null or p_plan not in ('professional','business') or p_card_required is null then
    raise exception using errcode='22023',message='Invalid trial selection';
  end if;
  perform 1 from public.st_v2_workspaces where id=p_workspace and owner=p_owner for update;
  if not found or not coalesce(sectalk_private.st_v2_role(p_workspace,p_owner)='owner',false)
      or sectalk_private.st_v2_active(p_owner) is not true then
    raise exception using errcode='42501',message='Workspace trial unavailable';
  end if;
  if sectalk_private.st_v2_effective_plan(p_owner)<>'free' then
    raise exception using errcode='PT409',message='This workspace already has a paid plan';
  end if;
  select * into trial from sectalk_private.st_v7_workspace_trials where workspace_id=p_workspace;
  if trial.started_at is not null then
    if trial.plan=p_plan and trial.expires_at>now() then
      return jsonb_build_object('state','active','expires_at',trial.expires_at);
    end if;
    raise exception using errcode='PT409',message='This workspace has used its trial';
  end if;
  if trial.reserved_until>now() then
    if trial.plan=p_plan and trial.requested_by=p_owner then
      return jsonb_build_object('state','pending','reservation',trial.reservation,
        'provider_session',trial.provider_session,'expires_epoch',floor(extract(epoch from trial.reserved_until)));
    end if;
    raise exception using errcode='PT409',message='A trial request is already pending';
  end if;
  select v.version into version from sectalk_private.st_v6_active_plans() v where v.plan=p_plan and v.visible;
  if version is null then raise exception using errcode='PT422',message='Trial plan is unavailable'; end if;
  insert into sectalk_private.st_v7_workspace_trials as t
    (workspace_id,requested_by,plan,version,reserved_until,started_at,expires_at)
  values(p_workspace,p_owner,p_plan,version,case when p_card_required then now()+interval '4 hours' end,
    case when not p_card_required then now() end,case when not p_card_required then now()+interval '336 hours' end)
  on conflict(workspace_id) do update set requested_by=excluded.requested_by,reservation=gen_random_uuid(),
    plan=excluded.plan,version=excluded.version,reserved_until=excluded.reserved_until,provider_session=null,
    started_at=excluded.started_at,expires_at=excluded.expires_at returning t.* into trial;
  if not p_card_required then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(p_workspace,p_owner,'billing.trial_started');
    return jsonb_build_object('state','active','expires_at',trial.expires_at);
  end if;
  return jsonb_build_object('state','pending','reservation',trial.reservation,
    'expires_epoch',floor(extract(epoch from trial.reserved_until)));
end $$;

create function public.st_v7_attach_trial_checkout(p_reservation uuid,p_provider_session text)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  if p_provider_session is null or p_provider_session !~ '^cs_(test|live)_[A-Za-z0-9]{5,128}$' then return false; end if;
  update sectalk_private.st_v7_workspace_trials set provider_session=p_provider_session
    where reservation=p_reservation and reserved_until>now() and started_at is null
    and (provider_session is null or provider_session=p_provider_session);
  return found;
end $$;

create function public.st_v7_complete_trial_checkout(p_reservation uuid,p_provider_session text,p_completed_at timestamptz)
returns boolean language plpgsql security definer set search_path='' as $$
declare trial sectalk_private.st_v7_workspace_trials;
declare workspace uuid;
begin
  select t.workspace_id into workspace from sectalk_private.st_v7_workspace_trials t where t.reservation=p_reservation;
  if not found or p_completed_at is null or p_completed_at>now()+interval '1 minute' then return false; end if;
  perform 1 from public.st_v2_workspaces where id=workspace for update;
  select * into trial from sectalk_private.st_v7_workspace_trials
    where reservation=p_reservation and provider_session=p_provider_session for update;
  if not found then return false; end if;
  if trial.started_at is not null then return true; end if;
  if p_completed_at not between trial.reserved_until-interval '4 hours 1 minute' and trial.reserved_until
      or now()>trial.reserved_until+interval '1 day'
      or not coalesce(sectalk_private.st_v2_role(workspace,trial.requested_by)='owner',false)
      or sectalk_private.st_v2_active(trial.requested_by) is not true
      or sectalk_private.st_v2_effective_plan(trial.requested_by)<>'free' then return false; end if;
  update sectalk_private.st_v7_workspace_trials set started_at=now(),expires_at=now()+interval '336 hours'
    where reservation=p_reservation;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(workspace,trial.requested_by,'billing.trial_started');
  return true;
end $$;

revoke all on function public.st_v7_workspace_trial_status(uuid),public.st_v7_start_workspace_trial(uuid,uuid,text,boolean),
  public.st_v7_attach_trial_checkout(uuid,text),public.st_v7_complete_trial_checkout(uuid,text,timestamptz)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_workspace_trial_status(uuid) to authenticated;
grant execute on function public.st_v7_start_workspace_trial(uuid,uuid,text,boolean),public.st_v7_attach_trial_checkout(uuid,text),
  public.st_v7_complete_trial_checkout(uuid,text,timestamptz) to service_role;

commit;
