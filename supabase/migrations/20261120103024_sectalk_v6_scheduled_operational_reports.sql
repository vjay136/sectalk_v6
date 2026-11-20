begin;

create table sectalk_private.st_v6_operational_report_schedules (
  owner uuid primary key references public.st_profiles on delete cascade,
  cadence text not null check(cadence in ('daily','weekly')),
  active boolean not null,
  verified_email text,
  next_at timestamptz not null
);
create index st_v6_operational_report_schedule_due on sectalk_private.st_v6_operational_report_schedules(next_at,owner) where active;

create table sectalk_private.st_v6_operational_report_runs (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references sectalk_private.st_v6_operational_report_schedules(owner) on delete cascade,
  scheduled_at timestamptz not null,
  period_end timestamptz not null,
  cadence text not null check(cadence in ('daily','weekly')),
  rows jsonb not null check(jsonb_typeof(rows)='array'),
  state text not null default 'pending' check(state in ('pending','sent','failed','cancelled')),
  next_attempt_at timestamptz not null default now(),
  lease_id uuid,
  attempts integer not null default 0,
  unique(owner,scheduled_at)
);
create index st_v6_operational_report_run_due on sectalk_private.st_v6_operational_report_runs(next_attempt_at,id) where state='pending';
create index st_v6_operational_report_run_retention on sectalk_private.st_v6_operational_report_runs(scheduled_at);
alter table sectalk_private.st_v6_operational_report_runs enable row level security;
alter table sectalk_private.st_v6_operational_report_schedules enable row level security;
revoke all on sectalk_private.st_v6_operational_report_runs,sectalk_private.st_v6_operational_report_schedules
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_operational_report_access()
returns boolean language sql stable set search_path='' as $$
  select public.st_staff_status()='verified' and sectalk_private.st_v2_active(auth.uid()) and exists(
    select 1 from auth.sessions s join auth.mfa_factors f on f.id=s.factor_id and f.user_id=s.user_id
    where s.id::text=auth.jwt()->>'session_id' and s.user_id=auth.uid() and s.aal='aal2'
      and (s.not_after is null or s.not_after>now()) and f.status='verified' and f.factor_type='totp')
$$;

create function sectalk_private.st_v6_operational_report_mailbox(p_owner uuid)
returns text language sql stable set search_path='' as $$
  select lower(u.email) from auth.users u where u.id=p_owner and u.email_confirmed_at is not null
    and coalesce(u.email_change,'')=''
    and sectalk_private.st_v2_active(u.id)
    and exists(select 1 from sectalk_private.staff s where s.user_id=u.id)
    and exists(select 1 from auth.mfa_factors f where f.user_id=u.id and f.status='verified' and f.factor_type='totp')
$$;

create function sectalk_private.st_v6_operational_report_span(p_cadence text)
returns interval language sql immutable set search_path='' as $$
  select case p_cadence when 'daily' then interval '24 hours' when 'weekly' then interval '168 hours' end
$$;

create function sectalk_private.st_v6_operational_report_snapshot(p_end timestamptz,p_span interval)
returns jsonb language sql stable set search_path='' as $$
  with recent as materialized (
    select r.* from sectalk_private.st_v6_operation_rollups r
    where r.bucket>=p_end-p_span and r.bucket<p_end
  ), totals as (
    select r.operation,sum(r.requests)::bigint as requests,sum(r.client_errors)::bigint as client_errors,
      sum(r.server_errors)::bigint as server_errors,sum(r.throttled)::bigint as throttled,
      sum(r.unavailable)::bigint as unavailable,max(r.peak_in_flight) as peak_in_flight
    from recent r group by r.operation having sum(r.requests)>=10
  ), bands as (
    select r.operation,h.band::integer as band,sum(h.samples) as samples
    from recent r cross join lateral unnest(r.latency_histogram) with ordinality h(samples,band)
    group by r.operation,h.band
  ), distribution as (
    select b.operation,b.band,sum(b.samples) over(partition by b.operation order by b.band) as cumulative
    from bands b
  ), summaries as (
    select t.operation,t.requests,t.client_errors,t.server_errors,t.throttled,t.unavailable,
      t.peak_in_flight,
      min(d.band) filter(where d.cumulative>=ceil(t.requests*0.50)) as p50_band,
      min(d.band) filter(where d.cumulative>=ceil(t.requests*0.95)) as p95_band
    from totals t join distribution d on d.operation=t.operation
    group by t.operation,t.requests,t.client_errors,t.server_errors,t.throttled,t.unavailable,t.peak_in_flight
  )
  select coalesce(jsonb_agg(to_jsonb(s) order by s.operation),'[]') from summaries s
$$;

create function public.st_v6_operational_report_settings()
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid(); schedule sectalk_private.st_v6_operational_report_schedules;
begin
  if not sectalk_private.st_v6_operational_report_access() then
    raise exception 'MFA-verified staff access required' using errcode='42501';
  end if;
  select * into schedule from sectalk_private.st_v6_operational_report_schedules p where p.owner=actor;
  return jsonb_build_object(
    'available',sectalk_private.st_v6_operational_report_mailbox(actor) is not null,
    'active',coalesce(schedule.active and schedule.verified_email=sectalk_private.st_v6_operational_report_mailbox(actor),false),
    'cadence',coalesce(schedule.cadence,'daily'),
    'next_at',case when schedule.active and schedule.verified_email=sectalk_private.st_v6_operational_report_mailbox(actor)
      then schedule.next_at end,
    'runs',coalesce((select jsonb_agg(to_jsonb(history) order by history.period_end desc,history.id desc)
      from (select r.id,r.cadence,r.period_end,r.state from sectalk_private.st_v6_operational_report_runs r
        where r.owner=actor and r.scheduled_at>=now()-interval '30 days' order by r.period_end desc,r.id desc limit 30) history),'[]'));
end
$$;

create function public.st_v6_set_operational_report(p_cadence text,p_active boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); mailbox text; span interval;
begin
  if not sectalk_private.st_v6_operational_report_access() then
    raise exception 'MFA-verified staff access required' using errcode='42501';
  end if;
  span:=sectalk_private.st_v6_operational_report_span(p_cadence);
  if span is null or p_active is null then raise exception 'Choose daily or weekly reports'; end if;
  mailbox:=sectalk_private.st_v6_operational_report_mailbox(actor);
  if p_active and mailbox is null then raise exception 'Confirm your current profile email to schedule reports'; end if;
  perform sectalk_private.limit_action('v6_operational_report_schedule',15);
  insert into sectalk_private.st_v6_operational_report_schedules as s(owner,cadence,active,verified_email,next_at)
    values(actor,p_cadence,p_active,case when p_active then mailbox end,now()+span)
  on conflict(owner) do update set cadence=excluded.cadence,active=excluded.active,
    verified_email=excluded.verified_email,next_at=excluded.next_at
    where (s.cadence,s.active,s.verified_email) is distinct from (excluded.cadence,excluded.active,excluded.verified_email);
  if found then
    update sectalk_private.st_v6_operational_report_runs r set state='cancelled',lease_id=null
    where r.owner=actor and r.state='pending';
  end if;
end
$$;

create function public.st_v6_operational_report_export(p_run uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare report jsonb;
begin
  if not sectalk_private.st_v6_operational_report_access() then
    raise exception 'MFA-verified staff access required' using errcode='42501';
  end if;
  select jsonb_build_object('cadence',r.cadence,'period_end',r.period_end,'rows',r.rows) into report
  from sectalk_private.st_v6_operational_report_runs r where r.id=p_run and r.owner=auth.uid()
    and r.scheduled_at>=now()-interval '30 days';
  return report;
end
$$;

create function public.st_v6_claim_operational_reports(p_request uuid)
returns table(id uuid,lease uuid,email text,cadence text,period_end timestamptz,rows jsonb)
language plpgsql security definer set search_path='' as $$
declare schedule record; boundary timestamptz; interval_length interval;
begin
  if not sectalk_private.st_v6_acquire_worker_request('operational_reports',p_request) then return; end if;
  delete from sectalk_private.st_v6_operational_report_runs r where r.scheduled_at<now()-interval '30 days';
  for schedule in
    select s.* from sectalk_private.st_v6_operational_report_schedules s
    where s.active and s.next_at<=now()
    order by s.next_at,s.owner limit 20 for update of s skip locked
  loop
    if schedule.verified_email is distinct from sectalk_private.st_v6_operational_report_mailbox(schedule.owner) then
      update sectalk_private.st_v6_operational_report_schedules s set active=false,verified_email=null where s.owner=schedule.owner;
      continue;
    end if;
    interval_length:=sectalk_private.st_v6_operational_report_span(schedule.cadence);
    boundary:=date_bin(interval '5 minutes',now(),'2000-01-01 00:00:00+00'::timestamptz);
    insert into sectalk_private.st_v6_operational_report_runs(owner,scheduled_at,period_end,cadence,rows)
    values(schedule.owner,schedule.next_at,boundary,schedule.cadence,
      sectalk_private.st_v6_operational_report_snapshot(boundary,interval_length))
    on conflict(owner,scheduled_at) do nothing;
    update sectalk_private.st_v6_operational_report_schedules s set next_at=now()+interval_length where s.owner=schedule.owner;
  end loop;
  update sectalk_private.st_v6_operational_report_runs r set state='failed',lease_id=null
  where r.state='pending' and r.next_attempt_at<=now() and r.attempts>=3;
  update sectalk_private.st_v6_operational_report_runs r set state='cancelled',lease_id=null
  from sectalk_private.st_v6_operational_report_schedules s where r.owner=s.owner and r.state='pending'
    and (not s.active or s.verified_email is distinct from sectalk_private.st_v6_operational_report_mailbox(s.owner));
  return query
  with ready as (
    select r.id from sectalk_private.st_v6_operational_report_runs r
    where r.state='pending' and r.next_attempt_at<=now() and r.attempts<3
    order by r.next_attempt_at,r.id limit 20 for update of r skip locked
  ), claimed as (
    update sectalk_private.st_v6_operational_report_runs r set lease_id=gen_random_uuid(),
      next_attempt_at=now()+interval '45 seconds',attempts=r.attempts+1
    from ready where r.id=ready.id returning r.*
  )
  select claimed.id,claimed.lease_id,s.verified_email,claimed.cadence,claimed.period_end,claimed.rows
  from claimed join sectalk_private.st_v6_operational_report_schedules s on s.owner=claimed.owner;
end
$$;

create function public.st_v6_confirm_operational_report(p_run uuid,p_lease uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v6_operational_report_runs r
    join sectalk_private.st_v6_operational_report_schedules s on s.owner=r.owner
    where r.id=p_run and r.lease_id=p_lease and r.state='pending' and r.next_attempt_at>now()
      and s.active and s.verified_email=sectalk_private.st_v6_operational_report_mailbox(s.owner))
$$;

create function public.st_v6_finish_operational_report(p_run uuid,p_lease uuid,p_state text)
returns void language sql security definer set search_path='' as $$
  update sectalk_private.st_v6_operational_report_runs r set
    state=case when p_state='retry' then case when r.attempts<3 then 'pending' else 'failed' end else p_state end,
    next_attempt_at=now()+make_interval(secs=>30*r.attempts),lease_id=null
  where r.id=p_run and r.lease_id=p_lease and r.state='pending' and p_state in ('retry','sent','failed','cancelled')
$$;

alter table sectalk_private.st_v6_worker_acquisitions drop constraint st_v6_worker_acquisitions_channel_check,
  add check(channel in ('web_push','email','operational_reports'));

revoke all on function sectalk_private.st_v6_operational_report_access(),sectalk_private.st_v6_operational_report_mailbox(uuid),
  sectalk_private.st_v6_operational_report_span(text),sectalk_private.st_v6_operational_report_snapshot(timestamptz,interval),
  public.st_v6_operational_report_settings(),public.st_v6_set_operational_report(text,boolean),
  public.st_v6_operational_report_export(uuid),public.st_v6_claim_operational_reports(uuid),
  public.st_v6_confirm_operational_report(uuid,uuid),public.st_v6_finish_operational_report(uuid,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_operational_report_settings(),public.st_v6_set_operational_report(text,boolean),
  public.st_v6_operational_report_export(uuid) to authenticated;
grant execute on function public.st_v6_claim_operational_reports(uuid),public.st_v6_confirm_operational_report(uuid,uuid),
  public.st_v6_finish_operational_report(uuid,uuid,text) to service_role;

commit;
