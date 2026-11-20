begin;

create table sectalk_private.st_v6_case_on_call (
  user_id uuid not null references sectalk_private.staff on delete cascade,
  tier smallint not null check(tier between 1 and 3),
  starts_at timestamptz not null,
  ends_at timestamptz not null check(ends_at>starts_at),
  primary key(user_id,tier,starts_at)
);
create index st_v6_case_on_call_tier on sectalk_private.st_v6_case_on_call(tier,starts_at,ends_at,user_id);

create table sectalk_private.st_v6_case_escalations (
  id uuid primary key default gen_random_uuid(),
  report_id uuid not null references public.st_reports on delete cascade,
  tier smallint not null check(tier between 1 and 3),
  assignee uuid not null references public.st_profiles,
  assigned_at timestamptz not null,
  acknowledge_by timestamptz not null,
  action_by timestamptz not null,
  acknowledged_at timestamptz,
  superseded_at timestamptz,
  unique(report_id,tier)
);
create index st_v6_case_escalation_assignee on sectalk_private.st_v6_case_escalations(assignee,assigned_at desc)
  where superseded_at is null;
alter table sectalk_private.st_v6_case_on_call enable row level security;
alter table sectalk_private.st_v6_case_escalations enable row level security;
revoke all on sectalk_private.st_v6_case_on_call,sectalk_private.st_v6_case_escalations from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_on_call_eligible(p_user uuid)
returns boolean language sql stable set search_path='' as $$
  select sectalk_private.st_v2_active(p_user) and exists(
    select 1 from auth.mfa_factors f where f.user_id=p_user and f.factor_type='totp' and f.status='verified')
$$;

create function sectalk_private.st_v6_on_call_tier(p_user uuid)
returns smallint language sql stable set search_path='' as $$
  select coalesce(max(r.tier),0)::smallint from sectalk_private.st_v6_case_on_call r
  where r.user_id=p_user and now()>=r.starts_at and now()<r.ends_at
    and sectalk_private.st_v6_on_call_eligible(p_user)
$$;

create function public.st_v6_case_escalation(p_report uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare current_tier smallint:=sectalk_private.st_v6_on_call_tier(auth.uid()); state text; stage record;
begin
  if not sectalk_private.st_v6_case_collaboration_access(p_report) then
    raise exception 'Case escalation is unavailable' using errcode='42501';
  end if;
  select r.status into state from public.st_reports r where r.id=p_report;
  select e.*, p.name as assignee_name into stage from sectalk_private.st_v6_case_escalations e
  join public.st_profiles p on p.id=e.assignee
  where e.report_id=p_report and e.superseded_at is null;
  return jsonb_build_object('tier',stage.tier,'assignee',stage.assignee_name,
    'assigned_at',stage.assigned_at,'acknowledge_by',stage.acknowledge_by,'action_by',stage.action_by,
    'acknowledged_at',stage.acknowledged_at,
    'can_acknowledge',coalesce(state in ('open','reviewing') and stage.assignee=auth.uid()
      and current_tier>=stage.tier and stage.acknowledged_at is null,false),
    'can_route',coalesce(state in ('open','reviewing') and current_tier>=coalesce(stage.tier,1)
      and coalesce(stage.tier<3,true) and (stage.id is null or stage.acknowledged_at is not null
      or stage.acknowledge_by<=now()
      or sectalk_private.st_v6_on_call_tier(stage.assignee)<stage.tier),false));
end $$;

create function public.st_v6_update_case_escalation(
  p_report uuid,p_action text,p_expected_tier smallint,p_reason text
) returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  current_tier smallint:=sectalk_private.st_v6_on_call_tier(actor);
  report public.st_reports;
  stage sectalk_private.st_v6_case_escalations;
  destination smallint;
  recipient uuid;
  moment timestamptz;
  reason text:=btrim(p_reason);
begin
  if not sectalk_private.st_v6_case_collaboration_access(p_report) or current_tier=0 then
    raise exception 'Case escalation is unavailable' using errcode='42501';
  end if;
  if p_action is null or p_action not in ('route','acknowledge') or p_expected_tier is null
    or p_expected_tier not between 0 and 3 or reason is null or char_length(reason) not between 1 and 500 then
    raise exception 'Choose an escalation action and enter a reason up to 500 characters' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v6_case_escalation',30);
  select r.* into report from public.st_reports r where r.id=p_report for update;
  if report.status not in ('open','reviewing') or not found then
    raise exception 'Only active cases can be routed' using errcode='22023';
  end if;
  select e.* into stage from sectalk_private.st_v6_case_escalations e
    where e.report_id=p_report and e.superseded_at is null;
  if coalesce(stage.tier,0)<>p_expected_tier then
    raise exception 'The case routing changed. Refresh and try again' using errcode='40001';
  end if;
  if current_tier<coalesce(stage.tier,1) then
    raise exception 'Case escalation is unavailable' using errcode='42501';
  end if;
  moment:=clock_timestamp();
  if p_action='acknowledge' then
    if stage.assignee is distinct from actor then
      raise exception 'Only the assigned on-call responder can acknowledge this stage' using errcode='42501';
    end if;
    if stage.acknowledged_at is not null then return; end if;
    update sectalk_private.st_v6_case_escalations set acknowledged_at=moment where id=stage.id;
    insert into sectalk_private.audit(actor,report_id,action,note)
      values(actor,p_report,'case_route_acknowledged',reason);
    return;
  end if;

  if stage.tier=3 then raise exception 'This case is already routed to Platform' using errcode='22023'; end if;
  if stage.id is not null and stage.acknowledged_at is null and stage.acknowledge_by>moment
    and sectalk_private.st_v6_on_call_tier(stage.assignee)>=stage.tier then
    raise exception 'Wait for acknowledgment or the current stage deadline' using errcode='22023';
  end if;
  destination:=coalesce(stage.tier,0)+1;
  select r.user_id into recipient from sectalk_private.st_v6_case_on_call r
    where r.tier=destination and moment>=r.starts_at and moment<r.ends_at
      and r.user_id not in (report.reporter,report.subject)
      and sectalk_private.st_v6_on_call_eligible(r.user_id)
    order by r.starts_at desc,r.user_id limit 1;
  if recipient is null then
    raise exception 'No eligible on-call responder is available for that stage' using errcode='22023';
  end if;
  update sectalk_private.st_v6_case_escalations set superseded_at=moment where id=stage.id;
  insert into sectalk_private.st_v6_case_escalations(report_id,tier,assignee,assigned_at,acknowledge_by,action_by)
    values(p_report,destination,recipient,moment,
      moment+(case destination when 1 then interval '2 hours' when 2 then interval '1 hour' else interval '30 minutes' end),
      moment+(case destination when 1 then interval '24 hours' when 2 then interval '12 hours' else interval '6 hours' end));
  insert into sectalk_private.audit(actor,report_id,action,note)
    values(actor,p_report,'case_routed',format('%s: %s',(array['L1','L2','Platform'])[destination],reason));
  if not sectalk_private.st_v6_quiet_for(recipient,null)
    and sectalk_private.st_v6_notification_enabled(recipient,'security') then
    perform realtime.send('{}'::jsonb,'case_escalation','st:account:'||recipient,true);
  end if;
end $$;

create function public.st_v6_case_escalation_assignments()
returns table(report_id uuid,tier smallint,acknowledge_by timestamptz,action_by timestamptz,acknowledged_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
declare current_tier smallint:=sectalk_private.st_v6_on_call_tier(auth.uid());
begin
  if not coalesce(sectalk_private.st_v6_case_redaction_staff(),false) or current_tier=0 then return; end if;
  return query select e.report_id,e.tier,e.acknowledge_by,e.action_by,e.acknowledged_at
    from sectalk_private.st_v6_case_escalations e join public.st_reports r on r.id=e.report_id
    where e.assignee=auth.uid() and e.superseded_at is null and e.tier<=current_tier and r.status in ('open','reviewing')
      and sectalk_private.st_v6_case_collaboration_access(r.id)
    order by coalesce(case when e.acknowledged_at is null then e.acknowledge_by end,e.action_by),e.id limit 50;
end $$;

revoke all on function sectalk_private.st_v6_on_call_eligible(uuid),sectalk_private.st_v6_on_call_tier(uuid),
  public.st_v6_case_escalation(uuid),public.st_v6_update_case_escalation(uuid,text,smallint,text),
  public.st_v6_case_escalation_assignments() from public,anon,authenticated,service_role;
grant execute on function public.st_v6_case_escalation(uuid),public.st_v6_update_case_escalation(uuid,text,smallint,text),
  public.st_v6_case_escalation_assignments() to authenticated;
commit;
