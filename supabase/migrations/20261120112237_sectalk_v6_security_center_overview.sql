begin;

create index st_v6_case_milestones_recent on sectalk_private.audit(created_at,report_id)
  where action in ('reviewing','escalated','warn','suspend','restrict','remove','resolved','dismissed');
create index st_v6_case_milestones_by_report on sectalk_private.audit(report_id,created_at) include(action)
  where action in ('reviewing','escalated','warn','suspend','restrict','remove','resolved','dismissed');

create function sectalk_private.st_v6_case_response_averages(p_start timestamptz,p_end timestamptz)
returns jsonb language sql stable set search_path='' as $$
  with cohort as materialized (
    select distinct a.report_id from sectalk_private.audit a
    where a.created_at>=p_start and a.created_at<p_end
      and a.action in ('reviewing','escalated','warn','suspend','restrict','remove','resolved','dismissed')
  ), events as (
    select r.reporter,r.subject,r.created_at,first.acknowledged,first.resolved
    from cohort c join public.st_reports r on r.id=c.report_id
    cross join lateral (
      select min(a.created_at) as acknowledged,
        min(a.created_at) filter(where a.action in ('resolved','dismissed')) as resolved
      from sectalk_private.audit a
      where a.report_id=r.id and a.created_at>=r.created_at and a.created_at<p_end
        and a.action in ('reviewing','escalated','warn','suspend','restrict','remove','resolved','dismissed')
    ) first
  ), samples as (
    select 'acknowledgement' as kind,reporter,subject,acknowledged-created_at as elapsed
      from events where acknowledged>=p_start
    union all
    select 'resolution',reporter,subject,resolved-created_at from events where resolved>=p_start
  ), totals as (
    select kind,count(*) as samples,round(avg(extract(epoch from elapsed))/60)::bigint as minutes
    from samples group by kind having count(distinct reporter)>=5 and count(distinct subject)>=5
  )
  select jsonb_build_object(
    'since',p_start,'until',p_end,
    'acknowledgement',(select jsonb_build_object('minutes',minutes,'samples',samples) from totals where kind='acknowledgement'),
    'resolution',(select jsonb_build_object('minutes',minutes,'samples',samples) from totals where kind='resolution'))
$$;

create function sectalk_private.st_v6_overview_report_trend(p_closed_week date)
returns jsonb language sql stable set search_path='' as $$
  with totals as (
    select date_trunc('week',r.created_at at time zone 'UTC')::date as week_start,
      (count(*)/5)*5 as reports
    from public.st_reports r
    where r.created_at>=(p_closed_week-56)::timestamp at time zone 'UTC'
      and r.created_at<p_closed_week::timestamp at time zone 'UTC'
    group by 1 having count(distinct r.reporter)>=5 and count(distinct r.subject)>=5
  )
  select jsonb_agg(jsonb_build_object('week_start',p_closed_week-n.weeks_ago*7,'reports',t.reports)
    order by p_closed_week-n.weeks_ago*7)
  from generate_series(1,8) n(weeks_ago) left join totals t on t.week_start=p_closed_week-n.weeks_ago*7
$$;

create function public.st_v6_security_center_overview()
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  incident_role text;
  incident_scope text;
  incidents bigint;
  open_cases bigint;
  reviewing_cases bigint;
  as_of timestamptz:=statement_timestamp();
  closed_week date:=date_trunc('week',as_of at time zone 'UTC')::date;
begin
  if not coalesce(sectalk_private.st_v6_operational_report_access(),false) then
    raise exception 'MFA-verified staff access required' using errcode='42501';
  end if;
  select count(*) filter(where r.status='open'),count(*) filter(where r.status='reviewing')
    into open_cases,reviewing_cases from public.st_reports r where r.status in ('open','reviewing');
  incident_role:=public.st_v6_incident_access();
  if incident_role in ('lead','responder') then
    incident_scope:=case when incident_role='lead' then 'all' else 'assigned_or_created' end;
    select count(*) into incidents from sectalk_private.st_v6_security_incidents i
    where i.status<>'resolved' and (incident_role='lead' or actor in (i.created_by,i.assigned_to));
  end if;
  return jsonb_build_object(
    'as_of',as_of,'open_cases',open_cases,'reviewing_cases',reviewing_cases,'queue_depth',open_cases+reviewing_cases,
    'open_incidents',incidents,'incident_scope',incident_scope,
    'trend',sectalk_private.st_v6_overview_report_trend(closed_week),
    'response_times',sectalk_private.st_v6_case_response_averages(as_of-interval '168 hours',as_of));
end
$$;

revoke all on function sectalk_private.st_v6_case_response_averages(timestamptz,timestamptz),
  sectalk_private.st_v6_overview_report_trend(date),
  public.st_v6_security_center_overview() from public,anon,authenticated,service_role;
grant execute on function public.st_v6_security_center_overview() to authenticated;

commit;
