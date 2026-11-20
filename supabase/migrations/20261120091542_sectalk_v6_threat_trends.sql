begin;

create index st_v6_report_trend_cohort on public.st_reports(category,created_at)
  include(id,reporter,subject);
create index st_v6_report_enforcement on sectalk_private.audit(report_id,created_at)
  where action in ('warn','suspend','restrict','remove');

create function public.st_v6_threat_trends(p_category text)
returns table(week_start date, reports bigint, actioned bigint)
language plpgsql stable security definer set search_path='' as $$
declare
  cutoff_day date := date_trunc('week',now() at time zone 'UTC')::date;
  cutoff timestamptz := cutoff_day::timestamp at time zone 'UTC';
begin
  if public.st_staff_status()<>'verified' or not sectalk_private.st_v2_active(auth.uid()) then
    raise exception 'Verified staff access required' using errcode='42501';
  end if;
  if p_category is null or p_category not in
    ('harassment','threat','scam','impersonation','spam','sexual_content','other') then
    raise exception 'Choose a report category' using errcode='22023';
  end if;

  return query
  with cohort as materialized (
    select date_trunc('week',r.created_at at time zone 'UTC')::date as week,
      r.reporter,r.subject,
      exists(select 1 from sectalk_private.audit a where a.report_id=r.id
        and a.created_at<cutoff and a.action in ('warn','suspend','restrict','remove')) as enforced
    from public.st_reports r
    where r.category=p_category and r.created_at>=cutoff-interval '1344 hours' and r.created_at<cutoff
  ), totals as (
    select c.week, count(*) as filed, count(*) filter(where c.enforced) as acted,
      count(distinct c.reporter) as reporters, count(distinct c.subject) as subjects,
      count(distinct c.reporter) filter(where c.enforced) as acted_reporters,
      count(distinct c.subject) filter(where c.enforced) as acted_subjects
    from cohort c group by c.week
  )
  select cutoff_day-w.weeks_ago*7,
    case when t.reporters>=5 and t.subjects>=5 then (t.filed/5)*5 end,
    case when t.acted_reporters>=5 and t.acted_subjects>=5 then (t.acted/5)*5 end
  from generate_series(1,8) w(weeks_ago) left join totals t on t.week=cutoff_day-w.weeks_ago*7
  order by w.weeks_ago;
end
$$;

revoke all on function public.st_v6_threat_trends(text) from public,anon,authenticated;
grant execute on function public.st_v6_threat_trends(text) to authenticated;

commit;
