begin;

create index st_v6_security_reports_period on public.st_reports(created_at,category) include(id,reporter,subject);

-- Apply the same reporting cohorts and rounding as Threat trends to a single closed UTC period.
create function sectalk_private.st_v6_security_report_cohort(p_start timestamptz,p_end timestamptz)
returns table(category text,reports bigint,actioned bigint)
language sql stable set search_path='' as $$
  with categories as (
    select c.category,c.position from unnest(array[
      'harassment','threat','scam','impersonation','spam','sexual_content','other'
    ]) with ordinality c(category,position)
  ), cohort as materialized (
    select r.category,r.reporter,r.subject,
      exists(select 1 from sectalk_private.audit a where a.report_id=r.id
        and a.created_at<p_end and a.action in ('warn','suspend','restrict','remove')) as enforced
    from public.st_reports r where r.created_at>=p_start and r.created_at<p_end
  ), totals as (
    select c.category,count(*) as filed,count(*) filter(where c.enforced) as acted,
      count(distinct c.reporter) as reporters,count(distinct c.subject) as subjects,
      count(distinct c.reporter) filter(where c.enforced) as acted_reporters,
      count(distinct c.subject) filter(where c.enforced) as acted_subjects
    from cohort c group by c.category
  )
  select c.category,
    case when t.reporters>=5 and t.subjects>=5 then (t.filed/5)*5 end,
    case when t.acted_reporters>=5 and t.acted_subjects>=5 then (t.acted/5)*5 end
  from categories c left join totals t on t.category=c.category
  order by c.position
$$;

create function public.st_v6_security_report(p_period text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare
  closed_at date;
  opened_at date;
  rows jsonb;
begin
  if not sectalk_private.st_v6_operational_report_access() then
    raise exception 'MFA-verified staff access required' using errcode='42501';
  end if;
  if p_period='daily' then
    closed_at:=(now() at time zone 'UTC')::date;
    opened_at:=closed_at-1;
  elsif p_period='weekly' then
    closed_at:=date_trunc('week',now() at time zone 'UTC')::date;
    opened_at:=closed_at-7;
  else
    raise exception 'Choose a daily or weekly security report' using errcode='22023';
  end if;
  select jsonb_agg(to_jsonb(report) order by report.category) into rows
  from sectalk_private.st_v6_security_report_cohort(
    opened_at::timestamp at time zone 'UTC',closed_at::timestamp at time zone 'UTC') report;
  return jsonb_build_object('period',p_period,'period_start',opened_at,'period_end',closed_at,'rows',rows);
end
$$;

revoke all on function sectalk_private.st_v6_security_report_cohort(timestamptz,timestamptz),
  public.st_v6_security_report(text) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_security_report(text) to authenticated;

commit;
