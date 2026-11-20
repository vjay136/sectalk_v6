begin;

create index st_v6_report_queue_filters
  on public.st_reports(status,category,created_at,id);
create index st_v6_report_sla_audit
  on sectalk_private.audit(report_id,created_at)
  where action in ('reviewing','escalated','warn','suspend','restrict','remove','restore','resolved','dismissed','redacted');

create function public.st_v6_abuse_queue(
  p_category text default null,p_status text default 'active',p_due text default 'any',p_offset integer default 0
)
returns table(id uuid,subject_handle text,category text,status text,created_at timestamptz,
  acknowledge_by timestamptz,resolve_by timestamptz,acknowledged_at timestamptz,closed_at timestamptz,
  next_due timestamptz,overdue boolean)
language plpgsql stable security definer set search_path='' as $$
begin
  if sectalk_private.st_v6_case_redaction_staff() is not true then
    raise exception 'Verified staff access is required' using errcode='42501';
  end if;
  if (p_category is not null and p_category not in ('harassment','threat','scam','impersonation','spam','sexual_content','other'))
    or p_status is null or p_status not in ('active','open','reviewing','closed','resolved','dismissed','any')
    or p_due is null or p_due not in ('any','overdue','next_day')
    or p_offset is null or p_offset not between 0 and 10000
  then raise exception 'Choose valid moderation queue filters' using errcode='22023'; end if;

  return query
  with reports as (
    select r.id,r.subject,r.category,r.status,r.created_at,
      r.created_at+case
        when r.category in ('threat','sexual_content') then interval '2 hours'
        when r.category='other' then interval '24 hours'
        else interval '8 hours' end ack_due,
      r.created_at+case
        when r.category in ('threat','sexual_content') then interval '24 hours'
        when r.category='other' then interval '168 hours'
        else interval '72 hours' end action_due,
      a.first_decision,
      case when r.status in ('resolved','dismissed') then a.last_closure end last_closure
    from public.st_reports r cross join lateral (
      select min(h.created_at) first_decision,
        max(h.created_at) filter(where h.action in ('resolved','dismissed')) last_closure
      from sectalk_private.audit h where h.report_id=r.id
        and h.action in ('reviewing','escalated','warn','suspend','restrict','remove','restore','resolved','dismissed','redacted')
    ) a
    where (p_category is null or r.category=p_category)
      and (p_status='any' or p_status=r.status or (p_status='active' and r.status in ('open','reviewing'))
        or (p_status='closed' and r.status in ('resolved','dismissed')))
  ), clocks as (
    select r.*,case when r.status in ('open','reviewing')
      then case when r.first_decision is null then r.ack_due else r.action_due end end deadline
    from reports r
  )
  select r.id,p.handle,r.category,r.status,r.created_at,r.ack_due,r.action_due,r.first_decision,r.last_closure,
    r.deadline,coalesce(r.deadline<=now(),false)
  from clocks r join public.st_profiles p on p.id=r.subject
  where p_due='any' or (p_due='overdue' and r.deadline<=now())
    or (p_due='next_day' and r.deadline>now() and r.deadline<=now()+interval '24 hours')
  order by r.deadline asc nulls last,r.created_at desc,r.id
  limit 51 offset p_offset;
end $$;

revoke all on function public.st_v6_abuse_queue(text,text,text,integer) from public,anon,authenticated;
grant execute on function public.st_v6_abuse_queue(text,text,text,integer) to authenticated;

commit;
