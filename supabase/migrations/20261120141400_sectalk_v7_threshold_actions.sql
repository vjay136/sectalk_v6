begin;

alter table public.st_reports add column requested_priority boolean not null default false;
create unique index st_v7_priority_direct_report_once on public.st_reports(reporter,message_id)
  where requested_priority;
alter table public.st_reports add constraint st_v7_priority_report_scope
  check(not requested_priority or (chat_id is not null and message_id is not null and category in ('threat','sexual_content')));

create function public.st_v7_request_priority_message_review(p_chat uuid,p_message uuid,p_revision timestamptz,
  p_category text,p_details text,p_share_file boolean default false)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); message_row public.st_messages; report_id uuid;
begin
  if not coalesce(sectalk_private.st_v2_active(actor),false)
    or not coalesce(sectalk_private.member(p_chat,actor),false) then
    raise exception using errcode='42501',message='This message is unavailable';
  end if;
  select m.* into message_row from public.st_messages m where m.chat_id=p_chat and m.id=p_message
    and m.sender<>actor and m.expires_at is null and m.revoked_at is null for update;
  if not found or p_revision is distinct from coalesce(message_row.edited_at,message_row.created_at)
    or exists(select 1 from public.st_v5_hidden_messages h where h.user_id=actor and h.message_id=p_message) then
    raise exception using errcode='42501',message='This message is unavailable or has changed';
  end if;
  if p_category is null or p_category not in ('threat','sexual_content') then
    raise exception using errcode='22023',message='Choose a threat or sexual-content category to request urgent review';
  end if;
  select r.id into report_id from public.st_reports r where r.reporter=actor and r.message_id=p_message and r.requested_priority;
  if report_id is not null then return report_id; end if;
  perform sectalk_private.limit_action('priority_message_review',2);
  report_id:=public.st_v5_report(p_chat,p_message,p_category,p_details,p_share_file);
  update public.st_reports set requested_priority=true where id=report_id and reporter=actor;
  return report_id;
end
$$;

revoke all on function public.st_v7_request_priority_message_review(uuid,uuid,timestamptz,text,text,boolean) from public,anon;
grant execute on function public.st_v7_request_priority_message_review(uuid,uuid,timestamptz,text,text,boolean) to authenticated;

create function public.st_v7_priority_abuse_queue(
  p_category text default null,p_status text default 'active',p_due text default 'any',p_offset integer default 0
)
returns table(id uuid,subject_handle text,category text,status text,created_at timestamptz,
  acknowledge_by timestamptz,resolve_by timestamptz,acknowledged_at timestamptz,closed_at timestamptz,
  next_due timestamptz,overdue boolean,requested_priority boolean)
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
    select r.id,r.subject,r.category,r.status,r.created_at,r.requested_priority,
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
    r.deadline,coalesce(r.deadline<=now(),false),r.requested_priority
  from clocks r join public.st_profiles p on p.id=r.subject
  where p_due='any' or (p_due='overdue' and r.deadline<=now())
    or (p_due='next_day' and r.deadline>now() and r.deadline<=now()+interval '24 hours')
  order by (r.requested_priority and r.status in ('open','reviewing')) desc,r.deadline asc nulls last,r.created_at desc,r.id
  limit 51 offset p_offset;
end $$;

revoke all on function public.st_v7_priority_abuse_queue(text,text,text,integer) from public,anon,authenticated;
grant execute on function public.st_v7_priority_abuse_queue(text,text,text,integer) to authenticated;

commit;
