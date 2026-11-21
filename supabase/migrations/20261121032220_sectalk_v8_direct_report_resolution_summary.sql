begin;

create table sectalk_private.st_v8_direct_report_resolution_summaries (
  decision bigint primary key references sectalk_private.audit(id) on delete cascade,
  report uuid not null references public.st_reports(id) on delete cascade,
  summary text not null check(char_length(summary) between 4 and 500)
);
alter table sectalk_private.st_v8_direct_report_resolution_summaries enable row level security;
revoke all on sectalk_private.st_v8_direct_report_resolution_summaries from public,anon,authenticated,service_role;
create trigger st_v8_reporter_summary_immutable before update on sectalk_private.st_v8_direct_report_resolution_summaries
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

create function public.st_v8_resolve_direct_report(p_report uuid,p_action text,p_staff_note text,p_reporter_summary text)
returns void language plpgsql security definer set search_path='' as $$
declare r public.st_reports; decision_id bigint; staff_actor uuid:=auth.uid();
  shared_summary text:=btrim(p_reporter_summary,E' \t\r\n');
begin
  if not coalesce(sectalk_private.st_v6_case_redaction_staff(),false)
    or not coalesce(public.st_v7_current_session_valid(),false)
    or public.st_v7_login_risk_status() is distinct from 'clear' or public.st_v7_account_under_lockdown() then
    raise exception 'Verified staff access is required' using errcode='42501'; end if;
  if p_action is null or p_action not in ('resolved','dismissed') or shared_summary is null
    or char_length(shared_summary) not between 4 and 500
    or p_staff_note is null or char_length(btrim(p_staff_note)) not between 4 and 500 then
    raise exception 'Enter a separate staff reason and reporter summary of 4–500 characters' using errcode='22023'; end if;

  select * into r from public.st_reports x where x.id=p_report and x.chat_id is not null and x.group_chat_id is null for update;
  if r.id is null or staff_actor in (r.reporter,r.subject) then raise exception 'Direct report unavailable' using errcode='42501'; end if;
  if r.status not in ('open','reviewing') then raise exception 'This report already has a final decision' using errcode='PT409'; end if;

  -- Keep the existing case transition and its internal audit separate from the deliberately shared summary.
  perform public.st_v5_moderate(p_report,p_action,p_staff_note);
  select a.id into strict decision_id from sectalk_private.audit a
    where (a.report_id,a.actor,a.action)=(r.id,staff_actor,p_action) order by a.id desc limit 1;
  insert into sectalk_private.st_v8_direct_report_resolution_summaries(decision,report,summary)
    values(decision_id,r.id,shared_summary);
end $$;

create function public.st_v8_my_message_report_timeline(p_report uuid)
returns table(action text,at timestamptz,summary text)
language sql stable security definer set search_path='' as $$
  with owned as materialized (
    select r.id,r.created_at,r.chat_id is not null as direct from public.st_reports r where r.id=p_report
      and r.reporter=auth.uid() and public.st_v7_current_session_valid()
      and public.st_v7_login_risk_status()='clear' and not public.st_v7_account_under_lockdown()
  ), entries as (
    select 'submitted'::text action,r.created_at at,null::text summary,0::bigint id from owned r
    union all
    select a.action,a.created_at,case when r.direct and a.action in ('resolved','dismissed') then d.summary end,a.id
    from owned r join sectalk_private.audit a on a.report_id=r.id
    left join sectalk_private.st_v8_direct_report_resolution_summaries d on (d.report,d.decision)=(r.id,a.id)
    where a.action in ('reviewing','escalated','warn','suspend','restrict','remove','restore','resolved','dismissed','redacted')
  )
  select e.action,e.at,e.summary from entries e order by e.at desc,e.id desc limit 100;
$$;

create or replace function public.st_v5_case(p_report uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare result jsonb; attachment jsonb; report_scope text;
begin
  result:=public.st_case(p_report);
  select jsonb_build_object('id',f.id,'filename',f.filename,'size_bytes',f.size_bytes) into attachment
    from sectalk_private.st_v5_attachment_reports e join public.st_v5_files f on f.id=e.file_id where e.report_id=p_report;
  select case when r.group_chat_id is null then 'direct' else 'group' end into report_scope from public.st_reports r where r.id=p_report;
  return result||jsonb_build_object('attachment',attachment,
    'message_redaction_available',sectalk_private.st_v6_case_redaction_available(p_report),'report_scope',report_scope);
end $$;

revoke all on function public.st_v8_resolve_direct_report(uuid,text,text,text),public.st_v8_my_message_report_timeline(uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_resolve_direct_report(uuid,text,text,text),public.st_v8_my_message_report_timeline(uuid) to authenticated;
notify pgrst,'reload schema';
commit;
