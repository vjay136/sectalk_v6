begin;

create index st_v6_usage_message_times on public.st_messages(created_at) include(sender);
create index st_v6_usage_call_times on public.st_calls(created_at) include(caller);
create index st_v6_usage_meeting_times on public.st_v3_meetings(created_at) include(host_id);
create index st_v6_usage_completion_times on public.st_v6_task_audit(created_at) include(actor_id)
  where action='status' and detail->>'to'='done';

create function public.st_v6_usage_metrics(p_window text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare
  cutoff timestamptz:=date_trunc('day',now(),'UTC');
  begins timestamptz;
  metrics jsonb;
begin
  if public.st_staff_status()<>'verified' or not sectalk_private.st_v2_active(auth.uid())
    then raise exception 'Verified staff access required' using errcode='42501'; end if;
  begins:=case p_window when '7d' then cutoff-interval '168 hours' when '30d' then cutoff-interval '720 hours' end;
  if begins is null then raise exception 'Choose 7 days or 30 days' using errcode='22023'; end if;

  with events as materialized (
    select 'messages'::text as kind,m.sender as actor from public.st_messages m
      where m.created_at>=begins and m.created_at<cutoff
    union all select 'calls',c.caller from public.st_calls c where c.created_at>=begins and c.created_at<cutoff
    union all select 'meetings',m.host_id from public.st_v3_meetings m where m.created_at>=begins and m.created_at<cutoff
    union all select 'tasks',a.actor_id from public.st_v6_task_audit a
      where a.created_at>=begins and a.created_at<cutoff and a.action='status' and a.detail->>'to'='done'
  ), totals as (
    select e.kind,count(*) as volume,count(distinct e.actor) as people from events e group by e.kind
    union all select 'accounts',count(distinct e.actor),count(distinct e.actor) from events e
  )
  select coalesce(jsonb_object_agg(t.kind,(t.volume/10)*10) filter(where t.volume>=10 and t.people>=5),'{}'::jsonb)
    into metrics from totals t;
  return jsonb_build_object('through',cutoff,'metrics',metrics);
end $$;

revoke all on function public.st_v6_usage_metrics(text) from public,anon,authenticated;
grant execute on function public.st_v6_usage_metrics(text) to authenticated;

commit;
