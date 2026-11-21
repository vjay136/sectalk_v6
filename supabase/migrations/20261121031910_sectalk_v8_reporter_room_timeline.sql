begin;

create function public.st_v8_my_room_report_timeline(p_report uuid)
returns table(action text,at timestamptz,scope text)
language sql stable security definer set search_path='' as $$
  with owned as materialized (
    select r.id,r.workspace_id,r.created_at,r.share_with_workspace,r.handed_off_at
    from sectalk_private.st_v6_room_reports r
    where r.id=p_report and r.reporter=auth.uid()
      and public.st_v7_current_session_valid() and public.st_v7_login_risk_status()='clear'
      and not public.st_v7_account_under_lockdown()
  ), events as (
    select 'submitted'::text action,r.created_at at,null::text scope,0 event_order,0::bigint audit_id from owned r
    union all
    select 'reviewing',a.occurred_at,'platform',1,a.id from owned r
    cross join lateral (
      select h.id,h.occurred_at from sectalk_private.st_v6_room_report_audit h
      where h.report_id=r.id and h.source='platform' and h.action in ('reviewing','route_l1')
      order by h.occurred_at,h.id limit 1
    ) a
    union all
    select 'handoff',r.handed_off_at,'workspace',2,0 from owned r
    where r.share_with_workspace and r.handed_off_at is not null
    union all
    select 'returned_to_platform',a.occurred_at,'platform',3,a.id from owned r
    join sectalk_private.st_v6_room_report_audit a on a.report_id=r.id and a.action='route_platform' and a.source='workspace'
    where r.share_with_workspace and r.handed_off_at is not null and a.occurred_at>=r.handed_off_at
    union all
    select 'quarantined',x.decided_at,'workspace',4,0 from owned r
    join sectalk_private.st_v7_soc_responses x on (x.case_id,x.workspace)=(r.id,r.workspace_id)
      and x.action='quarantine_room_post' and x.decision='executed'
    where r.share_with_workspace and r.handed_off_at is not null and x.decided_at>=r.handed_off_at
    union all
    select a.action,a.occurred_at,a.source,5,a.id from owned r
    join sectalk_private.st_v6_room_report_audit a on a.report_id=r.id and a.action in ('resolved','dismissed')
    where a.source='platform' or (a.source='workspace' and r.share_with_workspace and r.handed_off_at is not null
      and a.occurred_at>=r.handed_off_at)
  )
  select e.action,e.at,e.scope from events e order by e.at,e.event_order,e.audit_id limit 100;
$$;

revoke all on function public.st_v8_my_room_report_timeline(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_my_room_report_timeline(uuid) to authenticated;
notify pgrst,'reload schema';
commit;
