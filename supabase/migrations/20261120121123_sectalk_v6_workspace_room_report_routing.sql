begin;

create table sectalk_private.st_v6_room_report_stages (
  report_id uuid not null references sectalk_private.st_v6_room_reports on delete cascade,
  stage smallint not null check(stage between 1 and 4),
  assignee uuid not null references public.st_profiles,
  assigned_at timestamptz not null,
  acknowledge_by timestamptz not null,
  action_by timestamptz not null,
  acknowledged_at timestamptz,
  primary key(report_id,stage)
);
create index st_v6_room_report_stages_assignee on sectalk_private.st_v6_room_report_stages(assignee,report_id,stage desc);
alter table sectalk_private.st_v6_room_report_stages enable row level security;
revoke all on sectalk_private.st_v6_room_report_stages from public,anon,authenticated,service_role;
alter table sectalk_private.st_v6_room_report_audit drop constraint st_v6_room_report_audit_action_check,
  add constraint st_v6_room_report_audit_action_check check(action in
  ('handoff','reviewing','resolved','dismissed','route_l1','route_l2','route_platform','acknowledge_l1',
   'acknowledge_l2','acknowledge_workspace','acknowledge_platform'));

-- Match existing already-shared reports to one eligible responder without sending another alert.
insert into sectalk_private.st_v6_room_report_stages(report_id,stage,assignee,assigned_at,acknowledge_by,action_by)
select rr.id,3,a.user_id,rr.handed_off_at,rr.handed_off_at+interval '2 hours',rr.handed_off_at+interval '24 hours'
from sectalk_private.st_v6_room_reports rr cross join lateral (
  select m.user_id from public.st_v2_members m where m.workspace_id=rr.workspace_id
    and m.user_id<>rr.reporter and m.user_id is distinct from rr.subject
    and sectalk_private.st_v6_room_report_admin(rr.workspace_id,rr.room_id,m.user_id)
    and sectalk_private.st_v6_on_call_eligible(m.user_id)
  order by m.user_id limit 1
) a where rr.handed_off_at is not null;

create function sectalk_private.st_v6_room_report_stage_operator(
  p_scope text,p_stage smallint,p_workspace uuid,p_room uuid,p_actor uuid
) returns boolean language sql stable set search_path='' as $$
  select case when p_stage=3 then p_scope='workspace'
      and sectalk_private.st_v6_room_report_admin(p_workspace,p_room,p_actor)
      and coalesce(sectalk_private.st_v6_retirement_has_mfa(),false)
    else p_scope='platform' and coalesce(sectalk_private.st_v6_case_redaction_staff(),false)
      and sectalk_private.st_v6_on_call_tier(p_actor)>=least(greatest(p_stage,1),3)
    end
$$;

alter function public.st_v6_room_report_queue(text) rename to st_v6_room_report_queue_legacy;
revoke execute on function public.st_v6_room_report_queue_legacy(text) from authenticated;
create function public.st_v6_room_report_queue(p_scope text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
begin
  return coalesce((select jsonb_agg(
    item.value || jsonb_build_object('stage',s.stage,'acknowledge_by',s.acknowledge_by,
      'action_by',s.action_by,'acknowledged_at',s.acknowledged_at,
      'assigned_to_you',coalesce(s.assignee=auth.uid(),false),
      'can_decide',coalesce(rr.status in ('open','reviewing') and
        (not rr.share_with_workspace or (s.stage=4 and s.assignee=auth.uid() and op.allowed
          and s.acknowledged_at is not null)),false),
      'can_acknowledge',coalesce(s.assignee=auth.uid() and s.acknowledged_at is null
        and rr.status in ('open','reviewing') and op.allowed,false),
      'can_route',coalesce(rr.share_with_workspace and rr.status in ('open','reviewing')
        and coalesce(s.stage,0)<4 and op.allowed
        and (s.stage is null or (s.assignee=auth.uid() and s.acknowledged_at is not null)
          or (s.acknowledge_by<=now() and (s.stage<>3 or s.assignee=auth.uid()))),false)
    ) order by item.ordinality)
    from jsonb_array_elements(public.st_v6_room_report_queue_legacy(p_scope)) with ordinality item(value,ordinality)
    join sectalk_private.st_v6_room_reports rr on rr.id=(item.value->>'id')::uuid
    left join lateral (select t.* from sectalk_private.st_v6_room_report_stages t
      where t.report_id=rr.id order by t.stage desc limit 1) s on true
    cross join lateral (select sectalk_private.st_v6_room_report_stage_operator(
      p_scope,coalesce(s.stage,0::smallint),rr.workspace_id,rr.room_id,auth.uid()) as allowed) op
    where p_scope='platform' or (s.stage=3 and s.assignee=auth.uid())
  ),'[]');
end $$;

alter function public.st_v6_review_room_report(uuid,text,text,text) rename to st_v6_review_room_report_legacy;
revoke execute on function public.st_v6_review_room_report_legacy(uuid,text,text,text) from authenticated;
create function public.st_v6_review_room_report(
  p_report uuid,p_scope text,p_action text,p_reason text,p_expected_stage smallint default null
)
returns void language plpgsql security definer set search_path='' as $$
declare
  item sectalk_private.st_v6_room_reports;
  current_stage sectalk_private.st_v6_room_report_stages;
  actor uuid:=auth.uid();
  moment timestamptz;
  destination smallint;
  recipient uuid;
  reason text:=btrim(p_reason);
  event_name text;
begin
  if not coalesce((p_scope='platform' and coalesce(sectalk_private.st_v6_case_redaction_staff(),false))
    or (p_scope='workspace' and public.st_v6_room_report_review_access()='verified'),false) then
    raise exception 'Room report review is unavailable' using errcode='42501';
  end if;
  select * into item from sectalk_private.st_v6_room_reports where id=p_report for update;
  if not found or actor in (item.reporter,item.subject) then
    raise exception 'Room report review is unavailable' using errcode='42501';
  end if;
  select * into current_stage from sectalk_private.st_v6_room_report_stages
    where report_id=p_report order by stage desc limit 1;
  if p_scope='workspace' and (current_stage.stage is distinct from 3
    or current_stage.assignee is distinct from actor
    or not sectalk_private.st_v6_room_report_admin(item.workspace_id,item.room_id,actor)) then
    raise exception 'Room report review is unavailable' using errcode='42501';
  end if;
  if p_action in ('reviewing','resolved','dismissed') then
    if item.share_with_workspace and (current_stage.stage is distinct from 4
      or current_stage.assignee is distinct from actor or current_stage.acknowledged_at is null
      or not sectalk_private.st_v6_room_report_stage_operator(
        p_scope,current_stage.stage,item.workspace_id,item.room_id,actor)) then
      raise exception 'The assigned Platform responder must acknowledge the final stage before deciding' using errcode='42501';
    end if;
    perform public.st_v6_review_room_report_legacy(p_report,p_scope,p_action,p_reason);
    return;
  end if;
  if p_action not in ('route','acknowledge') or p_action is null or reason is null
    or char_length(reason) not between 1 and 500 or item.status not in ('open','reviewing') then
    raise exception 'Choose an active stage action and enter a reason up to 500 characters' using errcode='22023';
  end if;
  if not item.share_with_workspace or not sectalk_private.st_v6_room_report_stage_operator(
    p_scope,coalesce(current_stage.stage,0::smallint),item.workspace_id,item.room_id,actor) then
    raise exception 'Room report routing is unavailable' using errcode='42501';
  end if;
  if p_expected_stage is distinct from coalesce(current_stage.stage,0) then
    raise exception 'The room report stage changed. Refresh and try again' using errcode='40001';
  end if;
  perform sectalk_private.limit_action('v6_room_report_route',30);
  moment:=clock_timestamp();
  if p_action='acknowledge' then
    if current_stage.assignee is distinct from actor then
      raise exception 'Only the assigned responder can acknowledge this stage' using errcode='42501';
    end if;
    if current_stage.acknowledged_at is not null then return; end if;
    update sectalk_private.st_v6_room_report_stages set acknowledged_at=moment
      where report_id=p_report and stage=current_stage.stage;
    insert into sectalk_private.st_v6_room_report_audit(report_id,actor,action,source,reason)
      values(p_report,actor,(array['acknowledge_l1','acknowledge_l2','acknowledge_workspace',
        'acknowledge_platform'])[current_stage.stage],p_scope,reason);
    return;
  end if;
  if p_action='route' and current_stage.stage is not null
    and not ((current_stage.assignee=actor and current_stage.acknowledged_at is not null)
      or (current_stage.acknowledge_by<=moment and (current_stage.stage<>3 or current_stage.assignee=actor))) then
    raise exception 'An acknowledgment or expired stage deadline is required' using errcode='22023';
  end if;
  destination:=coalesce(current_stage.stage,0)+1;
  if destination>4 then raise exception 'This report is already at the Platform stage' using errcode='22023'; end if;
  if destination=3 then
    select m.user_id into recipient from public.st_v2_members m where m.workspace_id=item.workspace_id
      and m.user_id<>item.reporter and m.user_id is distinct from item.subject
      and sectalk_private.st_v6_room_report_admin(item.workspace_id,item.room_id,m.user_id)
      and sectalk_private.st_v6_on_call_eligible(m.user_id)
    order by (m.role='owner') desc,m.user_id limit 1;
    event_name:='workspace_room_report';
  else
    select r.user_id into recipient from sectalk_private.st_v6_case_on_call r
      where r.tier=least(destination,3) and moment>=r.starts_at and moment<r.ends_at
        and r.user_id<>item.reporter and r.user_id is distinct from item.subject
        and sectalk_private.st_v6_on_call_eligible(r.user_id)
    order by r.starts_at desc,r.user_id limit 1;
    event_name:='room_report_routed';
  end if;
  if recipient is null then raise exception 'No eligible responder is available for the next stage' using errcode='22023'; end if;
  insert into sectalk_private.st_v6_room_report_stages
    (report_id,stage,assignee,assigned_at,acknowledge_by,action_by)
  values(p_report,destination,recipient,moment,
    moment+(array[interval '2 hours',interval '1 hour',interval '2 hours',interval '30 minutes'])[destination],
    moment+(array[interval '24 hours',interval '12 hours',interval '24 hours',interval '6 hours'])[destination]);
  update sectalk_private.st_v6_room_reports set status='reviewing',
    handed_off_at=case when destination=3 then coalesce(handed_off_at,moment) else handed_off_at end
    where id=p_report;
  insert into sectalk_private.st_v6_room_report_audit(report_id,actor,action,source,reason)
    values(p_report,actor,(array['route_l1','route_l2','handoff','route_platform'])[destination],p_scope,reason);
  if not sectalk_private.st_v6_quiet_for(recipient,null)
    and sectalk_private.st_v6_notification_enabled(recipient,'security') then
    perform realtime.send('{}',event_name,'st:account:'||recipient,true);
  end if;
end $$;

revoke all on function sectalk_private.st_v6_room_report_stage_operator(text,smallint,uuid,uuid,uuid),
  public.st_v6_room_report_queue(text),public.st_v6_review_room_report(uuid,text,text,text,smallint)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_room_report_queue(text),public.st_v6_review_room_report(uuid,text,text,text,smallint)
  to authenticated;
commit;
