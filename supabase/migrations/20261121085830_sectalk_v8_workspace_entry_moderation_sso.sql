begin;

-- Gate workspace reviewer operations using the caller session. Platform routing and reporter status have separate authorization.

create or replace function public.st_v6_room_report_queue_legacy(p_scope text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
begin
  if p_scope='platform' then
    if not coalesce(sectalk_private.st_v6_case_redaction_staff(),false) then
      raise exception 'Room report review is unavailable' using errcode='42501';
    end if;
    return coalesce((select jsonb_agg(to_jsonb(q) order by q.created_at desc,q.id) from (
      select rr.id,rr.category,rr.status,rr.created_at,rr.details,rr.share_with_workspace,rr.handed_off_at,
        r.name as room_name,p.body as evidence
      from sectalk_private.st_v6_room_reports rr left join public.st_v6_rooms r
        on r.id=rr.room_id and r.workspace_id=rr.workspace_id
      left join public.st_v6_room_posts p on p.room_id=r.id and p.id=rr.post_id
        and p.removed_at is null and p.sender=rr.subject
      where rr.reporter<>auth.uid() and rr.subject is distinct from auth.uid()
      order by rr.created_at desc,rr.id limit 100
    ) q),'[]');
  elsif p_scope='workspace' then
    if public.st_v6_room_report_review_access()<>'verified' then
      raise exception 'Room report review is unavailable' using errcode='42501';
    end if;
    return coalesce((select jsonb_agg(to_jsonb(q) order by q.created_at desc,q.id) from (
      select rr.id,rr.category,rr.status,rr.created_at,rr.handed_off_at,r.name as room_name,
        w.name as workspace_name,p.body as evidence
      from sectalk_private.st_v6_room_reports rr join public.st_v6_rooms r
        on r.id=rr.room_id and r.workspace_id=rr.workspace_id
      join public.st_v2_workspaces w on w.id=r.workspace_id
      left join public.st_v6_room_posts p on p.room_id=r.id and p.id=rr.post_id
        and p.removed_at is null and p.sender=rr.subject
      where rr.share_with_workspace and rr.handed_off_at is not null
        and rr.reporter<>auth.uid() and rr.subject is distinct from auth.uid()
        and sectalk_private.st_v8_entry_sso_allows(rr.workspace_id)
        and sectalk_private.st_v6_room_report_admin(rr.workspace_id,rr.room_id,auth.uid())
      order by rr.created_at desc,rr.id limit 100
    ) q),'[]');
  end if;
  raise exception 'Choose a valid room report queue' using errcode='22023';
end $$;

create or replace function public.st_v6_review_room_report(
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
    or not sectalk_private.st_v8_entry_sso_allows(item.workspace_id)
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

create or replace function public.st_v7_workspace_room_review_queue()
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if public.st_v6_room_report_review_access() <> 'verified' then
    raise exception using errcode='42501',message='Room report review is unavailable';
  end if;
  return coalesce((select jsonb_agg(to_jsonb(q) order by q.created_at desc,q.id) from (
    select r.id,r.category,r.status,r.created_at,r.handed_off_at,r.share_with_workspace,room.name as room_name,
      w.name as workspace_name,p.body as evidence,s.stage,s.assigned_at,s.acknowledge_by,s.action_by,s.acknowledged_at,
      true as assigned_to_you, (r.status in ('open','reviewing') and s.acknowledged_at is null) as can_acknowledge,
      (r.status in ('open','reviewing') and (s.acknowledged_at is not null or s.acknowledge_by<=now())) as can_route,
      (r.status in ('open','reviewing') and s.acknowledged_at is not null) as can_delegate,
      (r.status in ('open','reviewing') and s.acknowledged_at is not null and r.category in ('spam','other')) as can_decide
    from sectalk_private.st_v6_room_report_stages s
    join sectalk_private.st_v6_room_reports r on r.id=s.report_id
    join public.st_v6_rooms room on room.id=r.room_id and room.workspace_id=r.workspace_id
    join public.st_v2_workspaces w on w.id=r.workspace_id
    left join public.st_v6_room_posts p on p.room_id=r.room_id and p.id=r.post_id
      and p.removed_at is null and p.sender=r.subject
    where s.assignee=actor and s.stage=3 and r.share_with_workspace and r.handed_off_at is not null
      and r.reporter<>actor and r.subject is distinct from actor
      and not exists(select 1 from sectalk_private.st_v6_room_report_stages newer where newer.report_id=r.id and newer.stage>3)
      and sectalk_private.st_v8_entry_sso_allows(r.workspace_id)
      and sectalk_private.st_v6_room_report_admin(r.workspace_id,r.room_id,actor)
    order by r.created_at desc,r.id limit 100
  ) q),'[]');
end
$$;

create or replace function public.st_v7_workspace_room_reviewers(p_report uuid)
returns table(id uuid,name text,handle text) language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid(); item sectalk_private.st_v6_room_reports;
begin
  select r.* into item from sectalk_private.st_v6_room_reports r
    where r.id=p_report and r.share_with_workspace and r.handed_off_at is not null and r.status in ('open','reviewing')
      and r.reporter<>actor and r.subject is distinct from actor;
  if not found or public.st_v6_room_report_review_access()<>'verified'
    or not sectalk_private.st_v8_entry_sso_allows(item.workspace_id)
    or not sectalk_private.st_v6_room_report_admin(item.workspace_id,item.room_id,actor) or not exists(
      select 1 from sectalk_private.st_v6_room_report_stages s where s.report_id=p_report and s.stage=3
      and s.assignee=actor and s.acknowledged_at is not null
      and not exists(select 1 from sectalk_private.st_v6_room_report_stages newer where newer.report_id=p_report and newer.stage>3)
    ) then raise exception using errcode='42501',message='Room assignment is unavailable'; end if;
  return query select p.id,p.name,p.handle from public.st_v2_members m join public.st_profiles p on p.id=m.user_id
    where m.workspace_id=item.workspace_id and m.user_id<>actor and m.user_id<>item.reporter
      and m.user_id is distinct from item.subject
      and sectalk_private.st_v6_room_report_admin(item.workspace_id,item.room_id,m.user_id)
      and sectalk_private.st_v6_on_call_eligible(m.user_id)
    order by p.name,p.id limit 50;
end
$$;

create or replace function public.st_v7_workspace_room_case_action(p_report uuid,p_action text,p_reason text,
  p_expected_assignment timestamptz,p_reviewer uuid default null)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); item sectalk_private.st_v6_room_reports;
  assignment sectalk_private.st_v6_room_report_stages; reason text:=btrim(p_reason); moment timestamptz;
begin
  if public.st_v6_room_report_review_access()<>'verified' then
    raise exception using errcode='42501',message='Room review is unavailable';
  end if;
  select r.* into item from sectalk_private.st_v6_room_reports r where r.id=p_report for update;
  if not found or not item.share_with_workspace or item.handed_off_at is null or actor=item.reporter
     or actor is not distinct from item.subject or not sectalk_private.st_v8_entry_sso_allows(item.workspace_id)
     or not sectalk_private.st_v6_room_report_admin(item.workspace_id,item.room_id,actor) then
    raise exception using errcode='42501',message='Room review is unavailable';
  end if;
  select s.* into assignment from sectalk_private.st_v6_room_report_stages s
    where s.report_id=p_report order by s.stage desc limit 1 for update;
  if not found or assignment.stage<>3 or assignment.assignee<>actor or assignment.acknowledged_at is null then
    raise exception using errcode='42501',message='Only the acknowledged assignee can perform this action';
  end if;
  if assignment.assigned_at is distinct from p_expected_assignment then
    raise exception using errcode='40001',message='The assignment has changed. Refresh and try again.';
  end if;
  if item.status not in ('open','reviewing') or p_action is null or p_action not in ('delegate','resolved','dismissed')
    or reason is null or char_length(reason) not between 4 and 500 then
    raise exception using errcode='22023',message='Choose a review action and enter a reason between 4 and 500 characters';
  end if;
  if p_action='delegate' then
    if p_reviewer is null or p_reviewer in (actor,item.reporter) or p_reviewer is not distinct from item.subject
      or not sectalk_private.st_v6_room_report_admin(item.workspace_id,item.room_id,p_reviewer)
      or not sectalk_private.st_v6_on_call_eligible(p_reviewer) then
      raise exception using errcode='42501',message='The selected reviewer is unavailable for this room';
    end if;
    perform sectalk_private.limit_action('workspace_room_case_delegate',12);
    moment:=clock_timestamp();
    update sectalk_private.st_v6_room_report_stages set assignee=p_reviewer,assigned_at=moment,
      acknowledge_by=least(action_by,moment+interval '2 hours'),acknowledged_at=null where report_id=p_report and stage=3;
    insert into sectalk_private.st_v7_room_review_assignments(report_id,previous,assigned,reason,transferred_at)
      values(p_report,actor,p_reviewer,reason,moment);
    insert into sectalk_private.st_v6_room_report_audit(report_id,actor,action,source,reason)
      values(p_report,actor,'workspace_reassigned','workspace',reason);
    if not sectalk_private.st_v6_quiet_for(p_reviewer,null) and sectalk_private.st_v6_notification_enabled(p_reviewer,'security') then
      perform realtime.send('{}','workspace_room_report','st:account:'||p_reviewer,true);
    end if;
  else
    if p_reviewer is not null or item.category not in ('spam','other') then
      raise exception using errcode='42501',message='This case requires Platform review';
    end if;
    perform public.st_v6_review_room_report_legacy(p_report,'workspace',p_action,reason);
    perform realtime.send('{}','room_report_decided','st:account:'||item.reporter,true);
  end if;
end
$$;

commit;
