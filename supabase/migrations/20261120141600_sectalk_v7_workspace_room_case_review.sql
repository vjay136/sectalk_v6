begin;

alter table sectalk_private.st_v6_room_report_audit drop constraint st_v6_room_report_audit_action_check,
  add constraint st_v6_room_report_audit_action_check check(action in
  ('handoff','reviewing','resolved','dismissed','route_l1','route_l2','route_platform','acknowledge_l1',
   'acknowledge_l2','acknowledge_workspace','acknowledge_platform','workspace_reassigned'));

create table sectalk_private.st_v7_room_review_assignments (
  id bigint generated always as identity primary key,
  report_id uuid not null references sectalk_private.st_v6_room_reports on delete cascade,
  previous uuid references public.st_profiles on delete set null,
  assigned uuid references public.st_profiles on delete set null,
  reason text not null check(char_length(reason) between 4 and 500),
  transferred_at timestamptz not null default clock_timestamp(),
  check(previous<>assigned)
);
alter table sectalk_private.st_v7_room_review_assignments enable row level security;
revoke all on sectalk_private.st_v7_room_review_assignments from public,anon,authenticated,service_role;

create function public.st_v7_workspace_room_review_queue()
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
      and sectalk_private.st_v6_room_report_admin(r.workspace_id,r.room_id,actor)
    order by r.created_at desc,r.id limit 100
  ) q),'[]');
end
$$;

create function public.st_v7_workspace_room_reviewers(p_report uuid)
returns table(id uuid,name text,handle text) language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid(); item sectalk_private.st_v6_room_reports;
begin
  select r.* into item from sectalk_private.st_v6_room_reports r
    where r.id=p_report and r.share_with_workspace and r.handed_off_at is not null and r.status in ('open','reviewing')
      and r.reporter<>actor and r.subject is distinct from actor;
  if not found or public.st_v6_room_report_review_access()<>'verified'
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

create function public.st_v7_workspace_room_case_action(p_report uuid,p_action text,p_reason text,
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
     or actor is not distinct from item.subject or not sectalk_private.st_v6_room_report_admin(item.workspace_id,item.room_id,actor) then
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

create function public.st_v7_my_room_report_status()
returns table(id uuid,category text,status text,created_at timestamptz,share_with_workspace boolean,handed_off_at timestamptz,
  decision_scope text,decided_at timestamptz)
language sql stable security definer set search_path='' as $$
  select r.id,r.category,r.status,r.created_at,r.share_with_workspace,r.handed_off_at,a.source,a.occurred_at
  from sectalk_private.st_v6_room_reports r
  left join lateral (
    select audit.source,audit.occurred_at from sectalk_private.st_v6_room_report_audit audit
    where audit.report_id=r.id and r.status in ('resolved','dismissed') and audit.action=r.status
    order by audit.occurred_at desc,audit.id desc limit 1
  ) a on true
  where r.reporter=auth.uid() order by r.created_at desc,r.id limit 100
$$;

revoke all on function public.st_v7_workspace_room_review_queue(),public.st_v7_workspace_room_reviewers(uuid),
  public.st_v7_workspace_room_case_action(uuid,text,text,timestamptz,uuid),public.st_v7_my_room_report_status()
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_workspace_room_review_queue(),public.st_v7_workspace_room_reviewers(uuid),
  public.st_v7_workspace_room_case_action(uuid,text,text,timestamptz,uuid),public.st_v7_my_room_report_status() to authenticated;
commit;
