begin;

-- Submitted room scope is recorded independently of the personal-chat case store.
create table sectalk_private.st_v6_room_reports (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null,
  room_id uuid not null,
  post_id uuid not null,
  reporter uuid not null references public.st_profiles on delete cascade,
  subject uuid references public.st_profiles on delete set null,
  category text not null check(category in ('harassment','threat','scam','impersonation','spam','sexual_content','other')),
  details text not null check(char_length(details)<=1500),
  share_with_workspace boolean not null,
  status text not null default 'open' check(status in ('open','reviewing','resolved','dismissed')),
  created_at timestamptz not null default clock_timestamp(),
  handed_off_at timestamptz,
  check(handed_off_at is null or share_with_workspace),
  unique(reporter,room_id,post_id)
);
create index st_v6_room_reports_staff on sectalk_private.st_v6_room_reports(status,created_at desc,id);
create index st_v6_room_reports_org on sectalk_private.st_v6_room_reports(workspace_id,room_id,created_at desc)
  where handed_off_at is not null;
create index st_v6_room_reports_mine on sectalk_private.st_v6_room_reports(reporter,created_at desc,id);

create table sectalk_private.st_v6_room_report_audit (
  id bigint generated always as identity primary key,
  report_id uuid not null references sectalk_private.st_v6_room_reports on delete cascade,
  actor uuid references public.st_profiles on delete set null,
  action text not null check(action in ('handoff','reviewing','resolved','dismissed')),
  source text not null check(source in ('platform','workspace')),
  reason text not null,
  occurred_at timestamptz not null default clock_timestamp()
);
create index st_v6_room_report_audit_report on sectalk_private.st_v6_room_report_audit(report_id,id desc);
alter table sectalk_private.st_v6_room_reports enable row level security;
alter table sectalk_private.st_v6_room_report_audit enable row level security;
revoke all on sectalk_private.st_v6_room_reports,sectalk_private.st_v6_room_report_audit
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_room_report_admin(
  p_workspace uuid,p_room uuid,p_user uuid
) returns boolean language sql stable set search_path='' as $$
  select coalesce(sectalk_private.st_v2_role(p_workspace,p_user) in ('owner','admin'),false)
    and exists(select 1 from public.st_v6_rooms r where r.id=p_room and r.workspace_id=p_workspace
      and sectalk_private.st_v6_room_role(r.id,p_user) is not null)
$$;

create function public.st_v6_submit_room_report(p_room uuid,p_post uuid,p_category text,p_details text,p_share boolean)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); source record; report uuid;
begin
  if p_share is null or p_category is null
    or p_category not in ('harassment','threat','scam','impersonation','spam','sexual_content','other')
    or char_length(coalesce(p_details,''))>1500 then
    raise exception 'Choose a category and enter at most 1,500 characters' using errcode='22023';
  end if;
  if sectalk_private.st_v6_room_role(p_room) is null then
    raise exception 'Room post is unavailable for reporting' using errcode='42501';
  end if;
  select r.workspace_id,p.sender into source from public.st_v6_room_posts p
    join public.st_v6_rooms r on r.id=p.room_id
    where p.room_id=p_room and p.id=p_post and p.removed_at is null and p.sender<>actor
    for share of p,r;
  if not found then raise exception 'Room post is unavailable for reporting' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v6_room_report',10);
  insert into sectalk_private.st_v6_room_reports(workspace_id,room_id,post_id,reporter,subject,category,details,share_with_workspace)
    values(source.workspace_id,p_room,p_post,actor,source.sender,p_category,btrim(coalesce(p_details,'')),p_share)
    on conflict(reporter,room_id,post_id) do nothing returning id into report;
  if report is null then
    select r.id into report from sectalk_private.st_v6_room_reports r
      where r.reporter=actor and r.room_id=p_room and r.post_id=p_post;
  end if;
  return report;
end $$;

create function public.st_v6_my_room_reports()
returns table(id uuid,category text,status text,created_at timestamptz,share_with_workspace boolean,handed_off_at timestamptz)
language sql stable security definer set search_path='' as $$
  select r.id,r.category,r.status,r.created_at,r.share_with_workspace,r.handed_off_at
  from sectalk_private.st_v6_room_reports r where r.reporter=auth.uid()
  order by r.created_at desc,r.id limit 100
$$;

create function public.st_v6_room_report_review_access()
returns text language sql stable security definer set search_path='' as $$
  select case when sectalk_private.st_v2_active(auth.uid()) and exists(
    select 1 from public.st_v2_members m where m.user_id=auth.uid()
      and sectalk_private.st_v2_role(m.workspace_id,m.user_id) in ('owner','admin'))
  then case when sectalk_private.st_v6_retirement_has_mfa() then 'verified' else 'mfa' end else 'none' end
$$;

create function public.st_v6_room_report_queue(p_scope text)
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
        and sectalk_private.st_v6_room_report_admin(rr.workspace_id,rr.room_id,auth.uid())
      order by rr.created_at desc,rr.id limit 100
    ) q),'[]');
  end if;
  raise exception 'Choose a valid room report queue' using errcode='22023';
end $$;

create function public.st_v6_review_room_report(p_report uuid,p_scope text,p_action text,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare
  item sectalk_private.st_v6_room_reports;
  actor uuid:=auth.uid();
  reason text:=btrim(p_reason);
  recipients uuid[];
begin
  if (p_scope='platform' and not coalesce(sectalk_private.st_v6_case_redaction_staff(),false))
    or (p_scope='workspace' and public.st_v6_room_report_review_access()<>'verified')
    or p_scope is null or p_scope not in ('platform','workspace') then
    raise exception 'Room report review is unavailable' using errcode='42501';
  end if;
  select rr.* into item from sectalk_private.st_v6_room_reports rr where rr.id=p_report for update;
  if not found or actor in (item.reporter,item.subject)
    or (p_scope='workspace' and (not item.share_with_workspace or item.handed_off_at is null
      or not sectalk_private.st_v6_room_report_admin(item.workspace_id,item.room_id,actor))) then
    raise exception 'Room report review is unavailable' using errcode='42501';
  end if;
  if reason is null or char_length(reason) not between 1 and 500 or p_action is null
    or p_action not in ('handoff','reviewing','resolved','dismissed') then
    raise exception 'Choose an action and enter a reason up to 500 characters' using errcode='22023';
  end if;
  if item.status in ('resolved','dismissed') then
    raise exception 'This room report is closed' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v6_room_report_review',30);
  if p_action='handoff' then
    if p_scope<>'platform' or not item.share_with_workspace then
      raise exception 'The reporter has not authorized this handoff' using errcode='42501';
    end if;
    if item.handed_off_at is not null then return; end if;
    select array_agg(m.user_id) into recipients from public.st_v2_members m
    where m.workspace_id=item.workspace_id and m.user_id<>item.reporter
      and m.user_id is distinct from item.subject
      and sectalk_private.st_v6_room_report_admin(item.workspace_id,item.room_id,m.user_id)
      and sectalk_private.st_v6_on_call_eligible(m.user_id);
    if recipients is null then
      raise exception 'No verified workspace admin has access to this room' using errcode='22023';
    end if;
    update sectalk_private.st_v6_room_reports set handed_off_at=clock_timestamp(),status='reviewing' where id=item.id;
    perform realtime.send('{}','workspace_room_report','st:account:'||recipient,true)
      from unnest(recipients) recipient
      where not sectalk_private.st_v6_quiet_for(recipient,null)
        and sectalk_private.st_v6_notification_enabled(recipient,'security');
  else
    if p_action=item.status then return; end if;
    update sectalk_private.st_v6_room_reports set status=p_action where id=item.id;
  end if;
  insert into sectalk_private.st_v6_room_report_audit(report_id,actor,action,source,reason)
    values(item.id,actor,p_action,p_scope,reason);
end $$;

revoke all on function sectalk_private.st_v6_room_report_admin(uuid,uuid,uuid),
  public.st_v6_submit_room_report(uuid,uuid,text,text,boolean),public.st_v6_my_room_reports(),
  public.st_v6_room_report_review_access(),public.st_v6_room_report_queue(text),
  public.st_v6_review_room_report(uuid,text,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_submit_room_report(uuid,uuid,text,text,boolean),public.st_v6_my_room_reports(),
  public.st_v6_room_report_review_access(),public.st_v6_room_report_queue(text),
  public.st_v6_review_room_report(uuid,text,text,text) to authenticated;
commit;
