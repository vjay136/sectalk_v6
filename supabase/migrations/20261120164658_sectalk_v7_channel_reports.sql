begin;

create table sectalk_private.st_v7_channel_reports (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null,
  channel_id uuid not null,
  post_id uuid not null,
  reporter uuid not null references public.st_profiles on delete cascade,
  subject uuid references public.st_profiles on delete set null,
  category text not null check(category in ('harassment','threat','scam','impersonation','spam','sexual_content','other')),
  details text not null check(char_length(details)<=1500),
  evidence text not null check(char_length(evidence) between 1 and 4000),
  tenant_consent boolean not null,
  handed_off_at timestamptz,
  state text not null default 'open' check(state in ('open','reviewing','resolved','dismissed')),
  created_at timestamptz not null default clock_timestamp(),
  unique(reporter,channel_id,post_id),
  check(handed_off_at is null or (tenant_consent and category in ('spam','other')))
);
create index st_v7_channel_reports_queue on sectalk_private.st_v7_channel_reports(state,created_at desc);
create index st_v7_channel_reports_by_actor on sectalk_private.st_v7_channel_reports(reporter,created_at desc);

create table sectalk_private.st_v7_channel_report_actions (
  id bigint generated always as identity primary key,
  report_id uuid not null references sectalk_private.st_v7_channel_reports on delete cascade,
  actor uuid references public.st_profiles on delete set null,
  action text not null check(action in ('handoff','reviewing','resolved','dismissed')),
  review_scope text not null check(review_scope in ('platform','workspace')),
  reason text not null check(char_length(reason) between 1 and 500),
  at timestamptz not null default clock_timestamp()
);
create index st_v7_channel_report_actions_history on sectalk_private.st_v7_channel_report_actions(report_id,id);
alter table sectalk_private.st_v7_channel_reports enable row level security;
alter table sectalk_private.st_v7_channel_report_actions enable row level security;
revoke all on sectalk_private.st_v7_channel_reports,sectalk_private.st_v7_channel_report_actions
  from public,anon,authenticated,service_role;

create function public.st_v7_submit_channel_report(p_channel uuid,p_post uuid,p_category text,p_details text,
  p_share_with_safety boolean,p_share_with_workspace boolean)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); source record; receipt uuid;
begin
  if p_share_with_safety is not true or p_share_with_workspace is null then
    raise exception using errcode='22023',message='Consent is required before sharing this channel message';
  end if;
  if p_category is null or p_category not in ('harassment','threat','scam','impersonation','spam','sexual_content','other')
    or char_length(coalesce(p_details,''))>1500 then raise exception using errcode='22023',message='Choose a report category'; end if;
  select c.workspace_id,p.sender,p.body into source from public.st_v2_posts p
    join public.st_v2_channels c on c.id=p.channel_id
    where p.id=p_post and p.channel_id=p_channel and p.sender<>actor
      and sectalk_private.st_v2_post_read(p.channel_id,p.sender,actor)
    for share of p,c;
  if not found then raise exception using errcode='42501',message='The channel message is unavailable for reporting'; end if;
  select r.id into receipt from sectalk_private.st_v7_channel_reports r
    where r.reporter=actor and r.channel_id=p_channel and r.post_id=p_post;
  if receipt is not null then return receipt; end if;
  perform sectalk_private.limit_action('v7_channel_report',10);
  insert into sectalk_private.st_v7_channel_reports(workspace_id,channel_id,post_id,reporter,subject,category,details,evidence,tenant_consent)
    values(source.workspace_id,p_channel,p_post,actor,source.sender,p_category,btrim(coalesce(p_details,'')),source.body,p_share_with_workspace)
    on conflict(reporter,channel_id,post_id) do nothing returning id into receipt;
  if receipt is null then
    select r.id into receipt from sectalk_private.st_v7_channel_reports r
      where r.reporter=actor and r.channel_id=p_channel and r.post_id=p_post;
  end if;
  return receipt;
end $$;

create function public.st_v7_my_channel_reports()
returns jsonb language sql stable security definer set search_path='' as $$
  select coalesce(jsonb_agg(to_jsonb(chosen) order by chosen.created_at desc,chosen.id),'[]'::jsonb)
  from (select r.id,r.category,r.state,r.created_at,
    coalesce((select jsonb_agg(jsonb_build_object('action',a.action,'at',a.at) order by a.id)
      from sectalk_private.st_v7_channel_report_actions a where a.report_id=r.id),'[]'::jsonb) timeline
    from sectalk_private.st_v7_channel_reports r where r.reporter=(select auth.uid())
    order by r.created_at desc,r.id limit 100) chosen;
$$;

create function sectalk_private.st_v7_channel_report_staff(p_scope text)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce(case p_scope
    when 'platform' then sectalk_private.st_v6_case_redaction_staff()
    when 'workspace' then public.st_v6_room_report_review_access()='verified'
    else false end,false);
$$;

create function sectalk_private.st_v7_channel_report_local(p_channel uuid,p_workspace uuid,p_actor uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce(sectalk_private.st_v2_role(p_workspace,p_actor) in ('owner','admin'),false)
    and sectalk_private.st_v6_channel_content_access(p_channel,p_actor);
$$;

create function public.st_v7_channel_report_queue(p_scope text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_v7_channel_report_staff(p_scope) then
    raise exception using errcode='42501',message='Channel report review is unavailable';
  end if;
  return coalesce((select jsonb_agg(to_jsonb(q) order by q.created_at desc,q.id) from(
    select r.id,r.category,r.state,r.created_at,r.handed_off_at,r.category in ('spam','other') and r.tenant_consent as handoff_allowed,
      case when p_scope='platform' then r.details else '' end as details,r.evidence,c.name as channel_name,w.name as workspace_name
    from sectalk_private.st_v7_channel_reports r
    left join public.st_v2_channels c on c.id=r.channel_id and c.workspace_id=r.workspace_id
    left join public.st_v2_workspaces w on w.id=r.workspace_id
    where auth.uid()<>r.reporter and auth.uid() is distinct from r.subject
      and (p_scope='platform' or (r.handed_off_at is not null and
        sectalk_private.st_v7_channel_report_local(r.channel_id,r.workspace_id,auth.uid())))
    order by r.created_at desc,r.id limit 100
  ) q),'[]'::jsonb);
end $$;

create function public.st_v7_review_channel_report(p_report uuid,p_scope text,p_action text,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare item sectalk_private.st_v7_channel_reports; actor uuid:=auth.uid(); why text:=btrim(p_reason);
begin
  if not sectalk_private.st_v7_channel_report_staff(p_scope) then
    raise exception using errcode='42501',message='Channel report review is unavailable';
  end if;
  if why is null or char_length(why) not between 1 and 500 or p_action is null
      or p_action not in ('handoff','reviewing','resolved','dismissed') then
    raise exception using errcode='22023',message='Choose a decision and enter a review reason';
  end if;
  select * into item from sectalk_private.st_v7_channel_reports where id=p_report for update;
  if not found or actor=item.reporter or actor is not distinct from item.subject or
    (p_scope='workspace' and (item.handed_off_at is null or
      not sectalk_private.st_v7_channel_report_local(item.channel_id,item.workspace_id,actor))) then
    raise exception using errcode='42501',message='Channel report review is unavailable';
  end if;
  if item.state in ('resolved','dismissed') then raise exception using errcode='PT409',message='The report is closed'; end if;
  if p_action='handoff' then
    if p_scope<>'platform' or not item.tenant_consent or item.category not in ('spam','other') then
      raise exception using errcode='42501',message='This report requires platform review';
    end if;
    if item.handed_off_at is not null then return; end if;
    if not exists(select 1 from public.st_v2_members m where m.workspace_id=item.workspace_id
      and m.user_id not in (actor,item.reporter) and m.user_id is distinct from item.subject
      and sectalk_private.st_v7_channel_report_local(item.channel_id,item.workspace_id,m.user_id)
      and sectalk_private.st_v6_on_call_eligible(m.user_id)) then
      raise exception using errcode='PT409',message='No eligible workspace reviewer can read this channel';
    end if;
    update sectalk_private.st_v7_channel_reports set handed_off_at=clock_timestamp(),state='reviewing' where id=item.id;
  else
    if item.state=p_action then return; end if;
    update sectalk_private.st_v7_channel_reports set state=p_action where id=item.id;
  end if;
  perform sectalk_private.limit_action('v7_channel_review',30);
  insert into sectalk_private.st_v7_channel_report_actions(report_id,actor,action,review_scope,reason)
    values(item.id,actor,p_action,p_scope,why);
  perform realtime.send('{}','channel_report_updated','st:account:'||item.reporter,true);
end $$;

revoke all on function public.st_v7_submit_channel_report(uuid,uuid,text,text,boolean,boolean),public.st_v7_my_channel_reports(),
  public.st_v7_channel_report_queue(text),public.st_v7_review_channel_report(uuid,text,text,text),
  sectalk_private.st_v7_channel_report_staff(text),sectalk_private.st_v7_channel_report_local(uuid,uuid,uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_submit_channel_report(uuid,uuid,text,text,boolean,boolean),
  public.st_v7_my_channel_reports(),public.st_v7_channel_report_queue(text),public.st_v7_review_channel_report(uuid,text,text,text)
  to authenticated;

commit;
