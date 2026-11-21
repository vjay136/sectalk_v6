begin;

create table sectalk_private.st_v8_workspace_schedule_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_schedule_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_schedule_sso from public,anon,authenticated,service_role;

-- This policy applies to current-caller schedule requests. Role lookups are kept separate
-- for guest capabilities, provider admission and cross-user lobby checks.
create function sectalk_private.st_v8_schedule_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_schedule_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_schedule_sso_allows(uuid) from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v8_schedule_sso_allows(uuid) to authenticated;

create function public.st_v8_workspace_schedule_requires_sso(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v2_active(auth.uid())
    and sectalk_private.st_v2_role(p_workspace,auth.uid()) is not null
    and not sectalk_private.st_v8_schedule_sso_allows(p_workspace);
$$;

create function public.st_v8_workspace_schedule_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_schedule_sso_policy',5);
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
      raise insufficient_privilege;
    end if;
    if p_require then
      select * into setup from sectalk_private.st_v7_workspace_sso c where c.workspace=p_workspace;
      if not found or sectalk_private.st_v7_workspace_sso_provider(p_workspace,setup.domain,setup.protocol)
        is distinct from setup.provider or not exists(
          select 1 from sectalk_private.st_v7_workspace_sso_sessions r join auth.sessions s on (s.id,s.user_id)=(r.session,r.principal)
          where r.workspace=p_workspace and (r.protocol,r.provider)=(setup.protocol,setup.provider)
            and sectalk_private.st_v2_active(r.principal) and sectalk_private.st_v2_role(p_workspace,r.principal) is not null
            and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
        ) then return '{"access":"verified","error":"verified_provider_session_required"}'; end if;
      insert into sectalk_private.st_v8_workspace_schedule_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_schedule_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.schedule_sso_required'
          else 'workspace.schedule_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_schedule_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_schedule_policy(uuid,boolean),
  public.st_v8_workspace_schedule_requires_sso(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_schedule_policy(uuid,boolean),
  public.st_v8_workspace_schedule_requires_sso(uuid) to authenticated;

-- Room calls use the independent room scope. Existing host and participant
-- roles still decide which meeting records each caller may access.
create function sectalk_private.st_v8_meeting_schedule_sso_allows(p_meeting uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce((select m.room_id is not null or sectalk_private.st_v8_schedule_sso_allows(m.workspace_id)
    from public.st_v3_meetings m where m.id=p_meeting),false);
$$;
revoke all on function sectalk_private.st_v8_meeting_schedule_sso_allows(uuid) from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v8_meeting_schedule_sso_allows(uuid) to authenticated;

create policy st_v8_schedule_sso on public.st_v3_meetings as restrictive for select to authenticated
  using(room_id is not null or sectalk_private.st_v8_schedule_sso_allows(workspace_id));
create policy st_v8_schedule_sso on public.st_v3_attendance as restrictive for select to authenticated
  using(sectalk_private.st_v8_meeting_schedule_sso_allows(meeting_id));
create policy st_v8_schedule_sso on public.st_v3_notifications as restrictive for select to authenticated
  using(meeting_id is null or sectalk_private.st_v8_meeting_schedule_sso_allows(meeting_id));

create or replace function public.st_v3_schedule(p_workspace uuid,p_title text,p_agenda text,p_start timestamptz,p_end timestamptz,p_id uuid)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); m public.st_v3_meetings;
begin
  perform sectalk_private.limit_action('v3_schedule',8);
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor) then raise exception 'Meeting action unavailable'; end if;
  if not sectalk_private.st_v8_schedule_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to schedule a meeting' using errcode='42501';
  end if;
  if p_start<now()-interval '2 minutes' or p_start>now()+interval '365 days'
    then raise exception 'Choose a start time in the next year'; end if;
  insert into public.st_v3_meetings(id,workspace_id,host_id,title,agenda,starts_at,ends_at)
    values(p_id,p_workspace,actor,btrim(p_title),btrim(coalesce(p_agenda,'')),p_start,p_end)
    on conflict(id) do nothing returning * into m;
  if not found then
    if exists(select 1 from public.st_v3_meetings where id=p_id and host_id=actor and workspace_id=p_workspace
      and title=btrim(p_title) and agenda=btrim(coalesce(p_agenda,'')) and starts_at=p_start and ends_at=p_end) then return p_id; end if;
    raise exception 'Meeting ID already in use';
  end if;
  insert into public.st_v3_notifications(recipient,workspace_id,meeting_id,kind)
    select user_id,p_workspace,p_id,'meeting.scheduled' from public.st_v2_members
    where workspace_id=p_workspace and user_id<>actor on conflict do nothing;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(p_workspace,actor,'meeting.scheduled',p_id);
  return m.id;
end $$;

create or replace function public.st_v6_start_instant_meeting(p_id uuid,p_workspace uuid,p_title text,p_minutes integer)
returns uuid language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  meeting_title text:=coalesce(nullif(btrim(p_title),''),'Instant meeting');
  started_at timestamptz:=clock_timestamp();
  duration interval;
begin
  perform sectalk_private.limit_action('v3_schedule',8);
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor) then
    raise exception 'Meeting action unavailable';
  end if;
  if not sectalk_private.st_v8_schedule_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to start an instant meeting' using errcode='42501';
  end if;
  if p_id is null or p_minutes is null or p_minutes not between 15 and 480 or char_length(meeting_title)>100 then
    raise exception 'Choose a title up to 100 characters and a duration from 15 minutes to 8 hours';
  end if;
  duration:=make_interval(mins=>p_minutes);

  insert into public.st_v3_meetings(id,workspace_id,host_id,title,starts_at,ends_at,is_instant)
    values(p_id,p_workspace,actor,meeting_title,started_at,started_at+duration,true)
    on conflict(id) do nothing;
  if not found then
    if exists(select 1 from public.st_v3_meetings m where m.id=p_id and m.workspace_id=p_workspace
      and m.host_id=actor and m.is_instant and m.title=meeting_title and m.ends_at-m.starts_at=duration) then
      return p_id;
    end if;
    raise exception 'Meeting ID already in use';
  end if;

  perform public.st_v3_meeting_state(p_id,'live');
  insert into public.st_v3_notifications(recipient,workspace_id,meeting_id,kind)
    select user_id,p_workspace,p_id,'meeting.started' from public.st_v2_members
    where workspace_id=p_workspace and user_id<>actor;
  return p_id;
end $$;

create or replace function public.st_v6_schedule_series(p_workspace uuid,p_id uuid,p_title text,p_agenda text,
  p_start timestamptz,p_end timestamptz,p_frequency text,p_count integer,p_zone text)
returns uuid language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  meeting_title text:=btrim(p_title);
  meeting_agenda text:=btrim(coalesce(p_agenda,''));
  duration interval:=p_end-p_start;
  step interval;
  occurrence integer;
  begins timestamptz;
  existing integer;
begin
  perform sectalk_private.limit_action('v3_schedule',8);
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor) then raise exception 'Meeting action unavailable'; end if;
  if not sectalk_private.st_v8_schedule_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to schedule a meeting series' using errcode='42501';
  end if;
  if p_id is null or meeting_title is null or char_length(meeting_title) not between 1 and 100 or char_length(meeting_agenda)>2000
    or p_start is null or p_end is null or duration<=interval '0 seconds' or duration>interval '8 hours'
    or p_count is null or p_count not between 2 and 12 or p_frequency is null or p_frequency not in ('daily','weekly')
    or not exists(select 1 from pg_catalog.pg_timezone_names z where z.name=p_zone)
    then raise exception 'Choose valid meeting times, a time zone, and 2 to 12 occurrences'; end if;
  step:=case when p_frequency='daily' then interval '1 day' else interval '7 days' end;
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('sectalk:meeting-series:'||p_id::text,0));
  select count(*) into existing from public.st_v3_meetings m where m.series_id=p_id;
  if existing>0 and existing<>p_count then raise exception 'Meeting series ID already in use'; end if;
  if existing=0 and (p_start<now()-interval '2 minutes' or
    ((p_start at time zone p_zone)+step*(p_count-1)) at time zone p_zone>now()+interval '365 days')
    then raise exception 'Choose meeting occurrences within the next year'; end if;

  for occurrence in 1..p_count loop
    begins:=case when occurrence=1 then p_start
      else ((p_start at time zone p_zone)+step*(occurrence-1)) at time zone p_zone end;
    if existing>0 then
      if not exists(select 1 from public.st_v3_meetings m where m.series_id=p_id and m.series_index=occurrence
        and m.workspace_id=p_workspace and m.host_id=actor and m.series_total=p_count
        and m.title=meeting_title and m.agenda=meeting_agenda and m.starts_at=begins and m.ends_at=begins+duration)
        then raise exception 'Meeting series ID already in use'; end if;
    else
      insert into public.st_v3_meetings(id,workspace_id,host_id,title,agenda,starts_at,ends_at,series_id,series_index,series_total)
        values(case when occurrence=1 then p_id else gen_random_uuid() end,p_workspace,actor,meeting_title,meeting_agenda,
          begins,begins+duration,p_id,occurrence,p_count);
    end if;
  end loop;
  if existing=0 then
    insert into public.st_v3_notifications(recipient,workspace_id,meeting_id,kind)
      select user_id,p_workspace,p_id,'meeting.scheduled' from public.st_v2_members where workspace_id=p_workspace and user_id<>actor;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(p_workspace,actor,'meeting.series_scheduled',p_id);
  end if;
  return p_id;
end $$;

create or replace function public.st_v3_meeting_state(p_meeting uuid,p_state text)
returns void language plpgsql security definer set search_path='' as $$
declare m public.st_v3_meetings; actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v3_meeting_state',20);
  select * into m from public.st_v3_meetings where id=p_meeting for update;
  if not found or not sectalk_private.st_v3_is_host(p_meeting,actor) or not sectalk_private.st_v2_active(actor)
    then raise exception 'Meeting action unavailable'; end if;
  if p_state is null or p_state not in ('live','ended') then raise exception 'Invalid meeting state'; end if;
  if p_state='live' and not sectalk_private.st_v8_meeting_schedule_sso_allows(p_meeting) then
    raise exception 'Sign in through your workspace provider to open the meeting lobby' using errcode='42501';
  end if;
  if p_state=m.status then return; end if;
  if p_state='live' and (m.status<>'scheduled' or m.starts_at>now()+interval '15 minutes' or now()>=m.ends_at) then
    raise exception 'A meeting can start up to 15 minutes before it is scheduled'; end if;
  update public.st_v3_meetings set status=p_state where id=p_meeting;
  if p_state='live' then
    insert into public.st_v3_attendance(meeting_id,user_id,status,admitted_at) values(p_meeting,actor,'admitted',clock_timestamp())
      on conflict(meeting_id,user_id) do update set status='admitted',admitted_at=clock_timestamp(),left_at=null;
  else
    update public.st_v3_attendance set status='left',left_at=clock_timestamp() where meeting_id=p_meeting and status in ('admitted','waiting');
  end if;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(m.workspace_id,actor,'meeting.'||p_state,p_meeting);
end $$;

create or replace function public.st_v3_request_admission(p_meeting uuid)
returns text language plpgsql security definer set search_path='' as $$
declare m public.st_v3_meetings; actor uuid:=auth.uid(); access_state text;
begin
  perform sectalk_private.limit_action('v3_join',16);
  select * into m from public.st_v3_meetings where id=p_meeting for update;
  if not found or not sectalk_private.st_v3_meeting_visible(p_meeting,actor) or not sectalk_private.st_v2_active(actor)
    or m.status='ended' or m.ends_at<=now() or m.starts_at>now()+interval '15 minutes'
    or not sectalk_private.open_pair(actor,m.host_id) then raise exception 'Meeting is unavailable or has not opened yet'; end if;
  if not sectalk_private.st_v8_meeting_schedule_sso_allows(p_meeting) then
    raise exception 'Sign in through your workspace provider to request meeting admission' using errcode='42501';
  end if;
  if actor=m.host_id and m.status='live' and sectalk_private.st_v3_is_host(p_meeting,actor) then
    insert into public.st_v3_attendance(meeting_id,user_id,status,admitted_at)
      values(p_meeting,actor,'admitted',clock_timestamp())
      on conflict(meeting_id,user_id) do update set status='admitted',admitted_at=coalesce(public.st_v3_attendance.admitted_at,clock_timestamp()),left_at=null;
  else
    insert into public.st_v3_attendance(meeting_id,user_id,status) values(p_meeting,actor,'waiting') on conflict(meeting_id,user_id)
      do update set status='waiting',requested_at=clock_timestamp(),admitted_at=null,left_at=null
      where public.st_v3_attendance.status='left';
  end if;
  select status into access_state from public.st_v3_attendance where meeting_id=p_meeting and user_id=actor;
  return access_state;
end $$;

create or replace function sectalk_private.st_v6_lobby_decide(p_meeting uuid,p_user uuid,p_allow boolean)
returns integer language plpgsql security definer set search_path='' as $$
declare
  meeting public.st_v3_meetings;
  actor uuid:=auth.uid();
  recipient uuid;
  seats integer:=1;
  changed integer:=0;
  activity text;
begin
  perform sectalk_private.limit_action('v3_admit',45);
  select * into meeting from public.st_v3_meetings where id=p_meeting for update;
  if not found or p_allow is null or meeting.status<>'live' or meeting.ends_at<=clock_timestamp()
    or not sectalk_private.st_v3_is_host(p_meeting,actor) or not sectalk_private.st_v2_active(actor)
    or (p_user is null and not p_allow) or (p_user is not null and p_user=actor) then
    raise exception 'Meeting action unavailable';
  end if;
  if not sectalk_private.st_v8_meeting_schedule_sso_allows(p_meeting) then
    raise exception 'Sign in through your workspace provider to manage the meeting lobby' using errcode='42501';
  end if;
  if p_user is not null and (not sectalk_private.st_v3_meeting_visible(p_meeting,p_user)
    or not sectalk_private.st_v2_active(p_user) or not sectalk_private.open_pair(actor,p_user)) then
    raise exception 'Meeting action unavailable';
  end if;
  if p_allow then
    select greatest(0,12-count(*))::integer into seats from public.st_v3_attendance
      where meeting_id=p_meeting and status='admitted';
    if seats=0 and p_user is not null then raise exception 'The meeting is at its attendee limit'; end if;
  end if;
  activity:=case when p_allow then 'meeting.admitted' else 'meeting.declined' end;
  for recipient in
    select a.user_id from public.st_v3_attendance a
    where a.meeting_id=p_meeting and a.status='waiting' and a.user_id<>actor
      and (p_user is null or a.user_id=p_user)
      and sectalk_private.st_v3_meeting_visible(p_meeting,a.user_id)
      and sectalk_private.st_v2_active(a.user_id)
      and sectalk_private.open_pair(actor,a.user_id)
    order by a.requested_at,a.user_id limit seats
    for update of a
  loop
    update public.st_v3_attendance set status=case when p_allow then 'admitted' else 'declined' end,
      admitted_at=case when p_allow then clock_timestamp() else null end where meeting_id=p_meeting and user_id=recipient;
    insert into public.st_v3_notifications(recipient,workspace_id,meeting_id,kind)
      values(recipient,meeting.workspace_id,p_meeting,activity)
      on conflict on constraint st_v3_notifications_recipient_meeting_id_kind_key
      do update set read_at=null,created_at=clock_timestamp();
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(meeting.workspace_id,actor,activity,p_meeting);
    changed:=changed+1;
  end loop;
  if p_user is not null and changed=0 then raise exception 'Attendee is no longer waiting'; end if;
  return changed;
end $$;

commit;
