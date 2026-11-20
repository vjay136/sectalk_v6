begin;

create function sectalk_private.st_v6_lobby_decide(p_meeting uuid,p_user uuid,p_allow boolean)
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
revoke all on function sectalk_private.st_v6_lobby_decide(uuid,uuid,boolean) from public,anon,authenticated;

create or replace function public.st_v3_admit(p_meeting uuid,p_user uuid,p_allow boolean)
returns void language plpgsql security definer set search_path='' as $$
begin
  if p_user is null then raise exception 'Meeting action unavailable'; end if;
  perform sectalk_private.st_v6_lobby_decide(p_meeting,p_user,p_allow);
end $$;

create function public.st_v6_admit_all(p_meeting uuid)
returns integer language sql security definer set search_path='' as $$
  select sectalk_private.st_v6_lobby_decide(p_meeting,null,true)
$$;
revoke all on function public.st_v6_admit_all(uuid) from public,anon,authenticated;
grant execute on function public.st_v6_admit_all(uuid) to authenticated;

create or replace function public.st_v3_media_access(p_meeting uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v3_meetings m join public.st_v3_attendance a on m.id=a.meeting_id
    where m.id=p_meeting and a.user_id=auth.uid() and a.status='admitted' and m.status='live' and m.ends_at>now()
      and sectalk_private.st_v2_role(m.workspace_id,auth.uid()) is not null
      and sectalk_private.st_v2_active(auth.uid()) and sectalk_private.st_v3_is_host(m.id,m.host_id)
      and sectalk_private.st_v2_active(m.host_id) and sectalk_private.open_pair(m.host_id,auth.uid()))
$$;

commit;
