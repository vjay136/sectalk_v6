begin;

alter table public.st_v3_meetings add column is_instant boolean not null default false;
alter table public.st_v3_notifications
  drop constraint st_v3_notifications_kind_check,
  add constraint st_v3_notifications_kind_check
    check(kind in ('meeting.scheduled','meeting.started','meeting.admitted','meeting.declined'));

create function public.st_v6_start_instant_meeting(p_id uuid,p_workspace uuid,p_title text,p_minutes integer)
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

revoke all on function public.st_v6_start_instant_meeting(uuid,uuid,text,integer) from public,anon,authenticated;
grant execute on function public.st_v6_start_instant_meeting(uuid,uuid,text,integer) to authenticated;

commit;
