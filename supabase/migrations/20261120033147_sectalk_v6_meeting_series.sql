begin;

alter table public.st_v3_meetings
  add column series_id uuid,
  add column series_index integer,
  add column series_total integer,
  add constraint st_v6_meeting_series_valid check(
    num_nonnulls(series_id,series_index,series_total)=0 or
    (num_nonnulls(series_id,series_index,series_total)=3 and series_total between 2 and 12
      and series_index between 1 and series_total and (series_index=1)=(id=series_id))
  );
create unique index st_v6_meeting_series_position on public.st_v3_meetings(series_id,series_index) where series_id is not null;

create function public.st_v6_schedule_series(p_workspace uuid,p_id uuid,p_title text,p_agenda text,
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

revoke all on function public.st_v6_schedule_series(uuid,uuid,text,text,timestamptz,timestamptz,text,integer,text) from public,anon,authenticated;
grant execute on function public.st_v6_schedule_series(uuid,uuid,text,text,timestamptz,timestamptz,text,integer,text) to authenticated;

commit;
