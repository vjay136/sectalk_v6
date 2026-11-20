begin;

create table sectalk_private.st_v6_caption_session (
  meeting uuid primary key references public.st_v3_meetings on delete cascade,
  source_language text not null check(source_language in ('en','es','fr','de','hi')),
  expires_at timestamptz not null,
  stopped boolean not null default false,
  line_count integer not null default 0 check(line_count between 0 and 2400)
);
create table sectalk_private.st_v6_caption_consent (
  meeting uuid not null references sectalk_private.st_v6_caption_session on delete cascade,
  actor uuid not null references public.st_profiles on delete cascade,
  participant_sid text not null,
  granted boolean not null default true,
  last_chunk_at timestamptz,
  lease uuid,
  primary key(meeting,actor)
);
create table sectalk_private.st_v6_caption_line (
  meeting uuid not null references sectalk_private.st_v6_caption_session on delete cascade,
  sequence integer not null,
  actor uuid not null references public.st_profiles on delete cascade,
  speaker text not null,
  line text not null check(char_length(line) between 1 and 500),
  spoken_at timestamptz not null default clock_timestamp(),
  primary key(meeting,sequence)
);
alter table sectalk_private.st_v6_caption_session enable row level security;
alter table sectalk_private.st_v6_caption_consent enable row level security;
alter table sectalk_private.st_v6_caption_line enable row level security;
revoke all on sectalk_private.st_v6_caption_session,sectalk_private.st_v6_caption_consent,sectalk_private.st_v6_caption_line
  from public,anon,authenticated;

create function public.st_v6_meeting_caption_command(
  p_meeting uuid,p_actor uuid,p_action text,p_sid text default null,
  p_language text default null,p_lease uuid default null,p_text text default null,p_after integer default 0
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  meeting_row public.st_v3_meetings;
  session sectalk_private.st_v6_caption_session;
  consent sectalk_private.st_v6_caption_consent;
  is_host boolean;
  admitted boolean;
  active boolean;
  allowed boolean;
  lines jsonb:='[]';
  speaker text;
begin
  if p_action='view' then
    select * into meeting_row from public.st_v3_meetings where id=p_meeting;
  else
    select * into meeting_row from public.st_v3_meetings where id=p_meeting for share;
  end if;
  if not found or not coalesce(sectalk_private.st_v2_active(p_actor),false)
    or not coalesce(sectalk_private.st_v3_meeting_visible(p_meeting,p_actor),false)
    or not coalesce(sectalk_private.open_pair(meeting_row.host_id,p_actor),false)
    or sectalk_private.st_v2_role(meeting_row.workspace_id,p_actor) is null then return null; end if;
  is_host:=sectalk_private.st_v3_is_host(p_meeting,p_actor);
  admitted:=meeting_row.status='live' and meeting_row.ends_at>now() and exists(
    select 1 from public.st_v3_attendance where meeting_id=p_meeting and user_id=p_actor and status='admitted'
  );
  if admitted and p_action<>'view' then
    perform 1 from public.st_v3_attendance where meeting_id=p_meeting and user_id=p_actor and status='admitted' for share;
    admitted:=found;
  end if;
  if p_action='view' then
    select * into session from sectalk_private.st_v6_caption_session where meeting=p_meeting;
  else
    select * into session from sectalk_private.st_v6_caption_session where meeting=p_meeting for update;
  end if;
  select * into consent from sectalk_private.st_v6_caption_consent where meeting=p_meeting and actor=p_actor;
  active:=coalesce(not session.stopped and session.expires_at>now() and meeting_row.status='live' and meeting_row.ends_at>now(),false);
  allowed:=coalesce(consent.granted and p_sid=consent.participant_sid,false);

  if p_action='start' then
    if not (admitted and is_host) or p_sid is null or session.meeting is not null
      or p_language is null or p_language not in ('en','es','fr','de','hi') then return null; end if;
    insert into sectalk_private.st_v6_caption_session(meeting,source_language,expires_at)
      values(p_meeting,p_language,least(meeting_row.ends_at,now()+interval '2 hours')) on conflict do nothing;
    return jsonb_build_object('ok',true);
  elsif p_action='join' then
    if not (active and admitted) or p_sid is null then return null; end if;
    insert into sectalk_private.st_v6_caption_consent(meeting,actor,participant_sid)
      values(p_meeting,p_actor,p_sid) on conflict(meeting,actor) do update
      set granted=true,participant_sid=excluded.participant_sid,lease=null;
    return jsonb_build_object('ok',true);
  elsif p_action='withdraw' then
    if consent.actor is null then return null; end if;
    update sectalk_private.st_v6_caption_consent set granted=false,lease=null where meeting=p_meeting and actor=p_actor;
    delete from sectalk_private.st_v6_caption_line where meeting=p_meeting and actor=p_actor;
    return jsonb_build_object('ok',true);
  elsif p_action='stop' then
    if not (active and is_host and admitted) or p_sid is null then return null; end if;
    update sectalk_private.st_v6_caption_session set stopped=true where meeting=p_meeting;
    return jsonb_build_object('ok',true);
  elsif p_action='reserve' then
    if not (active and admitted and allowed) or session.line_count>=2400 or p_lease is null or
      consent.last_chunk_at>clock_timestamp()-interval '3500 milliseconds' then return null; end if;
    update sectalk_private.st_v6_caption_consent set last_chunk_at=clock_timestamp(),lease=p_lease
      where meeting=p_meeting and actor=p_actor;
    return jsonb_build_object('language',session.source_language);
  elsif p_action='publish' then
    if not (active and admitted and allowed) or session.line_count>=2400 or p_lease is null
      or consent.lease is distinct from p_lease or consent.last_chunk_at<clock_timestamp()-interval '20 seconds' then return null; end if;
    update sectalk_private.st_v6_caption_consent set lease=null where meeting=p_meeting and actor=p_actor;
    if char_length(trim(p_text)) between 1 and 500 then
      select name into speaker from public.st_profiles where id=p_actor;
      if speaker is null then return null; end if;
      update sectalk_private.st_v6_caption_session set line_count=line_count+1 where meeting=p_meeting returning * into session;
      insert into sectalk_private.st_v6_caption_line(meeting,sequence,actor,speaker,line)
        values(p_meeting,session.line_count,p_actor,speaker,trim(p_text));
    end if;
    return jsonb_build_object('ok',true);
  elsif p_action<>'view' then
    return null;
  end if;

  if not admitted and not coalesce(consent.granted,false) then return null; end if;
  if (active and admitted and allowed) or (not active and coalesce(consent.granted,false)) then
    select coalesce(jsonb_agg(to_jsonb(row) order by row.sequence),'[]') into lines from (
      select l.sequence,l.speaker,l.line,l.spoken_at from sectalk_private.st_v6_caption_line l
      where l.meeting=p_meeting and l.sequence>greatest(0,p_after)
        and sectalk_private.open_pair(p_actor,l.actor)
      order by case when active then -l.sequence else l.sequence end limit 100
    ) row;
  end if;
  return jsonb_build_object('active',active,'host',is_host,'admitted',admitted,
    'language',session.source_language,'consented',coalesce(consent.granted,false),'sending',active and admitted and allowed,'lines',lines);
end
$$;
revoke all on function public.st_v6_meeting_caption_command(uuid,uuid,text,text,text,uuid,text,integer) from public,anon,authenticated;
grant execute on function public.st_v6_meeting_caption_command(uuid,uuid,text,text,text,uuid,text,integer) to service_role;

commit;
