begin;

create table public.st_v6_meeting_chat (
  meeting_id uuid not null references public.st_v3_meetings(id) on delete cascade,
  id uuid not null,
  user_id uuid not null references public.st_profiles(id) on delete cascade,
  author_name text not null,
  body text not null check(char_length(btrim(body)) between 1 and 1000),
  sent_at timestamptz not null default clock_timestamp(),
  primary key(meeting_id,id)
);
create index st_v6_meeting_chat_recent on public.st_v6_meeting_chat(meeting_id,sent_at desc,id desc);

create table public.st_v6_meeting_controls (
  meeting_id uuid primary key references public.st_v3_meetings(id) on delete cascade,
  spotlight uuid,
  spotlight_admitted_at timestamptz,
  roster_revision bigint not null default 0,
  check((spotlight is null)=(spotlight_admitted_at is null))
);

alter table public.st_v6_meeting_chat enable row level security;
alter table public.st_v6_meeting_controls enable row level security;
revoke all on public.st_v6_meeting_chat,public.st_v6_meeting_controls from public,anon,authenticated;
grant select on public.st_v6_meeting_chat,public.st_v6_meeting_controls to authenticated;
create function sectalk_private.st_v6_meeting_visible_peer(p_meeting uuid,p_peer uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select public.st_v3_media_access(p_meeting) and (
    p_peer is null or sectalk_private.open_pair(auth.uid(),p_peer)
  )
$$;
revoke all on function sectalk_private.st_v6_meeting_visible_peer(uuid,uuid) from public,anon,authenticated;
grant execute on function sectalk_private.st_v6_meeting_visible_peer(uuid,uuid) to authenticated;
create policy st_v6_meeting_chat_read on public.st_v6_meeting_chat for select to authenticated using(
  sectalk_private.st_v6_meeting_visible_peer(meeting_id,user_id)
);
create policy st_v6_meeting_controls_read on public.st_v6_meeting_controls for select to authenticated using(
  sectalk_private.st_v6_meeting_visible_peer(meeting_id,spotlight)
);

create function public.st_v6_meeting_roster(p_meeting uuid)
returns table(user_id uuid,name text,is_host boolean) language plpgsql stable security definer set search_path='' as $$
begin
  if not public.st_v3_media_access(p_meeting) then
    raise exception 'Meeting participation is unavailable' using errcode='42501';
  end if;
  return query
    select a.user_id,p.name,a.user_id=m.host_id
    from public.st_v3_attendance a
    join public.st_v3_meetings m on m.id=a.meeting_id
    join public.st_profiles p on p.id=a.user_id
    where a.meeting_id=p_meeting and a.status='admitted'
      and sectalk_private.st_v6_engagement_author(p_meeting,a.user_id,a.admitted_at)
      and sectalk_private.open_pair(auth.uid(),a.user_id)
    order by (a.user_id=m.host_id) desc,a.admitted_at,a.user_id;
end $$;

create function public.st_v6_send_meeting_chat(p_meeting uuid,p_id uuid,p_body text)
returns void language plpgsql security definer set search_path='' as $$
declare
  message_text text:=btrim(p_body);
begin
  if p_id is null or message_text is null or char_length(message_text) not between 1 and 1000 then
    raise exception 'Enter a message between 1 and 1000 characters' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v6_meeting_chat',30);
  perform sectalk_private.st_v6_lock_engagement_admission(p_meeting);
  insert into public.st_v6_meeting_chat(meeting_id,id,user_id,author_name,body)
  select p_meeting,p_id,p.id,p.name,message_text from public.st_profiles p where p.id=auth.uid()
  on conflict(meeting_id,id) do nothing;
  if not found and not exists(
    select 1 from public.st_v6_meeting_chat
    where meeting_id=p_meeting and id=p_id and user_id=auth.uid() and body=message_text
  ) then
    raise exception 'Message could not be sent' using errcode='22023';
  end if;
end $$;

create function public.st_v6_set_meeting_spotlight(p_meeting uuid,p_participant uuid)
returns void language plpgsql security definer set search_path='' as $$
declare
  admission timestamptz;
begin
  perform sectalk_private.limit_action('v6_meeting_spotlight',24);
  perform sectalk_private.st_v6_lock_engagement_admission(p_meeting);
  if not sectalk_private.st_v3_is_host(p_meeting,auth.uid()) then
    raise exception 'Only the host can set the spotlight' using errcode='42501';
  end if;
  if p_participant is not null then
    select admitted_at into admission from public.st_v3_attendance
      where meeting_id=p_meeting and user_id=p_participant and status='admitted' for share;
    if not sectalk_private.st_v6_engagement_author(p_meeting,p_participant,admission) then
      raise exception 'Choose someone currently in the meeting' using errcode='22023';
    end if;
  end if;
  insert into public.st_v6_meeting_controls(meeting_id,spotlight,spotlight_admitted_at)
    values(p_meeting,p_participant,admission)
    on conflict(meeting_id) do update set spotlight=excluded.spotlight,
      spotlight_admitted_at=excluded.spotlight_admitted_at;
end $$;

create function sectalk_private.st_v6_meeting_roster_changed()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if tg_op='UPDATE' then
    if old.status is not distinct from new.status and old.admitted_at is not distinct from new.admitted_at then
      return new;
    end if;
    if old.status<>'admitted' and new.status<>'admitted' then
      return new;
    end if;
  elsif new.status<>'admitted' then
    return new;
  end if;
  insert into public.st_v6_meeting_controls as c(meeting_id,roster_revision) values(new.meeting_id,1)
    on conflict(meeting_id) do update set roster_revision=c.roster_revision+1,
      spotlight=case when c.spotlight=new.user_id then null else c.spotlight end,
      spotlight_admitted_at=case when c.spotlight=new.user_id then null else c.spotlight_admitted_at end;
  return new;
end $$;
create trigger st_v6_meeting_roster_changed after insert or update of status,admitted_at on public.st_v3_attendance
for each row execute function sectalk_private.st_v6_meeting_roster_changed();

revoke all on function public.st_v6_meeting_roster(uuid),public.st_v6_send_meeting_chat(uuid,uuid,text),
  public.st_v6_set_meeting_spotlight(uuid,uuid),sectalk_private.st_v6_meeting_roster_changed() from public,anon,authenticated;
grant execute on function public.st_v6_meeting_roster(uuid),public.st_v6_send_meeting_chat(uuid,uuid,text),
  public.st_v6_set_meeting_spotlight(uuid,uuid) to authenticated;
alter publication supabase_realtime add table public.st_v6_meeting_chat,public.st_v6_meeting_controls;

commit;
