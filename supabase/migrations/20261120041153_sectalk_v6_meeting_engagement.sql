begin;

create table public.st_v6_meeting_hands (
  meeting_id uuid not null,
  user_id uuid not null references public.st_profiles(id) on delete cascade,
  admitted_at timestamptz not null,
  raised_at timestamptz,
  primary key(meeting_id,user_id),
  foreign key(meeting_id,user_id) references public.st_v3_attendance(meeting_id,user_id) on delete cascade
);
create table public.st_v6_meeting_reactions (
  meeting_id uuid not null,
  user_id uuid not null references public.st_profiles(id) on delete cascade,
  admitted_at timestamptz not null,
  reaction text not null check(reaction in ('clap','thumbs_up','heart','celebrate')),
  reacted_at timestamptz not null,
  expires_at timestamptz not null check(expires_at=reacted_at+interval '8 seconds'),
  primary key(meeting_id,user_id),
  foreign key(meeting_id,user_id) references public.st_v3_attendance(meeting_id,user_id) on delete cascade
);

create function sectalk_private.st_v6_engagement_author(p_meeting uuid,p_author uuid,p_admitted_at timestamptz)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(
    select 1 from public.st_v3_attendance a join public.st_v3_meetings m on m.id=a.meeting_id
    where a.meeting_id=p_meeting and a.user_id=p_author and a.status='admitted'
      and a.admitted_at=p_admitted_at and sectalk_private.st_v2_role(m.workspace_id,p_author) is not null
      and sectalk_private.st_v2_active(p_author) and sectalk_private.open_pair(m.host_id,p_author)
  )
$$;
revoke all on function sectalk_private.st_v6_engagement_author(uuid,uuid,timestamptz) from public,anon,authenticated;
grant execute on function sectalk_private.st_v6_engagement_author(uuid,uuid,timestamptz) to authenticated;

alter table public.st_v6_meeting_hands enable row level security;
alter table public.st_v6_meeting_reactions enable row level security;
revoke all on public.st_v6_meeting_hands,public.st_v6_meeting_reactions from public,anon,authenticated;
grant select on public.st_v6_meeting_hands,public.st_v6_meeting_reactions to authenticated;
create policy st_v6_meeting_hands_read on public.st_v6_meeting_hands for select to authenticated using(
  public.st_v3_media_access(meeting_id) and sectalk_private.st_v6_engagement_author(meeting_id,user_id,admitted_at)
);
create policy st_v6_meeting_reactions_read on public.st_v6_meeting_reactions for select to authenticated using(
  expires_at>statement_timestamp() and public.st_v3_media_access(meeting_id)
    and sectalk_private.st_v6_engagement_author(meeting_id,user_id,admitted_at)
);

create function sectalk_private.st_v6_lock_engagement_admission(p_meeting uuid)
returns timestamptz language plpgsql security definer set search_path='' as $$
declare
  admission timestamptz;
begin
  perform 1 from public.st_v3_meetings where id=p_meeting and status='live' and ends_at>clock_timestamp() for share;
  if found then
    select a.admitted_at into admission from public.st_v3_attendance a
      where a.meeting_id=p_meeting and a.user_id=auth.uid() and a.status='admitted' for update;
  end if;
  if admission is null or not public.st_v3_media_access(p_meeting) then
    raise exception 'Meeting participation is unavailable' using errcode='42501';
  end if;
  return admission;
end $$;

create function public.st_v6_set_meeting_hand(p_meeting uuid,p_raised boolean)
returns void language plpgsql security definer set search_path='' as $$
declare admission timestamptz;
begin
  perform sectalk_private.limit_action('v6_meeting_hand',18);
  if p_raised is null then raise exception 'Choose whether to raise your hand' using errcode='22023'; end if;
  admission:=sectalk_private.st_v6_lock_engagement_admission(p_meeting);
  insert into public.st_v6_meeting_hands as h(meeting_id,user_id,admitted_at,raised_at)
    values(p_meeting,auth.uid(),admission,case when p_raised then clock_timestamp() end)
  on conflict(meeting_id,user_id) do update set admitted_at=excluded.admitted_at,raised_at=excluded.raised_at
    where h.admitted_at is distinct from excluded.admitted_at or (h.raised_at is not null) is distinct from p_raised;
end $$;

create function public.st_v6_send_meeting_reaction(p_meeting uuid,p_reaction text)
returns void language plpgsql security definer set search_path='' as $$
declare
  admission timestamptz;
  reacted timestamptz;
begin
  perform sectalk_private.limit_action('v6_meeting_reaction',18);
  if p_reaction is null or p_reaction not in ('clap','thumbs_up','heart','celebrate')
    then raise exception 'Choose an available meeting reaction' using errcode='22023'; end if;
  admission:=sectalk_private.st_v6_lock_engagement_admission(p_meeting);
  reacted:=clock_timestamp();
  insert into public.st_v6_meeting_reactions(meeting_id,user_id,admitted_at,reaction,reacted_at,expires_at)
    values(p_meeting,auth.uid(),admission,p_reaction,reacted,reacted+interval '8 seconds')
  on conflict(meeting_id,user_id) do update set admitted_at=excluded.admitted_at,reaction=excluded.reaction,
    reacted_at=excluded.reacted_at,expires_at=excluded.expires_at;
end $$;

create function sectalk_private.st_v6_clear_meeting_engagement()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if old.admitted_at is distinct from new.admitted_at or new.status<>'admitted' then
    delete from public.st_v6_meeting_hands where meeting_id=old.meeting_id and user_id=old.user_id;
    delete from public.st_v6_meeting_reactions where meeting_id=old.meeting_id and user_id=old.user_id;
  end if;
  return new;
end $$;
create trigger st_v6_clear_meeting_engagement after update of status,admitted_at on public.st_v3_attendance
for each row execute function sectalk_private.st_v6_clear_meeting_engagement();

revoke all on function sectalk_private.st_v6_lock_engagement_admission(uuid),
  sectalk_private.st_v6_clear_meeting_engagement(),public.st_v6_set_meeting_hand(uuid,boolean),
  public.st_v6_send_meeting_reaction(uuid,text) from public,anon,authenticated;
grant execute on function public.st_v6_set_meeting_hand(uuid,boolean),public.st_v6_send_meeting_reaction(uuid,text) to authenticated;
alter publication supabase_realtime add table public.st_v6_meeting_hands,public.st_v6_meeting_reactions;

commit;
