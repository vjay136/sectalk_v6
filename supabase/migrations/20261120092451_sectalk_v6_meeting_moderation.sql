begin;

alter table public.st_v3_meetings
  add column meeting_locked boolean not null default false,
  add column chat_disabled boolean not null default false,
  add column screen_share_disabled boolean not null default false;

alter table public.st_v3_attendance
  add column is_cohost boolean not null default false,
  add column removed_at timestamptz;

create function sectalk_private.st_v6_is_meeting_moderator(p_meeting uuid, p_actor uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select p_actor is not null and sectalk_private.st_v2_active(p_actor) and (
    sectalk_private.st_v3_is_host(p_meeting, p_actor) or exists (
      select 1 from public.st_v3_meetings m
      join public.st_v3_attendance a on a.meeting_id = m.id
      where m.id = p_meeting and m.status = 'live' and m.ends_at > now()
        and a.user_id = p_actor and a.status = 'admitted' and a.is_cohost
        and sectalk_private.st_v2_role(m.workspace_id, p_actor) is not null
        and sectalk_private.st_v2_active(m.host_id)
        and sectalk_private.st_v3_is_host(m.id, m.host_id)
        and sectalk_private.open_pair(m.host_id, p_actor)
    )
  )
$$;
revoke all on function sectalk_private.st_v6_is_meeting_moderator(uuid, uuid) from public, anon, authenticated;
grant execute on function sectalk_private.st_v6_is_meeting_moderator(uuid, uuid) to authenticated;

create policy st_v6_cohost_attendance_read on public.st_v3_attendance for select to authenticated
using (status = 'admitted' and sectalk_private.st_v6_is_meeting_moderator(meeting_id, (select auth.uid()))
  and sectalk_private.st_v6_meeting_visible_peer(meeting_id, user_id));

create function sectalk_private.st_v6_guard_meeting_attendance()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.status <> 'admitted' then new.is_cohost := false; end if;
  if new.status in ('waiting', 'admitted')
    and (tg_op = 'INSERT' or old.status <> new.status)
    and exists (select 1 from public.st_v3_meetings
      where id = new.meeting_id and meeting_locked and host_id <> new.user_id) then
    raise exception 'The meeting is locked' using errcode = '42501';
  end if;
  return new;
end
$$;
revoke all on function sectalk_private.st_v6_guard_meeting_attendance() from public, anon, authenticated;
create trigger st_v6_guard_meeting_attendance before insert or update of status on public.st_v3_attendance
for each row execute function sectalk_private.st_v6_guard_meeting_attendance();

create function sectalk_private.st_v6_guard_meeting_chat()
returns trigger language plpgsql security definer set search_path = '' as $$
declare disabled boolean;
begin
  select chat_disabled into disabled from public.st_v3_meetings where id = new.meeting_id for share;
  if disabled and not exists (select 1 from public.st_v6_meeting_chat
    where meeting_id = new.meeting_id and id = new.id and user_id = new.user_id and body = new.body) then
    raise exception 'Meeting chat is disabled' using errcode = '42501';
  end if;
  return new;
end
$$;
revoke all on function sectalk_private.st_v6_guard_meeting_chat() from public, anon, authenticated;
create trigger st_v6_guard_meeting_chat before insert on public.st_v6_meeting_chat
for each row execute function sectalk_private.st_v6_guard_meeting_chat();

create function public.st_v6_moderate_meeting(p_meeting uuid, p_action text, p_target uuid, p_enabled boolean)
returns uuid[] language plpgsql security definer set search_path = '' as $$
declare
  meeting public.st_v3_meetings;
  actor uuid := auth.uid();
  targets uuid[] := '{}';
  organizer boolean;
begin
  select * into meeting from public.st_v3_meetings where id = p_meeting for update;
  if not found then
    raise exception 'Meeting moderation is unavailable' using errcode = '42501';
  end if;
  if p_action = 'end' and meeting.status = 'ended' and (
    sectalk_private.st_v6_is_meeting_moderator(p_meeting, actor) or exists (
      select 1 from public.st_v2_workspace_audit audit where audit.workspace_id = meeting.workspace_id
        and audit.event = 'meeting.ended' and audit.target = p_meeting and audit.actor = auth.uid()
    )
  ) then return targets; end if;
  if not sectalk_private.st_v6_is_meeting_moderator(p_meeting, actor) then
    raise exception 'Meeting moderation is unavailable' using errcode = '42501';
  end if;
  if meeting.status <> 'live' or meeting.ends_at <= clock_timestamp() then
    raise exception 'Meeting moderation is unavailable' using errcode = '42501';
  end if;
  perform sectalk_private.limit_action('v6_moderate_meeting', 60);
  organizer := meeting.host_id = actor;

  if p_action in ('mute', 'mute_all', 'remove', 'cohost') then
    if p_action = 'cohost' and not organizer then
      raise exception 'Only the host can change co-hosts' using errcode = '42501';
    end if;
    select coalesce(array_agg(a.user_id), '{}'::uuid[]) into targets from public.st_v3_attendance a
      where a.meeting_id = p_meeting and (a.status = 'admitted' or (p_action = 'remove' and a.removed_at is not null))
        and a.user_id <> actor
        and a.user_id <> meeting.host_id and (organizer or not a.is_cohost)
        and sectalk_private.open_pair(actor, a.user_id)
        and (p_action = 'mute_all' or a.user_id = p_target);
    if p_action <> 'mute_all' and cardinality(targets) = 0 then
      raise exception 'Choose someone you can moderate in this meeting' using errcode = '42501';
    end if;
    if p_action = 'remove' then
      update public.st_v3_attendance set status = 'declined', removed_at = clock_timestamp(), left_at = clock_timestamp()
        where meeting_id = p_meeting and user_id = p_target and status = 'admitted';
      if not found then return targets; end if;
      delete from sectalk_private.st_v6_screen_presenters where meeting_id = p_meeting and user_id = p_target;
    elsif p_action = 'cohost' and p_enabled is not null then
      update public.st_v3_attendance set is_cohost = p_enabled
        where meeting_id = p_meeting and user_id = p_target and status = 'admitted';
    elsif p_action = 'cohost' then
      raise exception 'Choose whether to grant co-host access' using errcode = '22023';
    end if;
  elsif p_action = 'end' then
    update public.st_v3_meetings set status = 'ended' where id = p_meeting;
    update public.st_v3_attendance set status = 'left', left_at = clock_timestamp()
      where meeting_id = p_meeting and status in ('admitted', 'waiting');
    delete from sectalk_private.st_v6_screen_presenters where meeting_id = p_meeting;
  elsif p_action in ('lock', 'chat', 'screen') and p_enabled is not null then
    update public.st_v3_meetings set
      meeting_locked = case when p_action = 'lock' then p_enabled else meeting_locked end,
      chat_disabled = case when p_action = 'chat' then not p_enabled else chat_disabled end,
      screen_share_disabled = case when p_action = 'screen' then not p_enabled else screen_share_disabled end
      where id = p_meeting;
    if p_action = 'screen' and not p_enabled then
      delete from sectalk_private.st_v6_screen_presenters where meeting_id = p_meeting;
    end if;
  else
    raise exception 'Choose a valid meeting moderation action' using errcode = '22023';
  end if;

  insert into public.st_v2_workspace_audit(workspace_id, actor, event, target)
    values(meeting.workspace_id, actor, case when p_action = 'end' then 'meeting.ended' else 'meeting.moderation.' || p_action end, p_meeting);
  return targets;
end
$$;
revoke all on function public.st_v6_moderate_meeting(uuid, text, uuid, boolean) from public, anon, authenticated;
grant execute on function public.st_v6_moderate_meeting(uuid, text, uuid, boolean) to authenticated;

create or replace function public.st_v6_screen_presenter(
  p_meeting uuid, p_lease_digest text, p_action text
) returns boolean language plpgsql security definer set search_path = '' as $$
declare
  caller uuid := auth.uid();
  deadline timestamptz := clock_timestamp() + interval '60 seconds';
begin
  if caller is null or p_lease_digest is null or p_lease_digest !~ '^[a-f0-9]{64}$' then
    return false;
  end if;
  if p_action in ('claim', 'renew') and (not public.st_v3_media_access(p_meeting) or exists (select 1 from public.st_v3_meetings where id = p_meeting and screen_share_disabled)) then
    return false;
  end if;

  if p_action = 'claim' then
    insert into sectalk_private.st_v6_screen_presenters as presenter
      (meeting_id, user_id, lease_digest, expires_at)
    values (p_meeting, caller, p_lease_digest, deadline)
    on conflict (meeting_id) do update set
      user_id = excluded.user_id, lease_digest = excluded.lease_digest, expires_at = excluded.expires_at
    where presenter.expires_at <= clock_timestamp();
    return found;
  end if;

  if p_action in ('renew', 'closing') then
    update sectalk_private.st_v6_screen_presenters set expires_at = deadline
      where meeting_id = p_meeting and user_id = caller and lease_digest = p_lease_digest
      and (p_action = 'closing' or expires_at > clock_timestamp());
    return found;
  end if;

  if p_action = 'release' then
    delete from sectalk_private.st_v6_screen_presenters
      where meeting_id = p_meeting and user_id = caller and lease_digest = p_lease_digest;
    return found;
  end if;

  return false;
end;
$$;

commit;
