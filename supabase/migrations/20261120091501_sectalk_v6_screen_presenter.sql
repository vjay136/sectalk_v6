begin;

create table sectalk_private.st_v6_screen_presenters (
  meeting_id uuid primary key references public.st_v3_meetings on delete cascade,
  user_id uuid not null references public.st_profiles on delete cascade,
  lease_digest text not null check (lease_digest ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz not null
);
alter table sectalk_private.st_v6_screen_presenters enable row level security;

create function public.st_v6_screen_presenter(
  p_meeting uuid, p_lease_digest text, p_action text
) returns boolean language plpgsql security definer set search_path = '' as $$
declare
  caller uuid := auth.uid();
  deadline timestamptz := clock_timestamp() + interval '60 seconds';
begin
  if caller is null or p_lease_digest is null or p_lease_digest !~ '^[a-f0-9]{64}$' then
    return false;
  end if;
  if p_action in ('claim', 'renew') and not public.st_v3_media_access(p_meeting) then
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

revoke all on function public.st_v6_screen_presenter(uuid, text, text) from public, anon;
grant execute on function public.st_v6_screen_presenter(uuid, text, text) to authenticated;

commit;
