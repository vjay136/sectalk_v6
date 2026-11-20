begin;

create function sectalk_private.st_v7_session_deadline(p_created timestamptz,p_refreshed timestamp,p_native timestamptz)
returns timestamptz language sql immutable set search_path='' as $$
  select least(p_native,p_created+interval '720 hours',
    coalesce(p_refreshed at time zone 'UTC',p_created)+interval '168 hours')
$$;

-- Bound the native timebox without extending a tighter provider-assigned deadline.
create function sectalk_private.st_v7_bound_auth_session()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if tg_op='INSERT' then
    new.created_at:=coalesce(new.created_at,statement_timestamp());
  else
    if new.refreshed_at is distinct from old.refreshed_at
      and sectalk_private.st_v7_session_deadline(old.created_at,old.refreshed_at,old.not_after)<=statement_timestamp() then
      raise exception 'This authentication session has ended' using errcode='42501';
    end if;
    new.not_after:=least(new.not_after,old.not_after);
  end if;
  new.not_after:=least(new.not_after,new.created_at+interval '720 hours');
  return new;
end $$;
create trigger st_v7_bound_auth_session before insert or update of not_after,refreshed_at on auth.sessions
  for each row execute function sectalk_private.st_v7_bound_auth_session();
update auth.sessions set not_after=least(not_after,created_at+interval '720 hours')
  where created_at is not null and (not_after is null or not_after>created_at+interval '720 hours');

create function sectalk_private.st_v7_prune_auth_sessions()
returns integer language plpgsql set search_path='' as $$
declare removed integer;
begin
  with doomed as (
    select s.id from auth.sessions s where s.not_after<=statement_timestamp()
      or coalesce(s.refreshed_at at time zone 'UTC',s.created_at)<=statement_timestamp()-interval '168 hours'
    order by s.id limit 500 for update skip locked
  )
  delete from auth.sessions s using doomed where s.id=doomed.id;
  get diagnostics removed=row_count;
  return removed;
end $$;
select cron.schedule('sectalk-v7-expire-auth-sessions','* * * * *','select sectalk_private.st_v7_prune_auth_sessions()');

create function public.st_v7_current_session_valid()
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from auth.sessions s where s.id=case
      when auth.jwt()->>'session_id' ~* '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
      then (auth.jwt()->>'session_id')::uuid end and s.user_id=auth.uid()
    and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp())
$$;

create function sectalk_private.st_v7_manage_sessions()
returns boolean language sql stable security definer set search_path='' as $$
  select public.st_v7_current_session_valid() and (
    not exists(select 1 from auth.mfa_factors f where f.user_id=auth.uid() and f.status='verified')
    or coalesce(sectalk_private.st_v6_retirement_has_mfa(),false))
$$;

create function public.st_v7_list_sessions()
returns table(id uuid,device text,started_at timestamptz,refreshed_at timestamptz,expires_at timestamptz,current_device boolean)
language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_v7_manage_sessions() then
    raise exception 'Sign in and verify your authenticator to manage devices' using errcode='42501';
  end if;
  return query
  select s.id,
    (case when s.user_agent ilike '%Edg/%' then 'Edge'
          when s.user_agent ilike '%Chrome/%' then 'Chrome'
          when s.user_agent ilike '%Firefox/%' then 'Firefox'
          when s.user_agent ilike '%Safari/%' then 'Safari'
          else 'Browser or app' end) ||
    (case when s.user_agent ilike '%iPhone%' or s.user_agent ilike '%iPad%' then ' on iOS'
          when s.user_agent ilike '%Android%' then ' on Android'
          when s.user_agent ilike '%Windows%' then ' on Windows'
          when s.user_agent ilike '%Macintosh%' then ' on macOS'
          when s.user_agent ilike '%Linux%' then ' on Linux' else '' end),
    s.created_at,coalesce(s.refreshed_at at time zone 'UTC',s.created_at),
    sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after),
    s.id::text=auth.jwt()->>'session_id'
  from auth.sessions s where s.user_id=auth.uid()
    and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
  order by (s.id::text=auth.jwt()->>'session_id') desc,coalesce(s.refreshed_at at time zone 'UTC',s.created_at) desc,s.id
  limit 100;
end $$;

create function public.st_v7_revoke_session(p_session uuid)
returns boolean language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if not sectalk_private.st_v7_manage_sessions() then
    raise exception 'Sign in and verify your authenticator to manage devices' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v7_session_revoke',20);
  delete from auth.sessions s where s.user_id=actor and s.id=p_session;
  if not found then return false; end if;
  perform realtime.send('{}','session_lifecycle','st:account:'||actor,true);
  return true;
end $$;

revoke all on function sectalk_private.st_v7_session_deadline(timestamptz,timestamp,timestamptz),
  sectalk_private.st_v7_bound_auth_session(),sectalk_private.st_v7_prune_auth_sessions(),sectalk_private.st_v7_manage_sessions(),
  public.st_v7_current_session_valid(),public.st_v7_list_sessions(),public.st_v7_revoke_session(uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_current_session_valid(),public.st_v7_list_sessions(),public.st_v7_revoke_session(uuid) to authenticated;
commit;
