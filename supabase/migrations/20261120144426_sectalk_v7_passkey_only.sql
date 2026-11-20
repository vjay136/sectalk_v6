begin;

create table sectalk_private.st_v7_passkey_mode (
  user_id uuid primary key references auth.users on delete cascade,
  enabled boolean not null,
  changed_at timestamptz not null default statement_timestamp()
);
alter table sectalk_private.st_v7_passkey_mode enable row level security;
revoke all on sectalk_private.st_v7_passkey_mode from public,anon,authenticated,service_role;

create function public.st_v7_passkey_only(p_enabled boolean default null)
returns boolean language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
  active_session uuid;
begin
  if not public.st_v7_current_session_valid() or public.st_v7_login_risk_status()<>'clear'
    or public.st_v7_account_under_lockdown() then raise exception 'Verify your account first' using errcode='42501'; end if;
  if p_enabled is null then
    return coalesce((select m.enabled from sectalk_private.st_v7_passkey_mode m where m.user_id=actor),false);
  end if;
  active_session:=(auth.jwt()->>'session_id')::uuid;
  perform pg_advisory_xact_lock(hashtextextended(actor::text,704));
  if not exists(select 1 from auth.mfa_amr_claims a join auth.sessions s on s.id=a.session_id
    where s.id=active_session and s.user_id=actor and a.authentication_method='passkey'
      and a.created_at>clock_timestamp()-interval '5 minutes') then
    raise exception 'Confirm with a fresh passkey sign-in' using errcode='42501';
  end if;
  if p_enabled and not exists(select 1 from auth.webauthn_credentials c where c.user_id=actor) then
    raise exception 'Register a passkey first' using errcode='22023';
  end if;
  insert into sectalk_private.st_v7_passkey_mode as m(user_id,enabled) values(actor,p_enabled)
    on conflict(user_id) do update set enabled=excluded.enabled,changed_at=clock_timestamp();
  if p_enabled then
    delete from auth.sessions s where s.user_id=actor and not exists(
      select 1 from auth.mfa_amr_claims a where a.session_id=s.id and a.authentication_method='passkey');
    perform realtime.send('{}','session_lifecycle','st:account:'||actor,true);
  end if;
  return p_enabled;
end $$;
revoke all on function public.st_v7_passkey_only(boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_passkey_only(boolean) to authenticated;

create function sectalk_private.st_v7_enforce_passkey_grant()
returns trigger language plpgsql security definer set search_path='' as $$
declare actor uuid;
begin
  if new.authentication_method='passkey' then return new; end if;
  select s.user_id into actor from auth.sessions s where s.id=new.session_id;
  if actor is null then return new; end if;
  perform pg_advisory_xact_lock(hashtextextended(actor::text,704));
  if exists(select 1 from sectalk_private.st_v7_passkey_mode m where m.user_id=actor and m.enabled)
    and not exists(select 1 from auth.mfa_amr_claims a where a.session_id=new.session_id and a.authentication_method='passkey') then
    raise exception 'Sign-in method unavailable' using errcode='42501';
  end if;
  return new;
end $$;
create trigger st_v7_enforce_passkey_grant before insert on auth.mfa_amr_claims
  for each row execute function sectalk_private.st_v7_enforce_passkey_grant();

create function sectalk_private.st_v7_keep_last_passkey()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform pg_advisory_xact_lock(hashtextextended(old.user_id::text,704));
  if exists(select 1 from auth.users u where u.id=old.user_id and u.deleted_at is null)
    and exists(select 1 from sectalk_private.st_v7_passkey_mode m where m.user_id=old.user_id and m.enabled)
    and not exists(select 1 from auth.webauthn_credentials c where c.user_id=old.user_id and c.id<>old.id) then
    raise exception 'Keep at least one passkey while passwordless-only sign-in is enabled' using errcode='42501';
  end if;
  return old;
end $$;
create trigger st_v7_keep_last_passkey before delete on auth.webauthn_credentials
  for each row execute function sectalk_private.st_v7_keep_last_passkey();
revoke all on function sectalk_private.st_v7_enforce_passkey_grant(),sectalk_private.st_v7_keep_last_passkey()
  from public,anon,authenticated,service_role;

create or replace function public.st_v7_account_data_unavailable()
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v7_account_lockdowns l where l.user_id=auth.uid()
    and (l.released_at is null or not public.st_v7_current_session_valid()))
    or (not public.st_v7_current_session_valid() and (
      exists(select 1 from sectalk_private.st_v7_account_admin_audit a where a.target=auth.uid()
        and a.action in ('force_logout','reset_completed','session_revoked'))
      or exists(select 1 from sectalk_private.st_v7_account_security_events e where e.user_id=auth.uid()
        and e.kind in ('recovery','authenticator') and e.action='completed')
      or exists(select 1 from sectalk_private.st_v7_passkey_mode m where m.user_id=auth.uid())));
$$;

create or replace function public.st_v7_step_up_pending()
returns boolean language sql stable security definer set search_path='' as $$
  select public.st_v7_login_risk_status() in ('email','authenticator','refresh')
    or (not public.st_v7_current_session_valid() and exists(
      select 1 from sectalk_private.st_v7_passkey_mode m where m.user_id=auth.uid()))
$$;

commit;
