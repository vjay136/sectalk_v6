begin;

-- Challenge enrolled users even when the current sign-in has no anomaly score.
create or replace function public.st_v7_login_risk_status()
returns text language plpgsql stable security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  token jsonb:=auth.jwt();
  signed_session uuid;
  risk sectalk_private.st_v7_signin_risk;
  proof_at timestamptz;
begin
  if not public.st_v7_current_session_valid() then return 'inactive'; end if;
  signed_session:=(token->>'session_id')::uuid;
  if exists(select 1 from auth.mfa_factors f where f.user_id=actor and f.status='verified') then
    if token->>'aal'='aal2' and exists(
      select 1 from auth.sessions s join auth.mfa_factors f
       on f.id=s.factor_id and f.user_id=s.user_id and f.status='verified' and f.factor_type='totp'
      join auth.mfa_amr_claims a on a.session_id=s.id and a.authentication_method='totp'
      where s.id=signed_session and s.user_id=actor and s.aal='aal2') then return 'clear'; end if;
    return 'authenticator';
  end if;
  select r.* into risk from sectalk_private.st_v7_signin_risk r where r.session_id=signed_session and r.user_id=actor;
  if not found then return 'clear'; end if;
  proof_at:=least(risk.mailbox_verified_at,risk.trusted_device_verified_at);
  if proof_at is not null then
    if token->>'iat' ~ '^[0-9]{1,12}$'
      and to_timestamp((token->>'iat')::double precision)>date_trunc('second',proof_at) then
      return 'clear';
    end if;
    return 'refresh';
  end if;
  return 'email';
end $$;

create or replace function public.st_v7_guard_account_lockdown()
returns void language plpgsql stable security definer set search_path='' as $$
declare route text:=regexp_replace(coalesce(current_setting('request.path',true),''),'^/rest/v1','');
begin
  if auth.role()='authenticated' and route not in ('/rpc/st_v7_current_session_valid','/rpc/st_v7_account_lock_status')
    and not public.st_v7_account_under_lockdown() and public.st_v7_account_data_unavailable() then
    raise exception 'This sign-in session has ended' using errcode='PT401';
  end if;
  if auth.role()='authenticated' and public.st_v7_account_under_lockdown() and route not in (
    '/rpc/st_v7_account_lock_status','/rpc/st_v7_current_session_valid','/rpc/st_v7_account_recovery_status','/rpc/st_v7_login_risk_status',
    '/rpc/st_v7_begin_device_bundle','/rpc/st_v7_pending_device_bundle','/rpc/st_v7_note_lockdown_password_recovery',
    '/rpc/st_v7_recover_account_lockdown') then
    raise exception 'This account is locked. Complete account recovery before accessing SecTalk data' using errcode='PT423';
  end if;
  if auth.role()='authenticated' and public.st_v7_step_up_pending() and route not in (
    '/rpc/st_v7_login_risk_status','/rpc/st_v7_account_lock_status','/rpc/st_v7_current_session_valid',
    '/rpc/st_v7_request_signin_code','/rpc/st_v7_confirm_signin_code','/rpc/st_v7_account_recovery_status',
    '/rpc/st_v7_recovery_security_reset','/rpc/st_v7_recover_authenticator','/rpc/st_v7_note_lockdown_password_recovery',
    '/rpc/st_v7_begin_device_bundle','/rpc/st_v7_pending_device_bundle') then
    raise exception 'Verify this sign-in before continuing' using errcode='PT403';
  end if;
end $$;

-- Postgres Changes checks each published row's underlying SELECT policy.
-- Cover each currently published application table with the same assurance rule.
do $$
declare published record;
begin
  for published in select schemaname,tablename from pg_publication_tables
    where pubname='supabase_realtime' and schemaname='public'
      and tablename not in ('st_messages','st_v6_room_posts','st_chats')
  loop
    execute format('create policy st_v7_native_totp_select on %I.%I as restrictive for select to authenticated
      using (not (select public.st_v7_step_up_pending()))', published.schemaname,published.tablename);
  end loop;
end $$;
commit;
