begin;

create table sectalk_private.st_v7_signin_risk (
  session_id uuid primary key references auth.sessions on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  observed_at timestamptz not null default clock_timestamp(),
  challenge uuid unique,
  challenge_at timestamptz,
  mailbox_verified_at timestamptz,
  trusted_device_verified_at timestamptz
);
alter table sectalk_private.st_v7_signin_risk enable row level security;
revoke all on sectalk_private.st_v7_signin_risk from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_password_session_outlier(observed auth.sessions)
returns boolean language sql stable set search_path='' as $$
  select observed.ip is not null and exists(
    select 1 from sectalk_private.st_v7_device_sessions b
    join sectalk_private.st_v7_devices d on d.id=b.device_id and d.owner=b.owner
    join auth.sessions baseline on baseline.id=b.session_id and baseline.user_id=b.owner
    where b.owner=observed.user_id and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null
      and baseline.created_at<observed.created_at and baseline.ip is not null
      and sectalk_private.st_v7_login_browser(baseline.user_agent) is not null
      and sectalk_private.st_v7_session_deadline(baseline.created_at,baseline.refreshed_at,baseline.not_after)>statement_timestamp()
    having bool_and(sectalk_private.st_v7_login_network(baseline.ip)<>sectalk_private.st_v7_login_network(observed.ip)
      and sectalk_private.st_v7_login_browser(baseline.user_agent)
        <>coalesce(sectalk_private.st_v7_login_browser(observed.user_agent),'other'))
  )
$$;

create function sectalk_private.st_v7_record_signin_risk()
returns trigger language plpgsql security definer set search_path='' as $$
declare observed auth.sessions;
begin
  if new.authentication_method='password' then
    select s.* into observed from auth.sessions s where s.id=new.session_id;
    if found and sectalk_private.st_v7_password_session_outlier(observed) then
      insert into sectalk_private.st_v7_signin_risk(session_id,user_id)
        values(observed.id,observed.user_id) on conflict do nothing;
    end if;
  end if;
  return new;
end $$;
create trigger st_v7_record_signin_risk after insert on auth.mfa_amr_claims
  for each row execute function sectalk_private.st_v7_record_signin_risk();

create function public.st_v7_login_risk_status()
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
  select r.* into risk from sectalk_private.st_v7_signin_risk r where r.session_id=signed_session and r.user_id=actor;
  if not found then return 'clear'; end if;
  if exists(select 1 from auth.mfa_factors f where f.user_id=actor and f.status='verified') then
    if token->>'aal'='aal2' and exists(
      select 1 from auth.sessions s join auth.mfa_factors f
       on f.id=s.factor_id and f.user_id=s.user_id and f.status='verified' and f.factor_type='totp'
      join auth.mfa_amr_claims a on a.session_id=s.id and a.authentication_method='totp'
      where s.id=signed_session and s.user_id=actor and s.aal='aal2') then return 'clear'; end if;
    return 'authenticator';
  end if;
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

create function public.st_v7_request_signin_code()
returns uuid language plpgsql security definer set search_path='' as $$
declare challenge_id uuid;
begin
  if public.st_v7_login_risk_status()<>'email' or public.st_v7_account_under_lockdown()
    or not exists(select 1 from auth.users u where u.id=auth.uid() and u.email_confirmed_at is not null) then
    raise exception 'Sign-in verification is unavailable' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v7_send_signin_code',5);
  update sectalk_private.st_v7_signin_risk r set
    challenge=case when r.challenge_at>clock_timestamp()-interval '10 minutes' then r.challenge else gen_random_uuid() end,
    challenge_at=case when r.challenge_at>clock_timestamp()-interval '10 minutes' then r.challenge_at else clock_timestamp() end
  where r.session_id=(auth.jwt()->>'session_id')::uuid and r.user_id=auth.uid() and r.mailbox_verified_at is null
  returning r.challenge into challenge_id;
  if challenge_id is null then raise exception 'Sign-in verification is unavailable' using errcode='42501'; end if;
  return challenge_id;
end $$;

create function public.st_v7_confirm_signin_code(p_challenge uuid)
returns boolean language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); otp_session uuid:=nullif(auth.jwt()->>'session_id','')::uuid;
begin
  if not public.st_v7_current_session_valid() or not sectalk_private.st_v7_security_session('otp')
    or public.st_v7_account_under_lockdown() or not exists(select 1 from auth.users u
     where u.id=actor and u.email_confirmed_at is not null)
    or exists(select 1 from auth.mfa_factors f where f.user_id=actor and f.status='verified') then return false; end if;
  perform sectalk_private.limit_action('v7_confirm_signin_code',10);
  update sectalk_private.st_v7_signin_risk r
  set mailbox_verified_at=clock_timestamp(),challenge=null
  where r.challenge=p_challenge and r.user_id=actor and r.mailbox_verified_at is null
    and r.challenge_at>clock_timestamp()-interval '10 minutes'
    and r.session_id<>otp_session
    and exists(select 1 from auth.sessions s join auth.mfa_amr_claims a
      on a.session_id=s.id and a.authentication_method='otp'
      where s.id=otp_session and s.user_id=actor and s.created_at>=r.challenge_at and a.updated_at>=r.challenge_at);
  return found;
end $$;

create function public.st_v7_step_up_pending()
returns boolean language sql stable security definer set search_path='' as $$
  select public.st_v7_login_risk_status() in ('email','authenticator','refresh')
$$;

create policy st_v7_signin_gate_broadcast on realtime.messages as restrictive for select to authenticated
 using(not (select public.st_v7_step_up_pending()));
create policy st_v7_signin_gate_direct on public.st_messages as restrictive for select to authenticated
 using(not (select public.st_v7_step_up_pending()));
create policy st_v7_signin_gate_room on public.st_v6_room_posts as restrictive for select to authenticated
 using(not (select public.st_v7_step_up_pending()));
create policy st_v7_signin_gate_chats on public.st_chats as restrictive for select to authenticated
 using(not (select public.st_v7_step_up_pending()));
create policy st_v7_signin_gate_objects on storage.objects as restrictive for all to authenticated
 using(not (select public.st_v7_step_up_pending())) with check(not (select public.st_v7_step_up_pending()));

revoke all on function sectalk_private.st_v7_password_session_outlier(auth.sessions),
  sectalk_private.st_v7_record_signin_risk(),public.st_v7_login_risk_status(),public.st_v7_request_signin_code(),
  public.st_v7_confirm_signin_code(uuid),public.st_v7_step_up_pending() from public,anon,authenticated,service_role;
grant execute on function public.st_v7_login_risk_status(),public.st_v7_request_signin_code(),
  public.st_v7_confirm_signin_code(uuid),public.st_v7_step_up_pending() to authenticated;

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
    '/rpc/st_v7_recovery_security_reset','/rpc/st_v7_note_lockdown_password_recovery',
    '/rpc/st_v7_begin_device_bundle','/rpc/st_v7_pending_device_bundle') then
    raise exception 'Verify this sign-in before continuing' using errcode='PT403';
  end if;
end $$;

create function sectalk_private.st_v7_trusted_device_for_signin(p_user uuid,p_session uuid,p_device uuid,p_signing text,p_agreement text)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v7_signin_risk r join sectalk_private.st_v7_devices d on d.owner=r.user_id
    where r.user_id=p_user and r.session_id=p_session and d.id=p_device and d.created_at<=r.observed_at
      and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null
      and d.signing_key=p_signing and d.agreement_key=p_agreement)
    and not exists(select 1 from auth.mfa_factors f where f.user_id=p_user and f.status='verified')
$$;
revoke all on function sectalk_private.st_v7_trusted_device_for_signin(uuid,uuid,uuid,text,text) from public,anon,authenticated,service_role;

create or replace function public.st_v7_begin_device_bundle(p_device uuid,p_signing text,p_agreement text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  session_key uuid;
  pending sectalk_private.st_v7_device_challenges;
begin
  if not sectalk_private.st_v7_manage_sessions() then
    raise exception 'Verify this session before registering a device' using errcode='42501';
  end if;
  session_key:=(auth.jwt()->>'session_id')::uuid;
  if p_device is null or p_signing is null or p_agreement is null
    or p_signing !~ '^[A-Za-z0-9_-]{87}$' or p_agreement !~ '^[A-Za-z0-9_-]{87}$'
    or p_signing=p_agreement then raise exception 'Invalid device key bundle' using errcode='22023'; end if;
  if public.st_v7_account_under_lockdown() and not exists(
    select 1 from sectalk_private.st_v7_account_lockdowns l join sectalk_private.st_v7_devices d on d.owner=l.user_id
    where l.user_id=actor and l.released_at is null and d.id=p_device and d.created_at<=l.locked_at
      and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null
      and d.signing_key=p_signing and d.agreement_key=p_agreement) then
    raise exception 'Use a device that was trusted before account lockdown' using errcode='42501';
  end if;
  if public.st_v7_step_up_pending() and not sectalk_private.st_v7_trusted_device_for_signin(
    actor,session_key,p_device,p_signing,p_agreement) then
    raise exception 'Use a previously trusted device or verify this sign-in' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v7_device_registration',10);
  insert into sectalk_private.st_v7_device_challenges(session_id,owner,device_id,signing_key,agreement_key)
    values(session_key,actor,p_device,p_signing,p_agreement)
    on conflict(session_id) do update set id=excluded.id,device_id=excluded.device_id,signing_key=excluded.signing_key,
      agreement_key=excluded.agreement_key,nonce=excluded.nonce,expires_at=excluded.expires_at
    returning * into pending;
  return jsonb_build_object('challenge',pending.id,'owner',actor,'session',session_key,'device',p_device,'nonce',pending.nonce);
end $$;

create or replace function public.st_v7_finish_device_bundle(p_owner uuid,p_session uuid,p_challenge uuid,p_signature text)
returns boolean language plpgsql security definer set search_path='' as $$
declare
  pending sectalk_private.st_v7_device_challenges;
  existing sectalk_private.st_v7_devices;
  binding uuid;
begin
  if p_signature is null or p_signature !~ '^[A-Za-z0-9_-]{86}$' then return false; end if;
  perform 1 from auth.users where id=p_owner for update;
  if not found then return false; end if;
  -- Lock before consuming the challenge so explicit revocation and enrollment serialize.
  perform 1 from auth.sessions s where s.id=p_session and s.user_id=p_owner
    and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp() for update;
  if not found then return false; end if;
  delete from sectalk_private.st_v7_device_challenges d where d.id=p_challenge and d.owner=p_owner
    and d.session_id=p_session and d.expires_at>statement_timestamp() returning * into pending;
  if not found then return false; end if;
  select device_id into binding from sectalk_private.st_v7_device_sessions where session_id=p_session;
  if binding is not null and binding<>pending.device_id then return false; end if;
  select d.* into existing from sectalk_private.st_v7_devices d where d.id=pending.device_id for update;
  if found then
    if existing.owner<>p_owner or (existing.state='blocked' or existing.locked_at is not null or existing.wiped_at is not null) or existing.signing_key<>pending.signing_key
      or existing.agreement_key<>pending.agreement_key then return false; end if;
  else
    if (select count(*) from sectalk_private.st_v7_devices where owner=p_owner)>=100 then return false; end if;
    insert into sectalk_private.st_v7_devices(id,owner,signing_key,agreement_key,bundle_signature)
      values(pending.device_id,p_owner,pending.signing_key,pending.agreement_key,p_signature)
      on conflict do nothing;
    if not found then return false; end if;
    insert into sectalk_private.st_v7_device_trust_audit(device_id,state,source)
      values(pending.device_id,'known','owner');
  end if;
  insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id)
    values(p_session,p_owner,pending.device_id) on conflict(session_id) do nothing;
  if sectalk_private.st_v7_trusted_device_for_signin(
    p_owner,p_session,pending.device_id,pending.signing_key,pending.agreement_key) then
    update sectalk_private.st_v7_signin_risk r set
      trusted_device_verified_at=coalesce(r.trusted_device_verified_at,clock_timestamp()),challenge=null
    where r.session_id=p_session and r.user_id=p_owner;
  end if;
  return true;
end $$;

commit;
