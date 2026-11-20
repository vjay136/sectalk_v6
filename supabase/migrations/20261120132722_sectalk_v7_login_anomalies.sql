begin;

create table sectalk_private.st_v7_login_candidates (
  session_id uuid primary key references auth.sessions on delete cascade,
  ready_at timestamptz not null default (clock_timestamp()+interval '15 seconds')
);
create index st_v7_login_candidates_ready on sectalk_private.st_v7_login_candidates(ready_at,session_id);
create table sectalk_private.st_v7_login_anomalies (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  observed_session uuid not null unique,
  observed_at timestamptz not null,
  detected_at timestamptz not null default clock_timestamp(),
  state text not null default 'pending' check(state in ('pending','recognized','locked','recovered')),
  reviewed_at timestamptz
);
create index st_v7_login_anomalies_owner on sectalk_private.st_v7_login_anomalies(user_id,detected_at desc);
create table sectalk_private.st_v7_account_lockdowns (
  user_id uuid primary key references auth.users on delete cascade,
  anomaly uuid not null references sectalk_private.st_v7_login_anomalies on delete cascade,
  locked_at timestamptz not null,
  ready_at timestamptz not null,
  otp_password_at timestamptz,
  released_at timestamptz
);
alter table sectalk_private.st_v7_login_candidates enable row level security;
alter table sectalk_private.st_v7_login_anomalies enable row level security;
alter table sectalk_private.st_v7_account_lockdowns enable row level security;
revoke all on sectalk_private.st_v7_login_candidates,sectalk_private.st_v7_login_anomalies,
  sectalk_private.st_v7_account_lockdowns from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_login_browser(p_user_agent text)
returns text language sql immutable set search_path='' as $$
  select case when p_user_agent ilike '%Edg/%' then 'edge'
    when p_user_agent ilike '%Chrome/%' then 'chrome' when p_user_agent ilike '%Firefox/%' then 'firefox'
    when p_user_agent ilike '%Safari/%' then 'safari' end
$$;

create function sectalk_private.st_v7_login_network(p_ip inet)
returns cidr language sql immutable set search_path='' as $$
  select network(set_masklen(p_ip,case family(p_ip) when 4 then 24 else 56 end))
$$;

create function sectalk_private.st_v7_observe_native_login()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if exists(select 1 from sectalk_private.st_v7_devices d where d.owner=new.user_id
    and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null) then
    insert into sectalk_private.st_v7_login_candidates(session_id) values(new.id) on conflict do nothing;
  end if;
  return new;
end $$;
create trigger st_v7_observe_native_login after insert on auth.sessions
  for each row execute function sectalk_private.st_v7_observe_native_login();

create function sectalk_private.st_v7_detect_login_anomalies()
returns integer language plpgsql set search_path='' as $$
declare observed auth.sessions; item uuid; alert_id uuid; detected integer:=0;
begin
  for item in select c.session_id from sectalk_private.st_v7_login_candidates c where c.ready_at<=statement_timestamp()
    order by c.ready_at,c.session_id for update skip locked limit 300
  loop
    delete from sectalk_private.st_v7_login_candidates where session_id=item;
    select s.* into observed from auth.sessions s where s.id=item;
    if not found or observed.ip is null or sectalk_private.st_v7_login_browser(observed.user_agent) is null
      or not exists(select 1 from auth.mfa_amr_claims a where a.session_id=item and a.authentication_method='password')
      or exists(select 1 from sectalk_private.st_v7_account_lockdowns l where l.user_id=observed.user_id and l.released_at is null)
      or exists(select 1 from sectalk_private.st_v7_device_sessions b join sectalk_private.st_v7_devices d on d.id=b.device_id
        where b.session_id=item and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null)
      then continue; end if;

    if not exists(
      select 1 from sectalk_private.st_v7_device_sessions b join sectalk_private.st_v7_devices d on d.id=b.device_id
      join auth.sessions baseline on baseline.id=b.session_id and baseline.user_id=b.owner
      where b.owner=observed.user_id and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null
        and baseline.created_at<observed.created_at and baseline.ip is not null
        and sectalk_private.st_v7_login_browser(baseline.user_agent) is not null
        and sectalk_private.st_v7_session_deadline(baseline.created_at,baseline.refreshed_at,baseline.not_after)>statement_timestamp()
      having bool_and(sectalk_private.st_v7_login_network(baseline.ip)<>sectalk_private.st_v7_login_network(observed.ip)
        and sectalk_private.st_v7_login_browser(baseline.user_agent)<>sectalk_private.st_v7_login_browser(observed.user_agent))
      ) then continue; end if;

    if exists(select 1 from sectalk_private.st_v7_login_anomalies a where a.user_id=observed.user_id and a.state='pending'
      and a.detected_at>statement_timestamp()-interval '15 minutes') then continue; end if;
    alert_id:=null;
    insert into sectalk_private.st_v7_login_anomalies(user_id,observed_session,observed_at)
      values(observed.user_id,item,observed.created_at) on conflict do nothing returning id into alert_id;
    if alert_id is not null then
      detected:=detected+1;
      perform realtime.send('{}','login_anomaly','st:account:'||observed.user_id,true);
    end if;
  end loop;
  return detected;
end $$;
select cron.schedule('sectalk-v7-detect-login-anomalies','* * * * *','select sectalk_private.st_v7_detect_login_anomalies()');

create function public.st_v7_account_under_lockdown()
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v7_account_lockdowns l where l.user_id=auth.uid() and l.released_at is null)
$$;

create function public.st_v7_account_data_unavailable()
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v7_account_lockdowns l where l.user_id=auth.uid()
    and (l.released_at is null or not public.st_v7_current_session_valid()))
$$;

create function public.st_v7_guard_account_lockdown()
returns void language plpgsql stable security definer set search_path='' as $$
declare route text:=regexp_replace(coalesce(current_setting('request.path',true),''),'^/rest/v1','');
begin
  if auth.role()='authenticated' and route not in ('/rpc/st_v7_current_session_valid','/rpc/st_v7_account_lock_status')
    and not public.st_v7_account_under_lockdown() and public.st_v7_account_data_unavailable() then
    raise exception 'This sign-in session has ended' using errcode='PT401';
  end if;
  if auth.role()='authenticated' and public.st_v7_account_under_lockdown() and route not in (
    '/rpc/st_v7_account_lock_status','/rpc/st_v7_current_session_valid','/rpc/st_v7_account_recovery_status',
    '/rpc/st_v7_begin_device_bundle','/rpc/st_v7_pending_device_bundle','/rpc/st_v7_note_lockdown_password_recovery',
    '/rpc/st_v7_recover_account_lockdown') then
    raise exception 'This account is locked. Complete account recovery before accessing SecTalk data' using errcode='PT423';
  end if;
end $$;

create policy st_v7_locked_account_broadcasts on realtime.messages as restrictive for select to authenticated
  using(not (select public.st_v7_account_data_unavailable()));
create policy st_v7_locked_account_messages on public.st_messages as restrictive for select to authenticated
  using(not (select public.st_v7_account_data_unavailable()));
create policy st_v7_locked_account_chats on public.st_chats as restrictive for select to authenticated
  using(not (select public.st_v7_account_data_unavailable()));

create function sectalk_private.st_v7_trusted_native_device(p_actor uuid,p_before timestamptz)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v7_device_sessions b join sectalk_private.st_v7_devices d
    on d.id=b.device_id and d.owner=b.owner where b.owner=p_actor and b.session_id::text=auth.jwt()->>'session_id'
    and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null and d.created_at<=p_before)
$$;

create function sectalk_private.st_v7_recent_account_assurance()
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v7_manage_sessions() and sectalk_private.st_v7_security_session(
    case when exists(select 1 from auth.mfa_factors f where f.user_id=auth.uid() and f.status='verified')
      then 'totp' else 'password' end)
$$;

create function public.st_v7_list_login_anomalies()
returns table(id uuid,observed_at timestamptz,detected_at timestamptz,state text)
language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_v7_manage_sessions() then raise exception 'Verify this account to review login activity' using errcode='42501'; end if;
  return query select a.id,a.observed_at,a.detected_at,a.state from sectalk_private.st_v7_login_anomalies a
  where a.user_id=auth.uid() order by a.detected_at desc,a.id limit 25;
end $$;

create function public.st_v7_review_login_anomaly(p_anomaly uuid,p_action text)
returns boolean language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); target sectalk_private.st_v7_login_anomalies; reviewed timestamptz:=clock_timestamp();
begin
  if p_action is null or p_action not in ('recognize','lockdown')
    or not sectalk_private.st_v7_recent_account_assurance() then
    raise exception 'Verify your current account credentials to review this sign-in' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v7_login_review',10);
  perform 1 from auth.users where id=actor for update;
  select a.* into target from sectalk_private.st_v7_login_anomalies a where a.id=p_anomaly and a.user_id=actor for update;
  if not found or target.state<>'pending' then return false; end if;
  if target.observed_session::text=auth.jwt()->>'session_id'
    or not sectalk_private.st_v7_trusted_native_device(actor,target.observed_at) then
    raise exception 'Use a device that was trusted before this sign-in' using errcode='42501';
  end if;
  if p_action='recognize' then
    update sectalk_private.st_v7_login_anomalies set state='recognized',reviewed_at=reviewed where id=target.id;
  else
    if public.st_v7_account_under_lockdown() then return false; end if;
    update sectalk_private.st_v7_login_anomalies set state='locked',reviewed_at=reviewed where id=target.id;
    insert into sectalk_private.st_v7_account_lockdowns(user_id,anomaly,locked_at,ready_at)
      values(actor,target.id,reviewed,reviewed+interval '15 minutes')
      on conflict(user_id) do update set anomaly=excluded.anomaly,locked_at=excluded.locked_at,
        ready_at=excluded.ready_at,otp_password_at=null,released_at=null;
    delete from auth.sessions where user_id=actor;
    perform realtime.send('{}','session_lifecycle','st:account:'||actor,true);
  end if;
  perform realtime.send('{}','login_anomaly','st:account:'||actor,true);
  return true;
end $$;

create function public.st_v7_account_lock_status()
returns jsonb language sql stable security definer set search_path='' as $$
  select coalesce((select jsonb_build_object('locked',true,'ready_at',l.ready_at,
    'password_verified',l.otp_password_at is not null) from sectalk_private.st_v7_account_lockdowns l
    where l.user_id=auth.uid() and l.released_at is null and public.st_v7_current_session_valid()),'{"locked":false}')
$$;

create function public.st_v7_note_lockdown_password_recovery()
returns boolean language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); proof_at timestamptz; credential_at timestamptz; active_lock sectalk_private.st_v7_account_lockdowns;
begin
  if not public.st_v7_account_under_lockdown() then return true; end if;
  if not public.st_v7_current_session_valid() or not sectalk_private.st_v7_security_session('otp') then return false; end if;
  select l.* into active_lock from sectalk_private.st_v7_account_lockdowns l where l.user_id=actor and l.released_at is null for update;
  if not found then return false; end if;
  select max(a.updated_at) into proof_at from auth.mfa_amr_claims a
    where a.session_id::text=auth.jwt()->>'session_id' and a.authentication_method='otp';
  select max(e.occurred_at) into credential_at from sectalk_private.st_v7_account_security_events e
    where e.user_id=actor and e.kind='password' and e.action='completed' and e.occurred_at>greatest(active_lock.locked_at,proof_at);
  if credential_at is null then return false; end if;
  update sectalk_private.st_v7_account_lockdowns set otp_password_at=credential_at where user_id=actor;
  return true;
end $$;

create function public.st_v7_recover_account_lockdown()
returns boolean language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); active_lock sectalk_private.st_v7_account_lockdowns;
begin
  if not sectalk_private.st_v7_recent_account_assurance() then
    raise exception 'Verify current account credentials before restoring access' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v7_lockdown_recovery',8);
  perform 1 from auth.users where id=actor for update;
  select l.* into active_lock from sectalk_private.st_v7_account_lockdowns l
    where l.user_id=actor and l.released_at is null for update;
  if not found then return false; end if;
  if active_lock.ready_at>clock_timestamp() or active_lock.otp_password_at is null
    or not sectalk_private.st_v7_trusted_native_device(actor,active_lock.locked_at) then return false; end if;
  delete from auth.sessions where user_id=actor and id::text<>auth.jwt()->>'session_id';
  update sectalk_private.st_v7_account_lockdowns set released_at=clock_timestamp() where user_id=actor;
  update sectalk_private.st_v7_login_anomalies set state='recovered' where id=active_lock.anomaly;
  perform realtime.send('{}','login_anomaly','st:account:'||actor,true);
  return true;
end $$;

revoke all on function sectalk_private.st_v7_login_browser(text),sectalk_private.st_v7_login_network(inet),
  sectalk_private.st_v7_observe_native_login(),sectalk_private.st_v7_detect_login_anomalies(),
  sectalk_private.st_v7_trusted_native_device(uuid,timestamptz),sectalk_private.st_v7_recent_account_assurance(),
  public.st_v7_account_under_lockdown(),public.st_v7_account_data_unavailable(),public.st_v7_guard_account_lockdown(),public.st_v7_list_login_anomalies(),
  public.st_v7_review_login_anomaly(uuid,text),public.st_v7_account_lock_status(),public.st_v7_note_lockdown_password_recovery(),
  public.st_v7_recover_account_lockdown() from public,anon,authenticated,service_role;
grant execute on function public.st_v7_guard_account_lockdown() to anon,authenticated,service_role;
grant execute on function public.st_v7_account_under_lockdown(),public.st_v7_account_data_unavailable(),public.st_v7_list_login_anomalies(),
  public.st_v7_review_login_anomaly(uuid,text),public.st_v7_account_lock_status(),public.st_v7_note_lockdown_password_recovery(),
  public.st_v7_recover_account_lockdown() to authenticated;

do $$
begin
  if exists(select 1 from pg_catalog.pg_roles r, unnest(r.rolconfig) setting
    where r.rolname='authenticator' and setting like 'pgrst.db_pre_request=%'
      and setting<>'pgrst.db_pre_request=public.st_v7_guard_account_lockdown') then
    raise exception 'Chain the SecTalk lockdown guard through the existing PostgREST pre-request hook before applying';
  end if;
  alter role authenticator set pgrst.db_pre_request='public.st_v7_guard_account_lockdown';
end $$;
notify pgrst,'reload config';

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
  perform sectalk_private.limit_action('v7_device_registration',10);
  insert into sectalk_private.st_v7_device_challenges(session_id,owner,device_id,signing_key,agreement_key)
    values(session_key,actor,p_device,p_signing,p_agreement)
    on conflict(session_id) do update set id=excluded.id,device_id=excluded.device_id,signing_key=excluded.signing_key,
      agreement_key=excluded.agreement_key,nonce=excluded.nonce,expires_at=excluded.expires_at
    returning * into pending;
  return jsonb_build_object('challenge',pending.id,'owner',actor,'session',session_key,'device',p_device,'nonce',pending.nonce);
end $$;

commit;
