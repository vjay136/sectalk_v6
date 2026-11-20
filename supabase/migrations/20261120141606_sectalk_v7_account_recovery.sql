begin;

create table sectalk_private.st_v7_recovery_keys (
  user_id uuid primary key references auth.users on delete cascade,
  factor_id uuid not null references auth.mfa_factors on delete cascade,
  key_hash bytea not null,
  created_at timestamptz not null default statement_timestamp()
);
create table sectalk_private.st_v7_recovery_device_approvals (
  user_id uuid primary key references auth.users on delete cascade,
  request_id uuid not null unique default gen_random_uuid(),
  requester_session uuid not null,
  approved_at timestamptz,
  approving_device uuid references sectalk_private.st_v7_devices on delete set null
);
alter table sectalk_private.st_v7_recovery_keys enable row level security;
alter table sectalk_private.st_v7_recovery_device_approvals enable row level security;
revoke all on sectalk_private.st_v7_recovery_keys, sectalk_private.st_v7_recovery_device_approvals
  from public,anon,authenticated,service_role;

create function public.st_v7_manage_recovery_key(p_action text)
returns text language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  native_factor uuid;
  clear_key text;
begin
  if not coalesce(public.st_v7_current_session_valid(),false)
    or public.st_v7_login_risk_status()<>'clear' or public.st_v7_account_under_lockdown()
    or exists(select 1 from sectalk_private.staff where user_id=actor) then return 'unavailable'; end if;
  if p_action='status' then
    return case when exists(select 1 from sectalk_private.st_v7_recovery_keys k where k.user_id=actor)
      then 'configured' else 'missing' end;
  end if;
  if p_action is null or p_action not in ('issue','revoke') or not sectalk_private.st_v7_security_session('totp') then
    return 'unavailable';
  end if;
  perform 1 from auth.users u where u.id=actor for update;
  select s.factor_id into native_factor from auth.sessions s
    where s.id::text=auth.jwt()->>'session_id' and s.user_id=actor;
  if native_factor is null or (p_action='issue' and
    (select count(*) from auth.mfa_factors f where f.user_id=actor and f.status='verified')<>1) then return 'unavailable'; end if;
  perform sectalk_private.limit_action('account_recovery_key',5);
  delete from sectalk_private.st_v7_recovery_keys k where k.user_id=actor;
  if p_action='issue' then
    clear_key:=upper(encode(extensions.gen_random_bytes(32),'hex'));
    insert into sectalk_private.st_v7_recovery_keys(user_id,factor_id,key_hash)
      values(actor,native_factor,extensions.digest(clear_key,'sha256'));
  end if;
  update sectalk_private.st_v7_account_security_changes c set state='cancelled',binding=null,approved_until=null
    where c.user_id=actor and c.kind='recovery' and c.binding is not null and c.state='pending'
      and not exists(select 1 from sectalk_private.account_recovery_sets r where r.user_id=actor and c.binding=any(r.code_hashes))
      and not exists(select 1 from sectalk_private.st_v7_recovery_device_approvals a where a.user_id=actor
        and extensions.digest(a.request_id::text,'sha256')=c.binding);
  if found then perform sectalk_private.st_v7_record_security_event(actor,'recovery','cancelled'); end if;
  return coalesce(clear_key,'revoked');
end $$;

create function sectalk_private.st_v7_request_device_recovery(p_actor uuid,p_event_time timestamptz)
returns text language plpgsql set search_path='' as $$
declare
  pending sectalk_private.st_v7_account_security_changes;
  approval sectalk_private.st_v7_recovery_device_approvals;
  current_session uuid:=(auth.jwt()->>'session_id')::uuid;
begin
  select c.* into pending from sectalk_private.st_v7_account_security_changes c where c.user_id=p_actor for update;
  select a.* into approval from sectalk_private.st_v7_recovery_device_approvals a where a.user_id=p_actor;
  if pending.state in ('pending','approved') and pending.expires_at>p_event_time then
    if pending.kind<>'recovery' or approval.request_id is null
      or pending.binding is distinct from extensions.digest(approval.request_id::text,'sha256') then return 'unavailable'; end if;
    if approval.approved_at is null or pending.ready_at>p_event_time then return 'pending'; end if;
    perform 1 from sectalk_private.st_v7_devices d where d.id=approval.approving_device and d.owner=p_actor
      and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null for share;
    if not found then return 'unavailable'; end if;
    perform sectalk_private.st_v7_finish_authenticator_reset(p_actor,'recovery');
    delete from sectalk_private.st_v7_recovery_device_approvals where user_id=p_actor;
    return 'completed';
  end if;
  if not exists(select 1 from sectalk_private.st_v7_devices d where d.owner=p_actor
    and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null
    and exists(select 1 from sectalk_private.st_v7_device_sessions b join auth.sessions s on s.id=b.session_id and s.user_id=b.owner
      where b.device_id=d.id and b.owner=p_actor and s.aal='aal2' and s.id<>current_session
        and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp())) then
    return 'unavailable';
  end if;
  insert into sectalk_private.st_v7_recovery_device_approvals as a(user_id,requester_session)
    values(p_actor,current_session)
    on conflict(user_id) do update set request_id=excluded.request_id,requester_session=excluded.requester_session,
      approved_at=null,approving_device=null
    returning a.* into approval;
  insert into sectalk_private.st_v7_account_security_changes as c(user_id,kind,state,binding,requested_at,ready_at,expires_at)
    values(p_actor,'recovery','pending',extensions.digest(approval.request_id::text,'sha256'),p_event_time,
      p_event_time+interval '24 hours',p_event_time+interval '7 days')
    on conflict(user_id) do update set kind=excluded.kind,state=excluded.state,binding=excluded.binding,
      requested_at=excluded.requested_at,ready_at=excluded.ready_at,expires_at=excluded.expires_at,approved_until=null;
  perform sectalk_private.st_v7_record_security_event(p_actor,'recovery','requested');
  return 'pending';
end $$;

create function public.st_v7_device_recovery_to_approve()
returns uuid language sql stable security definer set search_path='' as $$
  select a.request_id from sectalk_private.st_v7_recovery_device_approvals a
  join sectalk_private.st_v7_account_security_changes c on c.user_id=a.user_id
  join sectalk_private.st_v7_device_sessions b on b.owner=a.user_id and b.session_id::text=auth.jwt()->>'session_id'
  join sectalk_private.st_v7_devices d on d.id=b.device_id and d.owner=b.owner
  join auth.sessions s on s.id=b.session_id and s.user_id=a.user_id
  join auth.mfa_factors f on f.id=s.factor_id and f.user_id=s.user_id
  where a.user_id=auth.uid() and a.requester_session<>b.session_id and a.approved_at is null
    and c.kind='recovery' and c.state='pending' and c.expires_at>statement_timestamp()
    and c.binding=extensions.digest(a.request_id::text,'sha256')
    and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null
    and d.created_at<c.requested_at and public.st_v7_login_risk_status()='clear'
    and s.aal='aal2' and f.status='verified' and f.factor_type='totp'
    and exists(select 1 from auth.mfa_amr_claims amr where amr.session_id=s.id
      and amr.authentication_method='totp' and amr.created_at<c.requested_at)
    and sectalk_private.st_v7_manage_sessions()
$$;

-- Only the existing proof-verifying Edge handler can invoke this RPC.
create function public.st_v7_finish_device_recovery_approval(
  p_owner uuid,p_session uuid,p_challenge uuid,p_signature text,p_recovery uuid
) returns boolean language plpgsql security definer set search_path='' as $$
declare approval sectalk_private.st_v7_recovery_device_approvals;
begin
  perform 1 from auth.users u where u.id=p_owner for update;
  select a.* into approval from sectalk_private.st_v7_recovery_device_approvals a
  join sectalk_private.st_v7_account_security_changes c on c.user_id=a.user_id
  join sectalk_private.st_v7_device_sessions b on b.session_id=p_session and b.owner=a.user_id
  join sectalk_private.st_v7_devices d on d.id=b.device_id and d.owner=b.owner
  join sectalk_private.st_v7_device_challenges ch on ch.session_id=b.session_id and ch.device_id=d.id and ch.owner=d.owner
  join auth.sessions s on s.id=b.session_id and s.user_id=b.owner
  join auth.mfa_factors f on f.id=s.factor_id and f.user_id=s.user_id
  where a.user_id=p_owner and a.request_id=p_recovery and a.requester_session<>p_session and a.approved_at is null
    and c.kind='recovery' and c.state='pending' and c.expires_at>statement_timestamp()
    and c.binding=extensions.digest(a.request_id::text,'sha256')
    and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null and d.created_at<c.requested_at
    and ch.id=p_challenge and ch.expires_at>statement_timestamp() and ch.signing_key=d.signing_key
    and s.aal='aal2' and f.status='verified' and f.factor_type='totp'
    and exists(select 1 from auth.mfa_amr_claims amr where amr.session_id=s.id
      and amr.authentication_method='totp' and amr.created_at<c.requested_at)
    and not exists(select 1 from sectalk_private.st_v7_account_lockdowns l where l.user_id=a.user_id and l.released_at is null)
  for update of a,c,d;
  if not found or not public.st_v7_finish_device_bundle(p_owner,p_session,p_challenge,p_signature) then return false; end if;
  update sectalk_private.st_v7_recovery_device_approvals a set approved_at=clock_timestamp(),
    approving_device=(select b.device_id from sectalk_private.st_v7_device_sessions b where b.session_id=p_session)
    where a.request_id=p_recovery;
  perform realtime.send('{}','account_security_lifecycle','st:account:'||p_owner,true);
  return true;
end $$;

revoke all on function public.st_v7_manage_recovery_key(text), public.st_v7_device_recovery_to_approve(),
  public.st_v7_finish_device_recovery_approval(uuid,uuid,uuid,text,uuid),
  sectalk_private.st_v7_request_device_recovery(uuid,timestamptz) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_manage_recovery_key(text),public.st_v7_device_recovery_to_approve() to authenticated;
grant execute on function public.st_v7_finish_device_recovery_approval(uuid,uuid,uuid,text,uuid) to service_role;

create or replace function public.st_v7_recovery_security_reset(p_code text)
returns text language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  pending sectalk_private.st_v7_account_security_changes;
  event_time timestamptz:=clock_timestamp();
  normal_code text;
  token bytea;
begin
  if not public.st_v7_current_session_valid() or not sectalk_private.st_v7_security_session('password') or exists(select 1 from sectalk_private.staff where user_id=actor)
    or p_code is null or length(p_code)>64 then return 'unavailable'; end if;
  perform 1 from auth.users where id=actor for update;
  if not found or not public.st_v7_current_session_valid() then return 'unavailable'; end if;
  perform sectalk_private.limit_action('account_authenticator_recovery',5);
  if p_code='device-approval' then return sectalk_private.st_v7_request_device_recovery(actor,event_time); end if;
  normal_code:=upper(regexp_replace(p_code,'[[:space:]-]','','g'));
  if normal_code !~ '^([0-9A-F]{32}|[0-9A-F]{64})$' then return 'unavailable'; end if;
  token:=extensions.digest(normal_code,'sha256');
  if not (exists(select 1 from sectalk_private.st_v7_recovery_keys k
    join auth.mfa_factors f on f.id=k.factor_id and f.user_id=k.user_id and f.status='verified' and f.factor_type='totp'
    where length(normal_code)=64 and k.user_id=actor and k.key_hash=token) or exists(select 1 from sectalk_private.account_recovery_sets r
    join auth.mfa_factors f on f.id=r.factor_id and f.user_id=r.user_id and f.status='verified' and f.factor_type='totp'
    where r.user_id=actor and token=any(r.code_hashes)))
    or (select count(*) from auth.mfa_factors f where f.user_id=actor and f.status='verified')<>1 then return 'unavailable'; end if;
  select r.* into pending from sectalk_private.st_v7_account_security_changes r where r.user_id=actor for update;
  if pending.state in ('pending','approved') and pending.expires_at>event_time then
    if pending.kind<>'recovery' or pending.binding is distinct from token then return 'unavailable'; end if;
    if pending.ready_at>event_time then return 'pending'; end if;
    perform sectalk_private.st_v7_finish_authenticator_reset(actor,'recovery');
    return 'completed';
  end if;
  insert into sectalk_private.st_v7_account_security_changes(user_id,kind,state,binding,requested_at,ready_at,expires_at)
    values(actor,'recovery','pending',token,event_time,event_time+interval '24 hours',event_time+interval '7 days')
    on conflict(user_id) do update set kind=excluded.kind,state=excluded.state,binding=excluded.binding,
      requested_at=excluded.requested_at,ready_at=excluded.ready_at,expires_at=excluded.expires_at,approved_until=null;
  perform sectalk_private.st_v7_record_security_event(actor,'recovery','requested');
  return 'pending';
end $$;
create or replace function public.st_v7_account_data_unavailable()
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v7_account_lockdowns l where l.user_id=auth.uid()
    and (l.released_at is null or not public.st_v7_current_session_valid()))
    or (not public.st_v7_current_session_valid() and (
      exists(select 1 from sectalk_private.st_v7_account_admin_audit a where a.target=auth.uid()
        and a.action in ('force_logout','reset_completed'))
      or exists(select 1 from sectalk_private.st_v7_account_security_events e where e.user_id=auth.uid()
        and e.kind in ('recovery','authenticator') and e.action='completed')));
$$;

commit;
