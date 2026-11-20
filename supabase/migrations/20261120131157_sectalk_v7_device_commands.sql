begin;

alter table sectalk_private.st_v7_devices
  add column locked_at timestamptz,
  add column wiped_at timestamptz;

create table sectalk_private.st_v7_device_commands (
  id uuid primary key default gen_random_uuid(),
  device_id uuid not null references sectalk_private.st_v7_devices on delete cascade,
  kind text not null check(kind in ('revoke','lock','wipe')),
  state text not null default 'pending' check(state in ('pending','delivered','acknowledged','cancelled')),
  requested_at timestamptz not null default clock_timestamp(),
  delivered_at timestamptz,
  acknowledged_at timestamptz,
  cancelled_at timestamptz,
  previous_lock timestamptz,
  receipt text,
  receipt_digest bytea
);
create unique index st_v7_device_single_open_command on sectalk_private.st_v7_device_commands(device_id)
  where state in ('pending','delivered');
create index st_v7_device_command_recent on sectalk_private.st_v7_device_commands(device_id,requested_at desc,id);

create table sectalk_private.st_v7_device_poll_nonces (
  device_id uuid not null references sectalk_private.st_v7_devices on delete cascade,
  nonce uuid not null,
  used_at timestamptz not null default clock_timestamp(),
  primary key(device_id,nonce)
);
alter table sectalk_private.st_v7_device_commands enable row level security;
alter table sectalk_private.st_v7_device_poll_nonces enable row level security;
revoke all on sectalk_private.st_v7_device_commands,sectalk_private.st_v7_device_poll_nonces
  from public,anon,authenticated,service_role;

create function public.st_v7_list_device_commands()
returns table(device uuid,locked boolean,wiped boolean,command uuid,kind text,state text,requested_at timestamptz,
  delivered_at timestamptz,acknowledged_at timestamptz,cancelled_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_v7_manage_sessions() then
    raise exception 'Verify this session to read device commands' using errcode='42501';
  end if;
  return query select d.id,d.locked_at is not null,d.wiped_at is not null,c.id,c.kind,c.state,c.requested_at,
    c.delivered_at,c.acknowledged_at,c.cancelled_at
  from sectalk_private.st_v7_devices d
  left join lateral (select a.* from sectalk_private.st_v7_device_commands a where a.device_id=d.id
    order by a.requested_at desc,a.id limit 1) c on true
  where d.owner=auth.uid() order by d.created_at desc,d.id limit 100;
end $$;

create function public.st_v7_issue_device_command(p_device uuid,p_action text,p_command uuid default null)
returns boolean language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  device sectalk_private.st_v7_devices;
  pending sectalk_private.st_v7_device_commands;
  assurance text;
begin
  if not sectalk_private.st_v7_manage_sessions() then
    raise exception 'Verify this session to manage devices' using errcode='42501';
  end if;
  if p_action is null or p_action not in ('revoke','lock','wipe','cancel','unlock') then
    raise exception 'Choose a valid remote device action' using errcode='22023';
  end if;
  assurance:=case when exists(select 1 from auth.mfa_factors f where f.user_id=actor and f.status='verified')
    then 'totp' else 'password' end;
  if not sectalk_private.st_v7_security_session(assurance) then
    raise exception 'Verify your current account credentials to change device access' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v7_remote_device',15);
  perform 1 from auth.users where id=actor for update;
  select d.* into device from sectalk_private.st_v7_devices d where d.id=p_device and d.owner=actor for update;
  if not found then return false; end if;
  select c.* into pending from sectalk_private.st_v7_device_commands c
    where c.device_id=device.id and c.state in ('pending','delivered') for update;

  if p_action='cancel' then
    if pending.id is distinct from p_command or pending.state is distinct from 'pending' then return false; end if;
    update sectalk_private.st_v7_device_commands set state='cancelled',cancelled_at=clock_timestamp() where id=pending.id;
    if pending.kind in ('lock','wipe') then
      update sectalk_private.st_v7_devices set locked_at=pending.previous_lock where id=device.id;
    end if;
  elsif p_action='unlock' then
    if device.wiped_at is not null or pending.kind='wipe' then return false; end if;
    if pending.kind='lock' and pending.state='pending' then
      update sectalk_private.st_v7_device_commands set state='cancelled',cancelled_at=clock_timestamp() where id=pending.id;
    end if;
    update sectalk_private.st_v7_devices set locked_at=null where id=device.id;
  else
    if device.wiped_at is not null or pending.id is not null
      or (p_action='lock' and device.locked_at is not null) then return false; end if;
    insert into sectalk_private.st_v7_device_commands(device_id,kind,previous_lock)
      values(device.id,p_action,device.locked_at);
    if p_action in ('lock','wipe') then
      update sectalk_private.st_v7_devices set locked_at=coalesce(locked_at,clock_timestamp()) where id=device.id;
    end if;
    delete from auth.sessions s using sectalk_private.st_v7_device_sessions d
      where s.id=d.session_id and s.user_id=actor and d.owner=actor and d.device_id=device.id;
    perform realtime.send('{}','session_lifecycle','st:account:'||actor,true);
  end if;
  perform realtime.send('{}','device_registry','st:account:'||actor,true);
  return true;
end $$;

create function public.st_v7_device_command_key(p_owner uuid,p_device uuid)
returns text language sql stable security definer set search_path='' as $$
  select d.signing_key from sectalk_private.st_v7_devices d where d.id=p_device and d.owner=p_owner
$$;

-- The service calls this only after validating the registered signing key and
-- the short-lived, device-bound proof at the same-origin device endpoint.
create function public.st_v7_claim_device_command(p_owner uuid,p_device uuid,p_nonce uuid,p_at timestamptz)
returns jsonb language plpgsql security definer set search_path='' as $$
declare device sectalk_private.st_v7_devices; command sectalk_private.st_v7_device_commands;
begin
  if p_nonce is null or p_at is null or abs(extract(epoch from statement_timestamp()-p_at))>90 then return null; end if;
  select d.* into device from sectalk_private.st_v7_devices d where d.id=p_device and d.owner=p_owner for update;
  if not found then return null; end if;
  delete from sectalk_private.st_v7_device_poll_nonces where device_id=device.id and used_at<=statement_timestamp()-interval '3 minutes';
  insert into sectalk_private.st_v7_device_poll_nonces(device_id,nonce) values(device.id,p_nonce) on conflict do nothing;
  if not found then return null; end if;

  select c.* into command from sectalk_private.st_v7_device_commands c
    where c.device_id=device.id and c.state in ('pending','delivered') for update;
  if command.state='pending' then
    update sectalk_private.st_v7_device_commands
      set state='delivered',delivered_at=clock_timestamp(),receipt=encode(extensions.gen_random_bytes(32),'hex')
      where id=command.id returning * into command;
    if command.kind='wipe' then
      update sectalk_private.st_v7_devices set wiped_at=clock_timestamp() where id=device.id
        returning * into device;
    end if;
    perform realtime.send('{}','device_registry','st:account:'||p_owner,true);
  end if;
  return jsonb_build_object('locked',device.locked_at is not null,'wiped',device.wiped_at is not null,'blocked',device.state='blocked',
    'command',case when command.id is not null then jsonb_build_object(
      'id',command.id,'kind',command.kind,'receipt',command.receipt) end);
end $$;

create function public.st_v7_ack_device_command(p_device uuid,p_command uuid,p_receipt text)
returns boolean language plpgsql security definer set search_path='' as $$
declare command sectalk_private.st_v7_device_commands; actor uuid; digest bytea;
begin
  if p_receipt is null or p_receipt !~ '^[a-f0-9]{64}$' then return false; end if;
  select c.* into command from sectalk_private.st_v7_device_commands c
    where c.id=p_command and c.device_id=p_device for update;
  if not found then return false; end if;
  digest:=extensions.digest(p_receipt,'sha256');
  if command.state='acknowledged' then return coalesce(command.receipt_digest=digest,false); end if;
  if command.state<>'delivered' or extensions.digest(command.receipt,'sha256') is distinct from digest then return false; end if;
  update sectalk_private.st_v7_device_commands
    set state='acknowledged',receipt=null,receipt_digest=digest,acknowledged_at=clock_timestamp() where id=command.id;
  select d.owner into actor from sectalk_private.st_v7_devices d where d.id=p_device;
  perform realtime.send('{}','device_registry','st:account:'||actor,true);
  return true;
end $$;

revoke all on function public.st_v7_list_device_commands(),public.st_v7_issue_device_command(uuid,text,uuid),
  public.st_v7_device_command_key(uuid,uuid),public.st_v7_claim_device_command(uuid,uuid,uuid,timestamptz),
  public.st_v7_ack_device_command(uuid,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_list_device_commands(),public.st_v7_issue_device_command(uuid,text,uuid) to authenticated;
grant execute on function public.st_v7_device_command_key(uuid,uuid),public.st_v7_claim_device_command(uuid,uuid,uuid,timestamptz),
  public.st_v7_ack_device_command(uuid,uuid,text) to service_role;

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
  return true;
end $$;

create or replace function public.st_v7_peer_device_bundles(p_peer uuid)
returns table(device uuid,signing_key text,agreement_key text,bundle_signature text)
language plpgsql stable security definer set search_path='' as $$
declare me uuid:=auth.uid();
begin
  if not sectalk_private.st_v7_manage_sessions() or not exists(
    select 1 from sectalk_private.st_v7_device_sessions b join sectalk_private.st_v7_devices d
      on d.id=b.device_id and d.owner=b.owner where b.owner=me and b.session_id::text=auth.jwt()->>'session_id'
      and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null)
    or not exists(select 1 from public.st_chats c where c.member_a=least(me,p_peer) and c.member_b=greatest(me,p_peer)
      and c.status='accepted' and sectalk_private.open_pair(c.member_a,c.member_b)) then return; end if;
  return query select d.id,d.signing_key,d.agreement_key,d.bundle_signature from sectalk_private.st_v7_devices d
  where d.owner=p_peer and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null and exists(
    select 1 from sectalk_private.st_v7_device_sessions b join auth.sessions s on s.id=b.session_id and s.user_id=b.owner
    where b.device_id=d.id and b.owner=p_peer
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
  ) order by d.created_at,d.id limit 100;
end $$;

commit;
