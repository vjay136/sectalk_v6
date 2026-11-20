begin;

create table sectalk_private.st_v7_devices (
  id uuid primary key,
  owner uuid not null references auth.users on delete cascade,
  state text not null default 'known' check(state in ('known','trusted','managed','blocked')),
  signing_key text not null check(signing_key ~ '^[A-Za-z0-9_-]{87}$'),
  agreement_key text not null check(agreement_key ~ '^[A-Za-z0-9_-]{87}$'),
  bundle_signature text not null check(bundle_signature ~ '^[A-Za-z0-9_-]{86}$'),
  created_at timestamptz not null default clock_timestamp(),
  unique(owner,id),
  unique(signing_key),
  unique(agreement_key)
);
create index st_v7_devices_owner on sectalk_private.st_v7_devices(owner,created_at desc);
create table sectalk_private.st_v7_device_sessions (
  session_id uuid primary key references auth.sessions on delete cascade,
  owner uuid not null,
  device_id uuid not null,
  foreign key(owner,device_id) references sectalk_private.st_v7_devices(owner,id) on delete cascade
);
create index st_v7_device_sessions_device on sectalk_private.st_v7_device_sessions(device_id,session_id);
create table sectalk_private.st_v7_device_challenges (
  id uuid primary key default gen_random_uuid(),
  session_id uuid not null unique references auth.sessions on delete cascade,
  owner uuid not null references auth.users on delete cascade,
  device_id uuid not null,
  signing_key text not null check(signing_key ~ '^[A-Za-z0-9_-]{87}$'),
  agreement_key text not null check(agreement_key ~ '^[A-Za-z0-9_-]{87}$'),
  nonce text not null default encode(extensions.gen_random_bytes(32),'hex'),
  expires_at timestamptz not null default (clock_timestamp()+interval '5 minutes')
);
create table sectalk_private.st_v7_device_trust_audit (
  id bigint generated always as identity primary key,
  device_id uuid not null references sectalk_private.st_v7_devices on delete cascade,
  state text not null check(state in ('known','trusted','managed','blocked')),
  source text not null check(source in ('owner','provider')),
  management_reference text,
  occurred_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v7_devices enable row level security;
alter table sectalk_private.st_v7_device_sessions enable row level security;
alter table sectalk_private.st_v7_device_challenges enable row level security;
alter table sectalk_private.st_v7_device_trust_audit enable row level security;
revoke all on sectalk_private.st_v7_devices,sectalk_private.st_v7_device_sessions,
  sectalk_private.st_v7_device_challenges,sectalk_private.st_v7_device_trust_audit
  from public,anon,authenticated,service_role;

create function public.st_v7_begin_device_bundle(p_device uuid,p_signing text,p_agreement text)
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
  perform sectalk_private.limit_action('v7_device_registration',10);
  insert into sectalk_private.st_v7_device_challenges(session_id,owner,device_id,signing_key,agreement_key)
    values(session_key,actor,p_device,p_signing,p_agreement)
    on conflict(session_id) do update set id=excluded.id,device_id=excluded.device_id,signing_key=excluded.signing_key,
      agreement_key=excluded.agreement_key,nonce=excluded.nonce,expires_at=excluded.expires_at
    returning * into pending;
  return jsonb_build_object('challenge',pending.id,'owner',actor,'session',session_key,'device',p_device,'nonce',pending.nonce);
end $$;

create function public.st_v7_pending_device_bundle(p_challenge uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('challenge',d.id,'owner',d.owner,'device',d.device_id,'session',d.session_id,
    'nonce',d.nonce,'signing',d.signing_key,'agreement',d.agreement_key)
  from sectalk_private.st_v7_device_challenges d where d.id=p_challenge and d.owner=auth.uid()
    and d.session_id::text=auth.jwt()->>'session_id' and d.expires_at>statement_timestamp()
    and sectalk_private.st_v7_manage_sessions()
$$;

create function public.st_v7_finish_device_bundle(p_owner uuid,p_session uuid,p_challenge uuid,p_signature text)
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
    if existing.owner<>p_owner or existing.state='blocked' or existing.signing_key<>pending.signing_key
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

create function public.st_v7_list_devices()
returns table(id uuid,state text,fingerprint text,created_at timestamptz,current_device boolean,active_sessions bigint)
language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_v7_manage_sessions() then
    raise exception 'Device registry requires a verified session' using errcode='42501';
  end if;
  return query select d.id,d.state,encode(extensions.digest(d.signing_key,'sha256'),'hex'),d.created_at,
    coalesce(b.current_device,false),coalesce(b.active_sessions,0)
  from sectalk_private.st_v7_devices d cross join lateral (
    select bool_or(s.id::text=auth.jwt()->>'session_id') current_device,count(*) active_sessions
    from sectalk_private.st_v7_device_sessions l join auth.sessions s on s.id=l.session_id and s.user_id=l.owner
    where l.device_id=d.id and l.owner=d.owner
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
  ) b
  where d.owner=auth.uid() order by coalesce(b.current_device,false) desc,d.created_at desc,d.id limit 100;
end $$;

create function public.st_v7_set_device_trust(p_device uuid,p_state text)
returns boolean language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  device sectalk_private.st_v7_devices;
  current_device uuid;
  state_before text;
  assurance text;
begin
  if not sectalk_private.st_v7_manage_sessions() then raise exception 'Verify this session' using errcode='42501'; end if;
  if p_state is null or p_state not in ('known','trusted','blocked') then
    raise exception 'This trust level cannot be set by the account holder' using errcode='42501';
  end if;
  assurance:=case when exists(select 1 from auth.mfa_factors f where f.user_id=actor and f.status='verified')
    then 'totp' else 'password' end;
  if not sectalk_private.st_v7_security_session(assurance) then
    raise exception 'Verify your current account credentials to change trust' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v7_device_trust',15);
  perform 1 from auth.users where id=actor for update;
  select d.* into device from sectalk_private.st_v7_devices d where d.id=p_device and d.owner=actor for update;
  if not found then return false; end if;
  if device.state=p_state then return true; end if;
  if device.state='blocked' or (device.state='managed' and p_state<>'blocked') then return false; end if;
  if p_state in ('known','trusted') then
    select d.id,d.state into current_device,state_before from sectalk_private.st_v7_device_sessions s
      join sectalk_private.st_v7_devices d on d.id=s.device_id and d.owner=s.owner
      where s.session_id=(auth.jwt()->>'session_id')::uuid and s.owner=actor;
    if coalesce(state_before,'unknown') not in ('trusted','managed') and
      (p_state<>'trusted' or current_device is distinct from p_device or exists(
        select 1 from sectalk_private.st_v7_device_trust_audit a join sectalk_private.st_v7_devices d on d.id=a.device_id
        where d.owner=actor and a.state in ('trusted','managed'))) then
      raise exception 'Approve this device from an existing trusted device' using errcode='42501';
    end if;
  end if;
  update sectalk_private.st_v7_devices set state=p_state where id=device.id;
  insert into sectalk_private.st_v7_device_trust_audit(device_id,state,source) values(device.id,p_state,'owner');
  if p_state='blocked' then
    delete from auth.sessions s using sectalk_private.st_v7_device_sessions b
      where s.id=b.session_id and s.user_id=actor and b.owner=actor and b.device_id=device.id;
    perform realtime.send('{}','session_lifecycle','st:account:'||actor,true);
  end if;
  perform realtime.send('{}','device_registry','st:account:'||actor,true);
  return true;
end $$;

create function public.st_v7_mark_device_managed(p_owner uuid,p_device uuid,p_managed boolean,p_reference text)
returns boolean language plpgsql security definer set search_path='' as $$
declare previous text; next_state text:=case when p_managed then 'managed' else 'known' end;
begin
  if p_managed is null or p_reference is null or char_length(btrim(p_reference)) not between 1 and 120 then return false; end if;
  perform 1 from auth.users where id=p_owner for update;
  select d.state into previous from sectalk_private.st_v7_devices d where d.owner=p_owner and d.id=p_device for update;
  if not found or previous='blocked' or (not p_managed and previous<>'managed') then return false; end if;
  if previous=next_state then return true; end if;
  update sectalk_private.st_v7_devices set state=next_state where id=p_device;
  insert into sectalk_private.st_v7_device_trust_audit(device_id,state,source,management_reference)
    values(p_device,next_state,'provider',btrim(p_reference));
  perform realtime.send('{}','device_registry','st:account:'||p_owner,true);
  return true;
end $$;

create function public.st_v7_peer_device_bundles(p_peer uuid)
returns table(device uuid,signing_key text,agreement_key text,bundle_signature text)
language plpgsql stable security definer set search_path='' as $$
declare me uuid:=auth.uid();
begin
  if not sectalk_private.st_v7_manage_sessions() or not exists(
    select 1 from sectalk_private.st_v7_device_sessions b join sectalk_private.st_v7_devices d
      on d.id=b.device_id and d.owner=b.owner where b.owner=me and b.session_id::text=auth.jwt()->>'session_id'
      and d.state in ('trusted','managed'))
    or not exists(select 1 from public.st_chats c where c.member_a=least(me,p_peer) and c.member_b=greatest(me,p_peer)
      and c.status='accepted' and sectalk_private.open_pair(c.member_a,c.member_b)) then return; end if;
  return query select d.id,d.signing_key,d.agreement_key,d.bundle_signature from sectalk_private.st_v7_devices d
  where d.owner=p_peer and d.state in ('trusted','managed') and exists(
    select 1 from sectalk_private.st_v7_device_sessions b join auth.sessions s on s.id=b.session_id and s.user_id=b.owner
    where b.device_id=d.id and b.owner=p_peer
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
  ) order by d.created_at,d.id limit 100;
end $$;

revoke all on function public.st_v7_begin_device_bundle(uuid,text,text),public.st_v7_pending_device_bundle(uuid),
  public.st_v7_finish_device_bundle(uuid,uuid,uuid,text),public.st_v7_list_devices(),public.st_v7_set_device_trust(uuid,text),
  public.st_v7_mark_device_managed(uuid,uuid,boolean,text),public.st_v7_peer_device_bundles(uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_begin_device_bundle(uuid,text,text),public.st_v7_pending_device_bundle(uuid),
  public.st_v7_list_devices(),public.st_v7_set_device_trust(uuid,text),public.st_v7_peer_device_bundles(uuid) to authenticated;
grant execute on function public.st_v7_finish_device_bundle(uuid,uuid,uuid,text),public.st_v7_mark_device_managed(uuid,uuid,boolean,text)
  to service_role;
commit;
