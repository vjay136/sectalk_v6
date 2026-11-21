begin;

create table sectalk_private.st_v8_olm_devices (
  device uuid primary key references sectalk_private.st_v7_devices on delete cascade,
  owner uuid not null references auth.users on delete cascade,
  bundle jsonb not null check(jsonb_typeof(bundle)='object' and octet_length(bundle::text)<=4096),
  proof text not null check(proof ~ '^[A-Za-z0-9_-]{86}$'),
  installed_at timestamptz not null default clock_timestamp(),
  foreign key(owner,device) references sectalk_private.st_v7_devices(owner,id) on delete cascade
);

create table sectalk_private.st_v8_olm_prekeys (
  device uuid not null references sectalk_private.st_v8_olm_devices on delete cascade,
  name text not null check(name ~ '^signed_curve25519:[A-Za-z0-9_+/-]{1,64}$'),
  payload jsonb not null check(jsonb_typeof(payload)='object' and octet_length(payload::text)<=512),
  created_at timestamptz not null default clock_timestamp(),
  used_at timestamptz,
  primary key(device,name)
);
create index st_v8_olm_available_prekeys on sectalk_private.st_v8_olm_prekeys(device,created_at,name) where used_at is null;

alter table sectalk_private.st_v8_olm_devices enable row level security;
alter table sectalk_private.st_v8_olm_prekeys enable row level security;
revoke all on sectalk_private.st_v8_olm_devices,sectalk_private.st_v8_olm_prekeys from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_olm_actor_device()
returns sectalk_private.st_v7_devices language sql stable security definer set search_path='' as $$
  select d from sectalk_private.st_v7_devices d
  join sectalk_private.st_v7_device_sessions s on (s.owner,s.device_id)=(d.owner,d.id)
  where d.owner=auth.uid() and s.session_id::text=auth.jwt()->>'session_id'
    and d.state in ('trusted','managed') and sectalk_private.st_v7_manage_sessions()
    and sectalk_private.st_v2_active(d.owner) and not public.st_v7_account_under_lockdown()
$$;

create function public.st_v8_olm_device_proof()
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare local_device sectalk_private.st_v7_devices:=sectalk_private.st_v8_olm_actor_device();
begin
  if local_device.id is null then raise exception 'An approved browser is required' using errcode='42501'; end if;
  return jsonb_build_object('owner',local_device.owner,'device',local_device.id,'signing',local_device.signing_key,
    'session',auth.jwt()->>'session_id','bundle',(select registered.bundle from sectalk_private.st_v8_olm_devices registered
      where registered.device=local_device.id));
end;
$$;

create function public.st_v8_olm_register_device(p_owner uuid,p_device uuid,p_session uuid,p_bundle jsonb,p_proof text,p_prekeys jsonb)
returns jsonb language plpgsql security definer set search_path='' as $$
declare current_bundle jsonb; invalid_conflict boolean;
begin
  if p_owner is null or p_device is null or p_session is null or p_proof is null or p_proof !~ '^[A-Za-z0-9_-]{86}$'
    or jsonb_typeof(p_bundle) is distinct from 'object' or octet_length(p_bundle::text)>4096
    or p_bundle->>'user_id' is distinct from ('@'||p_owner::text||':sectalk.invalid')
    or p_bundle->>'device_id' is distinct from p_device::text
    or jsonb_typeof(p_prekeys) is distinct from 'object' or octet_length(p_prekeys::text)>64000 then
    raise exception 'Invalid encrypted-device key registration' using errcode='22023';
  end if;
  if (select count(*) from jsonb_each(p_prekeys))>100 or exists(
    select 1 from jsonb_each(p_prekeys) keys where keys.key !~ '^signed_curve25519:[A-Za-z0-9_+/-]{1,64}$'
      or jsonb_typeof(keys.value) is distinct from 'object' or octet_length(keys.value::text)>512
  ) then raise exception 'Invalid one-time key batch' using errcode='22023'; end if;

  perform 1 from sectalk_private.st_v7_devices d
    join sectalk_private.st_v7_device_sessions binding on (binding.owner,binding.device_id)=(d.owner,d.id)
    join auth.sessions s on s.id=binding.session_id and s.user_id=d.owner
  where d.owner=p_owner and d.id=p_device and s.id=p_session and d.state in ('trusted','managed')
    and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>clock_timestamp()
    and sectalk_private.st_v2_active(d.owner) for update of d;
  if not found then raise exception 'Browser approval changed' using errcode='42501'; end if;

  select registered.bundle into current_bundle from sectalk_private.st_v8_olm_devices registered where registered.device=p_device;
  if current_bundle is not null and current_bundle is distinct from p_bundle then
    raise exception 'The encrypted device key changed. Approve a replacement browser.' using errcode='23505';
  end if;
  if current_bundle is null then
    insert into sectalk_private.st_v8_olm_devices(device,owner,bundle,proof) values(p_device,p_owner,p_bundle,p_proof);
  end if;
  select exists(select 1 from jsonb_each(p_prekeys) given join sectalk_private.st_v8_olm_prekeys previous
    on previous.device=p_device and previous.name=given.key where previous.payload is distinct from given.value) into invalid_conflict;
  if invalid_conflict then raise exception 'One-time key identifiers cannot be reassigned' using errcode='23505'; end if;
  if (select count(*) from sectalk_private.st_v8_olm_prekeys stored where stored.device=p_device and stored.used_at is null)
    +(select count(*) from jsonb_each(p_prekeys) given where not exists(select 1 from sectalk_private.st_v8_olm_prekeys stored
      where stored.device=p_device and stored.name=given.key))>200 then
    raise exception 'The approved browser already has enough available one-time keys' using errcode='22023';
  end if;

  insert into sectalk_private.st_v8_olm_prekeys(device,name,payload)
    select p_device,key,value from jsonb_each(p_prekeys) on conflict do nothing;
  return jsonb_build_object('signed_curve25519',(select count(*) from sectalk_private.st_v8_olm_prekeys
    where device=p_device and used_at is null));
end;
$$;

create function sectalk_private.st_v8_olm_pair_members(p_chat uuid,p_actor uuid)
returns uuid[] language sql stable security definer set search_path='' as $$
  select array[c.member_a,c.member_b] from public.st_chats c where c.id=p_chat and c.status='accepted'
    and p_actor in (c.member_a,c.member_b) and sectalk_private.open_pair(c.member_a,c.member_b)
$$;

create function public.st_v8_olm_pair_directory(p_chat uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare local_device sectalk_private.st_v7_devices:=sectalk_private.st_v8_olm_actor_device();
  pair uuid[]:=sectalk_private.st_v8_olm_pair_members(p_chat,auth.uid()); roster jsonb;
begin
  if local_device.id is null or pair is null then raise exception 'Encrypted conversation unavailable' using errcode='42501'; end if;
  select jsonb_agg(to_jsonb(row) order by row.owner,row.device) into roster from (
    select d.owner,d.id device,d.signing_key,d.agreement_key,d.bundle_signature,registered.bundle,registered.proof
    from sectalk_private.st_v7_devices d left join sectalk_private.st_v8_olm_devices registered on registered.device=d.id
    where d.owner=any(pair) and d.state in ('trusted','managed') order by d.owner,d.id limit 129
  ) row;
  if jsonb_array_length(roster)>128 then raise exception 'Encrypted device roster is too large' using errcode='22023'; end if;
  return jsonb_build_object('device',local_device.id,'members',pair,'roster',coalesce(roster,'[]'::jsonb));
end;
$$;

create function public.st_v8_olm_claim_prekey(p_chat uuid,p_device uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare local_device sectalk_private.st_v7_devices:=sectalk_private.st_v8_olm_actor_device();
  pair uuid[]:=sectalk_private.st_v8_olm_pair_members(p_chat,auth.uid()); claimed sectalk_private.st_v8_olm_prekeys;
begin
  if local_device.id is null or pair is null or p_device is null or p_device=local_device.id then
    raise exception 'Encrypted conversation unavailable' using errcode='42501';
  end if;
  perform 1 from sectalk_private.st_v7_devices d join sectalk_private.st_v8_olm_devices registered on registered.device=d.id
    where d.id=p_device and d.owner=any(pair) and d.state in ('trusted','managed') for share of d;
  if not found then raise exception 'Encrypted conversation unavailable' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v8_olm_prekey_claim',128);
  perform sectalk_private.limit_action('v8_olm_prekey_'||local_device.id::text||'_'||p_device::text,12);

  update sectalk_private.st_v8_olm_prekeys k set used_at=clock_timestamp()
    where (k.device,k.name)=(
      select next.device,next.name from sectalk_private.st_v8_olm_prekeys next
      where next.device=p_device and next.used_at is null order by next.created_at,next.name limit 1 for update skip locked
    ) returning k.* into claimed;
  if claimed.name is null then return null; end if;
  return jsonb_build_object(claimed.name,claimed.payload);
end;
$$;

revoke all on function sectalk_private.st_v8_olm_actor_device(),sectalk_private.st_v8_olm_pair_members(uuid,uuid),
  public.st_v8_olm_device_proof(),public.st_v8_olm_register_device(uuid,uuid,uuid,jsonb,text,jsonb),
  public.st_v8_olm_pair_directory(uuid),public.st_v8_olm_claim_prekey(uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_olm_device_proof(),public.st_v8_olm_pair_directory(uuid),
  public.st_v8_olm_claim_prekey(uuid,uuid) to authenticated;
grant execute on function public.st_v8_olm_register_device(uuid,uuid,uuid,jsonb,text,jsonb) to service_role;

commit;
