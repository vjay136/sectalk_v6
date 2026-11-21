begin;

create table sectalk_private.st_v8_olm_pair_consents (
  chat uuid not null references public.st_chats on delete cascade,
  actor uuid not null references auth.users on delete cascade,
  accepted_at timestamptz not null default clock_timestamp(),
  primary key(chat,actor)
);

create table sectalk_private.st_v8_olm_direct_events (
  chat uuid not null references public.st_chats on delete cascade,
  id uuid not null,
  sequence bigint generated always as identity,
  sender uuid not null,
  device uuid not null,
  epoch text not null check(epoch ~ '^[a-f0-9]{64}$'),
  session_key text not null check(session_key ~ '^[A-Za-z0-9+/]{43}$'),
  cipher jsonb not null check(jsonb_typeof(cipher)='object' and octet_length(cipher::text)<=10000),
  sent_at timestamptz not null default clock_timestamp(),
  primary key(chat,id),
  unique(chat,sequence)
);
create index st_v8_olm_direct_epoch on sectalk_private.st_v8_olm_direct_events(chat,epoch,device,session_key,sequence);

create table sectalk_private.st_v8_olm_direct_packets (
  chat uuid not null,
  message uuid not null,
  recipient uuid not null references sectalk_private.st_v8_olm_devices on delete cascade,
  packet jsonb not null check(jsonb_typeof(packet)='object' and octet_length(packet::text)<=12000),
  primary key(chat,message,recipient),
  foreign key(chat,message) references sectalk_private.st_v8_olm_direct_events(chat,id) on delete cascade
);
create index st_v8_olm_packet_receiver on sectalk_private.st_v8_olm_direct_packets(recipient,chat,message);

alter table sectalk_private.st_v8_olm_pair_consents enable row level security;
alter table sectalk_private.st_v8_olm_direct_events enable row level security;
alter table sectalk_private.st_v8_olm_direct_packets enable row level security;
revoke all on sectalk_private.st_v8_olm_pair_consents,sectalk_private.st_v8_olm_direct_events,
  sectalk_private.st_v8_olm_direct_packets from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_olm_pair_epoch(p_chat uuid,p_owner uuid)
returns text language sql stable security definer set search_path='' as $$
  with members as (select unnest(sectalk_private.st_v8_olm_pair_members(p_chat,p_owner)) as actor),
  devices as (
    select d.owner,d.id from members m join sectalk_private.st_v7_devices d on d.owner=m.actor
    join sectalk_private.st_v8_olm_devices registered on registered.device=d.id
    where d.state in ('trusted','managed')
  )
  select case when count(distinct owner)=2 and count(*)<=128 then
    encode(extensions.digest('sectalk-olm-pair-v1:'||p_chat::text||':'||string_agg(id::text,',' order by id),'sha256'),'hex') end
  from devices
$$;

create function public.st_v8_olm_pair_state(p_chat uuid,p_enable boolean default false)
returns jsonb language plpgsql security definer set search_path='' as $$
declare local_device sectalk_private.st_v7_devices:=sectalk_private.st_v8_olm_actor_device();
  members uuid[]:=sectalk_private.st_v8_olm_pair_members(p_chat,auth.uid()); accepted integer; opted_in boolean;
  epoch text;
begin
  if local_device.id is null or members is null or not exists(
    select 1 from sectalk_private.st_v8_olm_devices d where d.device=local_device.id) then
    raise exception 'Encrypted conversation unavailable' using errcode='42501';
  end if;

  if p_enable is true then
    perform sectalk_private.limit_action('v8_olm_direct_consent',30);
    perform 1 from public.st_chats c where c.id=p_chat for update;
    if sectalk_private.st_v8_olm_pair_members(p_chat,local_device.owner) is null then
      raise exception 'Encrypted conversation unavailable' using errcode='42501';
    end if;
    insert into sectalk_private.st_v8_olm_pair_consents(chat,actor) values(p_chat,local_device.owner) on conflict do nothing;
    if found then
      perform realtime.send(jsonb_build_object('chat',p_chat),'olm_pair_changed','st:account:'||member::text,true)
      from unnest(members) member;
    end if;
  end if;

  select count(*),coalesce(bool_or(actor=local_device.owner),false) into accepted,opted_in
  from sectalk_private.st_v8_olm_pair_consents where chat=p_chat and actor=any(members);
  if accepted=2 then epoch:=sectalk_private.st_v8_olm_pair_epoch(p_chat,local_device.owner); end if;
  return jsonb_build_object('enabled',accepted=2,'optedIn',opted_in,'epoch',epoch,'device',local_device.id);
end;
$$;

create function public.st_v8_olm_direct_send(p_chat uuid,p_message uuid,p_epoch text,p_cipher jsonb,p_packets jsonb default '[]')
returns jsonb language plpgsql security definer set search_path='' as $$
declare local_device sectalk_private.st_v7_devices:=sectalk_private.st_v8_olm_actor_device();
  members uuid[]; opened jsonb; saved sectalk_private.st_v8_olm_direct_events; token text;
begin
  if p_message is null or p_epoch is null or p_epoch !~ '^[a-f0-9]{64}$'
    or jsonb_typeof(p_cipher) is distinct from 'object' or octet_length(p_cipher::text)>10000
    or p_cipher->>'algorithm' is distinct from 'm.megolm.v1.aes-sha2'
    or coalesce(char_length(p_cipher->>'ciphertext'),0) not between 32 and 9802
    or coalesce(p_cipher->>'ciphertext','') !~ '^[A-Za-z0-9+/]+={0,2}$'
    or coalesce(p_cipher->>'session_id','') !~ '^[A-Za-z0-9+/]{43}$'
    or p_cipher-array['algorithm','ciphertext','session_id','sender_key','device_id']<>'{}'::jsonb
    or jsonb_typeof(p_packets) is distinct from 'array' or octet_length(p_packets::text)>600000
    or jsonb_array_length(p_packets)>128 then
    raise exception 'Invalid encrypted message' using errcode='22023';
  end if;
  token:=p_cipher->>'session_id';
  perform 1 from public.st_chats c where c.id=p_chat for update;
  opened:=public.st_v8_olm_pair_state(p_chat,false);
  members:=sectalk_private.st_v8_olm_pair_members(p_chat,local_device.owner);
  if local_device.id is null or members is null or opened->>'enabled'<>'true' then
    raise exception 'Encrypted conversation unavailable' using errcode='42501';
  end if;
  select * into saved from sectalk_private.st_v8_olm_direct_events e where e.chat=p_chat and e.id=p_message;
  if found then
    if saved.sender<>local_device.owner or saved.device<>local_device.id or saved.epoch<>p_epoch or saved.cipher<>p_cipher then
      raise exception 'This encrypted message identifier was already used' using errcode='23505';
    end if;
    return jsonb_build_object('id',saved.id,'sequence',saved.sequence::text);
  end if;
  if opened->>'epoch' is distinct from p_epoch then
    raise exception 'Approved browsers changed. Refresh encryption keys.' using errcode='40001';
  end if;

  perform 1 from sectalk_private.st_v7_devices d
    join sectalk_private.st_v8_olm_devices registered on registered.device=d.id
    where d.owner=any(members) and d.state in ('trusted','managed') order by d.id for share of d;
  if sectalk_private.st_v8_olm_pair_epoch(p_chat,local_device.owner) is distinct from p_epoch then
    raise exception 'Approved browsers changed. Refresh encryption keys.' using errcode='40001';
  end if;

  if exists(select 1 from jsonb_array_elements(p_packets) item
    where jsonb_typeof(item) is distinct from 'object'
      or coalesce(item->>'recipient','') !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
      or jsonb_typeof(item->'packet') is distinct from 'object' or octet_length((item->'packet')::text)>12000
      or item->'packet'->>'algorithm' is distinct from 'm.olm.v1.curve25519-aes-sha2'
      or jsonb_typeof(item->'packet'->'ciphertext') is distinct from 'object') then
    raise exception 'Invalid encrypted key envelope' using errcode='22023';
  end if;
  if exists(select 1 from jsonb_array_elements(p_packets) item
    left join sectalk_private.st_v7_devices d on d.id=(item->>'recipient')::uuid
    left join sectalk_private.st_v8_olm_devices ready on ready.device=d.id
    where ready.device is null or d.id=local_device.id or not (d.owner=any(members)) or d.state not in ('trusted','managed'))
    or (select count(distinct item->>'recipient') from jsonb_array_elements(p_packets) item)<>jsonb_array_length(p_packets) then
    raise exception 'Invalid encrypted key envelope recipient' using errcode='42501';
  end if;

  perform sectalk_private.limit_action('v8_olm_direct_send',150);

  insert into sectalk_private.st_v8_olm_direct_events(chat,id,sender,device,epoch,session_key,cipher)
    values(p_chat,p_message,local_device.owner,local_device.id,p_epoch,token,p_cipher) returning * into saved;
  insert into sectalk_private.st_v8_olm_direct_packets(chat,message,recipient,packet)
    select p_chat,p_message,(item->>'recipient')::uuid,item->'packet' from jsonb_array_elements(p_packets) item;
  perform realtime.send(jsonb_build_object('chat',p_chat),'olm_pair_changed','st:account:'||member::text,true)
    from unnest(members) member;
  return jsonb_build_object('id',saved.id,'sequence',saved.sequence::text);
end;
$$;

create function public.st_v8_olm_direct_read(p_chat uuid,p_before text default null)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare local_device sectalk_private.st_v7_devices:=sectalk_private.st_v8_olm_actor_device();
  cutoff bigint; result jsonb;
begin
  if p_before is not null and p_before !~ '^[1-9][0-9]{0,18}$' then
    raise exception 'Invalid encrypted history position' using errcode='22023';
  end if;
  cutoff:=p_before::bigint;
  if local_device.id is null or not exists(select 1 from sectalk_private.st_v8_olm_devices where device=local_device.id)
    or (select count(*) from sectalk_private.st_v8_olm_pair_consents c where c.chat=p_chat
      and c.actor=any(sectalk_private.st_v8_olm_pair_members(p_chat,local_device.owner)))<>2 then
    raise exception 'Encrypted conversation unavailable' using errcode='42501';
  end if;
  with candidates as (
    select * from sectalk_private.st_v8_olm_direct_events e where e.chat=p_chat and (cutoff is null or e.sequence<cutoff)
    order by e.sequence desc limit 51
  ), page as (
    select * from candidates order by sequence desc limit 50
  ), keys as (
    select distinct on (e.epoch,e.device,e.session_key) p.message,p.packet,e.sender,e.sequence from page v
    join sectalk_private.st_v8_olm_direct_events e on e.chat=p_chat and (e.epoch,e.device,e.session_key)=(v.epoch,v.device,v.session_key)
      and e.sequence<=v.sequence
    join sectalk_private.st_v8_olm_direct_packets p on (p.chat,p.message)=(e.chat,e.id) and p.recipient=local_device.id
    order by e.epoch,e.device,e.session_key,e.sequence
  )
  select jsonb_build_object('events',coalesce((select jsonb_agg(
    jsonb_build_object('id',e.id,'sequence',e.sequence::text,'actor',e.sender,'device',e.device,'epoch',e.epoch,'cipher',e.cipher,
      'sent',e.sent_at) order by e.sequence) from page e),'[]'::jsonb),
    'packets',coalesce((select jsonb_agg(jsonb_build_object('message',k.message,'actor',k.sender,'packet',k.packet)
      order by k.sequence) from keys k),'[]'::jsonb),
    'before',case when (select count(*) from candidates)>50 then (select min(sequence)::text from page) end) into result;
  return result;
end;
$$;

revoke all on function sectalk_private.st_v8_olm_pair_epoch(uuid,uuid),public.st_v8_olm_pair_state(uuid,boolean),
  public.st_v8_olm_direct_send(uuid,uuid,text,jsonb,jsonb),public.st_v8_olm_direct_read(uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_olm_pair_state(uuid,boolean),public.st_v8_olm_direct_send(uuid,uuid,text,jsonb,jsonb),
  public.st_v8_olm_direct_read(uuid,text) to authenticated;

commit;
