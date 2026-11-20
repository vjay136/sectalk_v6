begin;

create table sectalk_private.st_group_chats (
  id uuid primary key,
  owner uuid not null references auth.users on delete cascade,
  name text not null check(char_length(btrim(name)) between 1 and 64),
  epoch integer not null check(epoch>0),
  member_cap integer not null check(member_cap between 2 and 32)
);
create table sectalk_private.st_group_members (
  group_id uuid not null references sectalk_private.st_group_chats on delete cascade,
  actor uuid not null references auth.users on delete cascade,
  primary key(group_id,actor)
);
create table sectalk_private.st_group_envelopes (
  group_id uuid not null references sectalk_private.st_group_chats on delete cascade,
  epoch integer not null,
  device uuid not null,
  sealed text not null check(sealed ~ '^[A-Za-z0-9_-]{80}$'),
  ephemeral text not null check(ephemeral ~ '^[A-Za-z0-9_-]{87}$'),
  primary key(group_id,epoch,device)
);
create table sectalk_private.st_group_messages (
  group_id uuid not null references sectalk_private.st_group_chats on delete cascade,
  id uuid not null,
  epoch integer not null,
  actor uuid not null,
  device uuid not null,
  signing text not null,
  payload text not null check(length(payload) between 39 and 5600 and payload ~ '^[A-Za-z0-9_-]+$'),
  signature text not null check(signature ~ '^[A-Za-z0-9_-]{86}$'),
  sent timestamptz not null default clock_timestamp(),
  primary key(group_id,id)
);
create index st_group_members_actor on sectalk_private.st_group_members(actor,group_id);
create index st_group_messages_recent on sectalk_private.st_group_messages(group_id,sent desc,id desc);
alter table sectalk_private.st_group_chats enable row level security;
alter table sectalk_private.st_group_members enable row level security;
alter table sectalk_private.st_group_envelopes enable row level security;
alter table sectalk_private.st_group_messages enable row level security;
revoke all on sectalk_private.st_group_chats,sectalk_private.st_group_members,
  sectalk_private.st_group_envelopes,sectalk_private.st_group_messages from public,anon,authenticated;

create function public.st_group_chat(p_action text,p_group uuid default null,p_data jsonb default '{}')
returns jsonb language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); local_device sectalk_private.st_v7_devices; target sectalk_private.st_group_chats;
  roster uuid[]; manifests jsonb; sealed_keys jsonb; next_epoch integer; plan_cap integer; cap integer;
  roster_size integer; result jsonb; current_members boolean;
begin
  select d.* into local_device from sectalk_private.st_v7_device_sessions s
    join sectalk_private.st_v7_devices d on (d.owner,d.id)=(s.owner,s.device_id)
    where s.owner=me and s.session_id::text=auth.jwt()->>'session_id' and d.state in ('trusted','managed');
  if local_device.id is null or not coalesce(sectalk_private.st_v7_manage_sessions(),false) then
    raise exception using errcode='42501',message='An approved browser device is required';
  end if;
  if p_action='list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.name,x.id) from (
      select g.* from sectalk_private.st_group_chats g join sectalk_private.st_group_members m on m.group_id=g.id
      where m.actor=me order by g.name,g.id limit 100) x),'[]');
  end if;
  if p_group is null then raise exception using errcode='22023',message='A group is required'; end if;
  select g.* into target from sectalk_private.st_group_chats g where g.id=p_group for update;
  if p_action in ('preview','rotate') then
    if target.id is not null and target.owner<>me then raise exception using errcode='42501',message='Group unavailable'; end if;
    if (p_data->>'previous_epoch')::integer is distinct from coalesce(target.epoch,0) then
      raise exception using errcode='40001',message='Group roster changed. Reopen the member editor.';
    end if;
    if target.id is null and (select count(*) from sectalk_private.st_group_chats g where g.owner=me)>=100 then
      raise exception using errcode='22023',message='This account has reached its group limit';
    end if;
    plan_cap:=case sectalk_private.st_v2_effective_plan(me) when 'enterprise' then 32 when 'business' then 24
      when 'professional' then 16 when 'basic' then 8 else 4 end;
    cap:=(p_data->>'cap')::integer;
    if cap is null or cap<2 or cap>32 then raise exception using errcode='22023',message='Invalid member limit'; end if;
    if jsonb_typeof(p_data->'members') is distinct from 'array' or jsonb_array_length(p_data->'members')>32 then
      raise exception using errcode='22023',message='Invalid group roster';
    end if;
    select array_agg(distinct id order by id) into roster from (
      select me id union all select value::uuid from jsonb_array_elements_text(p_data->'members')) ids;
    roster_size:=cardinality(roster);
    if roster_size>least(plan_cap,cap) or (target.id is null and roster_size<2)
      or exists(select 1 from unnest(roster) peer where peer is null or (peer<>me
      and (not sectalk_private.open_pair(me,peer) or not exists(select 1 from public.st_chats c
        where (c.member_a,c.member_b)=(least(me,peer),greatest(me,peer)) and c.status='accepted')))) then
      raise exception using errcode='22023',message='Group roster exceeds the member limit or includes an unavailable contact';
    end if;
    select coalesce(jsonb_agg(jsonb_build_object('owner_id',d.owner,'device',d.id,'signing_key',d.signing_key,
      'agreement_key',d.agreement_key,'bundle_signature',d.bundle_signature) order by d.id),'[]')
      into manifests from sectalk_private.st_v7_devices d where d.owner=any(roster) and d.state in ('trusted','managed');
    if jsonb_array_length(manifests)>128 or (select count(distinct d->>'owner_id') from jsonb_array_elements(manifests) d)<>roster_size then
      raise exception using errcode='22023',message='Each member needs an approved device and the group supports up to 128 devices';
    end if;
    next_epoch:=coalesce(target.epoch,0)+1;
    if p_action='preview' then
      return jsonb_build_object('device',local_device.id,'epoch',next_epoch,'devices',manifests,'plan_cap',plan_cap);
    end if;
    perform sectalk_private.limit_action('group_chat_rotation',20);
    sealed_keys:=p_data->'envelopes';
    if (p_data->>'epoch')::integer is distinct from next_epoch or
      jsonb_typeof(sealed_keys) is distinct from 'object' or
      (select count(*) from jsonb_object_keys(sealed_keys))<>jsonb_array_length(manifests) or
      exists(select 1 from jsonb_array_elements(manifests) d where not (sealed_keys ? (d->>'device')))
      then raise exception using errcode='40001',message='Group roster or device list changed. Try again.'; end if;
    insert into sectalk_private.st_group_chats as g(id,owner,name,epoch,member_cap)
      values(p_group,me,btrim(p_data->>'name'),next_epoch,cap)
      on conflict(id) do update set name=excluded.name,epoch=excluded.epoch,member_cap=excluded.member_cap
      where g.owner=me and g.epoch=next_epoch-1;
    if not found then raise exception using errcode='40001',message='Group roster changed. Try again.'; end if;
    -- Removed accounts lose old envelopes too, including after readmission.
    delete from sectalk_private.st_group_envelopes e using sectalk_private.st_v7_devices d
      where e.group_id=p_group and e.device=d.id and not (d.owner=any(roster));
    delete from sectalk_private.st_group_members m where m.group_id=p_group and not (m.actor=any(roster));
    insert into sectalk_private.st_group_members(group_id,actor) select p_group,unnest(roster) on conflict do nothing;
    insert into sectalk_private.st_group_envelopes(group_id,epoch,device,sealed,ephemeral)
      select p_group,next_epoch,k.key::uuid,k.value->>'sealed',k.value->>'ephemeral' from jsonb_each(sealed_keys) k;
    return jsonb_build_object('epoch',next_epoch);
  end if;
  if target.id is null or not exists(select 1 from sectalk_private.st_group_members m where m.group_id=p_group and m.actor=me) then
    raise exception using errcode='42501',message='Group unavailable';
  end if;
  if p_action='send' then
    perform sectalk_private.limit_action('group_chat_message',60);
    -- Stop sends when a covered device is revoked. A fresh owner rotation drops it before more ciphertext is accepted.
    select not exists(select 1 from sectalk_private.st_group_envelopes e left join sectalk_private.st_v7_devices d on d.id=e.device
      where e.group_id=p_group and e.epoch=target.epoch and (d.id is null or d.state not in ('trusted','managed'))) into current_members;
    if (p_data->>'epoch')::integer is distinct from target.epoch or not current_members or not exists(
      select 1 from sectalk_private.st_group_envelopes e where e.group_id=p_group and e.epoch=target.epoch
        and e.device=local_device.id)
      then raise exception using errcode='40001',message='Group keys changed. Ask the owner to refresh encryption.'; end if;
    insert into sectalk_private.st_group_messages(group_id,id,epoch,actor,device,signing,payload,signature)
      values(p_group,(p_data->>'id')::uuid,target.epoch,me,local_device.id,local_device.signing_key,p_data->>'payload',p_data->>'signature');
    return '{}'::jsonb;
  end if;
  if p_action='read' then
    with newest as (
      select m.* from sectalk_private.st_group_messages m where m.group_id=p_group
        and exists(select 1 from sectalk_private.st_group_envelopes e where e.group_id=p_group and e.epoch=m.epoch and e.device=local_device.id)
      order by m.sent desc,m.id desc limit 50)
    select jsonb_build_object('group',to_jsonb(target),'device',local_device.id,
      'members',(select jsonb_agg(jsonb_build_object('id',m.actor,'name',p.name) order by m.actor)
        from sectalk_private.st_group_members m left join public.st_profiles p on p.id=m.actor where m.group_id=p_group),
      'envelopes',coalesce((select jsonb_agg(to_jsonb(e)-'group_id'-'device') from sectalk_private.st_group_envelopes e
        where e.group_id=p_group and e.device=local_device.id and (e.epoch=target.epoch or e.epoch in (select x.epoch from newest x))),'[]'),
      'messages',coalesce((select jsonb_agg(to_jsonb(x)-'group_id' order by x.sent,x.id) from newest x),'[]'))
      into result from (select 1) placeholder;
    return result;
  end if;
  raise exception using errcode='22023',message='Unknown group action';
end $$;
revoke all on function public.st_group_chat(text,uuid,jsonb) from public,anon;
grant execute on function public.st_group_chat(text,uuid,jsonb) to authenticated;
commit;
