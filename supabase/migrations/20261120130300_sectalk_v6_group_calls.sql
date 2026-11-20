begin;

create table sectalk_private.st_v6_group_call (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references public.st_profiles on delete cascade,
  video boolean not null default false,
  topology text not null default 'mesh' check(topology in ('mesh','promoting','sfu','demoting')),
  expires_at timestamptz not null default (clock_timestamp()+interval '2 hours'),
  ended boolean not null default false,
  promotion integer not null default 0,
  sfu_generation integer not null default 0,
  deadline timestamptz,
  mesh_roster uuid[] not null default '{}'
);
create table sectalk_private.st_v6_group_member (
  call_id uuid references sectalk_private.st_v6_group_call on delete cascade,
  actor uuid references public.st_profiles on delete cascade,
  state text not null check(state in ('invited','joined','left')),
  device uuid,
  auth_session text,
  ready integer not null default 0,
  primary key(call_id,actor)
);
create table sectalk_private.st_v6_group_signal (
  id bigint generated always as identity primary key,
  call_id uuid not null references sectalk_private.st_v6_group_call on delete cascade,
  sender uuid not null,
  target uuid not null,
  kind text not null check(kind in ('offer','answer','ice')),
  payload jsonb not null
);
create index st_v6_group_member_actor_idx on sectalk_private.st_v6_group_member(actor,state);
create index st_v6_group_signal_target_idx on sectalk_private.st_v6_group_signal(call_id,target,id);
alter table sectalk_private.st_v6_group_call enable row level security;
alter table sectalk_private.st_v6_group_member enable row level security;
alter table sectalk_private.st_v6_group_signal enable row level security;
revoke all on sectalk_private.st_v6_group_call,sectalk_private.st_v6_group_member,sectalk_private.st_v6_group_signal from public,anon,authenticated;

create function public.st_v6_group_call(
  p_action text,p_call uuid default null,p_device uuid default null,p_targets uuid[] default null,
  p_peer uuid default null,p_kind text default null,p_payload jsonb default null,
  p_after bigint default 0,p_generation integer default null,p_video boolean default false
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor_id uuid:=auth.uid(); session_key text:=auth.jwt()->>'session_id';
  group_row sectalk_private.st_v6_group_call;
  member_row sectalk_private.st_v6_group_member;
  mesh uuid[]; joined uuid[]; result jsonb;
begin
  if actor_id is null or p_device is null or nullif(session_key,'') is null or not coalesce(sectalk_private.st_v2_active(actor_id),false)
    then return null; end if;
  if p_action='list' then
    select coalesce(jsonb_agg(to_jsonb(row)),'[]') into result from (
      select c.id, c.owner, c.video, p.name as host_name,m.state from sectalk_private.st_v6_group_call c
      join sectalk_private.st_v6_group_member m on c.id=m.call_id
      join public.st_profiles p on p.id=c.owner
      where m.actor=actor_id and (m.state='invited' or (m.state='joined' and m.device=p_device and m.auth_session=session_key))
        and not c.ended and c.expires_at>now() and sectalk_private.open_pair(c.owner,actor_id)
      order by c.expires_at desc limit 20
    ) row;
    return result;
  elsif p_action='create' then
    perform sectalk_private.limit_action('group_call_start',5);
    insert into sectalk_private.st_v6_group_call(owner,video) values(actor_id,coalesce(p_video,false)) returning * into group_row;
    p_call:=group_row.id;
    insert into sectalk_private.st_v6_group_member(call_id,actor,state,device,auth_session)
      values(p_call,actor_id,'joined',p_device,session_key);
  else
    select * into group_row from sectalk_private.st_v6_group_call where id=p_call for update;
    if not found or group_row.ended or group_row.expires_at<=now() or not sectalk_private.open_pair(group_row.owner,actor_id)
      or not coalesce(sectalk_private.st_v2_active(group_row.owner),false) then return null; end if;
    select * into member_row from sectalk_private.st_v6_group_member where call_id=p_call and actor=actor_id;
    if not found or member_row.state='left' then return null; end if;
    if member_row.state='invited' and p_action not in ('accept','decline') then return null; end if;
    if member_row.state='joined' and (member_row.device is distinct from p_device or member_row.auth_session is distinct from session_key)
      then return null; end if;
  end if;

  update sectalk_private.st_v6_group_member m set state='left'
    where m.call_id=p_call and m.state='joined' and (not coalesce(sectalk_private.st_v2_active(m.actor),false)
      or not sectalk_private.open_pair(group_row.owner,m.actor));
  select coalesce(array_agg(actor order by actor),'{}') into joined from sectalk_private.st_v6_group_member
    where call_id=p_call and state='joined';

  if group_row.topology='promoting' and (group_row.deadline<=clock_timestamp() or not joined @> group_row.mesh_roster) then
    update sectalk_private.st_v6_group_member set state='invited',device=null,auth_session=null
      where call_id=p_call and state='joined' and not(actor=any(group_row.mesh_roster));
    update sectalk_private.st_v6_group_call set topology='mesh',deadline=null where id=p_call returning * into group_row;
  elsif group_row.topology='demoting' and (group_row.deadline<=clock_timestamp() or joined is distinct from group_row.mesh_roster) then
    update sectalk_private.st_v6_group_call set topology='sfu',deadline=clock_timestamp()+interval '8 seconds'
      where id=p_call returning * into group_row;
    delete from sectalk_private.st_v6_group_signal where call_id=p_call;
  elsif group_row.topology='sfu' and cardinality(joined)<=4 and
    (group_row.deadline is null or group_row.deadline<=clock_timestamp()) then
    update sectalk_private.st_v6_group_call set topology='demoting',promotion=promotion+1,mesh_roster=joined,
      deadline=clock_timestamp()+interval '18 seconds' where id=p_call returning * into group_row;
    delete from sectalk_private.st_v6_group_signal where call_id=p_call;
  end if;

  if p_action in ('create','invite') then
    if group_row.owner<>actor_id or coalesce(cardinality(p_targets),0) not between 1 and 7
      or exists(select 1 from unnest(p_targets) as wanted(contact) where wanted.contact=actor_id
        or not sectalk_private.open_pair(actor_id,wanted.contact)
        or not exists(select 1 from public.st_chats c where c.status='accepted'
          and c.member_a=least(actor_id,wanted.contact) and c.member_b=greatest(actor_id,wanted.contact))) then
      raise exception 'Choose available contacts' using errcode='42501';
    end if;
    if (select count(*) from (
      select actor from sectalk_private.st_v6_group_member where call_id=p_call
      union select unnest(p_targets)
    ) ids)>8 then raise exception 'Group calls support eight people' using errcode='22023'; end if;
    insert into sectalk_private.st_v6_group_member(call_id,actor,state)
      select p_call,id,'invited' from unnest(p_targets) id on conflict do nothing;
  elsif p_action='accept' then
    if member_row.state<>'invited' or group_row.topology in ('promoting','demoting') then return null; end if;
    if exists(select 1 from sectalk_private.st_v6_group_member m where m.call_id=p_call and m.state='joined'
      and not sectalk_private.open_pair(m.actor,actor_id)) then return null; end if;
    if group_row.topology='mesh' and cardinality(joined)>=4 then
      update sectalk_private.st_v6_group_call set topology='promoting',promotion=promotion+1,mesh_roster=joined,
        deadline=clock_timestamp()+interval '18 seconds' where id=p_call returning * into group_row;
    end if;
    update sectalk_private.st_v6_group_member set state='joined',device=p_device,auth_session=session_key
      where call_id=p_call and actor=actor_id;
  elsif p_action in ('leave','decline') then
    update sectalk_private.st_v6_group_member set state='left' where call_id=p_call and actor=actor_id;
    if actor_id=group_row.owner then update sectalk_private.st_v6_group_call set ended=true where id=p_call; end if;
    return jsonb_build_object('left',true);
  elsif p_action='ready' then
    if group_row.topology not in ('promoting','demoting') or p_generation is distinct from group_row.promotion then return null; end if;
    update sectalk_private.st_v6_group_member set ready=group_row.promotion where call_id=p_call and actor=actor_id;
    if not exists(select 1 from sectalk_private.st_v6_group_member where call_id=p_call and state='joined' and ready<>group_row.promotion) then
      if group_row.topology='promoting' then
        update sectalk_private.st_v6_group_call set topology='sfu',sfu_generation=promotion,deadline=null
          where id=p_call returning * into group_row;
        delete from sectalk_private.st_v6_group_signal where call_id=p_call;
      else
        update sectalk_private.st_v6_group_call set topology='mesh',deadline=null
          where id=p_call returning * into group_row;
      end if;
    end if;
  elsif p_action='sfu' then
    if group_row.topology not in ('sfu','promoting','demoting') or member_row.state<>'joined' then return null; end if;
    return jsonb_build_object('generation',case when group_row.topology='promoting' then group_row.promotion
      else group_row.sfu_generation end,'expires_at',group_row.expires_at,'video',group_row.video);
  elsif p_action='ice' then
    if group_row.topology not in ('mesh','promoting','demoting') or member_row.state<>'joined' then return null; end if;
    return jsonb_build_object('expires_at',group_row.expires_at);
  elsif p_action not in ('state','send','signals') then
    return null;
  end if;

  select coalesce(array_agg(actor order by actor),'{}') into joined from sectalk_private.st_v6_group_member
    where call_id=p_call and state='joined';
  if not(actor_id=any(joined)) then return null; end if;
  mesh:=case group_row.topology when 'mesh' then joined when 'promoting' then group_row.mesh_roster
    when 'demoting' then group_row.mesh_roster else '{}'::uuid[] end;
  if p_action='send' then
    if not(actor_id=any(mesh)) or p_peer is null or p_peer=actor_id or not(p_peer=any(mesh))
      or not sectalk_private.open_pair(actor_id,p_peer) or p_kind not in ('offer','answer','ice')
      or (p_kind='offer' and actor_id>p_peer) or (p_kind='answer' and actor_id<p_peer)
      or p_payload is null or octet_length(p_payload::text)>32000 then return null; end if;
    perform sectalk_private.limit_action('group_signal',240);
    insert into sectalk_private.st_v6_group_signal(call_id,sender,target,kind,payload)
      values(p_call,actor_id,p_peer,p_kind,p_payload);
    return jsonb_build_object('ok',true);
  elsif p_action='signals' then
    if not(actor_id=any(mesh)) then return '[]'::jsonb; end if;
    select coalesce(jsonb_agg(to_jsonb(row) order by row.id),'[]') into result from (
      select s.id,s.sender,s.kind,s.payload from sectalk_private.st_v6_group_signal s
      where s.call_id=p_call and s.target=actor_id and s.id>p_after and s.sender=any(mesh)
        and sectalk_private.open_pair(s.sender,actor_id) order by s.id limit 100
    ) row;
    return result;
  end if;
  if exists(select 1 from unnest(joined) u(id) where not sectalk_private.open_pair(u.id,actor_id)) then return null; end if;
  return jsonb_build_object('id',p_call,'owner',group_row.owner,'topology',group_row.topology,'video',group_row.video,
    'generation',group_row.promotion,'sfuGeneration',case when group_row.topology='promoting' then group_row.promotion
      else group_row.sfu_generation end,'joined',joined,'mesh',mesh,'expiresAt',group_row.expires_at,
    'names',(select jsonb_object_agg(id::text,name) from public.st_profiles where id=any(joined)));
end
$$;
revoke all on function public.st_v6_group_call(text,uuid,uuid,uuid[],uuid,text,jsonb,bigint,integer,boolean) from public,anon,authenticated;
grant execute on function public.st_v6_group_call(text,uuid,uuid,uuid[],uuid,text,jsonb,bigint,integer,boolean) to authenticated;
commit;
