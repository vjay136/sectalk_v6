begin;

create table sectalk_private.room_typing (
  room_id uuid not null references public.st_v6_rooms on delete cascade,
  user_id uuid not null references public.st_profiles on delete cascade,
  share_typing boolean not null default true,
  parent_id uuid,
  expires_at timestamptz,
  last_started_at timestamptz,
  primary key(room_id,user_id)
);
create index room_typing_expiries on sectalk_private.room_typing(room_id,expires_at desc) where share_typing;
alter table sectalk_private.room_typing enable row level security;
revoke all on sectalk_private.room_typing from public,anon,authenticated;

create function sectalk_private.st_v6_room_role(p_room uuid,p_user uuid)
returns text language sql stable security definer set search_path='' as $$
  select case when r.kind='admin' and workspace_role.role in ('owner','admin')
    then case when workspace_role.role='owner' then 'owner' else 'moderator' end
    when r.kind<>'admin' then m.role end
  from public.st_v6_rooms r
  cross join lateral (select sectalk_private.st_v2_role(r.workspace_id,p_user) as role) workspace_role
  left join public.st_v6_room_members m on m.room_id=r.id and m.user_id=p_user
  where r.id=p_room and sectalk_private.st_v2_active(p_user) and workspace_role.role is not null
    and not exists(select 1 from public.st_v6_room_bans b where b.room_id=r.id and b.user_id=p_user)
$$;
revoke all on function sectalk_private.st_v6_room_role(uuid,uuid) from public,anon,authenticated;

create or replace function sectalk_private.st_v6_room_role(p_room uuid)
returns text language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v6_room_role(p_room,auth.uid())
$$;

create function sectalk_private.st_v6_room_can_type(p_room uuid,p_user uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v6_rooms r
    cross join lateral (select sectalk_private.st_v6_room_role(p_room,p_user) as role) membership
    where r.id=p_room and not r.archived and membership.role<>'read_only'
      and (membership.role in ('owner','moderator') or (not r.locked and r.kind not in ('announcement','broadcast')))
      and not exists(select 1 from public.st_v6_room_timeouts t
        where t.room_id=p_room and t.user_id=p_user and t.until_at>statement_timestamp())
  )
$$;
revoke all on function sectalk_private.st_v6_room_can_type(uuid,uuid) from public,anon,authenticated;

create function public.st_v6_set_room_typing_policy(p_room uuid,p_share boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_room_typing_policy',20);
  perform id from public.st_v6_rooms where id=p_room and not archived for update;
  if not found or p_share is null or sectalk_private.st_v6_room_role(p_room) is null
    then raise exception 'Room unavailable'; end if;

  insert into sectalk_private.room_typing(room_id,user_id,share_typing) values(p_room,actor,p_share)
  on conflict(room_id,user_id) do update set share_typing=p_share,
    expires_at=case when p_share then room_typing.expires_at end;
end $$;

create function public.st_v6_room_typing(p_room uuid,p_parent uuid,p_active boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); pulse_at timestamptz; room_kind text;
begin
  perform sectalk_private.limit_action('v6_room_typing',75);
  if p_active is null or not sectalk_private.st_v6_room_can_type(p_room,actor) then return; end if;
  select kind into room_kind from public.st_v6_rooms where id=p_room for update;
  if not found or not sectalk_private.st_v6_room_can_type(p_room,actor) then return; end if;
  if p_parent is not null and (room_kind='announcement' or not exists(
    select 1 from public.st_v6_room_posts where room_id=p_room and id=p_parent and parent_id is null and removed_at is null
  )) then return; end if;
  if exists(select 1 from sectalk_private.room_typing
    where room_id=p_room and user_id=actor and not share_typing) then return; end if;

  pulse_at:=clock_timestamp();
  if p_active then
    insert into sectalk_private.room_typing as typing(room_id,user_id,parent_id,expires_at,last_started_at)
      values(p_room,actor,p_parent,pulse_at+interval '5 seconds',pulse_at)
    on conflict(room_id,user_id) do update set parent_id=p_parent,
      expires_at=excluded.expires_at,last_started_at=excluded.last_started_at
    where typing.last_started_at is null or typing.last_started_at<=pulse_at-interval '2 seconds';
  else
    update sectalk_private.room_typing set expires_at=null
    where room_id=p_room and user_id=actor and parent_id is not distinct from p_parent and expires_at>pulse_at;
  end if;
end $$;

create function public.st_v6_room_typing_status(p_room uuid,p_parent uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid(); typing_at timestamptz; share boolean;
begin
  if sectalk_private.st_v6_room_role(p_room) is null
    or not exists(select 1 from public.st_v6_rooms where id=p_room and not archived) then return '{}'::jsonb; end if;
  if p_parent is not null and not exists(select 1 from public.st_v6_room_posts
    where room_id=p_room and id=p_parent and parent_id is null and removed_at is null) then return '{}'::jsonb; end if;
  select share_typing into share from sectalk_private.room_typing where room_id=p_room and user_id=actor;
  select expires_at into typing_at from sectalk_private.room_typing typing
    where typing.room_id=p_room and typing.user_id<>actor and typing.share_typing
      and typing.parent_id is not distinct from p_parent and expires_at>statement_timestamp()
      and sectalk_private.st_v6_room_can_type(p_room,typing.user_id)
      and sectalk_private.open_pair(actor,typing.user_id)
    order by expires_at desc limit 1;
  return jsonb_build_object('typing_until',typing_at,'share_own_typing',coalesce(share,true));
end $$;

revoke all on function public.st_v6_set_room_typing_policy(uuid,boolean),public.st_v6_room_typing(uuid,uuid,boolean),
  public.st_v6_room_typing_status(uuid,uuid) from public,anon,authenticated;
grant execute on function public.st_v6_set_room_typing_policy(uuid,boolean),public.st_v6_room_typing(uuid,uuid,boolean),
  public.st_v6_room_typing_status(uuid,uuid) to authenticated;

commit;
