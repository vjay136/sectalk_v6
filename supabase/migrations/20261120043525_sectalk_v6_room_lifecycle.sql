begin;

alter table public.st_v6_room_audit add column details jsonb not null default '{}'::jsonb;

create function sectalk_private.st_v6_room_workspace_manager(p_room uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(
    select 1 from public.st_v6_rooms r
    where r.id=p_room and sectalk_private.st_v2_active(auth.uid())
      and sectalk_private.st_v2_role(r.workspace_id,auth.uid()) in ('owner','admin')
  )
$$;

revoke all on function sectalk_private.st_v6_room_workspace_manager(uuid) from public,anon,authenticated;
grant execute on function sectalk_private.st_v6_room_workspace_manager(uuid) to authenticated;

create policy st_v6_room_manager_directory on public.st_v6_rooms for select to authenticated
  using(sectalk_private.st_v6_room_workspace_manager(id));
create policy st_v6_room_manager_roster on public.st_v6_room_members for select to authenticated
  using(sectalk_private.st_v6_room_workspace_manager(room_id));
create function sectalk_private.st_v6_room_management_audit(p_room uuid)
returns setof public.st_v6_room_audit language sql stable security definer set search_path='' as $$
  select a.* from public.st_v6_room_audit a where a.room_id=p_room
    and sectalk_private.st_v6_room_workspace_manager(p_room)
    and (a.action like 'membership.%' or a.action in ('room.created','room.visibility','room.archive','room.restore')
      or sectalk_private.st_v6_room_role(p_room) in ('owner','moderator'))
  order by a.id desc limit 50
$$;

create function public.st_v6_room_management_audit(p_room uuid)
returns setof public.st_v6_room_audit language sql stable security invoker set search_path=''
begin atomic
  select * from sectalk_private.st_v6_room_management_audit(p_room);
end;

revoke all on function public.st_v6_room_management_audit(uuid),
  sectalk_private.st_v6_room_management_audit(uuid) from public,anon,authenticated;
grant execute on function public.st_v6_room_management_audit(uuid),
  sectalk_private.st_v6_room_management_audit(uuid) to authenticated;

create function sectalk_private.st_v6_manage_room(p_room uuid,p_action text,p_kind text,p_target uuid)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  room public.st_v6_rooms;
  audit_details jsonb:='{}'::jsonb;
  previous_owners jsonb;
begin
  if not sectalk_private.st_v6_room_workspace_manager(p_room) then
    raise exception 'Room management unavailable';
  end if;
  perform sectalk_private.limit_action('v6_manage_room',20);
  select * into room from public.st_v6_rooms where id=p_room for update;
  if not found or not sectalk_private.st_v6_room_workspace_manager(p_room) then
    raise exception 'Room management unavailable';
  end if;

  case p_action
    when 'visibility' then
      if room.archived or room.kind not in ('public','private') or room.template not in ('blank','project')
        or p_kind is null or p_kind not in ('public','private') then
        raise exception 'Visibility is unavailable for this room';
      end if;
      if room.kind=p_kind then return; end if;
      update public.st_v6_rooms set kind=p_kind where id=p_room;
      audit_details:=jsonb_build_object('from',room.kind,'to',p_kind);
    when 'transfer_owner' then
      if room.archived or room.kind='admin' or not sectalk_private.st_v2_active(p_target)
        or sectalk_private.st_v2_role(room.workspace_id,p_target) is null
        or exists(select 1 from public.st_v6_room_bans where room_id=p_room and user_id=p_target)
        or not exists(select 1 from public.st_v6_room_members where room_id=p_room and user_id=p_target) then
        raise exception 'Choose an active room member as the new owner';
      end if;
      select coalesce(jsonb_agg(user_id order by user_id),'[]'::jsonb) into previous_owners
        from public.st_v6_room_members where room_id=p_room and role='owner';
      if previous_owners=jsonb_build_array(p_target) then return; end if;
      update public.st_v6_room_members set role='moderator'
        where room_id=p_room and role='owner' and user_id<>p_target;
      update public.st_v6_room_members set role='owner' where room_id=p_room and user_id=p_target;
      audit_details:=jsonb_build_object('previous_owners',previous_owners);
    when 'archive', 'restore' then
      if room.archived=(p_action='archive') then return; end if;
      update public.st_v6_rooms set archived=(p_action='archive') where id=p_room;
    else raise exception 'Room management unavailable';
  end case;

  insert into public.st_v6_room_audit(room_id,actor,action,target,details)
    values(p_room,actor,case when p_action='transfer_owner' then 'membership.transfer_owner' else 'room.'||p_action end,
      case when p_action='transfer_owner' then p_target end,audit_details);
end $$;

create function public.st_v6_manage_room(p_room uuid,p_action text,p_kind text default null,p_target uuid default null)
returns void language sql security invoker set search_path=''
return sectalk_private.st_v6_manage_room(p_room,p_action,p_kind,p_target);

revoke all on function public.st_v6_manage_room(uuid,text,text,uuid),
  sectalk_private.st_v6_manage_room(uuid,text,text,uuid) from public,anon,authenticated;
grant execute on function public.st_v6_manage_room(uuid,text,text,uuid),
  sectalk_private.st_v6_manage_room(uuid,text,text,uuid) to authenticated;

commit;
