begin;

create or replace function public.st_v6_room_quiet_settings(p_room uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare rule sectalk_private.st_v6_room_quiet_rules;
begin
  if not sectalk_private.st_v8_room_structure_room_allows(p_room) then raise insufficient_privilege; end if;
  if sectalk_private.st_v6_room_role(p_room) is null then
    raise exception 'Notification settings unavailable';
  end if;
  select * into rule from sectalk_private.st_v6_room_quiet_rules
    where room_id=p_room and user_id=auth.uid();
  return jsonb_build_object('muted',coalesce(rule.muted,false),'snooze_until',rule.snooze_until,
    'days',rule.days,'starts_at',rule.starts_at,'ends_at',rule.ends_at,'zone',rule.zone,
    'active',sectalk_private.st_v6_room_alert_quiet(auth.uid(),p_room));
end
$$;

create or replace function public.st_v6_set_room_quiet(
  p_room uuid,p_action text,p_muted boolean default null,p_minutes integer default null,
  p_days smallint[] default null,p_start time default null,p_end time default null,p_zone text default null
)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_v8_room_structure_require(p_room);
  if sectalk_private.st_v6_room_role(p_room) is null then
    raise exception 'Notification settings unavailable';
  end if;
  perform sectalk_private.st_v6_set_conversation_quiet(p_room,null,p_action,p_muted,p_minutes,p_days,p_start,p_end,p_zone);
end
$$;

create or replace function sectalk_private.st_v6_channel_quiet_settings(p_channel uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare rule sectalk_private.st_v6_room_quiet_rules;
begin
  if not exists(select 1 from public.st_v2_channels c where c.id=p_channel
    and sectalk_private.st_v8_channel_structure_sso_allows(c.workspace_id)) then raise insufficient_privilege; end if;
  if not sectalk_private.st_v6_channel_content_access(p_channel,auth.uid()) then
    raise exception 'Notification settings unavailable';
  end if;
  select * into rule from sectalk_private.st_v6_room_quiet_rules
    where channel_id=p_channel and user_id=auth.uid();
  return jsonb_build_object('muted',coalesce(rule.muted,false),'snooze_until',rule.snooze_until,
    'days',rule.days,'starts_at',rule.starts_at,'ends_at',rule.ends_at,'zone',rule.zone,
    'active',sectalk_private.st_v6_channel_alert_quiet(auth.uid(),p_channel));
end
$$;

create or replace function sectalk_private.st_v6_set_channel_quiet(
  p_channel uuid,p_action text,p_muted boolean,p_minutes integer,
  p_days smallint[],p_start time,p_end time,p_zone text
)
returns void language plpgsql security definer set search_path='' as $$
declare space uuid;
begin
  select c.workspace_id into space from public.st_v2_channels c where c.id=p_channel;
  if not found or not sectalk_private.st_v6_channel_content_access(p_channel,auth.uid()) then
    raise exception 'Notification settings unavailable';
  end if;
  perform 1 from public.st_v2_workspaces w where w.id=space for key share;
  if not found or not sectalk_private.st_v8_channel_structure_sso_allows(space) then raise insufficient_privilege; end if;
  perform sectalk_private.st_v6_set_conversation_quiet(null,p_channel,p_action,p_muted,p_minutes,p_days,p_start,p_end,p_zone);
end
$$;

create or replace function public.st_v6_room_retirement(p_room uuid,p_action text default 'read')
returns jsonb language plpgsql security definer set search_path='' as $$
declare target public.st_v6_rooms;
declare requested timestamptz;
declare permitted boolean;
declare verified boolean:=sectalk_private.st_v6_retirement_has_mfa() is true;
declare wait_days integer;
begin
  if p_action is null or p_action not in ('read','schedule','cancel') then raise exception 'Invalid room retention action'; end if;
  select * into target from public.st_v6_rooms where id=p_room;
  if not found or not sectalk_private.st_v6_room_directory(p_room)
    or not sectalk_private.st_v8_room_structure_sso_allows(target.workspace_id) then
    raise exception 'Room retention is unavailable' using errcode='42501';
  end if;
  permitted:=coalesce(sectalk_private.st_v6_room_role(p_room)='owner'
    or sectalk_private.st_v2_role(target.workspace_id,auth.uid()) in ('owner','admin'),false);
  if p_action<>'read' then
    if not permitted or not verified then raise exception 'Verified room owner access is required' using errcode='42501'; end if;
    perform sectalk_private.st_v8_room_structure_require(p_room);
    perform sectalk_private.limit_action('v6_room_retirement',15);
    select * into target from public.st_v6_rooms where id=p_room for update;
    if not found or not sectalk_private.st_v6_room_directory(p_room) or not coalesce(
      sectalk_private.st_v6_room_role(p_room)='owner'
        or sectalk_private.st_v2_role(target.workspace_id,auth.uid()) in ('owner','admin'),false)
    then raise exception 'Room retention is unavailable' using errcode='42501'; end if;
    perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-workspace-hold:'||target.workspace_id::text,0));
    if p_action='schedule' then
      if not target.archived then raise exception 'Archive the room before scheduling deletion'; end if;
      insert into sectalk_private.st_v6_room_retirements(room_id,requested_by) values(p_room,auth.uid()) on conflict do nothing;
      if found then
        insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
          values(target.workspace_id,auth.uid(),'room.deletion_scheduled',p_room);
      end if;
    else
      delete from sectalk_private.st_v6_room_retirements where room_id=p_room;
      if found then
        insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
          values(target.workspace_id,auth.uid(),'room.deletion_cancelled',p_room);
      end if;
    end if;
  end if;
  select requested_at into requested from sectalk_private.st_v6_room_retirements where room_id=p_room;
  wait_days:=sectalk_private.st_v6_room_retention_days(target.workspace_id);
  return jsonb_build_object('retention_days',wait_days,'can_manage',permitted,'verified',verified,
    'held',permitted and verified and requested is not null and sectalk_private.st_v6_room_is_held(target.workspace_id,p_room),
    'requested_at',requested,'eligible_at',requested+make_interval(days=>wait_days));
end $$;

commit;
