begin;

create function public.st_v7_sensitive_action_status(p_kind text)
returns text language plpgsql stable security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  native_session uuid;
begin
  if p_kind is null or p_kind not in ('billing','room_role','export','integration_key')
    or not public.st_v7_current_session_valid() or public.st_v7_account_under_lockdown()
    or public.st_v7_login_risk_status()<>'clear' then return 'unavailable'; end if;
  if p_kind in ('export','integration_key') or exists(select 1 from auth.mfa_factors f where f.user_id=actor and f.status='verified') then
    return case when sectalk_private.st_v7_security_session('totp') then 'verified' else 'totp' end;
  end if;
  native_session:=(auth.jwt()->>'session_id')::uuid;
  if exists(select 1 from auth.mfa_amr_claims a where a.session_id=native_session
      and a.authentication_method='passkey' and a.created_at>statement_timestamp()-interval '5 minutes')
    or sectalk_private.st_v7_security_session('password') then return 'verified'; end if;
  if public.st_v7_passkey_only() then return 'passkey'; end if;
  return 'password';
end $$;
revoke all on function public.st_v7_sensitive_action_status(text) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_sensitive_action_status(text) to authenticated;

create or replace function public.st_v6_room_membership(p_room uuid,p_action text,p_target uuid default null,p_role text default 'member')
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); r public.st_v6_rooms; stage public.st_v6_room_entries; room_role text;
        target uuid:=coalesce(p_target,actor); target_role text;
begin
  perform sectalk_private.limit_action('v6_room_membership',30);
  select * into r from public.st_v6_rooms where id=p_room for update;
  if not found or r.kind='admin' or r.archived or not sectalk_private.st_v2_active(actor)
    or sectalk_private.st_v2_role(r.workspace_id,actor) is null
    or exists(select 1 from public.st_v6_room_bans where room_id=p_room and user_id=actor)
    then raise exception 'Room unavailable'; end if;
  room_role:=sectalk_private.st_v6_room_role(p_room);
  select role into target_role from public.st_v6_room_members where room_id=p_room and user_id=target;
  select * into stage from public.st_v6_room_entries where room_id=p_room and user_id=target and expires_at>now();

  if p_action in ('join','request','accept','decline') and target=actor then
    if p_action='join' and r.kind in ('public','announcement','broadcast') then
      insert into public.st_v6_room_members(room_id,user_id,role)
        values(p_room,actor,case when r.kind='broadcast' then 'read_only' else 'member' end) on conflict do nothing;
    elsif p_action='request' and r.kind='private' and room_role is null then
      insert into public.st_v6_room_entries values(p_room,actor,'request','member',now()+interval '7 days')
        on conflict(room_id,user_id) do update set expires_at=excluded.expires_at
        where public.st_v6_room_entries.kind='request' or public.st_v6_room_entries.expires_at<=now();
    elsif p_action in ('accept','decline') and stage.kind='invite' then
      if p_action='accept' then
        insert into public.st_v6_room_members values(p_room,actor,stage.invited_role) on conflict do nothing;
      end if;
      delete from public.st_v6_room_entries where room_id=p_room and user_id=actor;
    else raise exception 'Room unavailable'; end if;
  elsif p_action in ('invite','approve','deny','role','remove','ban','unban','mute','timeout','unmute')
    and room_role in ('owner','moderator') and target<>actor and target_role is distinct from 'owner'
    and (target_role is distinct from 'moderator' or room_role='owner') then
    if p_action='role' and public.st_v7_sensitive_action_status('room_role')<>'verified' then
      raise exception 'Verify your current sign-in to change a room role' using errcode='42501';
    end if;
    if p_action in ('invite','approve','role') then
      if sectalk_private.st_v2_role(r.workspace_id,target) is null or not sectalk_private.st_v2_active(target)
        or exists(select 1 from public.st_v6_room_bans where room_id=p_room and user_id=target)
        or p_role is null or p_role not in ('member','guest','read_only','moderator')
        or (p_role='moderator' and (room_role<>'owner' or p_action<>'role')) then raise exception 'Room action unavailable'; end if;
      if p_action='invite' and target_role is null then
        insert into public.st_v6_room_entries values(p_room,target,'invite',p_role,now()+interval '7 days')
          on conflict(room_id,user_id) do update set kind='invite',invited_role=excluded.invited_role,expires_at=excluded.expires_at;
      elsif p_action='approve' and stage.kind='request' then
        insert into public.st_v6_room_members values(p_room,target,p_role) on conflict do nothing;
        delete from public.st_v6_room_entries where room_id=p_room and user_id=target;
      elsif p_action='role' and target_role is not null then
        update public.st_v6_room_members set role=p_role where room_id=p_room and user_id=target;
      else raise exception 'Room action unavailable'; end if;
    elsif p_action='deny' and stage.kind='request' then
      delete from public.st_v6_room_entries where room_id=p_room and user_id=target;
    elsif p_action in ('remove','ban') then
      if p_action='ban' then
        insert into public.st_v6_room_bans values(p_room,target) on conflict do nothing;
      end if;
      delete from public.st_v6_room_members where room_id=p_room and user_id=target;
      delete from public.st_v6_room_entries where room_id=p_room and user_id=target;
    elsif p_action='unban' then
      delete from public.st_v6_room_bans where room_id=p_room and user_id=target;
    elsif p_action in ('mute','timeout') and target_role is not null then
      insert into public.st_v6_room_timeouts values(p_room,target,case when p_action='mute' then 'infinity'::timestamptz else now()+interval '15 minutes' end)
        on conflict(room_id,user_id) do update set until_at=excluded.until_at;
    elsif p_action='unmute' then
      delete from public.st_v6_room_timeouts where room_id=p_room and user_id=target;
    else raise exception 'Room action unavailable'; end if;
  else raise exception 'Room action unavailable'; end if;
  insert into public.st_v6_room_audit(room_id,actor,action,target) values(p_room,actor,'membership.'||p_action,target);
end $$;
create or replace function public.st_v6_set_room_role_overrides(p_room uuid,p_role text,p_rules jsonb)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare member_role text;
begin
  perform sectalk_private.limit_action('v6_room_role_overrides',20);
  perform 1 from public.st_v6_rooms r where r.id=p_room and not r.archived for no key update;
  if not found then raise exception 'Room permissions are unavailable.' using errcode='42501'; end if;
  member_role:=sectalk_private.st_v6_room_role(p_room,actor);
  if p_role is null or p_role not in ('owner','moderator','member') or member_role is null
    or not (member_role='owner' or (member_role='moderator' and p_role='member')) then
    raise exception 'You cannot change permissions for that room role.' using errcode='42501';
  end if;
  if public.st_v7_sensitive_action_status('room_role')<>'verified' then
    raise exception 'Verify your current sign-in to change role permissions' using errcode='42501';
  end if;
  if p_rules is null or jsonb_typeof(p_rules)<>'object' or exists(
    select 1 from jsonb_each(p_rules) rule where rule.key not in ('post','react','upload','mention_all','start_call')
      or rule.value not in ('"allow"'::jsonb,'"deny"'::jsonb)
  ) then raise exception 'Choose valid room permissions.' using errcode='22023'; end if;
  if p_rules='{}'::jsonb then
    delete from sectalk_private.st_v6_room_role_overrides r where r.room=p_room and r.role=p_role;
  else
    insert into sectalk_private.st_v6_room_role_overrides as current_rule(room,role,rules) values(p_room,p_role,p_rules)
      on conflict(room,role) do update set rules=excluded.rules where current_rule.rules is distinct from excluded.rules;
  end if;
  if found then
    insert into public.st_v6_room_audit(room_id,actor,action,details)
      values(p_room,actor,'room.role_permissions',jsonb_build_object('role',p_role,'rules',p_rules));
  end if;
end
$$;

create or replace function sectalk_private.st_v6_manage_room(p_room uuid,p_action text,p_kind text,p_target uuid)
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
      if public.st_v7_sensitive_action_status('room_role')<>'verified' then
        raise exception 'Verify your current sign-in to transfer ownership' using errcode='42501';
      end if;
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

create or replace function sectalk_private.st_v6_manage_channel(p_channel uuid,p_action text,p_target uuid,p_visibility text)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); channel public.st_v2_channels; workspace uuid; audit_detail text;
begin
  if not sectalk_private.st_v6_channel_can_manage(p_channel,actor) then raise exception 'Channel management unavailable'; end if;
  perform sectalk_private.limit_action('v6_manage_channel',30);
  if p_action in ('add_member','transfer_owner') then
    select workspace_id into workspace from public.st_v2_channels where id=p_channel;
    perform 1 from public.st_v2_members where workspace_id=workspace and user_id=p_target and suspended_at is null for share;
    if not found or not sectalk_private.st_v2_active(p_target) then raise exception 'Choose an active workspace member'; end if;
  end if;
  select * into channel from public.st_v2_channels where id=p_channel for update;
  if not found or not sectalk_private.st_v6_channel_can_manage(p_channel,actor)
    or (channel.archived and p_action is distinct from 'restore' and p_action is distinct from 'archive') then
    raise exception 'Channel management unavailable';
  end if;

  if p_action in ('add_member','transfer_owner') and p_target=channel.owner then return; end if;

  case p_action
    when 'visibility' then
      if p_visibility is null or p_visibility not in ('workspace','private') then raise exception 'Choose a channel visibility'; end if;
      if channel.visibility=p_visibility then return; end if;
      update public.st_v2_channels set visibility=p_visibility where id=p_channel;
      audit_detail:=channel.visibility||' → '||p_visibility;
    when 'add_member' then
      insert into sectalk_private.st_v6_channel_members values(p_channel,p_target) on conflict do nothing;
      if not found then return; end if;
    when 'remove_member' then
      if p_target=channel.owner then raise exception 'Transfer ownership before removing the owner'; end if;
      delete from sectalk_private.st_v6_channel_members where channel_id=p_channel and user_id=p_target;
      if not found then return; end if;
    when 'transfer_owner' then
      if public.st_v7_sensitive_action_status('room_role')<>'verified' then
        raise exception 'Verify your current sign-in to transfer ownership' using errcode='42501';
      end if;
      update public.st_v2_channels set owner=p_target where id=p_channel;
      delete from sectalk_private.st_v6_channel_members where channel_id=p_channel and user_id=p_target;
      audit_detail:=channel.owner::text;
    when 'archive','restore' then
      if channel.archived=(p_action='archive') then return; end if;
      update public.st_v2_channels set archived=(p_action='archive') where id=p_channel;
    else raise exception 'Channel management unavailable';
  end case;

  insert into sectalk_private.st_v6_channel_audit(channel_id,actor,action,target,detail)
    values(p_channel,actor,p_action,case when p_action in ('add_member','remove_member','transfer_owner') then p_target end,audit_detail);
end $$;

create or replace function public.st_v6_record_audit_export(p_workspace uuid)
returns void language plpgsql security definer set search_path='' as $$
begin
  if public.st_v7_sensitive_action_status('export')<>'verified' then
    raise exception 'Fresh authenticator proof is required for this export' using errcode='42501';
  end if;
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Verified workspace audit export access is required' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v6_audit_export',10);
  insert into public.st_v2_workspace_audit(workspace_id,actor,event)
    values(p_workspace,auth.uid(),'workspace.audit_export_requested');
end $$;

create or replace function public.st_v6_operational_report_export(p_run uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare report jsonb;
begin
  if public.st_v7_sensitive_action_status('export')<>'verified' then
    raise exception 'Fresh authenticator proof is required for this export' using errcode='42501';
  end if;
  if not sectalk_private.st_v6_operational_report_access() then
    raise exception 'MFA-verified staff access required' using errcode='42501';
  end if;
  select jsonb_build_object('cadence',r.cadence,'period_end',r.period_end,'rows',r.rows) into report
  from sectalk_private.st_v6_operational_report_runs r where r.id=p_run and r.owner=auth.uid()
    and r.scheduled_at>=now()-interval '30 days';
  return report;
end
$$;

create or replace function public.st_v6_integration_access(p_workspace uuid)
returns text language sql stable security definer set search_path='' as $$
  select case
    when sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner'
      or not coalesce(sectalk_private.st_v2_active(auth.uid()),false) then 'none'
    when sectalk_private.st_v2_effective_plan(auth.uid()) not in ('business','enterprise') then 'upgrade'
    when sectalk_private.st_v6_holds_access(p_workspace)='verified'
      and public.st_v7_sensitive_action_status('integration_key')='verified' then 'verified'
    else 'mfa'
  end
$$;

commit;
