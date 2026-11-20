begin;

create function sectalk_private.st_v7_workspace_permission(p_workspace uuid,p_action text)
returns text language plpgsql stable security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  member_role text:=sectalk_private.st_v2_role(p_workspace,actor);
begin
  if not coalesce(sectalk_private.st_v2_active(actor),false) then return 'not_allowed'; end if;
  if not coalesce(case p_action
    when 'workspace.member.read' then member_role in ('owner','admin')
    when 'admin.user.suspend' then member_role in ('owner','admin')
    when 'admin.user.role.write' then member_role='owner'
    else false end,false) then return 'not_allowed'; end if;
  return case when sectalk_private.st_v7_admin_fresh() then 'allowed' else 'verification_required' end;
end $$;

create function sectalk_private.st_v7_room_override_permission(p_room uuid,p_role text)
returns text language plpgsql stable security definer set search_path='' as $$
declare
  actor_role text:=sectalk_private.st_v6_room_role(p_room,auth.uid());
begin
  if p_role is null or p_role not in ('owner','moderator','member') or actor_role is null
    or not (actor_role='owner' or (actor_role='moderator' and p_role='member'))
    or not exists(select 1 from public.st_v6_rooms where id=p_room and not archived) then return 'not_allowed'; end if;
  return case when public.st_v7_sensitive_action_status('room_role')='verified' then 'allowed' else 'verification_required' end;
end $$;

create function public.st_v7_permission_catalog(p_workspace uuid default null,p_room uuid default null)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  workspace_role text;
  room_role text;
  operator_role text:=public.st_v7_account_operator_access();
  declared_operator text;
  staff_role text:=public.st_staff_status();
  compliance_role text;
  integration_access text;
  room_policy jsonb;
  workspaces jsonb;
  rooms jsonb:='[]';
  workspace_actions jsonb:='{}';
  room_actions jsonb:='{}';
begin
  if not coalesce(public.st_v7_current_session_valid(),false) or not coalesce(sectalk_private.st_v2_active(actor),false)
    or public.st_v7_login_risk_status()<>'clear' or public.st_v7_account_under_lockdown() then
    raise exception 'Permission catalog requires a current verified session' using errcode='42501';
  end if;
  select coalesce(jsonb_agg(to_jsonb(w) order by w.name,w.id),'[]') into workspaces from (
    select w.id,w.name from public.st_v2_members m join public.st_v2_workspaces w on w.id=m.workspace_id
    where m.user_id=actor and m.suspended_at is null order by w.name,w.id limit 100
  ) w;
  workspace_role:=sectalk_private.st_v2_role(p_workspace,actor);
  if workspace_role is not null then
    select coalesce(jsonb_agg(to_jsonb(r) order by r.name,r.id),'[]') into rooms from (
      select r.id,r.name from public.st_v6_rooms r where r.workspace_id=p_workspace
        and (sectalk_private.st_v6_room_role(r.id,actor) is not null or sectalk_private.st_v6_room_workspace_manager(r.id))
      order by r.name,r.id limit 100
    ) r;
    compliance_role:=public.st_v7_compliance_access(p_workspace);
    integration_access:=public.st_v6_integration_access(p_workspace);
    workspace_actions:=jsonb_build_object(
      'workspace.member.read',sectalk_private.st_v7_workspace_permission(p_workspace,'workspace.member.read'),
      'admin.user.suspend',sectalk_private.st_v7_workspace_permission(p_workspace,'admin.user.suspend'),
      'admin.user.role.write',sectalk_private.st_v7_workspace_permission(p_workspace,'admin.user.role.write'),
      'audit.log.read',case when workspace_role in ('owner','admin') then 'allowed' else 'not_allowed' end,
      'integration.key.manage',case integration_access when 'verified' then 'allowed' when 'mfa' then 'verification_required'
        when 'upgrade' then 'plan_required' else 'not_allowed' end,
      'compliance.export.request',case when workspace_role<>'admin' then 'not_allowed'
        when compliance_role='admin' then 'allowed' when compliance_role='mfa' then 'verification_required' else 'not_allowed' end,
      'compliance.export.review',case when workspace_role<>'owner' then 'not_allowed'
        when compliance_role='owner' then 'allowed' when compliance_role='mfa' then 'verification_required' else 'not_allowed' end);
    if exists(select 1 from public.st_v6_rooms r where r.id=p_room and r.workspace_id=p_workspace
      and (sectalk_private.st_v6_room_role(r.id,actor) is not null or sectalk_private.st_v6_room_workspace_manager(r.id))) then
      room_role:=sectalk_private.st_v6_room_role(p_room,actor);
      room_policy:=public.st_v6_room_permission_state(p_room);
      room_actions:=jsonb_build_object(
        'messaging.message.send',case when room_policy->'post'='true'::jsonb then 'allowed' else 'not_allowed' end,
        'room.reaction.add',case when room_policy->'react'='true'::jsonb then 'allowed' else 'not_allowed' end,
        'room.mention.all',case when room_policy->'mention_all'='true'::jsonb then 'allowed' else 'not_allowed' end,
        'room.member.remove',case when room_role in ('owner','moderator') and exists(
          select 1 from public.st_v6_rooms r where r.id=p_room and not r.archived and r.kind<>'admin')
          then 'allowed' else 'not_allowed' end,
        'room.permission.write',sectalk_private.st_v7_room_override_permission(p_room,'member'));
    end if;
  end if;
  select a.capability into declared_operator from sectalk_private.st_v7_account_operators a where a.user_id=actor;
  return jsonb_build_object('workspaces',workspaces,'rooms',rooms,'workspace_role',workspace_role,'room_role',room_role,
    'operator_role',declared_operator,'workspace',workspace_actions,'room',room_actions,'platform',jsonb_build_object(
      'soc.queue.read',case staff_role when 'verified' then 'allowed' when 'mfa' then 'verification_required' else 'not_allowed' end,
      'platform.account.read',case when operator_role in ('operator','reviewer') then 'allowed'
        when operator_role='mfa' then 'verification_required' else 'not_allowed' end,
      'platform.session.revoke',case when operator_role='operator' then 'allowed'
        when operator_role='mfa' and declared_operator='operator' then 'verification_required' else 'not_allowed' end,
      'platform.recovery.review',case when operator_role='reviewer' then 'allowed'
        when operator_role='mfa' and declared_operator='reviewer' then 'verification_required' else 'not_allowed' end));
end $$;

revoke all on function sectalk_private.st_v7_workspace_permission(uuid,text),
  sectalk_private.st_v7_room_override_permission(uuid,text),public.st_v7_permission_catalog(uuid,uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_permission_catalog(uuid,uuid) to authenticated;

create or replace function public.st_v7_workspace_people_verified(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v7_workspace_permission(p_workspace,'workspace.member.read')='allowed'
$$;
create or replace function public.st_v2_set_member(p_workspace uuid,p_member uuid,p_role text)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  actor_role text;
  target_role text;
begin
  perform sectalk_private.limit_action('v2_role',12);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  actor_role:=sectalk_private.st_v2_role(p_workspace,actor);
  if not coalesce(actor_role in ('owner','admin'),false) or not sectalk_private.st_v2_active(actor)
    or p_member is null or p_member=actor or p_role is null or p_role not in ('admin','member','remove','suspend','restore')
  then raise exception 'Workspace action unavailable'; end if;
  select m.role into target_role from public.st_v2_members m
    where m.workspace_id=p_workspace and m.user_id=p_member;
  if target_role is null or target_role='owner'
    or (actor_role='admin' and (target_role<>'member' or p_role not in ('suspend','restore')))
  then raise exception 'Workspace member unavailable'; end if;
  if sectalk_private.st_v7_workspace_permission(p_workspace,case when p_role in ('suspend','restore') then 'admin.user.suspend' else 'admin.user.role.write' end)<>'allowed' then
    raise exception 'Workspace administrator verification required' using errcode='42501';
  end if;
  case p_role
    when 'remove' then
      delete from public.st_v2_members where workspace_id=p_workspace and user_id=p_member;
    when 'suspend' then
      update public.st_v2_members set suspended_at=clock_timestamp()
        where workspace_id=p_workspace and user_id=p_member and suspended_at is null;
    when 'restore' then
      update public.st_v2_members set suspended_at=null
        where workspace_id=p_workspace and user_id=p_member and suspended_at is not null;
    else
      update public.st_v2_members set role=p_role where workspace_id=p_workspace and user_id=p_member;
  end case;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,'member.'||p_role,p_member);
  end if;
end $$;
create or replace function public.st_v6_set_room_role_overrides(p_room uuid,p_role text,p_rules jsonb)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare member_role text;
begin
  perform sectalk_private.limit_action('v6_room_role_overrides',20);
  perform 1 from public.st_v6_rooms r where r.id=p_room and not r.archived for no key update;
  if not found then raise exception 'Room permissions are unavailable.' using errcode='42501'; end if;
  member_role:=sectalk_private.st_v7_room_override_permission(p_room,p_role);
  if member_role='not_allowed' then
    raise exception 'You cannot change permissions for that room role.' using errcode='42501';
  end if;
  if member_role<>'allowed' then
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
commit;
