begin;

-- The permission catalog executes with its owner's privileges, so its
-- selectors and summaries must apply the current caller's receipts directly.
create or replace function public.st_v7_permission_catalog(p_workspace uuid default null,p_room uuid default null)
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
  directory_allowed boolean;
  room_directory_allowed boolean:=true;
  managed_room_post_blocked boolean;
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
    room_directory_allowed:=sectalk_private.st_v8_room_structure_sso_allows(p_workspace);
    if room_directory_allowed then
      select coalesce(jsonb_agg(to_jsonb(r) order by r.name,r.id),'[]') into rooms from (
        select r.id,r.name from public.st_v6_rooms r where r.workspace_id=p_workspace
          and (sectalk_private.st_v6_room_role(r.id,actor) is not null or sectalk_private.st_v6_room_workspace_manager(r.id))
        order by r.name,r.id limit 100
      ) r;
    end if;
    directory_allowed:=sectalk_private.st_v8_directory_sso_allows(p_workspace);
    compliance_role:=public.st_v7_compliance_access(p_workspace);
    integration_access:=public.st_v6_integration_access(p_workspace);
    workspace_actions:=jsonb_build_object(
      'workspace.member.read',case when not directory_allowed and workspace_role in ('owner','admin') then 'sso_required'
        else sectalk_private.st_v7_workspace_permission(p_workspace,'workspace.member.read') end,
      'admin.user.suspend',case when not directory_allowed and workspace_role in ('owner','admin') then 'sso_required'
        else sectalk_private.st_v7_workspace_permission(p_workspace,'admin.user.suspend') end,
      'admin.user.role.write',case when not directory_allowed and workspace_role='owner' then 'sso_required'
        else sectalk_private.st_v7_workspace_permission(p_workspace,'admin.user.role.write') end,
      'audit.log.read',case when workspace_role not in ('owner','admin') then 'not_allowed'
        when not sectalk_private.st_v8_audit_sso_allows(p_workspace) then 'sso_required' else 'allowed' end,
      'integration.key.manage',case integration_access when 'verified' then 'allowed' when 'mfa' then 'verification_required'
        when 'upgrade' then 'plan_required' when 'sso' then 'sso_required' else 'not_allowed' end,
      'compliance.export.request',case when workspace_role<>'admin' then 'not_allowed'
        when compliance_role='admin' then 'allowed' when compliance_role='mfa' then 'verification_required' else 'not_allowed' end,
      'compliance.export.review',case when workspace_role<>'owner' then 'not_allowed'
        when compliance_role='owner' then 'allowed' when compliance_role='mfa' then 'verification_required' else 'not_allowed' end);
    if room_directory_allowed and exists(select 1 from public.st_v6_rooms r where r.id=p_room and r.workspace_id=p_workspace
      and (sectalk_private.st_v6_room_role(r.id,actor) is not null or sectalk_private.st_v6_room_workspace_manager(r.id))) then
      room_role:=sectalk_private.st_v6_room_role(p_room,actor);
      room_policy:=public.st_v6_room_permission_state(p_room);
      managed_room_post_blocked:=exists(select 1 from public.st_v6_rooms r where r.id=p_room and r.encryption_mode='managed'
        and not sectalk_private.st_v8_managed_content_session_allowed(p_workspace,actor,auth.jwt()->>'session_id'));
      room_actions:=jsonb_build_object(
        'messaging.message.send',case when room_policy->'post' is distinct from 'true'::jsonb then 'not_allowed'
          when managed_room_post_blocked then 'sso_required' else 'allowed' end,
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
    'room_requires_sso',not room_directory_allowed,'operator_role',declared_operator,'workspace',workspace_actions,
    'room',room_actions,'platform',jsonb_build_object(
      'soc.queue.read',case staff_role when 'verified' then 'allowed' when 'mfa' then 'verification_required' else 'not_allowed' end,
      'platform.account.read',case when operator_role in ('operator','reviewer') then 'allowed'
        when operator_role='mfa' then 'verification_required' else 'not_allowed' end,
      'platform.session.revoke',case when operator_role='operator' then 'allowed'
        when operator_role='mfa' and declared_operator='operator' then 'verification_required' else 'not_allowed' end,
      'platform.recovery.review',case when operator_role='reviewer' then 'allowed'
        when operator_role='mfa' and declared_operator='reviewer' then 'verification_required' else 'not_allowed' end));
end $$;

create or replace function public.st_v6_room_permission_state(p_room uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare member_role text:=sectalk_private.st_v6_room_role(p_room,actor);
declare target public.st_v6_rooms;
declare can_write boolean;
begin
  if member_role is null then return null; end if;
  select * into target from public.st_v6_rooms r where r.id=p_room;
  if not found or not sectalk_private.st_v8_room_structure_sso_allows(target.workspace_id) then return null; end if;
  can_write:=member_role<>'read_only' and not target.archived and
    (member_role in ('owner','moderator') or (not target.locked and target.kind not in ('announcement','broadcast')));
  return jsonb_build_object(
    'post',can_write and sectalk_private.st_v6_room_role_rule(p_room,actor,'post')<>'deny',
    'react',can_write and sectalk_private.st_v6_room_role_rule(p_room,actor,'react')<>'deny',
    'mention_all',sectalk_private.st_v6_room_all_mentions(p_room,actor),
    'editable',case when target.archived then '{}'::jsonb else coalesce((
      select jsonb_object_agg(a.role,coalesce(r.rules,'{}'::jsonb))
      from (values('owner'),('moderator'),('member')) a(role)
      left join sectalk_private.st_v6_room_role_overrides r on r.room=p_room and r.role=a.role
      where member_role='owner' or (member_role='moderator' and a.role='member')
    ),'{}'::jsonb) end
  );
end
$$;

create or replace function public.st_v7_custom_role_targets(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select case when sectalk_private.st_v7_file_egress_operator(p_workspace)='verified' then coalesce((
    select jsonb_agg(to_jsonb(t) order by scope,name) from (
      (select 'group' as scope,g.id,g.name from public.st_v6_workspace_groups g
        where g.workspace_id=p_workspace and g.kind in ('group','team','department')
        and sectalk_private.st_v8_groups_sso_allows(p_workspace) order by g.name limit 250)
      union all
      (select 'room',r.id,r.name from public.st_v6_rooms r
        where r.workspace_id=p_workspace and sectalk_private.st_v7_custom_role_target(p_workspace,'room',r.id)
        and sectalk_private.st_v8_room_structure_sso_allows(p_workspace)
        and sectalk_private.st_v6_room_role(r.id,auth.uid()) in ('owner','moderator') order by r.name limit 100)
      union all
      (select 'file',f.id,f.filename from sectalk_private.st_v6_workspace_files f
        where f.workspace=p_workspace and f.published_at is not null and f.deleted_at is null
        and sectalk_private.st_v8_file_sso_allows(p_workspace) order by f.filename limit 250)
    ) t),'[]') else '[]' end;
$$;

commit;
