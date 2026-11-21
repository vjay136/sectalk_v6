begin;

create table sectalk_private.st_v8_workspace_compliance_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_compliance_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_compliance_sso from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_compliance_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_compliance_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_compliance_sso_allows(uuid) from public,anon,authenticated,service_role;

create function public.st_v8_workspace_compliance_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_compliance_sso_policy',5);
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
      raise insufficient_privilege;
    end if;
    if p_require then
      select * into setup from sectalk_private.st_v7_workspace_sso c where c.workspace=p_workspace;
      if not found or sectalk_private.st_v7_workspace_sso_provider(p_workspace,setup.domain,setup.protocol)
        is distinct from setup.provider or not exists(
          select 1 from sectalk_private.st_v7_workspace_sso_sessions r join auth.sessions s on (s.id,s.user_id)=(r.session,r.principal)
          where r.workspace=p_workspace and (r.protocol,r.provider)=(setup.protocol,setup.provider)
            and sectalk_private.st_v2_active(r.principal) and sectalk_private.st_v2_role(p_workspace,r.principal) is not null
            and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
        ) then return '{"access":"verified","error":"verified_provider_session_required"}'; end if;
      insert into sectalk_private.st_v8_workspace_compliance_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_compliance_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.compliance_sso_required'
          else 'workspace.compliance_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_compliance_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_compliance_policy(uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_compliance_policy(uuid,boolean) to authenticated;

create function sectalk_private.st_v8_compliance_native_access(p_workspace uuid)
returns text language sql stable security definer set search_path='' as $$
  select case when r.kind not in ('owner','admin') or r.kind is null or not public.st_v7_current_session_valid()
       or not sectalk_private.st_v2_active(auth.uid()) then 'none'
    when not sectalk_private.st_v7_admin_fresh() then 'mfa' else r.kind end
  from (select sectalk_private.st_v2_role(p_workspace,auth.uid()) kind) r;
$$;

-- A service-side operation uses the native principal and session recorded
-- when its short-lived ticket was minted. It has no authenticated caller JWT.
create function sectalk_private.st_v8_compliance_ticket_sso_allows(p_workspace uuid,p_actor uuid,p_session uuid)
returns boolean language sql stable set search_path='' as $$
  select not exists(
    select 1 from sectalk_private.st_v8_workspace_compliance_sso policy where policy.workspace=p_workspace
      and not exists(
        select 1 from sectalk_private.st_v7_workspace_sso_sessions receipt
        join sectalk_private.st_v7_workspace_sso setup on setup.workspace=receipt.workspace
        where receipt.workspace=policy.workspace and (receipt.principal,receipt.session)=(p_actor,p_session)
          and (receipt.protocol,receipt.provider)=(policy.protocol,policy.provider)
          and (setup.protocol,setup.provider)=(policy.protocol,policy.provider)
          and sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol)=setup.provider));
$$;

-- The separate offboarding review grants authorize only their own cases.
create function sectalk_private.st_v8_is_offboarding_export(c sectalk_private.st_v7_compliance_cases)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v8_offboarding_requests r
    where (r.case_id,r.workspace,r.requester,r.reviewer)=(c.id,c.workspace_id,c.requester,c.reviewer));
$$;

create or replace function public.st_v7_compliance_access(p_workspace uuid)
returns text language sql stable security definer set search_path='' as $$
  select case when native.access in ('owner','admin')
    and not sectalk_private.st_v8_compliance_sso_allows(p_workspace) then 'sso'
    else native.access end
  from (select sectalk_private.st_v8_compliance_native_access(p_workspace) access) native;
$$;

revoke all on function sectalk_private.st_v8_compliance_native_access(uuid),
  sectalk_private.st_v8_compliance_ticket_sso_allows(uuid,uuid,uuid),
  sectalk_private.st_v8_is_offboarding_export(sectalk_private.st_v7_compliance_cases)
  from public,anon,authenticated,service_role;

create or replace function public.st_v7_begin_compliance_operation(p_case uuid,p_operation text)
returns uuid language plpgsql security definer set search_path='' as $$
declare c sectalk_private.st_v7_compliance_cases; operation_ticket uuid:=gen_random_uuid();
begin
  if p_operation is null or p_operation not in ('build','download') then
    raise exception 'Invalid export operation' using errcode='22023';
  end if;
  select q.* into c from sectalk_private.st_v7_compliance_cases q where q.id=p_case and q.requester=auth.uid() for update;
  if c.id is null or (case when sectalk_private.st_v8_is_offboarding_export(c)
      then sectalk_private.st_v8_compliance_native_access(c.workspace_id) not in ('owner','admin')
      else public.st_v7_compliance_access(c.workspace_id)<>'admin' end)
    or sectalk_private.st_v7_compliance_revalidate(c) is null then
    raise exception 'Approved export unavailable' using errcode='42501';
  end if;
  if c.ticket_until>statement_timestamp() or (p_operation='build' and c.artifact is not null)
    or (p_operation='download' and c.artifact is null) then
    raise exception 'The requested export operation is not currently available' using errcode='PT409';
  end if;
  perform sectalk_private.limit_action('v7_compliance_operation',20);
  update sectalk_private.st_v7_compliance_cases set operation=p_operation,ticket=operation_ticket,
    ticket_session=(auth.jwt()->>'session_id')::uuid,ticket_until=clock_timestamp()+interval '45 seconds' where id=c.id;
  return operation_ticket;
end $$;

create or replace function sectalk_private.st_v7_compliance_operation_live(c sectalk_private.st_v7_compliance_cases)
returns boolean language sql stable set search_path='' as $$
  select coalesce(c.ticket is not null and c.ticket_until>statement_timestamp() and c.operation in ('build','download')
    and (sectalk_private.st_v8_is_offboarding_export(c)
      or sectalk_private.st_v8_compliance_ticket_sso_allows(c.workspace_id,c.requester,c.ticket_session))
    and exists(select 1 from auth.sessions s join auth.mfa_factors f on f.id=s.factor_id and f.user_id=s.user_id
      join auth.mfa_amr_claims a on a.session_id=s.id and a.authentication_method='totp'
      where s.id=c.ticket_session and s.user_id=c.requester and s.aal='aal2'
      and f.status='verified' and f.factor_type='totp' and a.updated_at>statement_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()),false);
$$;

create or replace function sectalk_private.st_v7_evidence_operation_live(o sectalk_private.st_v7_evidence_operations)
returns boolean language sql stable set search_path='' as $$
  select coalesce(o.expires_at>statement_timestamp()
    and exists(select 1 from sectalk_private.st_v7_compliance_cases c where c.id=o.case_id
      and sectalk_private.st_v8_compliance_ticket_sso_allows(c.workspace_id,o.actor,o.session_id))
    and exists(
    select 1 from auth.sessions s join auth.mfa_factors f on f.id=s.factor_id and f.user_id=s.user_id
    join auth.mfa_amr_claims a on a.session_id=s.id and a.authentication_method='totp'
    where (s.id,s.user_id)=(o.session_id,o.actor) and s.aal='aal2'
      and f.status='verified' and f.factor_type='totp' and a.updated_at>statement_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()),false);
$$;

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
        when compliance_role='admin' then 'allowed' when compliance_role='mfa' then 'verification_required'
        when compliance_role='sso' then 'sso_required' else 'not_allowed' end,
      'compliance.export.review',case when workspace_role<>'owner' then 'not_allowed'
        when compliance_role='owner' then 'allowed' when compliance_role='mfa' then 'verification_required'
        when compliance_role='sso' then 'sso_required' else 'not_allowed' end);
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

commit;
