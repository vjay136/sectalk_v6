begin;

create table sectalk_private.st_v8_workspace_custom_role_admin_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_custom_role_admin_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_custom_role_admin_sso from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_custom_role_admin_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_custom_role_admin_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_custom_role_admin_sso_allows(uuid) from public,anon,authenticated,service_role;

create function public.st_v8_workspace_custom_role_admin_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_custom_role_admin_sso_policy',5);
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
      insert into sectalk_private.st_v8_workspace_custom_role_admin_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_custom_role_admin_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.custom_role_admin_sso_required'
          else 'workspace.custom_role_admin_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_custom_role_admin_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_custom_role_admin_policy(uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_custom_role_admin_policy(uuid,boolean) to authenticated;

-- This scope gates editing and browsing custom role definitions. Existing
-- delegated role use continues to follow its resource-specific policies.
create or replace function public.st_v7_workspace_custom_roles(p_workspace uuid,p_action text default 'read',
  p_role uuid default null,p_revision integer default null,p_definition jsonb default null,p_account uuid default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace);
  current_revision integer; def sectalk_private.st_v7_custom_role_versions; simulation text[]; stamp integer; previous_scope text; previous_target uuid;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if not sectalk_private.st_v8_custom_role_admin_sso_allows(p_workspace) then return '{"access":"sso"}'; end if;
  if p_action is distinct from 'read' then
    perform sectalk_private.limit_action('v7_custom_roles',20);
    perform 1 from public.st_v2_workspaces where id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
      raise exception using errcode='42501',message='Fresh workspace owner verification required';
    end if;
    if not sectalk_private.st_v8_custom_role_admin_sso_allows(p_workspace) then return '{"access":"sso"}'; end if;
    select h.revision into current_revision from sectalk_private.st_v7_custom_role_heads h where h.workspace=p_workspace and h.id=p_role;
    if p_role is null or p_revision is distinct from coalesce(current_revision,0) then
      raise exception using errcode='PT409',message='Role revision changed. Refresh before trying again';
    end if;
    if p_action='save' then
      if jsonb_typeof(p_definition) is distinct from 'object' or octet_length(p_definition::text)>1024
        or (p_definition->>'target') !~* '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
        or jsonb_typeof(p_definition->'permissions') is distinct from 'array'
        or jsonb_typeof(p_definition->'enabled') is distinct from 'boolean' then
        raise exception using errcode='22023',message='Enter a valid group-scoped role';
      end if;
      def.scope_type:=coalesce(p_definition->>'scope_type','group');
      if current_revision is not null then
        select v.scope_type,v.target into previous_scope,previous_target from sectalk_private.st_v7_custom_role_versions v
          where (v.workspace,v.role_id,v.revision)=(p_workspace,p_role,current_revision);
      end if;
      def.name:=btrim(p_definition->>'name'); def.target:=(p_definition->>'target')::uuid;
      def.device:=p_definition->>'device'; def.enabled:=(p_definition->>'enabled')::boolean;
      def.risk_max:=(p_definition->>'risk_max')::integer;
      def.utc_start:=(p_definition->>'utc_start')::integer; def.utc_end:=(p_definition->>'utc_end')::integer;
      select array_agg(distinct p) into def.permissions from jsonb_array_elements_text(p_definition->'permissions') p;
      if def.name is null or char_length(def.name) not between 1 and 64 or def.name~'[[:cntrl:]]'
        or not sectalk_private.st_v7_custom_role_target(p_workspace,def.scope_type,def.target)
        or (current_revision is not null and (def.scope_type,def.target) is distinct from (previous_scope,previous_target))
        or (def.scope_type='room' and sectalk_private.st_v6_room_role(def.target,auth.uid()) not in ('owner','moderator'))
        or (def.scope_type='room' and sectalk_private.st_v6_room_role(def.target,auth.uid()) is null)
        or coalesce(cardinality(def.permissions),0) not between 1 and 3
        or not (def.permissions<@(case def.scope_type when 'group' then array['rename','archive','restore']::text[]
          when 'room' then array['room.pin','room.unpin','room.slow']::text[]
          when 'file' then array['file.download','file.share']::text[] else '{}'::text[] end))
        or coalesce(def.device,'') not in ('any','trusted','managed')
        or (def.risk_max is not null and def.risk_max not between 0 and 100)
        or (def.utc_start is null)<>(def.utc_end is null)
        or (def.utc_start is not null and (def.utc_start not between 0 and 23 or def.utc_end not between 0 and 24 or def.utc_start=def.utc_end))
        or coalesce(current_revision,0)>=100
        or (current_revision is null and (select count(*) from sectalk_private.st_v7_custom_role_heads where workspace=p_workspace)>=25)
        then raise exception using errcode='22023',message='Enter supported permissions, an eligible resource and valid ABAC conditions';
      end if;
      stamp:=coalesce(current_revision,0)+1;
      insert into sectalk_private.st_v7_custom_role_heads values(p_workspace,p_role,stamp)
        on conflict(workspace,id) do update set revision=excluded.revision;
      insert into sectalk_private.st_v7_custom_role_versions(workspace,role_id,revision,name,target,permissions,device,risk_max,utc_start,utc_end,enabled,scope_type)
        values(p_workspace,p_role,stamp,def.name,def.target,def.permissions,def.device,def.risk_max,def.utc_start,def.utc_end,def.enabled,def.scope_type);
    elsif p_action in ('assign','revoke') and current_revision is not null and p_account is not null then
      if p_action='assign' then
        perform 1 from public.st_v2_members where workspace_id=p_workspace and user_id=p_account for no key update;
        if sectalk_private.st_v2_role(p_workspace,p_account) is distinct from 'member' or not sectalk_private.st_v2_active(p_account)
          then raise exception using errcode='42501',message='Assign only to an active ordinary workspace member'; end if;
        insert into sectalk_private.st_v7_custom_role_assignments values(p_workspace,p_role,p_account) on conflict do nothing;
      else delete from sectalk_private.st_v7_custom_role_assignments
          where workspace=p_workspace and role_id=p_role and account=p_account; end if;
    elsif p_action='gate' and current_revision is not null and jsonb_typeof(p_definition->'required')='boolean' then
      select * into def from sectalk_private.st_v7_custom_role_versions v
        where (v.workspace,v.role_id,v.revision)=(p_workspace,p_role,current_revision);
      if def.scope_type<>'file' or not sectalk_private.st_v7_custom_role_target(p_workspace,'file',def.target) then
        raise exception using errcode='42501',message='Select an eligible workspace file';
      end if;
      if (p_definition->>'required')::boolean then
        insert into sectalk_private.st_v7_file_custom_role_required values(p_workspace,def.target) on conflict do nothing;
      else
        delete from sectalk_private.st_v7_file_custom_role_required where workspace=p_workspace and file=def.target;
      end if;
    elsif p_action='simulate' and current_revision is not null then
      select * into def from sectalk_private.st_v7_custom_role_versions v
        where (v.workspace,v.role_id,v.revision)=(p_workspace,p_role,current_revision);
      simulation:=sectalk_private.st_v7_custom_role_conditions(def,p_definition->>'device',(p_definition->>'risk')::integer,
        (p_definition->>'hour')::integer);
      if not coalesce(p_definition->>'permission'=any(def.permissions),false) then simulation:=simulation||'permission'::text; end if;
      return jsonb_build_object('access','verified','allowed',cardinality(simulation)=0,'conditions',simulation);
    else raise exception using errcode='22023',message='Choose a supported role operation'; end if;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,auth.uid(),'workspace.custom_role_'||p_action,p_role);
  end if;
  return jsonb_build_object('access','verified','roles',coalesce((select jsonb_agg(jsonb_build_object(
    'id',h.id,'revision',h.revision,'name',v.name,'target',v.target,'scope_type',v.scope_type,'permissions',v.permissions,
    'file_gate',v.scope_type='file' and exists(select 1 from sectalk_private.st_v7_file_custom_role_required f
      where (f.workspace,f.file)=(v.workspace,v.target)),
    'device',v.device,'risk_max',v.risk_max,'utc_start',v.utc_start,'utc_end',v.utc_end,'enabled',v.enabled,
    'assignments',coalesce((select jsonb_agg(a.account order by a.account) from sectalk_private.st_v7_custom_role_assignments a
      where (a.workspace,a.role_id)=(h.workspace,h.id)),'[]'),
    'history',coalesce((select jsonb_agg(jsonb_build_object('revision',older.revision,'recordedAt',older.recorded_at) order by older.revision desc)
      from sectalk_private.st_v7_custom_role_versions older where (older.workspace,older.role_id)=(h.workspace,h.id)),'[]')
  ) order by v.name,h.id) from sectalk_private.st_v7_custom_role_heads h
    join sectalk_private.st_v7_custom_role_versions v on (v.workspace,v.role_id,v.revision)=(h.workspace,h.id,h.revision)
    where h.workspace=p_workspace),'[]'));
end
$$;

create or replace function public.st_v7_custom_role_targets(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select case when sectalk_private.st_v7_file_egress_operator(p_workspace)='verified'
    and sectalk_private.st_v8_custom_role_admin_sso_allows(p_workspace) then coalesce((
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
