begin;

create table sectalk_private.st_v8_workspace_groups_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_groups_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_groups_sso from public,anon,authenticated,service_role;

-- This policy applies to current-caller Groups and teams requests. School, onboarding,
-- and worker checks retain their respective role and capability rules.
create function sectalk_private.st_v8_groups_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_groups_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_groups_sso_allows(uuid) from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v8_groups_sso_allows(uuid) to authenticated;

create function public.st_v8_workspace_groups_requires_sso(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v2_active(auth.uid())
    and sectalk_private.st_v2_role(p_workspace,auth.uid()) is not null
    and not sectalk_private.st_v8_groups_sso_allows(p_workspace);
$$;

create function public.st_v8_workspace_groups_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_groups_sso_policy',5);
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
      insert into sectalk_private.st_v8_workspace_groups_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_groups_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.groups_sso_required'
          else 'workspace.groups_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_groups_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_groups_policy(uuid,boolean),
  public.st_v8_workspace_groups_requires_sso(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_groups_policy(uuid,boolean),
  public.st_v8_workspace_groups_requires_sso(uuid) to authenticated;

-- The roster policy already resolves membership through the visible parent
-- group. The School policy and classroom RPC continue to govern classes.
create policy st_v8_groups_sso on public.st_v6_workspace_groups as restrictive for select to authenticated
  using(kind='class' or sectalk_private.st_v8_groups_sso_allows(workspace_id));

create or replace function public.st_v6_workspace_group_create(p_workspace uuid,p_id uuid,p_kind text,p_name text,p_description text)
returns uuid language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  display_name text:=btrim(p_name);
  summary text:=btrim(coalesce(p_description,''));
begin
  perform sectalk_private.limit_action('v6_group_create',10);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor) then raise exception 'Workspace action unavailable'; end if;
  if not sectalk_private.st_v8_groups_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to manage groups and teams' using errcode='42501';
  end if;
  if p_id is null or p_kind is null or p_kind not in ('group','team','department')
    or display_name is null or char_length(display_name) not between 1 and 80 or char_length(summary)>500
    then raise exception 'Choose a valid type, name, and description'; end if;
  if exists(select 1 from public.st_v6_workspace_groups where workspace_id=p_workspace and id=p_id
    and kind=p_kind and name=display_name and description=summary) then return p_id; end if;
  if exists(select 1 from public.st_v6_workspace_groups where workspace_id=p_workspace and kind=p_kind and lower(name)=lower(display_name))
    then raise exception 'This workspace already has that name for the selected type'; end if;
  insert into public.st_v6_workspace_groups(workspace_id,id,kind,name,description)
    values(p_workspace,p_id,p_kind,display_name,summary);
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(p_workspace,actor,'group.created',p_id);
  return p_id;
end $$;

create or replace function public.st_v7_custom_group_access(p_workspace uuid,p_group uuid)
returns text[] language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid(); device_state text; risk_score integer; allowed text[];
begin
  if sectalk_private.st_v2_role(p_workspace,actor) is distinct from 'member'
    or not sectalk_private.st_v8_groups_sso_allows(p_workspace)
    or public.st_v7_current_session_valid() is not true or public.st_v7_account_under_lockdown()
    or public.st_v7_login_risk_status() is distinct from 'clear' or not sectalk_private.st_v2_active(actor)
    or not exists(select 1 from public.st_v6_workspace_groups g where g.workspace_id=p_workspace and g.id=p_group
      and g.kind in ('group','team','department')) then return '{}'; end if;
  select d.state,r.score into device_state,risk_score from auth.sessions s
    left join sectalk_private.st_v7_device_sessions b on b.session_id=s.id and b.owner=s.user_id
    left join sectalk_private.st_v7_devices d on (d.owner,d.id)=(b.owner,b.device_id)
    left join sectalk_private.st_v7_session_scores r on r.session_id=s.id and r.user_id=s.user_id
    where s.user_id=actor and s.id=(auth.jwt()->>'session_id')::uuid;
  select array_agg(distinct perm) into allowed
    from sectalk_private.st_v7_custom_role_assignments a
    join sectalk_private.st_v7_custom_role_heads h on (h.workspace,h.id)=(a.workspace,a.role_id)
    join sectalk_private.st_v7_custom_role_versions v on (v.workspace,v.role_id,v.revision)=(h.workspace,h.id,h.revision)
    cross join lateral unnest(v.permissions) perm
    where a.workspace=p_workspace and a.account=actor and v.target=p_group
      and cardinality(sectalk_private.st_v7_custom_role_conditions(v,device_state,risk_score,
        extract(hour from statement_timestamp() at time zone 'UTC')::integer))=0;
  return coalesce(allowed,'{}');
end
$$;

create or replace function public.st_v7_builtin_group_change(p_workspace uuid,p_id uuid,p_action text,
  p_name text default null,p_description text default null,p_user uuid default null)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  item public.st_v6_workspace_groups;
  display_name text:=btrim(p_name);
  summary text:=btrim(coalesce(p_description,''));
begin
  perform sectalk_private.limit_action('v6_group_change',30);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor) then raise exception 'Workspace action unavailable'; end if;
  if not sectalk_private.st_v8_groups_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to manage groups and teams' using errcode='42501';
  end if;
  select * into item from public.st_v6_workspace_groups where workspace_id=p_workspace and id=p_id;
  if not found then raise exception 'Workspace group unavailable'; end if;
  if item.archived_at is not null and p_action not in ('archive','restore') then
    raise exception 'Restore this entry before making changes'; end if;
  case p_action
    when 'rename' then
      if display_name is null or char_length(display_name) not between 1 and 80 or char_length(summary)>500
        then raise exception 'Choose a valid name and description'; end if;
      if exists(select 1 from public.st_v6_workspace_groups where workspace_id=p_workspace and id<>p_id
        and kind=item.kind and lower(name)=lower(display_name)) then raise exception 'That name is already in use'; end if;
      update public.st_v6_workspace_groups set name=display_name,description=summary where workspace_id=p_workspace and id=p_id
        and (name,description) is distinct from (display_name,summary);
    when 'archive' then
      update public.st_v6_workspace_groups set archived_at=clock_timestamp()
        where workspace_id=p_workspace and id=p_id and archived_at is null;
    when 'restore' then
      update public.st_v6_workspace_groups set archived_at=null where workspace_id=p_workspace and id=p_id and archived_at is not null;
    when 'member_added' then
      if p_user is null or sectalk_private.st_v2_role(p_workspace,p_user) is null or not sectalk_private.st_v2_active(p_user)
        then raise exception 'Choose a current workspace member'; end if;
      insert into public.st_v6_workspace_group_members(workspace_id,group_id,user_id)
        values(p_workspace,p_id,p_user) on conflict do nothing;
    when 'member_removed' then
      delete from public.st_v6_workspace_group_members where workspace_id=p_workspace and group_id=p_id and user_id=p_user;
    else raise exception 'Unsupported workspace group action';
  end case;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,'group.'||p_action,p_id);
  end if;
end $$;

commit;
