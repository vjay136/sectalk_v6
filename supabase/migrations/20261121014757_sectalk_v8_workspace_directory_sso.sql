begin;

create table sectalk_private.st_v8_workspace_directory_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_directory_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_directory_sso from public,anon,authenticated,service_role;

-- This policy applies to current-caller directory requests. Role lookups are kept separate
-- for normal workspace selection, automation and owner recovery.
create function sectalk_private.st_v8_directory_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_directory_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_directory_sso_allows(uuid) from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v8_directory_sso_allows(uuid) to authenticated;

create function public.st_v8_workspace_directory_requires_sso(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v2_active(auth.uid())
    and sectalk_private.st_v2_role(p_workspace,auth.uid()) is not null
    and not sectalk_private.st_v8_directory_sso_allows(p_workspace);
$$;

create function public.st_v8_workspace_directory_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_directory_sso_policy',5);
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
      insert into sectalk_private.st_v8_workspace_directory_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_directory_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.directory_sso_required'
          else 'workspace.directory_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_directory_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_directory_policy(uuid,boolean),
  public.st_v8_workspace_directory_requires_sso(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_directory_policy(uuid,boolean),
  public.st_v8_workspace_directory_requires_sso(uuid) to authenticated;

-- The caller can still read their own membership to select the workspace and
-- reach the owner recovery tab. The original membership policy also applies.
create policy st_v8_directory_sso on public.st_v2_members as restrictive for select to authenticated
  using(user_id=(select auth.uid()) or sectalk_private.st_v8_directory_sso_allows(workspace_id));

-- Workspace membership remains one source of profile visibility. An accepted
-- contact or another shared workspace can independently authorize the profile.
create or replace function sectalk_private.st_v2_shared_profile(p uuid,u uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v2_members a join public.st_v2_members b using(workspace_id)
    where a.user_id=u and a.suspended_at is null and b.user_id=p
      and sectalk_private.st_v8_directory_sso_allows(a.workspace_id))
$$;

create or replace function public.st_v7_workspace_people(
  p_workspace uuid,p_search text default '',p_role text default 'all',p_status text default 'all',p_after text default ''
)
returns table(id uuid,handle text,name text,role text,joined_at timestamptz,suspended_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
declare q text:=lower(btrim(coalesce(p_search,'')));
begin
  if not public.st_v7_workspace_people_verified(p_workspace) then
    raise exception 'Workspace administrator verification required' using errcode='42501';
  end if;
  if not sectalk_private.st_v8_directory_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to list members' using errcode='42501';
  end if;
  if char_length(q)>50 or p_role is null or p_role not in ('all','owner','admin','member')
    or p_status is null or p_status not in ('all','active','suspended') or p_after is null
    or p_after !~ '^[a-z0-9_]{0,24}$' then
    raise exception 'Invalid workspace people filter' using errcode='22023';
  end if;
  return query select p.id,p.handle,p.name,m.role,m.joined_at,m.suspended_at
    from public.st_v2_members m join public.st_profiles p on p.id=m.user_id
    where m.workspace_id=p_workspace and p.handle>p_after
      and (q='' or strpos(p.handle,q)=1 or strpos(lower(p.name),q)=1)
      and (p_role='all' or m.role=p_role)
      and (p_status='all' or (p_status='suspended')=(m.suspended_at is not null))
    order by p.handle limit 41;
end $$;

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
  if not sectalk_private.st_v8_directory_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to manage members' using errcode='42501';
  end if;
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

commit;
