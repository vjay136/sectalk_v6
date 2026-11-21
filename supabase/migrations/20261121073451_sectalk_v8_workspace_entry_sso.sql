begin;

create table sectalk_private.st_v8_workspace_entry_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_entry_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_entry_sso from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_entry_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_entry_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_entry_sso_allows(uuid) from public,anon,authenticated,service_role;

create function public.st_v8_workspace_entry_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_entry_sso_policy',5);
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
      insert into sectalk_private.st_v8_workspace_entry_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_entry_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.entry_sso_required'
          else 'workspace.entry_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_entry_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_entry_policy(uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_entry_policy(uuid,boolean) to authenticated;

-- The switcher can retain an existing membership and a display name to make
-- sign-in and owner recovery reachable; full workspace metadata stays in RLS.
grant execute on function sectalk_private.st_v8_entry_sso_allows(uuid) to authenticated;

create function public.st_v8_workspace_entry_shells(p_workspaces uuid[])
returns table(id uuid,name text) language sql stable security definer set search_path='' as $$
  select w.id,w.name from public.st_v2_members m
  join public.st_v2_workspaces w on w.id=m.workspace_id
  where m.user_id=auth.uid() and m.suspended_at is null
    and sectalk_private.st_v2_active(auth.uid())
    and cardinality(p_workspaces) between 1 and 100
    and m.workspace_id=any(p_workspaces)
    and not sectalk_private.st_v8_entry_sso_allows(m.workspace_id);
$$;
revoke all on function public.st_v8_workspace_entry_shells(uuid[]) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_entry_shells(uuid[]) to authenticated;

create policy st_v8_workspace_entry_sso on public.st_v2_workspaces as restrictive
  for select to authenticated using(sectalk_private.st_v8_entry_sso_allows(id));

create policy st_v8_workspace_entry_sso on public.st_v6_workspace_policy as restrictive
  for select to authenticated using(sectalk_private.st_v8_entry_sso_allows(workspace_id));

create or replace function sectalk_private.st_v8_directory_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v8_entry_sso_allows(p_workspace) and not exists(select 1 from sectalk_private.st_v8_workspace_directory_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;

create or replace function sectalk_private.st_v8_planner_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v8_entry_sso_allows(p_workspace) and not exists(select 1 from sectalk_private.st_v8_workspace_planner_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;

commit;
