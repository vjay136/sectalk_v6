begin;

create table sectalk_private.st_v8_workspace_invitation_admin_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_invitation_admin_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_invitation_admin_sso from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_invitation_admin_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_invitation_admin_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_invitation_admin_sso_allows(uuid) from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v8_invitation_admin_sso_allows(uuid) to authenticated;

create function public.st_v8_workspace_invitation_admin_requires_sso(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v2_active(auth.uid())
    and coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    and not sectalk_private.st_v8_invitation_admin_sso_allows(p_workspace);
$$;

create function public.st_v8_workspace_invitation_admin_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_invitation_admin_sso_policy',5);
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
      insert into sectalk_private.st_v8_workspace_invitation_admin_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_invitation_admin_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.invitation_admin_sso_required'
          else 'workspace.invitation_admin_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_invitation_admin_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_invitation_admin_requires_sso(uuid),
  public.st_v8_workspace_invitation_admin_policy(uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_invitation_admin_requires_sso(uuid),
  public.st_v8_workspace_invitation_admin_policy(uuid,boolean) to authenticated;

-- Incoming invitations retain established verified-account and capability rules.
-- The additional policy only limits management visibility for workspace staff.
create policy st_v8_invitation_admin_sso on public.st_v2_invites as restrictive for select to authenticated
  using(invitee=(select auth.uid()) or sectalk_private.st_v8_invitation_admin_sso_allows(workspace_id));

-- This helper is used by domain policy reads/writes and link issuance. Both
-- writes hold the workspace lock and check this predicate again before writing.
create or replace function sectalk_private.st_v6_manage_link_invites(p_workspace uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    and sectalk_private.st_v2_active(auth.uid())
    and sectalk_private.st_v8_invitation_admin_sso_allows(p_workspace)
$$;

create or replace function sectalk_private.st_v6_invite_workspace_handles(p_workspace uuid,p_handles text[])
returns table(handle text, sent boolean)
language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  title text;
  peer uuid;
  normalized_handle text;
begin
  select name into title from public.st_v2_workspaces where id=p_workspace for update;
  if title is null or not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor)
  then raise exception 'Workspace action unavailable'; end if;

  if not sectalk_private.st_v8_invitation_admin_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to send invitations' using errcode='42501';
  end if;
  if coalesce(cardinality(p_handles),0) not between 1 and 100 or array_ndims(p_handles)<>1
    or exists(select 1 from unnest(p_handles) h where h is null or char_length(h)>64)
  then raise exception 'Provide between 1 and 100 SecTalk handles'; end if;

  for normalized_handle in
    select lower(btrim(h)) from unnest(p_handles) with ordinality as input(h,position)
    group by lower(btrim(h)) order by min(position)
  loop
    handle:=normalized_handle;
    sent:=false;
    select p.id into peer from public.st_profiles p where p.handle=normalized_handle;
    if peer is not null and peer<>actor and sectalk_private.open_pair(actor,peer)
      and not exists(select 1 from public.st_v2_members where workspace_id=p_workspace and user_id=peer)
    then
      insert into public.st_v2_invites(workspace_id,invitee,created_by,workspace_name)
        values(p_workspace,peer,actor,title) on conflict(workspace_id,invitee) do nothing;
      sent:=found;
      if sent then
        insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
          values(p_workspace,actor,'member.invited',peer);
      end if;
    end if;
    return next;
  end loop;
end $$;

commit;
