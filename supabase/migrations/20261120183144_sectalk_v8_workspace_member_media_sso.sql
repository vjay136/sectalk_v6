begin;

create table sectalk_private.st_v8_workspace_member_media_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_member_media_sso enable row level security;
revoke all on sectalk_private.st_v8_workspace_member_media_sso from public,anon,authenticated,service_role;

-- This gate is for the current authenticated actor. It never infers the caller's
-- session from another participant or from the actor supplied to a worker.
create function sectalk_private.st_v8_workspace_session_receipt(p_workspace uuid,p_protocol text,p_provider text)
returns boolean language sql stable set search_path='' as $$
  select auth.uid() is not null and public.st_v7_current_session_valid()
    and exists(select 1 from sectalk_private.st_v7_workspace_sso c where c.workspace=p_workspace
      and c.protocol=p_protocol and c.provider=p_provider)
    and public.st_v7_workspace_uses_sso(p_workspace);
$$;
revoke all on function sectalk_private.st_v8_workspace_session_receipt(uuid,text,text) from public,anon,authenticated,service_role;

create function public.st_v8_workspace_member_media_allowed(p_meeting uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce((select case when p.workspace is null then true
      else sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) end
    from public.st_v3_meetings m left join sectalk_private.st_v8_workspace_member_media_sso p on p.workspace=m.workspace_id
    where m.id=p_meeting and auth.uid() is not null
      and sectalk_private.st_v2_active(auth.uid())
      and sectalk_private.st_v3_meeting_visible(m.id,auth.uid())),false);
$$;
revoke all on function public.st_v8_workspace_member_media_allowed(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_member_media_allowed(uuid) to authenticated;

create function public.st_v8_workspace_member_media_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_member_media_sso_policy',5);
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
      raise insufficient_privilege;
    end if;
    if p_require then
      select * into setup from sectalk_private.st_v7_workspace_sso c where c.workspace=p_workspace;
      if not found or sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol)
        is distinct from setup.provider or not exists(
          select 1 from sectalk_private.st_v7_workspace_sso_sessions r join auth.sessions s on s.id=r.session and s.user_id=r.principal
          where r.workspace=p_workspace and r.protocol=setup.protocol and r.provider=setup.provider
            and sectalk_private.st_v2_active(r.principal) and sectalk_private.st_v2_role(p_workspace,r.principal) is not null
            and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
        ) then return '{"access":"verified","error":"verified_provider_session_required"}'; end if;
      insert into sectalk_private.st_v8_workspace_member_media_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_member_media_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.member_media_sso_required'
          else 'workspace.member_media_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_member_media_sso p where p.workspace=p_workspace));
end $$;
revoke all on function public.st_v8_workspace_member_media_policy(uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_member_media_policy(uuid,boolean) to authenticated;

commit;
