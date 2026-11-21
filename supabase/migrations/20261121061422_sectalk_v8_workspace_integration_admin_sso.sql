begin;

create table sectalk_private.st_v8_workspace_integration_admin_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_integration_admin_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_integration_admin_sso from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_integration_admin_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_integration_admin_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_integration_admin_sso_allows(uuid) from public,anon,authenticated,service_role;

create function public.st_v8_workspace_integration_admin_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_integration_admin_sso_policy',5);
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
      insert into sectalk_private.st_v8_workspace_integration_admin_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_integration_admin_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.integration_admin_sso_required'
          else 'workspace.integration_admin_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_integration_admin_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_integration_admin_policy(uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_integration_admin_policy(uuid,boolean) to authenticated;

-- This is the native owner-facing management gate. Provider keys and signed
-- delivery jobs use their own capability checks without the owner's session.
create or replace function public.st_v6_integration_access(p_workspace uuid)
returns text language sql stable security definer set search_path='' as $$
  select case
    when sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner'
      or not coalesce(sectalk_private.st_v2_active(auth.uid()),false) then 'none'
    when not sectalk_private.st_v6_workspace_feature_entitled('integration_api',p_workspace) then 'upgrade'
    when not sectalk_private.st_v8_integration_admin_sso_allows(p_workspace) then 'sso'
    when sectalk_private.st_v6_holds_access(p_workspace)='verified'
      and public.st_v7_sensitive_action_status('integration_key')='verified' then 'verified'
    else 'mfa'
  end
$$;

create or replace function public.st_v6_revoke_integration_key(p_workspace uuid,p_key uuid)
returns void language plpgsql security definer set search_path='' as $$
begin
  if public.st_v6_integration_access(p_workspace)<>'verified' then
    raise exception using errcode='42501',message='Fresh integration administrator verification required';
  end if;
  perform 1 from public.st_v2_workspaces where id=p_workspace for key share;
  if public.st_v6_integration_access(p_workspace)<>'verified' then
    raise exception using errcode='42501',message='Integration access changed';
  end if;
  update sectalk_private.st_v6_integration_keys
    set revoked_at=clock_timestamp() where id=p_key and workspace_id=p_workspace and revoked_at is null;
  if found then insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,auth.uid(),'integration.key_revoked',p_key);
  end if;
end $$;

create or replace function public.st_v6_revoke_webhook(p_workspace uuid,p_endpoint uuid)
returns void language plpgsql security definer set search_path='' as $$
begin
  if public.st_v6_integration_access(p_workspace)<>'verified' then
    raise exception using errcode='42501',message='Fresh integration administrator verification required';
  end if;
  perform 1 from public.st_v2_workspaces where id=p_workspace for key share;
  if public.st_v6_integration_access(p_workspace)<>'verified' then
    raise exception using errcode='42501',message='Integration access changed';
  end if;
  update sectalk_private.st_v6_webhooks set revoked_at=clock_timestamp()
    where id=p_endpoint and workspace_id=p_workspace and revoked_at is null;
  if not found then return; end if;
  update sectalk_private.st_v6_webhook_jobs set state='cancelled',lease=null,lease_expires=null
    where endpoint_id=p_endpoint and state='queued';
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,auth.uid(),'integration.webhook_revoked',p_endpoint);
end $$;

commit;
