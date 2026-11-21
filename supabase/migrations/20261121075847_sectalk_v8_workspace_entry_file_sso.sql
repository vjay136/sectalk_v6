begin;

-- The app gate adds workspace entry requirements to the existing scoped file
-- policy. Independently approved residency and offboarding keep their RPCs.
create function public.st_v8_app_file_context(p_scope_type text,p_scope uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare context jsonb:=public.st_v8_scoped_file_context(p_scope_type,p_scope);
begin
  if context->>'access'='allowed' and not sectalk_private.st_v8_entry_sso_allows(
    sectalk_private.st_v8_scoped_file_workspace(p_scope_type,p_scope)
  ) then return '{"access":"sso_required"}'; end if;
  return context;
end $$;

create function public.st_v8_app_file_command(p_scope_type text,p_scope uuid,p_actor uuid,p_session uuid,
  p_action text,p_id uuid,p_name text,p_bytes integer,p_hash text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare workspace_key uuid:=sectalk_private.st_v8_scoped_file_workspace(p_scope_type,p_scope);
begin
  if exists(select 1 from sectalk_private.st_v8_workspace_entry_sso policy
    where policy.workspace=workspace_key and not exists(
      select 1 from sectalk_private.st_v7_workspace_sso_sessions receipt
      join sectalk_private.st_v7_workspace_sso setup on setup.workspace=receipt.workspace
      where receipt.workspace=policy.workspace and (receipt.principal,receipt.session)=(p_actor,p_session)
        and (receipt.protocol,receipt.provider)=(policy.protocol,policy.provider)
        and (setup.protocol,setup.provider)=(policy.protocol,policy.provider)
        and sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol)=setup.provider
    )) then return null; end if;
  return public.st_v8_scoped_file_command(p_scope_type,p_scope,p_actor,p_session,p_action,p_id,p_name,p_bytes,p_hash);
end $$;

revoke all on function public.st_v8_app_file_context(text,uuid),
  public.st_v8_app_file_command(text,uuid,uuid,uuid,text,uuid,text,integer,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_app_file_context(text,uuid) to authenticated;
grant execute on function public.st_v8_app_file_command(text,uuid,uuid,uuid,text,uuid,text,integer,text) to service_role;

create or replace function sectalk_private.st_v6_can_read_workspace_file_history(p_workspace uuid,p_uploader uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce(sectalk_private.st_v2_active(auth.uid()),false) and
    sectalk_private.st_v2_role(p_workspace,auth.uid()) is not null and
    sectalk_private.st_v8_entry_sso_allows(p_workspace) and sectalk_private.st_v8_file_sso_allows(p_workspace) and
    (p_uploader=auth.uid() or (sectalk_private.st_v6_holds_access(p_workspace)='verified' and exists(
      select 1 from sectalk_private.st_v6_workspace_file_history_policy p where p.workspace=p_workspace and p.enabled
    )))
$$;

commit;
