begin;

-- Owner-facing management uses the pinned entry and integration policies.
-- Independent external keys and signed webhook jobs keep their current scope.
create or replace function public.st_v6_integration_access(p_workspace uuid)
returns text language sql stable security definer set search_path='' as $$
  select case
    when sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner'
      or not coalesce(sectalk_private.st_v2_active(auth.uid()),false) then 'none'
    when not sectalk_private.st_v6_workspace_feature_entitled('integration_api',p_workspace) then 'upgrade'
    when not sectalk_private.st_v8_entry_sso_allows(p_workspace)
      or not sectalk_private.st_v8_integration_admin_sso_allows(p_workspace) then 'sso'
    when sectalk_private.st_v6_holds_access(p_workspace)='verified'
      and public.st_v7_sensitive_action_status('integration_key')='verified' then 'verified'
    else 'mfa'
  end
$$;

commit;
