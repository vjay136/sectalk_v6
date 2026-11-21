begin;

create or replace function sectalk_private.st_v8_enterprise_billing_roles(p_workspace uuid)
returns text[] language sql stable security definer set search_path='' as $$
  select case when not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    then array[]::text[] else array_remove(array[
    case when sectalk_private.st_v8_billing_sso_allows(p_workspace)
      and exists(select 1 from public.st_v2_workspaces w where w.id=p_workspace and w.owner=auth.uid()
        and sectalk_private.st_v2_role(p_workspace,auth.uid())='owner') then 'owner' end,
    case when sectalk_private.st_v8_billing_sso_allows(p_workspace)
      and sectalk_private.st_v7_billing_admin_allowed(p_workspace,auth.uid()) then 'billing' end,
    case when exists(select 1 from sectalk_private.st_v8_enterprise_billing_operators
      where workspace=p_workspace and actor=auth.uid()) then 'commercial' end
  ],null) end;
$$;

commit;
