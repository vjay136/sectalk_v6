begin;

-- The existing interactive billing grant and the workspace entry policy both apply.
-- Account billing and the service-only provider binding have separate authorization.
create or replace function sectalk_private.st_v8_billing_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v8_entry_sso_allows(p_workspace)
    and not exists(select 1 from sectalk_private.st_v8_workspace_billing_sso p
      where p.workspace=p_workspace
        and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;

commit;
