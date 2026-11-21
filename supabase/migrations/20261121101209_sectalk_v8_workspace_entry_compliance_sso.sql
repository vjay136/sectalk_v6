begin;

create or replace function public.st_v7_compliance_access(p_workspace uuid)
returns text language sql stable security definer set search_path='' as $$
  select case when native.access in ('owner','admin')
    and (not sectalk_private.st_v8_entry_sso_allows(p_workspace)
      or not sectalk_private.st_v8_compliance_sso_allows(p_workspace)) then 'sso'
    else native.access end
  from (select sectalk_private.st_v8_compliance_native_access(p_workspace) access) native;
$$;

-- Service workers recheck the actor and native session recorded on the ticket.
-- Separately approved offboarding exports retain their independent path.
create or replace function sectalk_private.st_v8_compliance_ticket_sso_allows(p_workspace uuid,p_actor uuid,p_session uuid)
returns boolean language sql stable set search_path='' as $$
  select not exists(
    select 1 from (
      select protocol,provider from sectalk_private.st_v8_workspace_compliance_sso where workspace=p_workspace
      union
      select protocol,provider from sectalk_private.st_v8_workspace_entry_sso where workspace=p_workspace
    ) policy where not exists(
      select 1 from sectalk_private.st_v7_workspace_sso_sessions receipt
      join sectalk_private.st_v7_workspace_sso setup on setup.workspace=receipt.workspace
      where receipt.workspace=p_workspace and (receipt.principal,receipt.session)=(p_actor,p_session)
        and (receipt.protocol,receipt.provider)=(policy.protocol,policy.provider)
        and (setup.protocol,setup.provider)=(policy.protocol,policy.provider)
        and sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol)=setup.provider));
$$;

commit;
