begin;

create or replace function public.st_v6_workspace_file_history_policy_status(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select case when sectalk_private.st_v6_holds_access(p_workspace)='none'
    or not sectalk_private.st_v8_policy_admin_sso_allows(p_workspace) then null
    else jsonb_build_object('enabled',coalesce((select p.enabled from sectalk_private.st_v6_workspace_file_history_policy p
        where p.workspace=p_workspace),false),
      'can_manage',sectalk_private.st_v2_role(p_workspace,auth.uid())='owner'
        and sectalk_private.st_v6_holds_access(p_workspace)='verified') end
$$;

create policy st_v8_workspace_entry_sso on public.st_v6_workspace_reaction_policy as restrictive
  for select to authenticated using(sectalk_private.st_v8_entry_sso_allows(workspace_id));

commit;
