begin;

create or replace function public.st_v7_workspace_trial_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare trial sectalk_private.st_v7_workspace_trials;
begin
  if sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner'
    or sectalk_private.st_v2_active(auth.uid()) is not true
    or not sectalk_private.st_v8_billing_sso_allows(p_workspace) then
    raise exception 'Workspace trial unavailable' using errcode='42501';
  end if;
  select * into trial from sectalk_private.st_v7_workspace_trials where workspace_id=p_workspace;
  return jsonb_build_object('state',case
    when trial.expires_at>now() then 'active'
    when trial.started_at is not null then 'used'
    when sectalk_private.st_v2_effective_plan(auth.uid())<>'free' then 'subscribed'
    when trial.reserved_until>now() then 'pending'
    else 'eligible' end,
    'plan',trial.plan,'expires_at',trial.expires_at,'reserved_until',trial.reserved_until);
end $$;

create function public.st_v8_workspace_trial_session(p_workspace uuid)
returns uuid language sql stable security definer set search_path='' as $$
  select case when sectalk_private.st_v2_role(p_workspace,auth.uid())='owner'
    and sectalk_private.st_v2_active(auth.uid())
    and sectalk_private.st_v8_billing_sso_allows(p_workspace)
    and public.st_v7_sensitive_action_status('billing')='verified'
    then (auth.jwt()->>'session_id')::uuid end;
$$;

create function public.st_v8_start_workspace_trial_for_session(
  p_workspace uuid,p_owner uuid,p_session uuid,p_plan text,p_card_required boolean
) returns jsonb language plpgsql security definer set search_path='' as $$
begin
  perform 1 from public.st_v2_workspaces w where (w.id,w.owner)=(p_workspace,p_owner) for update;
  if not found or sectalk_private.st_v2_active(p_owner) is not true then raise insufficient_privilege; end if;
  perform 1 from auth.sessions s where (s.id,s.user_id)=(p_session,p_owner)
    and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
    for share;
  if not found then raise insufficient_privilege; end if;

  -- The server supplies the session returned by the caller's authenticated RPC.
  -- Recheck both workspace policy pins under the same lock as the trial write.
  if exists(
    select 1 from (
      select p.protocol,p.provider from sectalk_private.st_v8_workspace_entry_sso p where p.workspace=p_workspace
      union all
      select p.protocol,p.provider from sectalk_private.st_v8_workspace_billing_sso p where p.workspace=p_workspace
    ) policy
    where not exists(
      select 1 from sectalk_private.st_v7_workspace_sso c
      join sectalk_private.st_v7_workspace_sso_sessions r using(workspace)
      where c.workspace=p_workspace and (r.session,r.principal)=(p_session,p_owner)
        and (c.protocol,c.provider)=(policy.protocol,policy.provider)
        and (r.protocol,r.provider)=(policy.protocol,policy.provider)
        and sectalk_private.st_v7_workspace_sso_provider(c.workspace,c.domain,c.protocol)=c.provider)
  ) then raise insufficient_privilege; end if;

  return public.st_v7_start_workspace_trial(p_workspace,p_owner,p_plan,p_card_required);
end $$;

revoke all on function public.st_v8_workspace_trial_session(uuid),
  public.st_v8_start_workspace_trial_for_session(uuid,uuid,uuid,text,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_trial_session(uuid) to authenticated;
grant execute on function public.st_v8_start_workspace_trial_for_session(uuid,uuid,uuid,text,boolean) to service_role;
revoke execute on function public.st_v7_start_workspace_trial(uuid,uuid,text,boolean) from service_role;

notify pgrst,'reload schema';
commit;
