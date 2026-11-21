begin;

-- Scope interactive policy administration to both the workspace entry policy and the optional management policy.

create or replace function sectalk_private.st_v8_policy_admin_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v8_entry_sso_allows(p_workspace)
    and not exists(select 1 from sectalk_private.st_v8_workspace_policy_admin_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;

create or replace function public.st_v6_tenant_feature_state(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare workspace_owner uuid;
declare access text:=sectalk_private.st_v6_holds_access(p_workspace);
begin
  if access='none' or not sectalk_private.st_v8_entry_sso_allows(p_workspace) then return null; end if;
  select w.owner into workspace_owner from public.st_v2_workspaces w where w.id=p_workspace;
  if not found then return null; end if;
  return jsonb_build_object('verified',access='verified','features',(
    select jsonb_agg(jsonb_build_object('feature',f.name,'paused',f.paused,'entitled',f.entitled,
      'release_allowed',f.release_allowed,'emergency_stop',f.emergency_stop,
      'effective',f.entitled and f.release_allowed and not f.paused,
      'can_change',access='verified' and (f.name<>'integration_api' or workspace_owner=actor)) order by f.idx)
    from (
      select i.name,i.idx,
        sectalk_private.st_v6_workspace_feature_entitled(i.name,p_workspace) as entitled,
        sectalk_private.st_v6_release_rule_allowed(i.name,
          case when i.name='integration_api' then workspace_owner else actor end,p_workspace) as release_allowed,
        exists(select 1 from sectalk_private.st_v6_tenant_feature_pauses o
          where o.workspace=p_workspace and o.feature=i.name) as paused,
        exists(select 1 from sectalk_private.st_v6_flag_rules r
          where r.feature=i.name and r.scope='global' and r.killed) as emergency_stop
      from (values ('task_creation',1),('recurring_meetings',2),('integration_api',3)) i(name,idx)
    ) f
  ));
end
$$;

create or replace function public.st_v6_set_tenant_feature_pause(p_workspace uuid,p_feature text,p_paused boolean)
returns void language plpgsql security definer set search_path='' as $$
begin
  if p_feature is null or p_feature not in ('task_creation','recurring_meetings','integration_api') or p_paused is null
    then raise exception 'Choose a valid workspace feature setting.' using errcode='22023'; end if;
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' or
    (p_feature='integration_api' and sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner')
    then raise exception 'Verified workspace permission is required.' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v6_tenant_feature_pause',20);
  perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
  if not found or sectalk_private.st_v6_holds_access(p_workspace)<>'verified' or
    (p_feature='integration_api' and sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner')
    then raise exception 'Verified workspace permission is required.' using errcode='42501'; end if;
  if not sectalk_private.st_v8_entry_sso_allows(p_workspace) then
    raise exception using errcode='42501',message='Sign in with workspace single sign-on to manage policies.';
  end if;
  if p_feature='recurring_meetings' then
    perform sectalk_private.st_v8_assert_workspace_policy_sso(p_workspace);
  end if;
  if p_paused then
    insert into sectalk_private.st_v6_tenant_feature_pauses(workspace,feature) values(p_workspace,p_feature)
      on conflict do nothing;
  else
    delete from sectalk_private.st_v6_tenant_feature_pauses where workspace=p_workspace and feature=p_feature;
  end if;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,auth.uid(),'workspace.feature.'||p_feature||case when p_paused then '.paused' else '.restored' end,p_workspace);
  end if;
end
$$;

create or replace function public.st_v7_workspace_ai_settings(p_workspace uuid,p_enabled boolean default null,
  p_processing_consent boolean default null,p_advisory_threshold integer default null,p_retention_days integer default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); member_role text; prior_cutoff timestamptz; state record;
begin
  member_role:=sectalk_private.st_v2_role(p_workspace,actor);
  if coalesce(member_role,'') not in ('owner','admin') or not coalesce(sectalk_private.st_v2_active(actor),false) then
    raise exception using errcode='42501',message='Workspace AI settings are unavailable';
  end if;
  if not sectalk_private.st_v8_entry_sso_allows(p_workspace) then
    raise exception using errcode='42501',message='Sign in with workspace single sign-on to manage policies.';
  end if;
  if num_nonnulls(p_enabled,p_processing_consent,p_advisory_threshold,p_retention_days)<>0 then
    if member_role<>'owner' then raise exception using errcode='42501',message='Only the workspace owner can change AI settings'; end if;
    if num_nonnulls(p_enabled,p_processing_consent,p_advisory_threshold,p_retention_days)<>4
      or p_advisory_threshold not between 1 and 3 or p_retention_days not between 1 and 90 then
      raise exception using errcode='22023',message='Invalid workspace AI settings';
    end if;
    perform sectalk_private.limit_action('workspace_ai_settings',12);
    perform 1 from public.st_v2_workspaces where id=p_workspace for update;
    if not found or sectalk_private.st_v2_role(p_workspace,actor) is distinct from 'owner' then
      raise exception using errcode='42501',message='Workspace AI settings are unavailable';
    end if;
    perform sectalk_private.st_v8_assert_workspace_policy_sso(p_workspace);
    select s.cutoff into prior_cutoff from sectalk_private.st_v7_workspace_ai_state(p_workspace) s;
    insert into sectalk_private.st_v7_workspace_ai_policy as current_policy
      (workspace,enabled,processing_consent,advisory_threshold,retention_days,retention_floor)
      values(p_workspace,p_enabled,p_processing_consent,p_advisory_threshold,p_retention_days,
        greatest(prior_cutoff,now()-make_interval(days=>p_retention_days)))
      on conflict(workspace) do update set enabled=excluded.enabled,processing_consent=excluded.processing_consent,
        advisory_threshold=excluded.advisory_threshold,retention_days=excluded.retention_days,
        retention_floor=excluded.retention_floor,epoch=gen_random_uuid()
      where (current_policy.enabled,current_policy.processing_consent,current_policy.advisory_threshold,current_policy.retention_days)
        is distinct from (excluded.enabled,excluded.processing_consent,excluded.advisory_threshold,excluded.retention_days);
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(p_workspace,actor,'workspace.ai_policy',p_workspace);
    end if;
  end if;
  select * into state from sectalk_private.st_v7_workspace_ai_state(p_workspace);
  return jsonb_build_object('owner',member_role='owner','enabled',state.enabled,'consent',state.consent,
    'threshold',state.threshold,'retentionDays',state.days);
end
$$;

commit;
