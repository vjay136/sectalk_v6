begin;

create table sectalk_private.st_v8_workspace_policy_admin_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_policy_admin_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_policy_admin_sso from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_policy_admin_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_policy_admin_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_policy_admin_sso_allows(uuid) from public,anon,authenticated,service_role;

create function public.st_v8_workspace_policy_admin_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_policy_admin_sso_policy',5);
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
      insert into sectalk_private.st_v8_workspace_policy_admin_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_policy_admin_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.policy_admin_sso_required'
          else 'workspace.policy_admin_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_policy_admin_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_policy_admin_policy(uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_policy_admin_policy(uuid,boolean) to authenticated;

-- Existing effective policy reads, background work, and snapshot logic
-- continue to use their private enforcement and access checks.
create function sectalk_private.st_v8_assert_workspace_policy_sso(p_workspace uuid)
returns void language plpgsql stable set search_path='' as $$
begin
  if not sectalk_private.st_v8_policy_admin_sso_allows(p_workspace) then
    raise exception using errcode='42501',message='Sign in with workspace single sign-on to manage policies.';
  end if;
end
$$;
revoke all on function sectalk_private.st_v8_assert_workspace_policy_sso(uuid) from public,anon,authenticated,service_role;

create or replace function public.st_v7_workspace_policies(p_workspace uuid,p_domain text,p_action text default 'read',
  p_revision integer default null,p_settings jsonb default null,p_target integer default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare assurance text:=sectalk_private.st_v7_file_egress_operator(p_workspace);
  latest integer; before_settings jsonb; after_settings jsonb; history jsonb; prior_setting text;
  query_result jsonb;
begin
  if assurance is distinct from 'verified' then return jsonb_build_object('access',assurance); end if;
  if not sectalk_private.st_v8_policy_admin_sso_allows(p_workspace) then return '{"access":"sso"}'; end if;
  if p_domain is null or p_domain not in ('messaging','files','calls','ai','retention','sharing','dlp','external')
    or p_action is null or p_action not in ('read','preview','apply','rollback') then
    raise exception using errcode='22023',message='Choose a supported workspace policy operation';
  end if;
  if p_action<>'read' then
    perform sectalk_private.limit_action('v7_unified_workspace_policies',40);
    if p_domain='retention' then
      perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
    end if;
    perform 1 from public.st_v2_workspaces where id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
      raise exception using errcode='42501',message='Fresh workspace owner verification required';
    end if;
    if not sectalk_private.st_v8_policy_admin_sso_allows(p_workspace) then return '{"access":"sso"}'; end if;
  end if;
  select coalesce(max(v.revision),0) into latest from sectalk_private.st_v7_policy_snapshots v
    where v.workspace=p_workspace and v.domain=p_domain;
  before_settings:=sectalk_private.st_v7_live_policy(p_workspace,p_domain);
  if p_action<>'read' then
    if p_revision is distinct from latest then raise exception using errcode='PT409',message='Policy changed. Refresh before updating.'; end if;
    prior_setting:=current_setting('sectalk.adm06_expected',true);
    perform set_config('sectalk.adm06_expected',p_workspace::text||'|'||p_domain||'|'||latest::text,true);
    if p_action='rollback' or (p_action='preview' and p_target is not null) then
      select v.settings into p_settings from sectalk_private.st_v7_policy_snapshots v
        where v.workspace=p_workspace and v.domain=p_domain and v.revision=p_target;
      if not found then raise exception using errcode='22023',message='Choose an available revision'; end if;
    end if;
    if p_action='preview' then
      -- Calling the enforcing writer inside a subtransaction exercises the same
      -- native checks. The sentinel rolls back revisions, audit and policy writes.
      begin
        perform sectalk_private.st_v7_apply_live_policy(p_workspace,p_domain,p_settings);
        after_settings:=sectalk_private.st_v7_live_policy(p_workspace,p_domain);
        select case p_domain
          when 'calls' then jsonb_build_object('available_to_requester',sectalk_private.st_v6_feature_allowed('recurring_meetings',auth.uid(),p_workspace))
          when 'external' then jsonb_build_object('allowlist_required',exists(select 1 from public.st_v6_workspace_policy w
            join public.st_v6_compliance_profiles pr on pr.id=w.compliance_profile where w.workspace_id=p_workspace and pr.require_domains))
          when 'retention' then jsonb_build_object('preservation_holds_still_apply',true)
          when 'sharing' then jsonb_build_object('document_rules_still_apply',true)
          else '{}'::jsonb end into query_result;
        raise exception using errcode='PZ006',message='Policy preview complete';
      exception when sqlstate 'PZ006' then null;
      end;
      perform set_config('sectalk.adm06_expected',coalesce(prior_setting,''),true);
      return jsonb_build_object('access','verified','revision',latest,'current',before_settings,'proposed',after_settings,'effect',query_result);
    end if;
    perform sectalk_private.st_v7_apply_live_policy(p_workspace,p_domain,p_settings);
    perform set_config('sectalk.adm06_expected',coalesce(prior_setting,''),true);
    if before_settings is distinct from sectalk_private.st_v7_live_policy(p_workspace,p_domain) then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(p_workspace,auth.uid(),'workspace.policy.'||p_domain||'.'||p_action,p_workspace);
    end if;
  end if;
  select coalesce(max(v.revision),0) into latest from sectalk_private.st_v7_policy_snapshots v
    where v.workspace=p_workspace and v.domain=p_domain;
  select coalesce(jsonb_agg(to_jsonb(h) order by h.revision desc),'[]') into history from (
    select v.revision,v.settings,v.recorded_at from sectalk_private.st_v7_policy_snapshots v
    where v.workspace=p_workspace and v.domain=p_domain order by revision desc limit 25) h;
  return jsonb_build_object('access','verified','revision',latest,'current',sectalk_private.st_v7_live_policy(p_workspace,p_domain),'history',history);
end
$$;

create or replace function public.st_v6_workspace_policy_versions(p_workspace uuid,p_policy text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare entries jsonb;
declare last_version integer;
declare current_settings jsonb;
begin
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Verified workspace policy access is required' using errcode='42501';
  end if;
  perform sectalk_private.st_v8_assert_workspace_policy_sso(p_workspace);
  if p_policy is null or p_policy not in ('retention','notifications') then
    raise exception 'Choose a valid workspace policy' using errcode='22023';
  end if;
  select coalesce(max(v.version),0) into last_version from sectalk_private.st_v6_workspace_policy_versions v
    where v.workspace_id=p_workspace and v.policy=p_policy;
  select jsonb_agg(to_jsonb(v) order by v.version desc) into entries from (
    select h.version,h.settings,h.recorded_at from sectalk_private.st_v6_workspace_policy_versions h
      where h.workspace_id=p_workspace and h.policy=p_policy order by h.version desc limit 25
  ) v;
  current_settings:=sectalk_private.st_v6_workspace_policy_current(p_workspace,p_policy);
  return jsonb_build_object('version',last_version,'current',current_settings,
    'entries',coalesce(entries,jsonb_build_array(jsonb_build_object('version',0,'settings',current_settings))));
end $$;

-- Native single-domain settings use the same policy write boundary.
create or replace function public.st_v6_set_workspace_reactions(p_workspace uuid,p_set text,p_limit integer)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_workspace_reactions',12);
  perform id from public.st_v2_workspaces where id=p_workspace for no key update;
  if not found or not sectalk_private.st_v2_active(actor)
    or not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    then raise exception 'Reaction settings unavailable'; end if;
  perform sectalk_private.st_v8_assert_workspace_policy_sso(p_workspace);
  if p_set is null or p_set not in ('all','native','essential','off') or p_limit is null or p_limit not between 1 and 8
    then raise exception 'Choose a supported emoji set and reaction limit'; end if;
  insert into public.st_v6_workspace_reaction_policy as current_policy(workspace_id,emoji_set,per_person)
    values(p_workspace,p_set,p_limit) on conflict(workspace_id) do update
    set emoji_set=excluded.emoji_set,per_person=excluded.per_person
    where (current_policy.emoji_set,current_policy.per_person) is distinct from (excluded.emoji_set,excluded.per_person);
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event)
      values(p_workspace,actor,'workspace.reaction_policy');
  end if;
end $$;

create or replace function public.st_v6_set_workspace_file_history_policy(p_workspace uuid,p_enabled boolean)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  if p_enabled is null or sectalk_private.st_v6_holds_access(p_workspace)<>'verified'
    or sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner' then
    raise exception 'Verified workspace ownership is required.' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v6_workspace_file_history_policy',12);
  perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
  if not found or sectalk_private.st_v6_holds_access(p_workspace)<>'verified'
    or sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner' then
    raise exception 'Verified workspace ownership is required.' using errcode='42501';
  end if;
  perform sectalk_private.st_v8_assert_workspace_policy_sso(p_workspace);
  insert into sectalk_private.st_v6_workspace_file_history_policy(workspace,enabled) values(p_workspace,p_enabled)
    on conflict(workspace) do update set enabled=excluded.enabled
      where st_v6_workspace_file_history_policy.enabled is distinct from excluded.enabled;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,auth.uid(),case when p_enabled then 'workspace.file_history_enabled'
        else 'workspace.file_history_disabled' end,p_workspace);
  end if;
  return p_enabled;
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

create or replace function public.st_v6_room_retention_policy(p_workspace uuid,p_days integer default null)
returns integer language plpgsql security definer set search_path='' as $$
begin
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Verify workspace governance access' using errcode='42501';
  end if;
  if not sectalk_private.st_v8_organization_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to manage organization settings' using errcode='42501';
  end if;
  perform sectalk_private.st_v8_assert_workspace_policy_sso(p_workspace);
  if p_days is null then return sectalk_private.st_v6_room_retention_days(p_workspace); end if;
  if p_days not between 7 and 3650 then raise exception 'Use a retention period from 7 to 3650 days'; end if;
  perform sectalk_private.limit_action('v6_room_retention',10);
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Workspace governance is unavailable' using errcode='42501';
  end if;
  if not sectalk_private.st_v8_organization_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to manage organization settings' using errcode='42501';
  end if;
  perform sectalk_private.st_v8_assert_workspace_policy_sso(p_workspace);
  insert into sectalk_private.st_v6_room_retention_policy(workspace_id,retention_days) values(p_workspace,p_days)
    on conflict(workspace_id) do update set retention_days=excluded.retention_days
    where st_v6_room_retention_policy.retention_days is distinct from excluded.retention_days;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event)
      values(p_workspace,auth.uid(),'workspace.room_retention_changed');
  end if;
  return p_days;
end $$;

create or replace function public.st_v7_save_file_egress_policy(p_workspace uuid,p_revision integer,p_policy jsonb)
returns integer language plpgsql security definer set search_path='' as $$
declare mode text:=p_policy->>'mode';
  next_revision integer;
begin
  if sectalk_private.st_v7_file_egress_operator(p_workspace)<>'verified' then
    raise exception 'Fresh workspace owner verification required' using errcode='42501';
  end if;
  if p_revision is null or p_revision<0 or jsonb_typeof(p_policy) is distinct from 'object'
    or octet_length(p_policy::text)>1024 or mode is null or mode not in ('inherit','require','block') then
    raise exception 'Choose a supported file egress policy' using errcode='22023';
  end if;
  if exists(select 1 from jsonb_each(p_policy) j
    where (case j.key
      when 'mode' then jsonb_typeof(j.value)='string'
      when 'device' then jsonb_typeof(j.value)='string' and j.value#>>'{}' in ('trusted','managed')
      when 'risk_max' then jsonb_typeof(j.value)='number' and j.value#>>'{}' ~ '^([0-9]|[1-9][0-9]|100)$'
      when 'network' then jsonb_typeof(j.value)='string' and j.value#>>'{}' like '%/%'
      when 'utc_start' then jsonb_typeof(j.value)='number' and j.value#>>'{}' ~ '^([0-9]|1[0-9]|2[0-3])$'
      when 'utc_end' then jsonb_typeof(j.value)='number' and j.value#>>'{}' ~ '^([0-9]|1[0-9]|2[0-3])$'
      when 'classification_max' then jsonb_typeof(j.value)='string' and j.value#>>'{}' in ('public','internal','confidential','restricted')
      when 'tenant_type' then jsonb_typeof(j.value)='string' and exists(
        select 1 from public.st_v6_workspace_templates t where t.id=j.value#>>'{}')
      else false end) is not true)
    or (mode='require' and p_policy-'mode'='{}'::jsonb)
    or (mode<>'require' and p_policy-'mode'<>'{}'::jsonb)
    or (p_policy?'utc_start')<>(p_policy?'utc_end')
    or (p_policy->>'utc_start')=(p_policy->>'utc_end') then
    raise exception 'Choose recognized attributes and valid policy values' using errcode='22023';
  end if;
  if p_policy?'network' then
    p_policy:=jsonb_set(p_policy,'{network}',to_jsonb((p_policy->>'network')::cidr::text));
  end if;
  perform sectalk_private.limit_action('v7_file_egress_policy',12);
  perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
  if not found or sectalk_private.st_v7_file_egress_operator(p_workspace)<>'verified' then
    raise exception 'Fresh workspace owner verification required' using errcode='42501';
  end if;
  perform sectalk_private.st_v8_assert_workspace_policy_sso(p_workspace);
  if p_revision=0 then
    insert into sectalk_private.st_v7_file_egress_policies(workspace,revision,policy)
      values(p_workspace,1,p_policy) on conflict(workspace) do nothing returning revision into next_revision;
  else
    update sectalk_private.st_v7_file_egress_policies set policy=p_policy,revision=p_revision+1
      where workspace=p_workspace and revision=p_revision returning revision into next_revision;
  end if;
  if next_revision is null then raise exception 'Policy changed. Reload to review its current settings.' using errcode='PT409'; end if;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,auth.uid(),'workspace.file_egress_'||mode,p_workspace);
  return next_revision;
end $$;

create or replace function public.st_v7_set_workspace_dlp(p_workspace uuid,p_revision integer,p_rules jsonb)
returns integer language plpgsql security definer set search_path='' as $$
declare prior integer; installed integer;
begin
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' or not coalesce(sectalk_private.st_v7_admin_fresh(),false) then
    raise exception 'Fresh authenticator verification required' using errcode='42501';
  end if;
  if jsonb_typeof(p_rules) is distinct from 'object' or p_revision is null or p_revision<0 then
    raise exception 'Invalid data loss policy' using errcode='22023';
  end if;
  if (select count(*) from jsonb_each_text(p_rules) e where e.key in ('pii','phi','payment_card','credential')
    and e.value in ('allow','warn','block','redact'))<>4 or (select count(*) from jsonb_object_keys(p_rules))<>4 then
    raise exception 'Choose an action for each sensitive pattern' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v7_workspace_dlp',15);
  perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
  if not found or sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Workspace data loss controls are unavailable' using errcode='42501';
  end if;
  perform sectalk_private.st_v8_assert_workspace_policy_sso(p_workspace);
  select revision into prior from sectalk_private.st_v7_workspace_dlp where workspace_id=p_workspace;
  if coalesce(prior,0)<>p_revision then raise exception 'Workspace policy changed. Reload before saving' using errcode='PT409'; end if;
  insert into sectalk_private.st_v7_workspace_dlp as d(workspace_id,revision,rules)
    values(p_workspace,1,p_rules) on conflict(workspace_id) do update
    set revision=d.revision+1,rules=excluded.rules,updated_at=clock_timestamp()
    returning revision into installed;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,auth.uid(),'workspace.data_loss_policy_changed',p_workspace);
  return installed;
end $$;

create or replace function sectalk_private.st_v6_workspace_link_policy_set(p_workspace uuid,p_domains text[])
returns void language plpgsql security definer set search_path='' as $$
declare normalized text[];
begin
  if not sectalk_private.st_v6_manage_link_invites(p_workspace) then
    raise exception 'Invitation settings unavailable' using errcode='42501';
  end if;
  if p_domains is null or cardinality(p_domains)>10
    or exists(select 1 from unnest(p_domains) d where d is null or length(d)>253
      or lower(btrim(d)) !~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:[.][a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$')
  then raise exception 'Enter up to ten valid email domains'; end if;
  perform sectalk_private.limit_action('v6_invite_link_policy',15);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if not sectalk_private.st_v6_manage_link_invites(p_workspace) then
    raise exception 'Invitation settings unavailable' using errcode='42501';
  end if;
  perform sectalk_private.st_v8_assert_workspace_policy_sso(p_workspace);
  normalized:=array(select distinct lower(btrim(d)) from unnest(p_domains) d order by lower(btrim(d)));
  insert into sectalk_private.st_v6_workspace_link_policy(workspace_id,domains) values(p_workspace,normalized)
  on conflict(workspace_id) do update set domains=excluded.domains
    where st_v6_workspace_link_policy.domains is distinct from excluded.domains;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event)
    values(p_workspace,auth.uid(),'workspace.link_policy_changed');
  end if;
end
$$;

create or replace function sectalk_private.st_v6_set_workspace_notification_policy(
  p_workspace uuid,p_categories text[],p_quiet_minutes integer
)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); categories text[];
begin
  if not sectalk_private.st_v2_active(actor)
    or not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false) then
    raise exception 'Workspace notification policy unavailable';
  end if;
  if p_categories is null or cardinality(p_categories)>4
    or (cardinality(p_categories)>0 and array_ndims(p_categories) is distinct from 1)
    or not coalesce(p_categories <@ array['mention','thread','task','admin'],false)
    or (p_quiet_minutes is not null and p_quiet_minutes not between 0 and 1440) then
    raise exception 'Choose valid workspace notification categories and a quiet limit of 0 to 1440 minutes';
  end if;
  perform sectalk_private.limit_action('v6_workspace_notification_policy',20);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if not found or not sectalk_private.st_v2_active(actor)
    or not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false) then
    raise exception 'Workspace notification policy unavailable';
  end if;
  perform sectalk_private.st_v8_assert_workspace_policy_sso(p_workspace);
  categories:=array(select distinct category from unnest(p_categories) category order by category);
  insert into sectalk_private.st_v6_workspace_notification_policy as policy
    (workspace_id,mandatory_categories,max_quiet_minutes)
    values(p_workspace,categories,p_quiet_minutes)
  on conflict(workspace_id) do update
    set mandatory_categories=excluded.mandatory_categories,max_quiet_minutes=excluded.max_quiet_minutes
    where (policy.mandatory_categories,policy.max_quiet_minutes) is distinct from
      (excluded.mandatory_categories,excluded.max_quiet_minutes);
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,'workspace.notification_policy_changed',p_workspace);
  end if;
end
$$;

commit;
