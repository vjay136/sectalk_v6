begin;

create or replace function sectalk_private.st_v6_impersonation_watch_list(p_workspace uuid)
returns table(member_id uuid,tier text)
language plpgsql stable security definer set search_path='' as $$
begin
  if not coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(auth.uid())
    or not sectalk_private.st_v8_entry_sso_allows(p_workspace)
  then raise exception 'Watch list unavailable' using errcode='42501'; end if;
  return query
    select w.member_id,w.tier from sectalk_private.st_v6_impersonation_watch w
    where w.workspace_id=p_workspace order by w.updated_at,w.member_id;
end
$$;

create or replace function sectalk_private.st_v6_set_impersonation_watch(p_workspace uuid,p_member uuid,p_tier text)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor)
    or not sectalk_private.st_v8_entry_sso_allows(p_workspace)
  then raise exception 'Watch list unavailable' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v6_impersonation_watch',20);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor)
    or not sectalk_private.st_v8_entry_sso_allows(p_workspace)
  then raise exception 'Watch list unavailable' using errcode='42501'; end if;
  if p_tier is null then
    delete from sectalk_private.st_v6_impersonation_watch where workspace_id=p_workspace and member_id=p_member;
  else
    if p_tier not in ('executive','vip') or sectalk_private.st_v2_role(p_workspace,p_member) is null
      or not sectalk_private.st_v2_active(p_member)
    then raise exception 'Choose an active workspace member and watch category'; end if;
    if not exists(select 1 from sectalk_private.st_v6_impersonation_watch where workspace_id=p_workspace and member_id=p_member)
      and (select count(*) from sectalk_private.st_v6_impersonation_watch where workspace_id=p_workspace)>=100
    then raise exception 'This workspace watch list is full'; end if;
    insert into sectalk_private.st_v6_impersonation_watch(workspace_id,member_id,tier)
      values(p_workspace,p_member,p_tier) on conflict(workspace_id,member_id) do update
      set tier=excluded.tier,updated_at=clock_timestamp()
      where st_v6_impersonation_watch.tier is distinct from excluded.tier;
  end if;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,case when p_tier is null then 'impersonation.watch_removed' else 'impersonation.watch_saved' end,p_member);
  end if;
end
$$;

create or replace function public.st_v7_workspace_rule_registry(p_workspace uuid,p_action text default 'view',
  p_version text default null,p_generation uuid default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); member_role text; state sectalk_private.st_v7_profile_rule_workspace; target text;
begin
  member_role:=sectalk_private.st_v2_role(p_workspace,actor);
  if coalesce(member_role,'') not in ('owner','admin') or not coalesce(sectalk_private.st_v2_active(actor),false)
    or not sectalk_private.st_v8_entry_sso_allows(p_workspace) then
    raise exception using errcode='42501',message='Rule registry unavailable';
  end if;
  if p_action is distinct from 'view' then
    if member_role<>'owner' or p_action is null or p_action not in ('stage','clear','promote','rollback') then
      raise exception using errcode='42501',message='Only the workspace owner can change rule versions';
    end if;
    perform sectalk_private.limit_action('workspace_rule_registry',15);
    perform 1 from public.st_v2_workspaces where id=p_workspace for update;
    if not found or sectalk_private.st_v2_role(p_workspace,actor) is distinct from 'owner'
      or not sectalk_private.st_v2_active(actor)
      or not sectalk_private.st_v8_entry_sso_allows(p_workspace) then
      raise exception using errcode='42501',message='Workspace owner required';
    end if;
    insert into sectalk_private.st_v7_profile_rule_workspace(workspace) values(p_workspace) on conflict do nothing;
    select * into state from sectalk_private.st_v7_profile_rule_workspace where workspace=p_workspace for update;
    if state.generation is distinct from p_generation then
      raise exception using errcode='40001',message='The registry changed. Refresh before trying again.';
    end if;
    if p_action='stage' then
      if p_version is null or p_version=state.active or not exists(
        select 1 from sectalk_private.st_v7_profile_rule_version where id=p_version) then
        raise exception using errcode='22023',message='Choose an inactive registered version';
      end if;
      if p_version is distinct from state.shadow then
        update sectalk_private.st_v7_profile_rule_workspace set shadow=p_version,generation=gen_random_uuid()
          where workspace=p_workspace returning * into state;
        target:=p_version;
      end if;
    elsif p_action='clear' then
      target:=state.shadow;
      if target is not null then
        update sectalk_private.st_v7_profile_rule_workspace set shadow=null,generation=gen_random_uuid()
          where workspace=p_workspace returning * into state;
      end if;
    elsif p_action='promote' then
      if state.shadow is null or not exists(select 1 from sectalk_private.st_v7_profile_rule_evaluation e
        where e.workspace=p_workspace and e.generation=state.generation and (e.active,e.shadow)=(state.active,state.shadow)) then
        raise exception using errcode='22023',message='Evaluate this shadow version before promoting it';
      end if;
      target:=state.shadow;
      update sectalk_private.st_v7_profile_rule_workspace
        set previous=active,active=shadow,shadow=null,generation=gen_random_uuid()
        where workspace=p_workspace returning * into state;
    else
      if state.previous is null then raise exception using errcode='22023',message='No previous active version'; end if;
      target:=state.previous;
      update sectalk_private.st_v7_profile_rule_workspace
        set previous=active,active=previous,shadow=null,generation=gen_random_uuid()
        where workspace=p_workspace returning * into state;
    end if;
    if target is not null then
      insert into sectalk_private.st_v7_profile_rule_history(workspace,action,actor,version)
        values(p_workspace,p_action,actor,target);
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(p_workspace,actor,'workspace.ai_rule.'||p_action,p_workspace);
    end if;
  else
    select * into state from sectalk_private.st_v7_profile_rule_workspace where workspace=p_workspace;
  end if;
  return jsonb_build_object(
    'owner',member_role='owner','active',coalesce(state.active,'profile-rules-v1'),'shadow',state.shadow,'previous',state.previous,
    'generation',coalesce(state.generation,'00000000-0000-0000-0000-000000000000'::uuid),
    'canPromote',exists(select 1 from sectalk_private.st_v7_profile_rule_evaluation where workspace=p_workspace and generation=state.generation),
    'versions',(select jsonb_agg(to_jsonb(v) order by v.id) from sectalk_private.st_v7_profile_rule_version v),
    'evaluations',coalesce((select jsonb_agg(to_jsonb(e) order by e.evaluated_at desc) from (
      select active,shadow,corpus,evaluated_at,active_counts,shadow_counts,disagreements
      from sectalk_private.st_v7_profile_rule_evaluation where workspace=p_workspace order by evaluated_at desc limit 8
    ) e),'[]'::jsonb),
    'history',coalesce((select jsonb_agg(to_jsonb(h) order by h.id desc) from (
      select id,action,version,at from sectalk_private.st_v7_profile_rule_history where workspace=p_workspace order by id desc limit 8
    ) h),'[]'::jsonb)
  );
end
$$;

create or replace function public.st_v7_workspace_active_profile_rules(p_workspace uuid)
returns text language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if not coalesce(sectalk_private.st_v2_active(actor),false) or coalesce(sectalk_private.st_v2_role(p_workspace,actor),'') not in ('owner','admin')
    or not sectalk_private.st_v8_entry_sso_allows(p_workspace) then
    raise exception using errcode='42501',message='Workspace advisory settings unavailable';
  end if;
  return coalesce((select active from sectalk_private.st_v7_profile_rule_workspace where workspace=p_workspace),'profile-rules-v1');
end
$$;

commit;
