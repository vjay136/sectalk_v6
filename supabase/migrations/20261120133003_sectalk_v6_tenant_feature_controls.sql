begin;

alter table sectalk_private.st_v6_flag_rules drop constraint st_v6_flag_rules_feature_check;
alter table sectalk_private.st_v6_flag_rules add constraint st_v6_flag_rules_feature_check
  check(feature in ('task_creation','recurring_meetings','integration_api'));
insert into sectalk_private.st_v6_flag_rules(feature,scope,target,enabled,rollout)
  values('integration_api','global','00000000-0000-0000-0000-000000000000',true,100);

create table sectalk_private.st_v6_tenant_feature_pauses (
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  feature text not null check(feature in ('task_creation','recurring_meetings','integration_api')),
  primary key(workspace,feature)
);
alter table sectalk_private.st_v6_tenant_feature_pauses enable row level security;
revoke all on sectalk_private.st_v6_tenant_feature_pauses from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_release_rule_allowed(p_feature text,p_actor uuid,p_workspace uuid)
returns boolean language sql stable set search_path='' as $$
  select p_actor is not null and (p_workspace is null or sectalk_private.st_v2_role(p_workspace,p_actor) is not null)
    and not exists(select 1 from sectalk_private.st_v6_flag_rules r
      where r.feature=p_feature and r.scope='global' and r.killed)
    and coalesce((
      select r.enabled and sectalk_private.st_v6_flag_bucket(p_feature,p_actor)<r.rollout
      from sectalk_private.st_v6_flag_rules r where r.feature=p_feature
      and (r.scope='global' or (r.scope='workspace' and r.target=p_workspace) or (r.scope='account' and r.target=p_actor))
      order by case r.scope when 'account' then 0 when 'workspace' then 1 else 2 end limit 1
    ),false)
$$;

create function sectalk_private.st_v6_workspace_feature_entitled(p_feature text,p_workspace uuid)
returns boolean language sql stable set search_path='' as $$
  select case p_feature
    when 'integration_api' then exists(select 1 from public.st_v2_workspaces w where w.id=p_workspace
      and sectalk_private.st_v2_active(w.owner)
      and sectalk_private.st_v2_effective_plan(w.owner) in ('business','enterprise'))
    when 'task_creation' then true
    when 'recurring_meetings' then true
    else false end
$$;

create or replace function sectalk_private.st_v6_feature_allowed(p_feature text,p_actor uuid,p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v6_release_rule_allowed(p_feature,p_actor,p_workspace)
    and sectalk_private.st_v6_workspace_feature_entitled(p_feature,p_workspace)
    and not exists(select 1 from sectalk_private.st_v6_tenant_feature_pauses o
      where o.workspace=p_workspace and o.feature=p_feature)
$$;

create function public.st_v6_tenant_feature_state(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare workspace_owner uuid;
declare access text:=sectalk_private.st_v6_holds_access(p_workspace);
begin
  if access='none' then return null; end if;
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

create function public.st_v6_set_tenant_feature_pause(p_workspace uuid,p_feature text,p_paused boolean)
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

create function sectalk_private.st_v6_guard_integration_key_feature()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if not sectalk_private.st_v6_feature_allowed('integration_api',new.created_by,new.workspace_id) then
    raise exception 'The workspace API is unavailable.' using errcode='42501';
  end if;
  return new;
end
$$;
create trigger st_v6_guard_integration_key_feature before insert on sectalk_private.st_v6_integration_keys
  for each row execute function sectalk_private.st_v6_guard_integration_key_feature();

revoke all on function sectalk_private.st_v6_release_rule_allowed(text,uuid,uuid),
  sectalk_private.st_v6_workspace_feature_entitled(text,uuid),sectalk_private.st_v6_guard_integration_key_feature(),
  public.st_v6_tenant_feature_state(uuid),public.st_v6_set_tenant_feature_pause(uuid,text,boolean)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_tenant_feature_state(uuid),public.st_v6_set_tenant_feature_pause(uuid,text,boolean) to authenticated;

create or replace function public.st_v6_save_flag_rule(p_feature text,p_scope text,p_target uuid,
  p_enabled boolean,p_rollout integer,p_killed boolean default false,p_remove boolean default false)
returns void language plpgsql security definer set search_path='' as $$
declare
  target_key uuid:=coalesce(p_target,'00000000-0000-0000-0000-000000000000');
  old_rule jsonb;
  saved_rule jsonb;
begin
  if not public.st_v6_can_manage_flags() then raise exception 'Verified flag operator access required' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v6_flag_rules',25);
  if p_feature is null or p_feature not in ('task_creation','recurring_meetings','integration_api') or p_scope is null
    or p_scope not in ('global','workspace','account') or p_enabled is null or p_rollout is null or p_rollout not between 0 and 100
    or p_killed is null or p_remove is null or (p_scope='global')<>(p_target is null)
    or (p_scope='global' and p_remove) or (p_scope<>'global' and p_killed)
    then raise exception 'Choose a valid feature rule' using errcode='22023'; end if;
  if not p_remove and ((p_scope='account' and not exists(select 1 from public.st_profiles where id=p_target))
    or (p_scope='workspace' and not exists(select 1 from public.st_v2_workspaces where id=p_target)))
    then raise exception 'The rule target could not be found' using errcode='22023'; end if;
  -- Serialize each feature's rule changes so audit history cannot miss a concurrent override.
  perform 1 from sectalk_private.st_v6_flag_rules r where r.feature=p_feature and r.scope='global' for update;
  select to_jsonb(r)-'changed_at' into old_rule from sectalk_private.st_v6_flag_rules r
    where r.feature=p_feature and r.scope=p_scope and r.target=target_key;
  if p_remove then
    delete from sectalk_private.st_v6_flag_rules r where r.feature=p_feature and r.scope=p_scope and r.target=target_key;
  else
    insert into sectalk_private.st_v6_flag_rules(feature,scope,target,enabled,rollout,killed)
      values(p_feature,p_scope,target_key,p_enabled,p_rollout,p_killed)
      on conflict(feature,scope,target) do update set enabled=excluded.enabled,rollout=excluded.rollout,
        killed=excluded.killed,changed_at=clock_timestamp()
      returning to_jsonb(st_v6_flag_rules)-'changed_at' into saved_rule;
  end if;
  if old_rule is distinct from saved_rule then
    insert into sectalk_private.st_v6_flag_audit(actor,feature,scope,target,before_rule,after_rule)
      values(auth.uid(),p_feature,p_scope,target_key,old_rule,saved_rule);
  end if;
end $$;

create or replace function public.st_v6_integration_read(p_digest text,p_resource text,p_after uuid,p_limit integer)
returns jsonb language plpgsql security definer set search_path='' as $$
declare api_key sectalk_private.st_v6_integration_keys; tenant public.st_v2_workspaces; result jsonb; used integer;
begin
  if (p_digest ~ '^[a-f0-9]{64}$') is not true or (p_resource in ('workspace','rooms')) is not true
    or (p_limit between 1 and 100) is not true then
    raise exception using errcode='22023',message='Invalid API request';
  end if;
  select * into api_key from sectalk_private.st_v6_integration_keys k where k.digest=decode(p_digest,'hex')
    and k.revoked_at is null and k.expires_at>now() for share;
  if not found then raise exception using errcode='PT401',message='Invalid API key'; end if;
  select * into tenant from public.st_v2_workspaces w where w.id=api_key.workspace_id;
  if not found or tenant.owner is distinct from api_key.created_by or sectalk_private.st_v2_active(tenant.owner) is not true
    or sectalk_private.st_v2_effective_plan(tenant.owner) not in ('business','enterprise')
    or not sectalk_private.st_v6_feature_allowed('integration_api',tenant.owner,tenant.id)
    or not (p_resource||':read'=any(api_key.scopes)) then
    raise exception using errcode='42501',message='API key scope is unavailable';
  end if;
  insert into sectalk_private.st_v6_api_rate as budget(key_id,minute,requests)
    values(api_key.id,date_trunc('minute',statement_timestamp()),1)
    on conflict(key_id,minute) do update set requests=budget.requests+1 where budget.requests<120
    returning requests into used;
  if used is null then raise exception using errcode='PT429',message='API request limit reached'; end if;
  if p_resource='workspace' then
    return jsonb_build_object('data',jsonb_build_object('id',tenant.id,'name',tenant.name,'created_at',tenant.created_at));
  end if;
  select jsonb_build_object('data',coalesce(jsonb_agg(jsonb_build_object('id',page.id,'name',page.name,'created_at',page.created_at)
    order by page.id) filter(where page.position<=p_limit),'[]'::jsonb),
    'next_cursor',case when count(*)>p_limit then (array_agg(page.id order by page.id))[p_limit] end)
  into result from (
    select r.id,r.name,r.created_at,row_number() over(order by r.id) position from public.st_v6_rooms r
    where r.workspace_id=tenant.id and r.kind='public' and r.classification in ('public','internal') and not r.archived
      and (p_after is null or r.id>p_after)
    order by r.id limit p_limit+1
  ) page;
  return result;
end $$;

commit;
