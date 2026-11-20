begin;

create table sectalk_private.st_v7_profile_rule_version (
  id text primary key,
  label text not null,
  effect text not null
);
insert into sectalk_private.st_v7_profile_rule_version values
  ('profile-rules-v1','Profile rules v1','Broad mode can warn on a one-edit username by itself.'),
  ('profile-rules-v2','Profile rules v2','Broad mode requires similar display names before warning on one-edit usernames.');

create table sectalk_private.st_v7_profile_rule_workspace (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  active text not null default 'profile-rules-v1' references sectalk_private.st_v7_profile_rule_version,
  shadow text references sectalk_private.st_v7_profile_rule_version,
  previous text references sectalk_private.st_v7_profile_rule_version,
  generation uuid not null default '00000000-0000-0000-0000-000000000000',
  check(shadow is null or shadow<>active),
  check(previous is null or previous<>active)
);
create table sectalk_private.st_v7_profile_rule_evaluation (
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  generation uuid not null,
  active text not null references sectalk_private.st_v7_profile_rule_version,
  shadow text not null references sectalk_private.st_v7_profile_rule_version,
  corpus text not null check(corpus='synthetic-profile-pairs-v1'),
  evaluated_at timestamptz not null default clock_timestamp(),
  active_counts integer[] not null,
  shadow_counts integer[] not null,
  disagreements integer not null check(disagreements between 0 and 8),
  primary key(workspace,generation),
  check(active<>shadow),
  check(array_ndims(active_counts)=1 and cardinality(active_counts)=4 and 0<=all(active_counts) and 8>=all(active_counts)),
  check(array_ndims(shadow_counts)=1 and cardinality(shadow_counts)=4 and 0<=all(shadow_counts) and 8>=all(shadow_counts))
);
create index st_v7_profile_rule_evaluation_recent on sectalk_private.st_v7_profile_rule_evaluation(workspace,evaluated_at desc);
create table sectalk_private.st_v7_profile_rule_history (
  id bigint generated always as identity primary key,
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  action text not null check(action in ('stage','clear','promote','rollback')),
  actor uuid not null,
  version text references sectalk_private.st_v7_profile_rule_version,
  at timestamptz not null default clock_timestamp()
);
create index st_v7_profile_rule_history_recent on sectalk_private.st_v7_profile_rule_history(workspace,id desc);
alter table sectalk_private.st_v7_profile_rule_version enable row level security;
alter table sectalk_private.st_v7_profile_rule_workspace enable row level security;
alter table sectalk_private.st_v7_profile_rule_evaluation enable row level security;
alter table sectalk_private.st_v7_profile_rule_history enable row level security;
revoke all on sectalk_private.st_v7_profile_rule_version,sectalk_private.st_v7_profile_rule_workspace,
  sectalk_private.st_v7_profile_rule_evaluation,sectalk_private.st_v7_profile_rule_history from public,anon,authenticated,service_role;

create function public.st_v7_workspace_rule_registry(p_workspace uuid,p_action text default 'view',
  p_version text default null,p_generation uuid default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); member_role text; state sectalk_private.st_v7_profile_rule_workspace; target text;
begin
  member_role:=sectalk_private.st_v2_role(p_workspace,actor);
  if coalesce(member_role,'') not in ('owner','admin') or not coalesce(sectalk_private.st_v2_active(actor),false) then
    raise exception using errcode='42501',message='Rule registry unavailable';
  end if;
  if p_action is distinct from 'view' then
    if member_role<>'owner' or p_action is null or p_action not in ('stage','clear','promote','rollback') then
      raise exception using errcode='42501',message='Only the workspace owner can change rule versions';
    end if;
    perform sectalk_private.limit_action('workspace_rule_registry',15);
    perform 1 from public.st_v2_workspaces where id=p_workspace for update;
    if not found or sectalk_private.st_v2_role(p_workspace,actor) is distinct from 'owner' then
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

create function public.st_v7_record_profile_rule_evaluation(p_workspace uuid,p_actor uuid,p_generation uuid,p_corpus text,
  p_active_counts integer[],p_shadow_counts integer[],p_disagreements integer)
returns boolean language plpgsql security definer set search_path='' as $$
declare state sectalk_private.st_v7_profile_rule_workspace;
begin
  if sectalk_private.st_v2_role(p_workspace,p_actor) is distinct from 'owner'
    or not coalesce(sectalk_private.st_v2_active(p_actor),false) then return false; end if;
  select * into state from sectalk_private.st_v7_profile_rule_workspace where workspace=p_workspace for update;
  if not found or state.generation is distinct from p_generation or state.shadow is null
    or p_corpus is distinct from 'synthetic-profile-pairs-v1'
    or p_active_counts is null or p_shadow_counts is null
    or array_position(p_active_counts,null) is not null or array_position(p_shadow_counts,null) is not null
    or (select sum(x) from unnest(p_active_counts) x) is distinct from 8::bigint
    or (select sum(x) from unnest(p_shadow_counts) x) is distinct from 8::bigint then return false; end if;
  insert into sectalk_private.st_v7_profile_rule_evaluation
    (workspace,generation,active,shadow,corpus,active_counts,shadow_counts,disagreements)
    values(p_workspace,p_generation,state.active,state.shadow,p_corpus,p_active_counts,p_shadow_counts,p_disagreements)
    on conflict(workspace,generation) do nothing;
  return true;
end
$$;

create function public.st_v7_workspace_active_profile_rules(p_workspace uuid)
returns text language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if not coalesce(sectalk_private.st_v2_active(actor),false) or coalesce(sectalk_private.st_v2_role(p_workspace,actor),'') not in ('owner','admin') then
    raise exception using errcode='42501',message='Workspace advisory settings unavailable';
  end if;
  return coalesce((select active from sectalk_private.st_v7_profile_rule_workspace where workspace=p_workspace),'profile-rules-v1');
end
$$;

revoke all on function public.st_v7_workspace_rule_registry(uuid,text,text,uuid),
  public.st_v7_workspace_active_profile_rules(uuid),
  public.st_v7_record_profile_rule_evaluation(uuid,uuid,uuid,text,integer[],integer[],integer) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_workspace_rule_registry(uuid,text,text,uuid),
  public.st_v7_workspace_active_profile_rules(uuid) to authenticated;
grant execute on function public.st_v7_record_profile_rule_evaluation(uuid,uuid,uuid,text,integer[],integer[],integer) to service_role;
commit;
