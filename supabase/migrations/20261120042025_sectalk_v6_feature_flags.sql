begin;

create table sectalk_private.st_v6_flag_operators (
  account_id uuid primary key references public.st_profiles on delete cascade
);
create table sectalk_private.st_v6_flag_rules (
  feature text not null check(feature in ('task_creation','recurring_meetings')),
  scope text not null check(scope in ('global','workspace','account')),
  target uuid not null,
  enabled boolean not null,
  rollout integer not null check(rollout between 0 and 100),
  killed boolean not null default false,
  changed_at timestamptz not null default clock_timestamp(),
  primary key(feature,scope,target),
  check((scope='global')=(target='00000000-0000-0000-0000-000000000000')),
  check(scope='global' or not killed)
);
create table sectalk_private.st_v6_flag_audit (
  id bigint generated always as identity primary key,
  actor uuid not null,
  feature text not null,
  scope text not null,
  target uuid not null,
  before_rule jsonb,
  after_rule jsonb,
  changed_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v6_flag_operators enable row level security;
alter table sectalk_private.st_v6_flag_rules enable row level security;
alter table sectalk_private.st_v6_flag_audit enable row level security;
revoke all on sectalk_private.st_v6_flag_operators,sectalk_private.st_v6_flag_rules,sectalk_private.st_v6_flag_audit
  from public,anon,authenticated;
insert into sectalk_private.st_v6_flag_rules(feature,scope,target,enabled,rollout) values
  ('task_creation','global','00000000-0000-0000-0000-000000000000',true,100),
  ('recurring_meetings','global','00000000-0000-0000-0000-000000000000',true,100);

create function sectalk_private.st_v6_flag_bucket(p_feature text,p_actor uuid)
returns integer language sql immutable strict set search_path='' as $$
  select ((('x'||left(md5(p_feature||':'||p_actor::text),8))::bit(32)::bigint)%100)::integer
$$;

create function sectalk_private.st_v6_feature_allowed(p_feature text,p_actor uuid,p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
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
revoke all on function sectalk_private.st_v6_flag_bucket(text,uuid),sectalk_private.st_v6_feature_allowed(text,uuid,uuid)
  from public,anon,authenticated;

create function public.st_v6_feature_available(p_feature text,p_workspace uuid default null)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v6_feature_allowed(p_feature,auth.uid(),p_workspace)
$$;

create function public.st_v6_can_manage_flags()
returns boolean language sql stable security definer set search_path='' as $$
  select public.st_staff_status()='verified' and sectalk_private.st_v2_active(auth.uid())
    and exists(select 1 from sectalk_private.st_v6_flag_operators where account_id=auth.uid())
$$;

create function public.st_v6_flag_rules()
returns table(feature text,scope text,target uuid,enabled boolean,rollout integer,killed boolean)
language plpgsql stable security definer set search_path='' as $$
begin
  if not public.st_v6_can_manage_flags() then raise exception 'Verified flag operator access required' using errcode='42501'; end if;
  return query select r.feature,r.scope,nullif(r.target,'00000000-0000-0000-0000-000000000000'::uuid),
    r.enabled,r.rollout,r.killed from sectalk_private.st_v6_flag_rules r
    order by (r.scope='global') desc,r.changed_at desc,r.feature limit 500;
end $$;

create function public.st_v6_save_flag_rule(p_feature text,p_scope text,p_target uuid,
  p_enabled boolean,p_rollout integer,p_killed boolean default false,p_remove boolean default false)
returns void language plpgsql security definer set search_path='' as $$
declare
  target_key uuid:=coalesce(p_target,'00000000-0000-0000-0000-000000000000');
  old_rule jsonb;
  saved_rule jsonb;
begin
  if not public.st_v6_can_manage_flags() then raise exception 'Verified flag operator access required' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v6_flag_rules',25);
  if p_feature is null or p_feature not in ('task_creation','recurring_meetings') or p_scope is null
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

create function sectalk_private.st_v6_gate_task_creation()
returns trigger language plpgsql security definer set search_path='' as $$
declare workspace uuid;
begin
  if new.room_id is not null then select r.workspace_id into workspace from public.st_v6_rooms r where r.id=new.room_id; end if;
  if not sectalk_private.st_v6_feature_allowed('task_creation',new.author_id,workspace)
    then raise exception 'Task creation is unavailable'; end if;
  return new;
end $$;

create function sectalk_private.st_v6_gate_recurring_meeting()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.series_id is not null and not sectalk_private.st_v6_feature_allowed('recurring_meetings',new.host_id,new.workspace_id)
    then raise exception 'Recurring meetings are unavailable'; end if;
  return new;
end $$;
revoke all on function sectalk_private.st_v6_gate_task_creation(),sectalk_private.st_v6_gate_recurring_meeting()
  from public,anon,authenticated;
create trigger st_v6_gate_task_creation before insert on public.st_v6_tasks
for each row execute function sectalk_private.st_v6_gate_task_creation();
create trigger st_v6_gate_recurring_meeting before insert on public.st_v3_meetings
for each row execute function sectalk_private.st_v6_gate_recurring_meeting();

revoke all on function public.st_v6_feature_available(text,uuid),public.st_v6_can_manage_flags(),public.st_v6_flag_rules(),
  public.st_v6_save_flag_rule(text,text,uuid,boolean,integer,boolean,boolean) from public,anon,authenticated;
grant execute on function public.st_v6_feature_available(text,uuid),public.st_v6_can_manage_flags(),public.st_v6_flag_rules(),
  public.st_v6_save_flag_rule(text,text,uuid,boolean,integer,boolean,boolean) to authenticated;

commit;
