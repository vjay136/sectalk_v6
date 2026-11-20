begin;

create table sectalk_private.st_v6_workspace_policy_versions(
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  policy text not null check(policy in ('retention','notifications')),
  version integer not null check(version>=0),
  settings jsonb not null,
  recorded_at timestamptz not null default clock_timestamp(),
  actor uuid,
  primary key(workspace_id,policy,version)
);
alter table sectalk_private.st_v6_workspace_policy_versions enable row level security;
revoke all on sectalk_private.st_v6_workspace_policy_versions from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_capture_workspace_policy_version()
returns trigger language plpgsql security definer set search_path='' as $$
declare policy_kind text;
declare previous jsonb;
declare current_settings jsonb;
declare next_version integer;
begin
  if tg_table_name='st_v6_room_retention_policy' then
    policy_kind:='retention';
    previous:=jsonb_build_object('days',case when tg_op='UPDATE' then old.retention_days else 30 end);
    current_settings:=jsonb_build_object('days',new.retention_days);
  else
    policy_kind:='notifications';
    previous:=case when tg_op='UPDATE'
      then jsonb_build_object('categories',old.mandatory_categories,'quiet_minutes',old.max_quiet_minutes)
      else '{"categories":[],"quiet_minutes":null}'::jsonb end;
    current_settings:=jsonb_build_object('categories',new.mandatory_categories,'quiet_minutes',new.max_quiet_minutes);
  end if;
  if previous=current_settings then return new; end if;
  insert into sectalk_private.st_v6_workspace_policy_versions(workspace_id,policy,version,settings)
    values(new.workspace_id,policy_kind,0,previous) on conflict do nothing;
  select max(v.version)+1 into next_version from sectalk_private.st_v6_workspace_policy_versions v
    where v.workspace_id=new.workspace_id and v.policy=policy_kind;
  insert into sectalk_private.st_v6_workspace_policy_versions(workspace_id,policy,version,settings,actor)
    values(new.workspace_id,policy_kind,next_version,current_settings,auth.uid());
  return new;
end $$;
revoke all on function sectalk_private.st_v6_capture_workspace_policy_version() from public,anon,authenticated;
create trigger st_v6_room_retention_version after insert or update on sectalk_private.st_v6_room_retention_policy
  for each row execute function sectalk_private.st_v6_capture_workspace_policy_version();
create trigger st_v6_workspace_notification_version after insert or update on sectalk_private.st_v6_workspace_notification_policy
  for each row execute function sectalk_private.st_v6_capture_workspace_policy_version();

create function sectalk_private.st_v6_workspace_policy_current(p_workspace uuid,p_policy text)
returns jsonb language sql stable set search_path='' as $$
  select case when p_policy='retention' then jsonb_build_object('days',sectalk_private.st_v6_room_retention_days(p_workspace))
  else coalesce((select jsonb_build_object('categories',p.mandatory_categories,'quiet_minutes',p.max_quiet_minutes)
    from sectalk_private.st_v6_workspace_notification_policy p where p.workspace_id=p_workspace),
    '{"categories":[],"quiet_minutes":null}'::jsonb) end
$$;
revoke all on function sectalk_private.st_v6_workspace_policy_current(uuid,text) from public,anon,authenticated;

create function public.st_v6_workspace_policy_versions(p_workspace uuid,p_policy text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare entries jsonb;
declare last_version integer;
declare current_settings jsonb;
begin
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Verified workspace policy access is required' using errcode='42501';
  end if;
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

create function public.st_v6_change_workspace_policy(
  p_workspace uuid,p_policy text,p_action text,p_settings jsonb,p_version integer,p_target integer default null
)
returns jsonb language plpgsql security definer set search_path='' as $$
declare state jsonb;
declare current_settings jsonb;
declare proposed jsonb;
declare candidate_days integer;
declare cap integer;
declare cats text[];
declare queued integer;
declare due integer;
begin
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Verified workspace policy access is required' using errcode='42501';
  end if;
  if p_policy is null or p_policy not in ('retention','notifications') or p_action is null
    or p_action not in ('preview','apply','rollback') or p_version is null or p_version<0
    or (p_settings is not null and octet_length(p_settings::text)>2048)
  then raise exception 'Choose a valid policy action' using errcode='22023'; end if;

  if p_action<>'preview' then
    if p_policy='notifications' then
      perform id from public.st_v2_workspaces where id=p_workspace for update;
    else
      perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
    end if;
  end if;
  state:=public.st_v6_workspace_policy_versions(p_workspace,p_policy);
  if (state->>'version')::integer<>p_version then
    raise exception 'Workspace policy changed. Refresh before making changes.' using errcode='40001';
  end if;
  current_settings:=state->'current';
  if p_target is not null then
    select h.settings into proposed from sectalk_private.st_v6_workspace_policy_versions h
      where h.workspace_id=p_workspace and h.policy=p_policy and h.version=p_target;
    if not found then raise exception 'Policy version is unavailable' using errcode='22023'; end if;
    if p_action='apply' then raise exception 'Use rollback for a previous revision' using errcode='22023'; end if;
  else
    if p_action='rollback' then raise exception 'Choose a version to restore' using errcode='22023'; end if;
    proposed:=p_settings;
  end if;
  if proposed is null or jsonb_typeof(proposed)<>'object' then
    raise exception 'Choose valid settings' using errcode='22023';
  end if;

  if p_policy='retention' then
    candidate_days:=(proposed->>'days')::integer;
    if candidate_days is null or candidate_days not between 7 and 3650 then
      raise exception 'Enter 7 to 3650 retention days' using errcode='22023';
    end if;
    proposed:=jsonb_build_object('days',candidate_days);
    if p_action='preview' then
      select count(*),count(*) filter(where q.requested_at+make_interval(days=>candidate_days)<=now()
          and not sectalk_private.st_v6_room_is_held(p_workspace,r.id))
        into queued,due
      from sectalk_private.st_v6_room_retirements q join public.st_v6_rooms r on r.id=q.room_id
      where r.workspace_id=p_workspace and r.archived;
      return jsonb_build_object('proposed',proposed,'queued',queued,'eligible_under_proposal',due);
    end if;
    perform public.st_v6_room_retention_policy(p_workspace,candidate_days);
  else
    if not (proposed ? 'categories') or jsonb_typeof(proposed->'categories')<>'array'
      or jsonb_array_length(proposed->'categories')>4 then
      raise exception 'Choose valid mandatory notification categories' using errcode='22023';
    end if;
    select array(select distinct value from jsonb_array_elements_text(proposed->'categories') order by value) into cats;
    cap:=(proposed->>'quiet_minutes')::integer;
    if array_position(cats,null) is not null or not cats<@array['admin','mention','task','thread']
      or (cap is not null and cap not between 0 and 1440) then
      raise exception 'Choose valid categories and quiet-hour limits' using errcode='22023';
    end if;
    proposed:=jsonb_build_object('categories',cats,'quiet_minutes',cap);
    if p_action='preview' then
      return jsonb_build_object('proposed',proposed,
        'active_members',(select count(*) from public.st_v2_members where workspace_id=p_workspace and suspended_at is null),
        'new_mandatory',array(select value from unnest(cats) value
          where not current_settings->'categories' ? value));
    end if;
    perform public.st_v6_set_workspace_notification_policy(p_workspace,cats,cap);
  end if;
  if p_action='rollback' and current_settings is distinct from proposed then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,auth.uid(),'workspace.policy_version_rolled_back',p_workspace);
  end if;
  return public.st_v6_workspace_policy_versions(p_workspace,p_policy);
end $$;

revoke all on function public.st_v6_workspace_policy_versions(uuid,text),
  public.st_v6_change_workspace_policy(uuid,text,text,jsonb,integer,integer) from public,anon,authenticated;
grant execute on function public.st_v6_workspace_policy_versions(uuid,text),
  public.st_v6_change_workspace_policy(uuid,text,text,jsonb,integer,integer) to authenticated;

commit;
