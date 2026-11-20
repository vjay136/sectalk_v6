begin;

create table sectalk_private.st_v7_playbook_grants (
  reviewer uuid not null references auth.users on delete cascade,
  signal_type text not null check(signal_type in ('detection','attachment_inspection','malware')),
  capability text not null check(capability in ('author','approver')),
  primary key(reviewer,signal_type,capability),
  foreign key(reviewer,signal_type) references sectalk_private.st_v7_threat_reviewers(user_id,signal_type) on delete cascade
);
create table sectalk_private.st_v7_playbooks (
  id uuid primary key default gen_random_uuid(),
  signal_type text not null check(signal_type in ('detection','attachment_inspection','malware')),
  current_version integer not null check(current_version>0)
);
create table sectalk_private.st_v7_playbook_versions (
  playbook uuid not null references sectalk_private.st_v7_playbooks,
  version integer not null,
  author uuid not null,
  name text not null check(char_length(name) between 3 and 80),
  severity text not null check(severity in ('any','low','medium','high')),
  actions text[] not null check(cardinality(actions) between 1 and 3),
  saved_at timestamptz not null default clock_timestamp(),
  primary key(playbook,version)
);
create table sectalk_private.st_v7_playbook_runs (
  id uuid primary key default gen_random_uuid(),
  item uuid not null,
  item_revision integer not null,
  playbook uuid not null,
  version integer not null,
  requester uuid not null,
  requested_at timestamptz not null default clock_timestamp(),
  approver uuid,
  decided_at timestamptz,
  decision text check(decision in ('executed','rejected')),
  reason text,
  foreign key(playbook,version) references sectalk_private.st_v7_playbook_versions(playbook,version),
  unique(item,item_revision,playbook,version),
  check(approver is distinct from requester),
  check((decision is null)=(decided_at is null) and (decision is null)=(approver is null) and (decision is null)=(reason is null))
);
create index st_v7_playbook_runs_pending on sectalk_private.st_v7_playbook_runs(requested_at desc,id) where decision is null;
create index st_v7_playbook_runs_item on sectalk_private.st_v7_playbook_runs(item,requested_at desc,id);
create table sectalk_private.st_v7_playbook_effects (
  run uuid not null references sectalk_private.st_v7_playbook_runs,
  step text not null check(step in ('mark_reviewing','verify_signal','document_findings')),
  actor uuid not null,
  occurred_at timestamptz not null default clock_timestamp(),
  primary key(run,step)
);
create table sectalk_private.st_v7_playbook_checklist_status (
  run uuid not null,
  step text not null check(step in ('verify_signal','document_findings')),
  actor uuid not null,
  completed_at timestamptz not null default clock_timestamp(),
  primary key(run,step),
  foreign key(run,step) references sectalk_private.st_v7_playbook_effects(run,step)
);
alter table sectalk_private.st_v7_playbook_grants enable row level security;
alter table sectalk_private.st_v7_playbooks enable row level security;
alter table sectalk_private.st_v7_playbook_versions enable row level security;
alter table sectalk_private.st_v7_playbook_runs enable row level security;
alter table sectalk_private.st_v7_playbook_effects enable row level security;
alter table sectalk_private.st_v7_playbook_checklist_status enable row level security;
revoke all on sectalk_private.st_v7_playbook_grants,sectalk_private.st_v7_playbooks,sectalk_private.st_v7_playbook_versions,
  sectalk_private.st_v7_playbook_runs,sectalk_private.st_v7_playbook_effects,sectalk_private.st_v7_playbook_checklist_status
  from public,anon,authenticated,service_role;
create trigger st_v7_immutable_playbook_version before update or delete on sectalk_private.st_v7_playbook_versions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v7_immutable_playbook_effect before update or delete on sectalk_private.st_v7_playbook_effects
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v7_immutable_playbook_completion before update or delete on sectalk_private.st_v7_playbook_checklist_status
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

create function sectalk_private.st_v7_guard_playbook_decision()
returns trigger language plpgsql set search_path='' as $$
begin
  if tg_op='UPDATE' and old.decision is null and new.decision is not null
    and (new.id,new.item,new.item_revision,new.playbook,new.version,new.requester,new.requested_at)
       =(old.id,old.item,old.item_revision,old.playbook,old.version,old.requester,old.requested_at) then
    return new;
  end if;
  raise exception 'Playbook request and decision history is immutable' using errcode='42501';
end $$;
create trigger st_v7_guard_playbook_decision before update or delete on sectalk_private.st_v7_playbook_runs
  for each row execute function sectalk_private.st_v7_guard_playbook_decision();

create function sectalk_private.st_v7_playbook_can(p_scope text,p_capability text)
returns boolean language sql stable security definer set search_path='' as $$
  select (public.st_v7_threat_triage_access()->>'status'='verified')
    and public.st_v7_account_under_lockdown() is false and exists(
    select 1 from sectalk_private.st_v7_playbook_grants g
    where g.reviewer=auth.uid() and g.signal_type=p_scope and (p_capability is null or g.capability=p_capability));
$$;

create function public.st_v7_playbook_catalog()
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('grants',coalesce((select jsonb_agg(jsonb_build_object('scope',g.signal_type,'role',g.capability))
    from sectalk_private.st_v7_playbook_grants g where g.reviewer=auth.uid()
      and sectalk_private.st_v7_playbook_can(g.signal_type,g.capability)),'[]'::jsonb),
    'versions',coalesce((select jsonb_agg(to_jsonb(entries)) from (
      select p.id,p.signal_type,v.version,v.name,v.severity,v.actions
      from sectalk_private.st_v7_playbooks p join sectalk_private.st_v7_playbook_versions v
        on (v.playbook,v.version)=(p.id,p.current_version)
      where sectalk_private.st_v7_playbook_can(p.signal_type,null)
      order by v.saved_at desc,p.id limit 60
    ) entries),'[]'::jsonb));
$$;

create function public.st_v7_save_playbook(p_id uuid,p_version integer,p_scope text,p_name text,p_severity text,p_actions text[])
returns uuid language plpgsql security definer set search_path='' as $$
declare playbook_id uuid:=p_id; next_version integer;
begin
  if not sectalk_private.st_v7_playbook_can(p_scope,'author') then
    raise exception 'Fresh playbook author permission for this signal type is required' using errcode='42501'; end if;
  if p_name is null or char_length(btrim(p_name)) not between 3 and 80
    or p_severity is null or p_severity not in ('any','low','medium','high')
    or p_version is null or p_version<0
    or p_actions is null or cardinality(p_actions) not between 1 and 3
    or array_ndims(p_actions)<>1 or array_lower(p_actions,1)<>1
    or exists(select 1 from unnest(p_actions) action where action is null
      or action not in ('mark_reviewing','verify_signal','document_findings'))
    or (select count(distinct action) from unnest(p_actions) action)<>cardinality(p_actions) then
    raise exception 'Specify valid playbook conditions and distinct supported steps' using errcode='22023'; end if;
  perform sectalk_private.limit_action('v7_save_playbook',12);
  if p_id is null and p_version=0 then
    -- Serialize the bounded per-scope catalog across separate authors.
    perform pg_advisory_xact_lock(hashtextextended('v7_playbook_catalog:'||p_scope,0));
    if (select count(*) from sectalk_private.st_v7_playbooks where signal_type=p_scope)>=20 then
      raise exception 'The signal scope has reached its playbook limit' using errcode='PT409'; end if;
    insert into sectalk_private.st_v7_playbooks(signal_type,current_version) values(p_scope,1)
      returning id,current_version into playbook_id,next_version;
  else
    update sectalk_private.st_v7_playbooks set current_version=current_version+1
      where id=p_id and signal_type=p_scope and current_version=p_version returning current_version into next_version;
    if next_version is null then raise exception 'Playbook version changed or is unavailable' using errcode='PT409'; end if;
  end if;
  insert into sectalk_private.st_v7_playbook_versions(playbook,version,author,name,severity,actions)
    values(playbook_id,next_version,auth.uid(),btrim(p_name),p_severity,p_actions);
  return playbook_id;
end $$;

create function sectalk_private.st_v7_playbook_plan(p_item sectalk_private.st_v7_threat_items,
  p_version sectalk_private.st_v7_playbook_versions)
returns boolean language sql stable set search_path='' as $$
  select coalesce(p_item.detected_at>=statement_timestamp()-interval '30 days'
    and p_item.state in ('open','reviewing') and (p_version.severity='any' or p_version.severity=p_item.severity)
    and (not ('mark_reviewing'=any(p_version.actions)) or p_item.state='open'),false);
$$;

create function public.st_v7_simulate_playbook(p_id uuid,p_version integer,p_item uuid,p_revision integer,p_request boolean)
returns jsonb language plpgsql security definer set search_path='' as $$
declare target sectalk_private.st_v7_threat_items;
  v sectalk_private.st_v7_playbook_versions;
  selected_scope text;
  run_key uuid;
  matches boolean;
begin
  if p_request is null then raise exception 'Choose simulation or submission' using errcode='22023'; end if;
  select p.signal_type into selected_scope from sectalk_private.st_v7_playbooks p where p.id=p_id and p.current_version=p_version;
  if not sectalk_private.st_v7_playbook_can(selected_scope,'author') then
    raise exception 'Playbook or signal is unavailable' using errcode='42501'; end if;
  select * into target from sectalk_private.st_v7_threat_items q where q.id=p_item and q.signal_type=selected_scope;
  if target.id is null then raise exception 'Playbook or signal is unavailable' using errcode='42501'; end if;
  if target.revision is distinct from p_revision then
    raise exception 'The signal changed since selection' using errcode='PT409'; end if;
  select * into strict v from sectalk_private.st_v7_playbook_versions a where (a.playbook,a.version)=(p_id,p_version);
  matches:=sectalk_private.st_v7_playbook_plan(target,v);
  if p_request then
    if not matches then raise exception 'The playbook conditions are not met' using errcode='PT409'; end if;
    perform sectalk_private.limit_action('v7_request_playbook',12);
    insert into sectalk_private.st_v7_playbook_runs(item,item_revision,playbook,version,requester)
      values(p_item,p_revision,p_id,p_version,auth.uid())
      on conflict(item,item_revision,playbook,version) do nothing returning id into run_key;
    if run_key is null then
      raise exception 'This version already has a request for this signal revision' using errcode='PT409'; end if;
  end if;
  return jsonb_build_object('matches',matches,'actions',v.actions,'run',run_key);
end $$;

create function public.st_v7_playbook_runs(p_item uuid default null)
returns jsonb language sql stable security definer set search_path='' as $$
  select coalesce(jsonb_agg(to_jsonb(entries)),'[]'::jsonb) from (
    select r.id,r.item,r.item_revision,p.signal_type,r.version,v.name,v.severity,v.actions,r.requested_at,r.decided_at,
      r.decision,r.reason, r.requester=auth.uid() own_request,
      r.decision is null and r.requester<>auth.uid() and v.author<>auth.uid() and
        sectalk_private.st_v7_playbook_can(p.signal_type,'approver') can_decide,
      coalesce((select jsonb_agg(jsonb_build_object('step',f.step,'completed',c.completed_at,'occurred_at',f.occurred_at)
        order by array_position(v.actions,f.step)) from sectalk_private.st_v7_playbook_effects f
        left join sectalk_private.st_v7_playbook_checklist_status c on (c.run,c.step)=(f.run,f.step)
        where f.run=r.id),'[]'::jsonb) effects
    from sectalk_private.st_v7_playbook_runs r join sectalk_private.st_v7_playbooks p on p.id=r.playbook
    join sectalk_private.st_v7_playbook_versions v on (v.playbook,v.version)=(r.playbook,r.version)
    where sectalk_private.st_v7_playbook_can(p.signal_type,null) and (p_item is null or p_item=r.item)
      and (r.requester=auth.uid() or sectalk_private.st_v7_playbook_can(p.signal_type,'approver') or r.decision='executed')
    order by (r.decision is null and r.requested_at>statement_timestamp()-interval '24 hours') desc,r.requested_at desc,r.id limit 60
  ) entries;
$$;

create function public.st_v7_decide_playbook(p_run uuid,p_approve boolean,p_reason text)
returns text language plpgsql security definer set search_path='' as $$
declare
  actor_id uuid:=auth.uid();
  target sectalk_private.st_v7_playbook_runs;
  signal sectalk_private.st_v7_threat_items;
  plan sectalk_private.st_v7_playbook_versions;
  selected_scope text;
  note text:=btrim(p_reason);
  result text;
begin
  select p.signal_type into selected_scope from sectalk_private.st_v7_playbook_runs r
    join sectalk_private.st_v7_playbooks p on p.id=r.playbook where r.id=p_run;
  if not sectalk_private.st_v7_playbook_can(selected_scope,'approver') then
    raise exception 'Playbook approval is unavailable' using errcode='42501'; end if;
  select r.* into strict target from sectalk_private.st_v7_playbook_runs r where r.id=p_run for update;
  select * into strict plan from sectalk_private.st_v7_playbook_versions v where (v.playbook,v.version)=(target.playbook,target.version);
  if actor_id in (target.requester,plan.author) then
    raise exception 'A separate reviewer must decide this request' using errcode='42501'; end if;
  perform 1 from sectalk_private.st_v7_threat_reviewers r
    where r.user_id=actor_id and r.signal_type=selected_scope for share;
  perform 1 from sectalk_private.st_v7_playbook_grants g where g.reviewer=actor_id
    and g.signal_type=selected_scope and g.capability='approver' for share;
  if not found then raise exception 'Playbook approval access changed' using errcode='42501'; end if;
  if target.decision is not null then
    if target.approver=actor_id and p_approve is not null and p_approve=(target.decision='executed') then return target.decision; end if;
    raise exception 'Another decision already resolved this request' using errcode='PT409';
  end if;
  if p_approve is null or note is null or char_length(note) not between 10 and 500 then
    raise exception 'Enter a decision reason between 10 and 500 characters' using errcode='22023'; end if;
  perform sectalk_private.limit_action('v7_decide_playbook',12);
  result:='rejected';
  if p_approve then
    perform 1 from sectalk_private.st_v7_playbook_grants g where g.reviewer=target.requester
      and g.signal_type=selected_scope and g.capability='author' for share;
    if not found then raise exception 'The requester no longer has author access' using errcode='PT409'; end if;
    select * into signal from sectalk_private.st_v7_threat_items where id=target.item and signal_type=selected_scope for update;
    if target.requested_at<=statement_timestamp()-interval '24 hours'
      or signal.revision is distinct from target.item_revision
      or not sectalk_private.st_v7_playbook_plan(signal,plan) then
      raise exception 'This simulation expired or the signal changed. Reject it and request a new simulation.' using errcode='PT409'; end if;
    if 'mark_reviewing'=any(plan.actions) then
      perform public.st_v7_apply_threat_triage(jsonb_build_array(jsonb_build_object('id',signal.id,'revision',signal.revision)),
        'reviewing',note);
    end if;
    insert into sectalk_private.st_v7_playbook_effects(run,step,actor)
      select p_run,step,actor_id from unnest(plan.actions) step;
    result:='executed';
  end if;
  update sectalk_private.st_v7_playbook_runs set approver=actor_id,decided_at=clock_timestamp(),decision=result,reason=note where id=p_run;
  return result;
end $$;

create function public.st_v7_complete_playbook_step(p_run uuid,p_step text)
returns boolean language plpgsql security definer set search_path='' as $$
declare selected_scope text;
begin
  if p_step is null or p_step not in ('verify_signal','document_findings') then
    raise exception 'Only checklist steps can be completed' using errcode='22023'; end if;
  select p.signal_type into selected_scope from sectalk_private.st_v7_playbook_runs r
    join sectalk_private.st_v7_playbooks p on p.id=r.playbook where r.id=p_run and r.decision='executed';
  if not sectalk_private.st_v7_playbook_can(selected_scope,'approver') then
    raise exception 'Playbook checklist is unavailable' using errcode='42501'; end if;
  insert into sectalk_private.st_v7_playbook_checklist_status(run,step,actor)
    select run,step,auth.uid() from sectalk_private.st_v7_playbook_effects f where f.run=p_run and f.step=p_step
    on conflict do nothing;
  return exists(select 1 from sectalk_private.st_v7_playbook_checklist_status c where c.run=p_run and c.step=p_step);
end $$;

revoke all on function sectalk_private.st_v7_guard_playbook_decision(),sectalk_private.st_v7_playbook_can(text,text),
  sectalk_private.st_v7_playbook_plan(sectalk_private.st_v7_threat_items,sectalk_private.st_v7_playbook_versions),
  public.st_v7_playbook_catalog(),public.st_v7_save_playbook(uuid,integer,text,text,text,text[]),
  public.st_v7_simulate_playbook(uuid,integer,uuid,integer,boolean),public.st_v7_playbook_runs(uuid),
  public.st_v7_decide_playbook(uuid,boolean,text),public.st_v7_complete_playbook_step(uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_playbook_catalog(),public.st_v7_save_playbook(uuid,integer,text,text,text,text[]),
  public.st_v7_simulate_playbook(uuid,integer,uuid,integer,boolean),public.st_v7_playbook_runs(uuid),
  public.st_v7_decide_playbook(uuid,boolean,text),public.st_v7_complete_playbook_step(uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
