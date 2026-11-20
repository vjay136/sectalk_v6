begin;

create table sectalk_private.st_v6_room_retention_policy (
  workspace_id uuid primary key references public.st_v2_workspaces on delete cascade,
  retention_days integer not null check(retention_days between 7 and 3650)
);
create table sectalk_private.st_v6_room_retirements (
  room_id uuid primary key references public.st_v6_rooms on delete cascade,
  requested_by uuid not null,
  requested_at timestamptz not null default clock_timestamp()
);
create index st_v6_room_retirements_pending on sectalk_private.st_v6_room_retirements(requested_at);
alter table sectalk_private.st_v6_room_retention_policy enable row level security;
alter table sectalk_private.st_v6_room_retirements enable row level security;
revoke all on sectalk_private.st_v6_room_retention_policy,sectalk_private.st_v6_room_retirements
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_room_retention_days(p_workspace uuid)
returns integer language sql stable set search_path='' as $$
  select coalesce((select retention_days from sectalk_private.st_v6_room_retention_policy
    where workspace_id=p_workspace),30)
$$;

create function sectalk_private.st_v6_retirement_has_mfa()
returns boolean language sql stable set search_path='' as $$
  select auth.jwt()->>'aal'='aal2' and exists(
    select 1 from auth.sessions s join auth.mfa_factors f on f.id=s.factor_id and f.user_id=s.user_id
    where s.id::text=auth.jwt()->>'session_id' and s.user_id=auth.uid() and s.aal='aal2'
      and (s.not_after is null or s.not_after>now()) and f.status='verified' and f.factor_type='totp')
$$;

create function public.st_v6_room_retention_policy(p_workspace uuid,p_days integer default null)
returns integer language plpgsql security definer set search_path='' as $$
begin
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Verify workspace governance access' using errcode='42501';
  end if;
  if p_days is null then return sectalk_private.st_v6_room_retention_days(p_workspace); end if;
  if p_days not between 7 and 3650 then raise exception 'Use a retention period from 7 to 3650 days'; end if;
  perform sectalk_private.limit_action('v6_room_retention',10);
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Workspace governance is unavailable' using errcode='42501';
  end if;
  insert into sectalk_private.st_v6_room_retention_policy(workspace_id,retention_days) values(p_workspace,p_days)
    on conflict(workspace_id) do update set retention_days=excluded.retention_days
    where st_v6_room_retention_policy.retention_days is distinct from excluded.retention_days;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event)
      values(p_workspace,auth.uid(),'workspace.room_retention_changed');
  end if;
  return p_days;
end $$;

create function public.st_v6_room_retirement(p_room uuid,p_action text default 'read')
returns jsonb language plpgsql security definer set search_path='' as $$
declare target public.st_v6_rooms;
declare requested timestamptz;
declare permitted boolean;
declare verified boolean:=sectalk_private.st_v6_retirement_has_mfa() is true;
declare wait_days integer;
begin
  if p_action is null or p_action not in ('read','schedule','cancel') then raise exception 'Invalid room retention action'; end if;
  select * into target from public.st_v6_rooms where id=p_room;
  if not found or not sectalk_private.st_v6_room_directory(p_room) then
    raise exception 'Room retention is unavailable' using errcode='42501';
  end if;
  permitted:=coalesce(sectalk_private.st_v6_room_role(p_room)='owner'
    or sectalk_private.st_v2_role(target.workspace_id,auth.uid()) in ('owner','admin'),false);
  if p_action<>'read' then
    if not permitted or not verified then raise exception 'Verified room owner access is required' using errcode='42501'; end if;
    perform sectalk_private.limit_action('v6_room_retirement',15);
    select * into target from public.st_v6_rooms where id=p_room for update;
    if not found or not sectalk_private.st_v6_room_directory(p_room) or not coalesce(
      sectalk_private.st_v6_room_role(p_room)='owner'
        or sectalk_private.st_v2_role(target.workspace_id,auth.uid()) in ('owner','admin'),false)
    then raise exception 'Room retention is unavailable' using errcode='42501'; end if;
    perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-workspace-hold:'||target.workspace_id::text,0));
    if p_action='schedule' then
      if not target.archived then raise exception 'Archive the room before scheduling deletion'; end if;
      insert into sectalk_private.st_v6_room_retirements(room_id,requested_by) values(p_room,auth.uid()) on conflict do nothing;
      if found then
        insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
          values(target.workspace_id,auth.uid(),'room.deletion_scheduled',p_room);
      end if;
    else
      delete from sectalk_private.st_v6_room_retirements where room_id=p_room;
      if found then
        insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
          values(target.workspace_id,auth.uid(),'room.deletion_cancelled',p_room);
      end if;
    end if;
  end if;
  select requested_at into requested from sectalk_private.st_v6_room_retirements where room_id=p_room;
  wait_days:=sectalk_private.st_v6_room_retention_days(target.workspace_id);
  return jsonb_build_object('retention_days',wait_days,'can_manage',permitted,'verified',verified,
    'held',permitted and verified and requested is not null and sectalk_private.st_v6_room_is_held(target.workspace_id,p_room),
    'requested_at',requested,'eligible_at',requested+make_interval(days=>wait_days));
end $$;

create function sectalk_private.st_v6_cancel_restored_room_retirement()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if old.archived and not new.archived then
    delete from sectalk_private.st_v6_room_retirements where room_id=new.id;
  end if;
  return new;
end $$;
create trigger st_v6_cancel_restored_room_retirement after update of archived on public.st_v6_rooms
  for each row execute function sectalk_private.st_v6_cancel_restored_room_retirement();

create function sectalk_private.st_v6_purge_retired_rooms()
returns integer language plpgsql security definer set search_path='' as $$
declare candidate record;
declare total integer:=0;
begin
  for candidate in
    select r.id,r.workspace_id,q.requested_at,q.requested_by
    from sectalk_private.st_v6_room_retirements q join public.st_v6_rooms r on r.id=q.room_id
    where q.requested_at<clock_timestamp()-interval '7 days' and r.archived
      and q.requested_at+make_interval(days=>sectalk_private.st_v6_room_retention_days(r.workspace_id))<=clock_timestamp()
      and not sectalk_private.st_v6_room_is_held(r.workspace_id,r.id)
    order by q.requested_at,r.id limit 25 for update of r skip locked
  loop
    begin
      perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-workspace-hold:'||candidate.workspace_id::text,0));
      if candidate.requested_at+make_interval(days=>sectalk_private.st_v6_room_retention_days(candidate.workspace_id))
        >clock_timestamp() then continue; end if;
      delete from public.st_v6_rooms where id=candidate.id and archived;
      if not found then continue; end if;
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      select candidate.workspace_id,coalesce(p.id,w.owner),'room.purged',candidate.id
      from public.st_v2_workspaces w left join public.st_profiles p on p.id=candidate.requested_by
      where w.id=candidate.workspace_id;
      total:=total+1;
    exception when raise_exception then
      if sqlerrm not in ('A workspace retention hold protects this scope','A workspace retention hold protects this message')
      then raise; end if;
    end;
  end loop;
  return total;
end $$;

revoke all on function sectalk_private.st_v6_room_retention_days(uuid),
  sectalk_private.st_v6_retirement_has_mfa(),sectalk_private.st_v6_cancel_restored_room_retirement(),
  sectalk_private.st_v6_purge_retired_rooms() from public,anon,authenticated,service_role;
revoke all on function public.st_v6_room_retention_policy(uuid,integer),public.st_v6_room_retirement(uuid,text)
  from public,anon,authenticated;
grant execute on function public.st_v6_room_retention_policy(uuid,integer),public.st_v6_room_retirement(uuid,text)
  to authenticated;
select cron.schedule('sectalk-v6-purge-retired-rooms','21 * * * *','select sectalk_private.st_v6_purge_retired_rooms()');

commit;
