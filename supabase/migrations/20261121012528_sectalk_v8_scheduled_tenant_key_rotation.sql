begin;

create table sectalk_private.st_v8_tenant_rotation_schedules (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  days integer not null check(days in (30,60,90)),
  authorized_by uuid not null,
  revision uuid not null default gen_random_uuid(),
  saved_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v8_tenant_rotation_schedules enable row level security;
revoke all on sectalk_private.st_v8_tenant_rotation_schedules from public,anon,authenticated,service_role;

alter table sectalk_private.st_v7_tenant_key_audit drop constraint st_v7_tenant_key_audit_event_check;
alter table sectalk_private.st_v7_tenant_key_audit add constraint st_v7_tenant_key_audit_event_check
  check(event in ('provisioned','rotated','destroy_requested','destroyed','rejected',
    'rotation_schedule_set','rotation_schedule_disabled','scheduled_rotation'));

create function sectalk_private.st_v8_scheduled_rotation_allowed(p_workspace uuid,p_actor uuid)
returns boolean language sql stable set search_path='' as $$
  select sectalk_private.st_v2_role(p_workspace,p_actor)='owner'
    and sectalk_private.st_v2_active(p_actor) is true
    and not exists(select 1 from sectalk_private.st_v7_tenant_key_destroy d
      where d.workspace=p_workspace and d.result is null)
    and not exists(select 1 from sectalk_private.st_v8_offboarding_requests r
      where r.workspace=p_workspace and r.state='read_only');
$$;

create function public.st_v8_tenant_rotation_schedule(p_workspace uuid,p_days integer default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_tenant_key_role(p_workspace);
  actor uuid:=auth.uid(); current_key record;
begin
  if p_days is not null then
    if access is distinct from 'owner' then
      raise exception 'Fresh workspace owner verification required' using errcode='42501';
    end if;
    if p_days not in (0,30,60,90) then
      raise exception 'Choose an available rotation interval' using errcode='22023';
    end if;
    perform sectalk_private.limit_action('v8_set_tenant_rotation_schedule',8);
    perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
    select s.current_version,s.destroyed_at,k.custody into current_key
      from sectalk_private.st_v7_tenant_key_state s left join sectalk_private.st_v7_tenant_key_versions k
        on (k.workspace,k.version)=(s.workspace,s.current_version) where s.workspace=p_workspace;
    if p_days=0 then
      delete from sectalk_private.st_v8_tenant_rotation_schedules where workspace=p_workspace;
      if found then
        insert into sectalk_private.st_v7_tenant_key_audit(workspace,actor,event,version)
          values(p_workspace,actor,'rotation_schedule_disabled',current_key.current_version);
      end if;
    else
      if current_key.custody is distinct from 'managed' or current_key.destroyed_at is not null
        or sectalk_private.st_v8_scheduled_rotation_allowed(p_workspace,actor) is not true then
        raise exception 'An active managed key is required' using errcode='PT409';
      end if;
      insert into sectalk_private.st_v8_tenant_rotation_schedules as s(workspace,days,authorized_by)
        values(p_workspace,p_days,actor) on conflict(workspace) do update
        set days=excluded.days,authorized_by=excluded.authorized_by,
          saved_at=excluded.saved_at,revision=excluded.revision
        where (s.days,s.authorized_by) is distinct from (excluded.days,excluded.authorized_by);
      if found then
        insert into sectalk_private.st_v7_tenant_key_audit(workspace,actor,event,version,reason)
          values(p_workspace,actor,'rotation_schedule_set',current_key.current_version,'Every '||p_days||' days');
      end if;
    end if;
  end if;
  if access not in ('owner','admin') then return jsonb_build_object('access',access); end if;

  return jsonb_build_object('access',access,'schedule',(select jsonb_build_object(
    'days',p.days,'paused',coalesce(s.destroyed_at is not null or k.custody is distinct from 'managed'
      or sectalk_private.st_v8_scheduled_rotation_allowed(p.workspace,p.authorized_by) is not true,true),
    'next',greatest(p.saved_at,k.created_at)+make_interval(days=>p.days))
    from sectalk_private.st_v8_tenant_rotation_schedules p
      left join sectalk_private.st_v7_tenant_key_state s on s.workspace=p.workspace
      left join sectalk_private.st_v7_tenant_key_versions k on (k.workspace,k.version)=(s.workspace,s.current_version)
    where p.workspace=p_workspace));
end $$;

create function public.st_v8_due_tenant_key_rotations()
returns table(workspace uuid,version integer,revision uuid)
language sql stable security definer set search_path='' as $$
  select p.workspace,s.current_version,p.revision
  from sectalk_private.st_v8_tenant_rotation_schedules p
  join sectalk_private.st_v7_tenant_key_state s on s.workspace=p.workspace
  join sectalk_private.st_v7_tenant_key_versions k on (k.workspace,k.version)=(s.workspace,s.current_version)
  where s.destroyed_at is null and k.custody='managed'
    and greatest(p.saved_at,k.created_at)+make_interval(days=>p.days)<=statement_timestamp()
    and sectalk_private.st_v8_scheduled_rotation_allowed(p.workspace,p.authorized_by)
  order by greatest(p.saved_at,k.created_at)+make_interval(days=>p.days),p.workspace
  limit 32;
$$;

create function public.st_v8_commit_scheduled_tenant_key_rotation(
  p_workspace uuid,p_previous integer,p_revision uuid,p_wrapped text
) returns boolean language plpgsql security definer set search_path='' as $$
declare policy sectalk_private.st_v8_tenant_rotation_schedules;
  current_key sectalk_private.st_v7_tenant_key_versions;
begin
  if p_workspace is null or p_previous is null or p_previous<1 or p_previous>=2147483647
    or p_revision is null or p_wrapped is null or p_wrapped !~ '^[A-Za-z0-9_-]{80}$' then return false; end if;
  perform 1 from public.st_v2_workspaces where id=p_workspace for share;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
  select * into policy from sectalk_private.st_v8_tenant_rotation_schedules
    where workspace=p_workspace and revision=p_revision;
  if not found then return false; end if;
  select k.* into current_key from sectalk_private.st_v7_tenant_key_state s
    join sectalk_private.st_v7_tenant_key_versions k on (k.workspace,k.version)=(s.workspace,s.current_version)
    where s.workspace=p_workspace and s.current_version=p_previous and s.destroyed_at is null and k.custody='managed';
  if not found or greatest(policy.saved_at,current_key.created_at)+make_interval(days=>policy.days)>statement_timestamp()
    or sectalk_private.st_v8_scheduled_rotation_allowed(p_workspace,policy.authorized_by) is not true then return false; end if;

  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,wrapped)
    values(p_workspace,p_previous+1,'managed',p_wrapped);
  update sectalk_private.st_v7_tenant_key_state set current_version=p_previous+1 where workspace=p_workspace;
  insert into sectalk_private.st_v7_tenant_key_audit(workspace,actor,event,version,reason)
    values(p_workspace,policy.authorized_by,'scheduled_rotation',p_previous+1,'Activated by the authorized workspace schedule');
  return true;
end $$;

create or replace function public.st_v7_request_tenant_key_destroy(p_workspace uuid,p_confirmation text,p_reason text)
returns uuid language plpgsql security definer set search_path='' as $$
declare task uuid; ver integer; note text:=btrim(p_reason);
begin
  if sectalk_private.st_v7_tenant_key_role(p_workspace)<>'owner' or not exists(
    select 1 from sectalk_private.st_v7_tenant_destroy_reviewers q
    where q.workspace=p_workspace and sectalk_private.st_v2_role(p_workspace,q.actor)='admin')
  then raise exception 'Destruction requires a verified owner and assigned independent reviewer' using errcode='42501'; end if;
  if p_confirmation is distinct from p_workspace::text or note is null or char_length(note) not between 15 and 240 then
    raise exception 'Confirm the exact workspace ID and enter the reason' using errcode='22023'; end if;
  perform sectalk_private.limit_action('v7_request_tenant_key_destroy',4);
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
  select current_version into ver from sectalk_private.st_v7_tenant_key_state where workspace=p_workspace and destroyed_at is null;
  if ver is null then raise exception 'There is no active protected key to destroy' using errcode='PT409'; end if;
  insert into sectalk_private.st_v7_tenant_key_destroy(workspace,requester,reason,version)
    values(p_workspace,auth.uid(),note,ver) returning id into task;
  insert into sectalk_private.st_v7_tenant_key_audit(workspace,actor,event,version,reason)
    values(p_workspace,auth.uid(),'destroy_requested',ver,note);
  return task;
end $$;

revoke all on function sectalk_private.st_v8_scheduled_rotation_allowed(uuid,uuid),
  public.st_v8_tenant_rotation_schedule(uuid,integer),public.st_v8_due_tenant_key_rotations(),
  public.st_v8_commit_scheduled_tenant_key_rotation(uuid,integer,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_tenant_rotation_schedule(uuid,integer) to authenticated;
grant execute on function public.st_v8_due_tenant_key_rotations(),
  public.st_v8_commit_scheduled_tenant_key_rotation(uuid,integer,uuid,text) to service_role;

commit;
