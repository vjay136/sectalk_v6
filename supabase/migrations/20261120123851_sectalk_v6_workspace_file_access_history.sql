begin;

create table sectalk_private.st_v6_workspace_file_history_policy (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  enabled boolean not null
);
create table sectalk_private.st_v6_workspace_file_history_subjects (
  workspace uuid not null,
  id uuid not null,
  uploader uuid not null,
  filename text not null,
  published_at timestamptz not null,
  removed_at timestamptz,
  primary key(workspace,id)
);
create index st_v6_workspace_file_subject_recent on sectalk_private.st_v6_workspace_file_history_subjects(workspace,published_at desc,id);
create table sectalk_private.st_v6_workspace_retired_file_ids (
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  id uuid not null,
  primary key(workspace,id)
);
create table sectalk_private.st_v6_workspace_file_events (
  id bigint generated always as identity primary key,
  workspace uuid not null,
  file_id uuid not null,
  actor uuid not null,
  event text not null check(event in ('published','view','download','share')),
  occurred_at timestamptz not null default clock_timestamp(),
  bucket timestamptz,
  foreign key(workspace,file_id) references sectalk_private.st_v6_workspace_file_history_subjects(workspace,id) on delete cascade
);
create index st_v6_workspace_file_event_recent on sectalk_private.st_v6_workspace_file_events(workspace,file_id,occurred_at desc,id desc);
create index st_v6_workspace_file_event_age on sectalk_private.st_v6_workspace_file_events(occurred_at,id);
create unique index st_v6_workspace_file_event_coalesce on sectalk_private.st_v6_workspace_file_events(workspace,file_id,actor,event,bucket)
  where bucket is not null;
alter table sectalk_private.st_v6_workspace_file_history_policy enable row level security;
alter table sectalk_private.st_v6_workspace_file_history_subjects enable row level security;
alter table sectalk_private.st_v6_workspace_retired_file_ids enable row level security;
alter table sectalk_private.st_v6_workspace_file_events enable row level security;
revoke all on sectalk_private.st_v6_workspace_file_history_policy,sectalk_private.st_v6_workspace_file_history_subjects,
  sectalk_private.st_v6_workspace_file_events,sectalk_private.st_v6_workspace_retired_file_ids
  from public,anon,authenticated,service_role;

insert into sectalk_private.st_v6_workspace_file_history_subjects(workspace,id,uploader,filename,published_at,removed_at)
  select workspace,id,uploader,filename,published_at,deleted_at
  from sectalk_private.st_v6_workspace_files where published_at is not null;

create function sectalk_private.st_v6_track_workspace_file_history_subject()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.published_at is null then return null; end if;
  insert into sectalk_private.st_v6_workspace_file_history_subjects(workspace,id,uploader,filename,published_at,removed_at)
    values(new.workspace,new.id,new.uploader,new.filename,new.published_at,new.deleted_at)
    on conflict(workspace,id) do update set removed_at=excluded.removed_at;
  if tg_op='UPDATE' and old.published_at is null then
    insert into sectalk_private.st_v6_workspace_file_events(workspace,file_id,actor,event)
      values(new.workspace,new.id,new.uploader,'published');
  end if;
  return null;
end
$$;
create trigger st_v6_track_workspace_file_history_subject
  after insert or update of published_at,deleted_at on sectalk_private.st_v6_workspace_files
  for each row execute function sectalk_private.st_v6_track_workspace_file_history_subject();

create function sectalk_private.st_v6_guard_workspace_file_identity()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if tg_op='INSERT' then
    if exists(select 1 from sectalk_private.st_v6_workspace_retired_file_ids r where r.workspace=new.workspace and r.id=new.id)
      then raise exception 'Choose a new workspace file identifier.' using errcode='PT409'; end if;
    return new;
  end if;
  if old.published_at is not null and exists(select 1 from public.st_v2_workspaces w where w.id=old.workspace) then
    insert into sectalk_private.st_v6_workspace_retired_file_ids(workspace,id) values(old.workspace,old.id)
      on conflict do nothing;
  end if;
  return old;
end
$$;
create trigger st_v6_guard_workspace_file_identity before insert or delete on sectalk_private.st_v6_workspace_files
  for each row execute function sectalk_private.st_v6_guard_workspace_file_identity();

create function public.st_v6_record_workspace_file_access(p_workspace uuid,p_file uuid,p_actor uuid,p_event text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare target sectalk_private.st_v6_workspace_files;
declare event_bucket timestamptz;
begin
  if p_event is null or p_event not in ('view','download','share') or
    not coalesce(sectalk_private.st_v2_active(p_actor),false) or
    sectalk_private.st_v2_role(p_workspace,p_actor) is null then return null; end if;
  select * into target from sectalk_private.st_v6_workspace_files f
    where f.workspace=p_workspace and f.id=p_file and f.published_at is not null and f.deleted_at is null for share;
  if not found then return null; end if;
  if p_event='view' then
    event_bucket:=date_bin(interval '5 minutes',statement_timestamp(),'2000-01-01T00:00:00Z'::timestamptz);
  elsif p_event='share' then
    event_bucket:=date_bin(interval '1 minute',statement_timestamp(),'2000-01-01T00:00:00Z'::timestamptz);
  end if;
  insert into sectalk_private.st_v6_workspace_file_events(workspace,file_id,actor,event,bucket)
    values(p_workspace,p_file,p_actor,p_event,event_bucket) on conflict do nothing;
  return jsonb_build_object('filename',target.filename,'size_bytes',target.size_bytes);
end
$$;

create function public.st_v6_workspace_file_history_policy_status(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select case when sectalk_private.st_v6_holds_access(p_workspace)='none' then null
    else jsonb_build_object('enabled',coalesce((select p.enabled from sectalk_private.st_v6_workspace_file_history_policy p
        where p.workspace=p_workspace),false),
      'can_manage',sectalk_private.st_v2_role(p_workspace,auth.uid())='owner'
        and sectalk_private.st_v6_holds_access(p_workspace)='verified') end
$$;

create function public.st_v6_set_workspace_file_history_policy(p_workspace uuid,p_enabled boolean)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  if p_enabled is null or sectalk_private.st_v6_holds_access(p_workspace)<>'verified'
    or sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner' then
    raise exception 'Verified workspace ownership is required.' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v6_workspace_file_history_policy',12);
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

create function sectalk_private.st_v6_can_read_workspace_file_history(p_workspace uuid,p_uploader uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce(sectalk_private.st_v2_active(auth.uid()),false) and
    sectalk_private.st_v2_role(p_workspace,auth.uid()) is not null and
    (p_uploader=auth.uid() or (sectalk_private.st_v6_holds_access(p_workspace)='verified' and exists(
      select 1 from sectalk_private.st_v6_workspace_file_history_policy p where p.workspace=p_workspace and p.enabled
    )))
$$;

create function public.st_v6_workspace_file_history_list(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select coalesce(jsonb_agg(to_jsonb(items) order by items.published_at desc,items.id),'[]'::jsonb)
  from (
    select s.id,s.filename,s.published_at,s.removed_at
    from sectalk_private.st_v6_workspace_file_history_subjects s where s.workspace=p_workspace
      and sectalk_private.st_v6_can_read_workspace_file_history(p_workspace,s.uploader)
      and (s.removed_at is null or s.removed_at>now()-interval '90 days')
    order by s.published_at desc,s.id limit 100
  ) items
$$;

create function public.st_v6_workspace_file_access_history(p_workspace uuid,p_file uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('filename',s.filename,'removed_at',s.removed_at,'events',coalesce((
    select jsonb_agg(jsonb_build_object('event',e.event,'actor',coalesce(p.name,'Former account'),
        'self',e.actor=auth.uid(),'occurred_at',e.occurred_at) order by e.occurred_at desc,e.id desc)
    from (
      select a.id,a.event,a.actor,a.occurred_at from sectalk_private.st_v6_workspace_file_events a
      where a.workspace=p_workspace and a.file_id=p_file and a.occurred_at>now()-interval '90 days'
      order by a.occurred_at desc,a.id desc limit 50
    ) e left join public.st_profiles p on p.id=e.actor
  ),'[]'::jsonb))
  from sectalk_private.st_v6_workspace_file_history_subjects s where s.workspace=p_workspace and s.id=p_file
    and sectalk_private.st_v6_can_read_workspace_file_history(p_workspace,s.uploader)
    and (s.removed_at is null or s.removed_at>now()-interval '90 days')
$$;

create function public.st_v6_prune_workspace_file_history()
returns void language plpgsql security definer set search_path='' as $$
begin
  delete from sectalk_private.st_v6_workspace_file_events a where a.id in (
    select e.id from sectalk_private.st_v6_workspace_file_events e where e.occurred_at<=now()-interval '90 days'
    order by e.occurred_at,e.id limit 400 for update skip locked
  );
  delete from sectalk_private.st_v6_workspace_file_history_subjects s where (s.workspace,s.id) in (
    select a.workspace,a.id from sectalk_private.st_v6_workspace_file_history_subjects a
    where a.published_at<=now()-interval '90 days'
      and not exists(select 1 from sectalk_private.st_v6_workspace_files f where f.workspace=a.workspace and f.id=a.id)
      and not exists(select 1 from sectalk_private.st_v6_workspace_file_events e where e.workspace=a.workspace and e.file_id=a.id)
    order by a.published_at,a.workspace,a.id limit 100 for update skip locked
  );
end
$$;

revoke all on function sectalk_private.st_v6_track_workspace_file_history_subject(),
  sectalk_private.st_v6_guard_workspace_file_identity(),
  sectalk_private.st_v6_can_read_workspace_file_history(uuid,uuid),public.st_v6_record_workspace_file_access(uuid,uuid,uuid,text),
  public.st_v6_workspace_file_history_policy_status(uuid),public.st_v6_set_workspace_file_history_policy(uuid,boolean),
  public.st_v6_workspace_file_history_list(uuid), public.st_v6_workspace_file_access_history(uuid,uuid),
  public.st_v6_prune_workspace_file_history() from public,anon,authenticated,service_role;
grant execute on function public.st_v6_record_workspace_file_access(uuid,uuid,uuid,text),
  public.st_v6_prune_workspace_file_history() to service_role;
grant execute on function public.st_v6_workspace_file_history_policy_status(uuid),public.st_v6_set_workspace_file_history_policy(uuid,boolean),
  public.st_v6_workspace_file_history_list(uuid),public.st_v6_workspace_file_access_history(uuid,uuid) to authenticated;

commit;
