begin;

create index st_v8_room_files_offboarding_scope on sectalk_private.st_v6_room_files(workspace,room,id);

create table sectalk_private.st_v8_offboarding_storage_plans (
  id uuid primary key default gen_random_uuid(),
  request uuid not null references sectalk_private.st_v8_offboarding_requests(id) on delete cascade,
  requester uuid not null,
  reviewer uuid not null check(reviewer<>requester),
  captured_at timestamptz not null default clock_timestamp(),
  reviewed_at timestamptz,
  snapshot jsonb not null check(jsonb_typeof(snapshot)='object'),
  sha256 text not null check(sha256~'^[0-9a-f]{64}$')
);
create index st_v8_offboarding_storage_latest on sectalk_private.st_v8_offboarding_storage_plans(request,captured_at desc,id desc);
alter table sectalk_private.st_v8_offboarding_storage_plans enable row level security;
revoke all on sectalk_private.st_v8_offboarding_storage_plans from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_offboarding_storage_snapshot(p_workspace uuid)
returns jsonb language sql stable set search_path='' set timezone='UTC' as $$
  with workspace_files as materialized (
    select p_workspace::text||'/'||f.id::text as name,f.size_bytes as bytes,f.published_at,f.deleted_at,
      encode(f.fingerprint,'hex') as fingerprint,true as scope_verified
    from sectalk_private.st_v6_workspace_files f where f.workspace=p_workspace order by f.id limit 501
  ), room_files as materialized (
    select p_workspace::text||'/rooms/'||f.room::text||'/'||f.id::text as name,f.size_bytes as bytes,f.published_at,f.deleted_at,
      f.sha256 as fingerprint,(r.id is not null) as scope_verified
    from sectalk_private.st_v6_room_files f left join public.st_v6_rooms r on (r.id,r.workspace_id)=(f.room,f.workspace)
    where f.workspace=p_workspace order by f.room,f.id limit 501
  ), records as materialized (
    select * from workspace_files union all select * from room_files
  ), objects as materialized (
    select o.name,o.id,o.version,o.metadata->>'size' as bytes,o.updated_at
    from storage.objects o
    where o.bucket_id='sectalk-workspace-files' and o.name like p_workspace::text||'/%'
    order by o.name limit 501
  ), matched as (
    select coalesce(r.name,o.name) as name,r.bytes as registered_bytes,r.published_at,r.deleted_at,r.fingerprint,
      o.id as object_id,o.version,o.bytes as object_bytes,o.updated_at,
      case when r.name is null then 'untracked'
           when r.published_at is null and r.deleted_at is null then 'pending'
           when o.id is null and r.deleted_at is not null then 'removed'
           when o.id is null then 'missing'
           when not r.scope_verified or nullif(btrim(o.version),'') is null or o.bytes is distinct from r.bytes::text then 'mismatch'
           when r.deleted_at is not null then 'retained'
           else 'published' end as status
    from records r full join objects o using(name)
  )
  select jsonb_build_object('format','sectalk-offboarding-current-storage-v1','bucket','sectalk-workspace-files',
    'workspace',p_workspace,'limitExceeded',(select count(*) from records)>500 or (select count(*) from objects)>500,
    'counts',jsonb_build_object('published',count(*) filter(where status='published'),
      'retained',count(*) filter(where status='retained'),'removed',count(*) filter(where status='removed'),
      'pending',count(*) filter(where status='pending'),'missing',count(*) filter(where status='missing'),
      'mismatch',count(*) filter(where status='mismatch'),'untracked',count(*) filter(where status='untracked')),
    'items',coalesce(jsonb_agg(to_jsonb(matched) order by matched.name),'[]'::jsonb))
    from matched;
$$;

create function public.st_v8_offboarding_storage_plan(p_workspace uuid,p_action text default 'status',
  p_plan uuid default null,p_confirmation text default null,p_sha256 text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); access_kind text; request_row sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_storage_plans; current_snapshot jsonb; current_digest text;
  held boolean; clean boolean;
begin
  if p_workspace is null or p_action is null or p_action not in ('status','capture','confirm')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not sectalk_private.st_v7_admin_fresh() then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if p_confirmation is distinct from p_workspace::text then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
  end if;
  access_kind:=sectalk_private.st_v8_offboarding_role(p_workspace,actor);
  select r.* into request_row from sectalk_private.st_v8_offboarding_requests r
    where r.workspace=p_workspace and r.state='read_only' and r.integration_shutdown is not null;
  if request_row.id is null or not ((actor=request_row.requester and access_kind='owner')
      or (actor=request_row.reviewer and access_kind='reviewer'))
    or sectalk_private.st_v8_offboarding_role(p_workspace,request_row.requester)<>'owner'
    or sectalk_private.st_v8_offboarding_role(p_workspace,request_row.reviewer)<>'reviewer' then
    raise exception 'Current staged owner and independent reviewer are required' using errcode='42501';
  end if;
  held:=sectalk_private.st_v8_offboarding_holds(p_workspace);
  if p_action<>'status' and held then
    raise exception 'Active preservation holds block Storage review' using errcode='42501';
  end if;
  if p_action<>'status' then perform sectalk_private.limit_action('v8_offboarding_storage_plan',15); end if;
  select s.* into plan from sectalk_private.st_v8_offboarding_storage_plans s where s.request=request_row.id
    order by s.captured_at desc,s.id desc limit 1;
  current_snapshot:=sectalk_private.st_v8_offboarding_storage_snapshot(p_workspace);
  current_digest:=encode(sha256(convert_to(current_snapshot::text,'UTF8')),'hex');
  clean:=not (current_snapshot->>'limitExceeded')::boolean and not exists(
    select 1 from jsonb_each_text(current_snapshot->'counts') c
    where c.key in ('pending','missing','mismatch','untracked') and c.value::integer<>0);
  if p_action='capture' then
    if access_kind<>'owner' then raise insufficient_privilege; end if;
    if (current_snapshot->>'limitExceeded')::boolean then
      raise exception 'Storage inventory exceeds the 500-record capture limit' using errcode='PT409';
    end if;
    if plan.id is null or plan.sha256<>current_digest or plan.captured_at<=statement_timestamp()-interval '24 hours' then
      insert into sectalk_private.st_v8_offboarding_storage_plans(request,requester,reviewer,snapshot,sha256)
        values(request_row.id,actor,request_row.reviewer,current_snapshot,current_digest) returning * into plan;
    end if;
  elsif p_action='confirm' then
    if access_kind<>'reviewer' or plan.id is null or p_plan is distinct from plan.id
      or p_sha256 is distinct from plan.sha256 or current_digest<>plan.sha256 or not clean
      or plan.captured_at<=statement_timestamp()-interval '24 hours' then
      raise exception 'Use the latest unchanged Storage inventory with no unresolved objects' using errcode='PT409';
    end if;
    if plan.reviewed_at is null then
      update sectalk_private.st_v8_offboarding_storage_plans set reviewed_at=clock_timestamp() where id=plan.id returning * into plan;
    end if;
  end if;
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'capturedAt',plan.captured_at,
    'reviewedAt',plan.reviewed_at,'held',held,'clean',clean,'counts',current_snapshot->'counts',
    'limitExceeded',current_snapshot->'limitExceeded',
    'current',coalesce(plan.sha256=current_digest and plan.captured_at>statement_timestamp()-interval '24 hours',false));
end $$;

revoke all on function sectalk_private.st_v8_offboarding_storage_snapshot(uuid),
  public.st_v8_offboarding_storage_plan(uuid,text,uuid,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_storage_plan(uuid,text,uuid,text,text) to authenticated;
notify pgrst,'reload schema';
commit;
