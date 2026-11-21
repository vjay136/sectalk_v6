begin;

create table sectalk_private.st_v8_offboarding_source_batches (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null,
  workspace uuid not null,
  owner_id uuid not null,
  reviewer_id uuid not null check(reviewer_id<>owner_id),
  manifest jsonb not null check(jsonb_typeof(manifest)='array' and jsonb_array_length(manifest) between 2 and 4),
  sha256 text not null check(sha256~'^[0-9a-f]{64}$'),
  created_at timestamptz not null default clock_timestamp(),
  unique(request_id,sha256)
);
create table sectalk_private.st_v8_offboarding_source_batch_decisions (
  batch uuid not null references sectalk_private.st_v8_offboarding_source_batches,
  action text not null check(action in ('approved','deleted')),
  actor uuid not null,
  happened_at timestamptz not null default clock_timestamp(),
  primary key(batch,action)
);
create trigger st_v8_source_batch_immutable before update or delete on sectalk_private.st_v8_offboarding_source_batches
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_source_batch_decision_immutable before update or delete on sectalk_private.st_v8_offboarding_source_batch_decisions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_source_batches enable row level security;
alter table sectalk_private.st_v8_offboarding_source_batch_decisions enable row level security;
revoke all on sectalk_private.st_v8_offboarding_source_batches,sectalk_private.st_v8_offboarding_source_batch_decisions
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_offboarding_source_batch_item(p_workspace uuid,p_kind text,p_scope uuid,
  p_record uuid,p_action text,p_plan uuid,p_sha256 text)
returns jsonb language plpgsql set search_path='' as $$
begin
  case p_kind
    when 'workspace_task' then return public.st_v8_offboarding_task_delete(
      p_workspace,p_record,p_action,p_workspace::text,p_plan,p_sha256);
    when 'channel_message' then return public.st_v8_offboarding_post_delete(
      p_workspace,p_scope,p_record,p_action,p_workspace::text,p_plan,p_sha256);
    when 'room_message' then return public.st_v8_offboarding_room_post_delete(
      p_workspace,p_scope,p_record,p_action,p_workspace::text,p_plan,p_sha256);
    when 'room_task' then return public.st_v8_offboarding_room_task_delete(
      p_workspace,p_scope,p_record,p_action,p_workspace::text,p_plan,p_sha256);
    else raise exception 'Unsupported deletion source' using errcode='22023';
  end case;
end $$;

create function sectalk_private.st_v8_offboarding_source_batch_item_deleted(p_kind text,p_plan uuid)
returns boolean language sql stable set search_path='' as $$
  select exists(
    select 1 from sectalk_private.st_v8_offboarding_task_decisions where p_kind='workspace_task' and deletion=p_plan and action='deleted'
    union all
    select 1 from sectalk_private.st_v8_offboarding_post_decisions where p_kind='channel_message' and deletion=p_plan and action='deleted'
    union all
    select 1 from sectalk_private.st_v8_offboarding_room_post_decisions where p_kind='room_message' and deletion=p_plan and action='deleted'
    union all
    select 1 from sectalk_private.st_v8_offboarding_room_task_decisions where p_kind='room_task' and deletion=p_plan and action='deleted')
$$;

create function public.st_v8_offboarding_source_batch_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare
  r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  candidates jsonb:='[]';
begin
  if auth.uid()=r.requester then
    select coalesce(jsonb_agg(to_jsonb(source) order by source.kind,source.title,source.id),'[]') into candidates from (
      select 'workspace_task' as kind,p_workspace as scope,(x->>'id')::uuid as id,x->>'title' as title
      from jsonb_array_elements(public.st_v8_offboarding_task_status(p_workspace)->'tasks') x
      where x->'copied'='true'
      union all
      select 'channel_message',(x->>'channel')::uuid,(x->>'id')::uuid,x->>'name'
      from jsonb_array_elements(public.st_v8_offboarding_post_status(p_workspace)->'posts') x
      where x->'copied'='true'
      union all
      select 'room_message',(x->>'room')::uuid,(x->>'id')::uuid,x->>'name'
      from jsonb_array_elements(public.st_v8_offboarding_room_post_status(p_workspace)->'posts') x
      where x->'copied'='true'
      union all
      select 'room_task',(x->>'room')::uuid,(x->>'id')::uuid,x->>'title'
      from jsonb_array_elements(public.st_v8_offboarding_room_task_status(p_workspace)->'tasks') x
      where x->'copied'='true'
    ) source;
  end if;
  return jsonb_build_object('held',sectalk_private.st_v8_offboarding_holds(p_workspace),'candidates',candidates,
    'batches',coalesce((select jsonb_agg(to_jsonb(x) order by x."createdAt" desc,x.id) from (
      select b.id,b.manifest,b.sha256,b.created_at as "createdAt",a.happened_at as "approvedAt",d.happened_at as "deletedAt"
      from sectalk_private.st_v8_offboarding_source_batches b
      left join sectalk_private.st_v8_offboarding_source_batch_decisions a on (a.batch,a.action)=(b.id,'approved')
      left join sectalk_private.st_v8_offboarding_source_batch_decisions d on (d.batch,d.action)=(b.id,'deleted')
      where (b.request_id,b.workspace,b.owner_id,b.reviewer_id)=(r.id,p_workspace,r.requester,r.reviewer)
      order by b.created_at desc,b.id limit 20
    ) x),'[]'));
end $$;

create function public.st_v8_offboarding_source_batch(
  p_workspace uuid,p_action text,p_confirmation text,p_sources jsonb default null,p_batch uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  batch sectalk_private.st_v8_offboarding_source_batches; source record; response jsonb;
  manifest jsonb:='[]'; fingerprint text; approved_at timestamptz; deleted_at timestamptz;
begin
  if p_workspace is null or p_confirmation is distinct from p_workspace::text
    or p_action is null or p_action not in ('capture','approve','delete') then raise insufficient_privilege; end if;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if actor is distinct from (case when p_action='approve' then r.reviewer else r.requester end)
    then raise insufficient_privilege; end if;
  -- Use the native item lock order before adding any batch locks.
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if actor is distinct from (case when p_action='approve' then r.reviewer else r.requester end)
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_offboarding_source_batch',4);

  if p_action='capture' then
    if p_batch is not null or p_sha256 is not null or jsonb_typeof(p_sources) is distinct from 'array' then
      raise exception 'Select exact approved sources for capture' using errcode='22023';
    end if;
    if jsonb_array_length(p_sources) not between 2 and 4 then
      raise exception 'Select between two and four sources' using errcode='22023';
    end if;
    if exists(select 1 from jsonb_array_elements(p_sources) x where jsonb_typeof(x) is distinct from 'object') then
      raise exception 'Each source must be an exact object' using errcode='22023';
    end if;
    if exists(select 1 from jsonb_array_elements(p_sources) x where (x-'kind'-'scope'-'id')<>'{}'
      or coalesce(x->>'kind','') not in ('workspace_task','channel_message','room_message','room_task')
      or coalesce(x->>'scope','') !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
      or coalesce(x->>'id','') !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
      or (x->>'kind'='workspace_task' and x->>'scope' is distinct from p_workspace::text)) then
      raise exception 'A source kind, scope or ID is invalid' using errcode='22023';
    end if;
    if exists(select 1 from jsonb_array_elements(p_sources) x group by x->>'kind',x->>'id' having count(*)>1) then
      raise exception 'Select each exact source once' using errcode='22023';
    end if;
    for source in select x->>'kind' as kind,(x->>'scope')::uuid as scope,(x->>'id')::uuid as id
        from jsonb_array_elements(p_sources) x order by 1,2,3
    loop
      response:=sectalk_private.st_v8_offboarding_source_batch_item(p_workspace,source.kind,source.scope,source.id,'capture',null,null);
      if response->>'plan' is null or response->>'sha256' is null or response->>'deletedAt' is not null then
        raise exception 'A source cannot be prepared for review' using errcode='PT409';
      end if;
      manifest:=manifest||jsonb_build_array(jsonb_build_object('kind',source.kind,'scope',source.scope,'id',source.id,
        'plan',response->>'plan','sha256',response->>'sha256'));
    end loop;
    fingerprint:=encode(sha256(convert_to(jsonb_build_array('sectalk-offboarding-source-batch-v1',
      p_workspace,r.id,r.requester,r.reviewer,manifest)::text,'UTF8')),'hex');
    insert into sectalk_private.st_v8_offboarding_source_batches(request_id,workspace,owner_id,reviewer_id,manifest,sha256)
      values(r.id,p_workspace,r.requester,r.reviewer,manifest,fingerprint) on conflict do nothing;
    select b.* into strict batch from sectalk_private.st_v8_offboarding_source_batches b
      where (b.request_id,b.sha256)=(r.id,fingerprint);
  else
    if p_sources is not null or p_batch is null or p_sha256 is null then
      raise exception 'Confirm the exact batch and digest' using errcode='PT409';
    end if;
    select b.* into batch from sectalk_private.st_v8_offboarding_source_batches b
      where (b.id,b.request_id,b.workspace,b.owner_id,b.reviewer_id,b.sha256)=
        (p_batch,r.id,p_workspace,r.requester,r.reviewer,p_sha256) for update;
    if batch.id is null then raise exception 'Confirm the exact batch and digest' using errcode='PT409'; end if;
    select d.happened_at into approved_at from sectalk_private.st_v8_offboarding_source_batch_decisions d
      where (d.batch,d.action,d.actor)=(batch.id,'approved',r.reviewer);
    select d.happened_at into deleted_at from sectalk_private.st_v8_offboarding_source_batch_decisions d
      where (d.batch,d.action,d.actor)=(batch.id,'deleted',r.requester);
    if deleted_at is null then
      if p_action='delete' and approved_at is null then raise insufficient_privilege; end if;
      for source in select x->>'kind' as kind,(x->>'scope')::uuid as scope,(x->>'id')::uuid as id,
          (x->>'plan')::uuid as plan,x->>'sha256' as sha256
          from jsonb_array_elements(batch.manifest) with ordinality as entries(x,position) order by position
      loop
        if sectalk_private.st_v8_offboarding_source_batch_item_deleted(source.kind,source.plan) then
          raise exception 'A source was already removed outside this batch' using errcode='PT409';
        end if;
        response:=sectalk_private.st_v8_offboarding_source_batch_item(p_workspace,source.kind,source.scope,source.id,
          p_action,source.plan,source.sha256);
        if response->>'plan' is distinct from source.plan::text or response->>'sha256' is distinct from source.sha256
          or response->>'approvedAt' is null or (p_action='delete' and response->>'deletedAt' is null) then
          raise exception 'A source failed to confirm its exact batch action' using errcode='PT409';
        end if;
      end loop;
      if p_action='approve' and approved_at is null then
        insert into sectalk_private.st_v8_offboarding_source_batch_decisions(batch,action,actor)
          values(batch.id,'approved',actor) returning happened_at into approved_at;
      elsif p_action='delete' then
        insert into sectalk_private.st_v8_offboarding_source_batch_decisions(batch,action,actor)
          values(batch.id,'deleted',actor) returning happened_at into deleted_at;
      end if;
    end if;
  end if;
  return jsonb_build_object('batch',batch.id,'manifest',batch.manifest,'sha256',batch.sha256,'approvedAt',approved_at,'deletedAt',deleted_at);
end $$;

revoke all on function sectalk_private.st_v8_offboarding_source_batch_item(uuid,text,uuid,uuid,text,uuid,text),
  sectalk_private.st_v8_offboarding_source_batch_item_deleted(text,uuid),public.st_v8_offboarding_source_batch_status(uuid),
  public.st_v8_offboarding_source_batch(uuid,text,text,jsonb,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_source_batch_status(uuid),
  public.st_v8_offboarding_source_batch(uuid,text,text,jsonb,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
