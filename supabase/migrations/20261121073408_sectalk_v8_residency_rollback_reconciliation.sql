begin;

create table sectalk_private.st_v8_residency_rollback_baselines (
  handoff uuid primary key references sectalk_private.st_v8_residency_write_handoffs(handoff) on delete cascade,
  snapshot jsonb not null,
  captured_at timestamptz not null default clock_timestamp()
);
create table sectalk_private.st_v8_residency_rollback_reviews (
  id uuid primary key default gen_random_uuid(),
  handoff uuid not null references sectalk_private.st_v8_residency_rollback_baselines on delete cascade,
  requester uuid not null,
  digest text not null check (digest~'^[0-9a-f]{64}$'),
  changes jsonb not null,
  captured_at timestamptz not null default clock_timestamp(),
  reviewer uuid,
  reviewed_at timestamptz,
  check (reviewer is distinct from requester),
  check ((reviewer is null)=(reviewed_at is null))
);
create index st_v8_residency_rollback_recent_review
  on sectalk_private.st_v8_residency_rollback_reviews(handoff,captured_at desc,id);
alter table sectalk_private.st_v8_residency_rollback_baselines enable row level security;
alter table sectalk_private.st_v8_residency_rollback_reviews enable row level security;
revoke all on sectalk_private.st_v8_residency_rollback_baselines,
  sectalk_private.st_v8_residency_rollback_reviews from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_residency_rollback_snapshot(p_workspace uuid)
returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  with rows_in_scope as (
    (select 'channel'::text kind,c.id,to_jsonb(c) body from public.st_v2_channels c
      where c.workspace_id=p_workspace order by c.id limit 501)
    union all
    (select 'channel_message',p.id,to_jsonb(p) from public.st_v2_posts p
      join public.st_v2_channels c on c.id=p.channel_id where c.workspace_id=p_workspace order by p.id limit 501)
    union all
    (select 'workspace_task',w.id,to_jsonb(w) from public.st_v2_items w
      where w.workspace_id=p_workspace order by w.id limit 501)
    union all
    (select 'room',r.id,to_jsonb(r) from public.st_v6_rooms r
      where r.workspace_id=p_workspace order by r.id limit 501)
    union all
    (select 'room_message',p.id,to_jsonb(p) from public.st_v6_room_posts p
      join public.st_v6_rooms r on r.id=p.room_id where r.workspace_id=p_workspace order by p.id limit 501)
    union all
    (select 'room_task',t.id,to_jsonb(t) from public.st_v6_tasks t
      join public.st_v6_rooms r on r.id=t.room_id where r.workspace_id=p_workspace order by t.id limit 501)
    union all
    (select 'workspace_file',f.id,to_jsonb(f) from sectalk_private.st_v6_workspace_files f
      where f.workspace=p_workspace order by f.id limit 501)
    union all
    (select 'room_file',f.id,to_jsonb(f) from sectalk_private.st_v6_room_files f
      where f.workspace=p_workspace order by f.id limit 501)
    union all
    (select 'storage_object',o.id,to_jsonb(o)-'last_accessed_at' from storage.objects o
      where o.bucket_id='sectalk-workspace-files' and o.name like p_workspace::text||'/%' order by o.id limit 501)
  ), families as (
    select s.kind,count(*)>500 capped,
      jsonb_agg(jsonb_build_array(s.id,encode(sha256(convert_to(s.body::text,'UTF8')),'hex')) order by s.id) records
    from rows_in_scope s group by s.kind
  )
  select coalesce(jsonb_object_agg(f.kind,jsonb_build_object('capped',f.capped,'records',f.records)),'{}'::jsonb) from families f
$$;

create function sectalk_private.st_v8_residency_capture_rollback_baseline()
returns trigger language plpgsql set search_path='' as $$
begin
  insert into sectalk_private.st_v8_residency_rollback_baselines(handoff,snapshot)
    values(new.handoff,sectalk_private.st_v8_residency_rollback_snapshot(new.workspace));
  return new;
end $$;
create trigger st_v8_residency_capture_rollback_baseline after update of phase
  on sectalk_private.st_v8_residency_write_handoffs for each row
  when (old.phase='standby' and new.phase='activated')
  execute function sectalk_private.st_v8_residency_capture_rollback_baseline();

create function sectalk_private.st_v8_residency_rollback_delta(p_baseline jsonb,p_current jsonb)
returns jsonb language sql stable set search_path='' as $$
  with old_rows as (
    select f.key kind,r.item->>0 id,r.item->>1 revision
    from jsonb_each(p_baseline) f cross join lateral jsonb_array_elements(f.value->'records') r(item)
  ), new_rows as (
    select f.key kind,r.item->>0 id,r.item->>1 revision
    from jsonb_each(p_current) f cross join lateral jsonb_array_elements(f.value->'records') r(item)
  ), compared as (
    select kind,id,case when o.id is null then 'added' when n.id is null then 'removed' else 'changed' end state,
      o.revision previous_revision,n.revision current_revision
    from old_rows o full join new_rows n using(kind,id) where o.revision is distinct from n.revision
  )
  select coalesce(jsonb_agg(jsonb_build_object('kind',x.kind,'id',x.id,'state',x.state,
    'before',x.previous_revision,'after',x.current_revision) order by x.kind,x.id),'[]'::jsonb) from compared x
$$;
revoke all on function sectalk_private.st_v8_residency_rollback_snapshot(uuid),
  sectalk_private.st_v8_residency_capture_rollback_baseline(),sectalk_private.st_v8_residency_rollback_delta(jsonb,jsonb)
  from public,anon,authenticated,service_role;

create function public.st_v8_residency_rollback_reconcile(p_workspace uuid,p_action text default 'status',
  p_review uuid default null,p_confirmation text default null,p_digest text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); actor_role text; transfer record; baseline jsonb; current_snapshot jsonb;
  delta jsonb; fingerprint text; latest sectalk_private.st_v8_residency_rollback_reviews; review_state text:='ready';
begin
  if p_workspace is null or p_action is null or p_action not in ('status','capture','confirm')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false) then raise insufficient_privilege; end if;
  actor_role:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
  if actor_role not in ('owner','reviewer') or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if (p_action='capture' and actor_role<>'owner') or (p_action='confirm' and actor_role<>'reviewer')
      or p_confirmation is distinct from p_workspace::text
      or not coalesce(sectalk_private.st_v7_admin_fresh(),false) then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    if actor_role is distinct from sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) then raise insufficient_privilege; end if;
    perform sectalk_private.limit_action('v8_residency_rollback_review',12);
  end if;
  select f.handoff,h.held_at into transfer from sectalk_private.st_v8_residency_write_handoffs f
    join sectalk_private.st_v8_residency_rollback_holds h using(workspace,approval,handoff)
    where f.workspace=p_workspace and f.phase='activated' and h.side='destination';
  if not found then
    if p_action='status' then return '{"state":"inactive"}'::jsonb; end if;
    raise insufficient_privilege;
  end if;
  select b.snapshot into baseline from sectalk_private.st_v8_residency_rollback_baselines b where b.handoff=transfer.handoff;
  if baseline is null then
    if p_action='status' then return '{"state":"baseline_missing"}'::jsonb; end if;
    raise exception 'An activation baseline was not captured for this handoff.' using errcode='PT409';
  end if;
  current_snapshot:=sectalk_private.st_v8_residency_rollback_snapshot(p_workspace);
  if exists(select 1 from jsonb_each(baseline) q where q.value->'capped'='true'::jsonb)
    or exists(select 1 from jsonb_each(current_snapshot) q where q.value->'capped'='true'::jsonb) then
    if p_action='status' then return '{"state":"capacity_exceeded"}'::jsonb; end if;
    raise exception 'The rollback census exceeds the current review limit.' using errcode='PT409';
  end if;
  fingerprint:=encode(sha256(convert_to(jsonb_build_array('sectalk-residency-rollback-delta-v1',
    p_workspace,transfer.handoff,baseline,current_snapshot)::text,'UTF8')),'hex');
  select * into latest from sectalk_private.st_v8_residency_rollback_reviews q where q.handoff=transfer.handoff
    order by q.captured_at desc,q.id desc limit 1;
  if p_action='capture' and (latest.id is null or latest.digest is distinct from fingerprint or
      latest.requester is distinct from actor_id or (latest.reviewer is not null and
        sectalk_private.st_v8_offboarding_role(p_workspace,latest.reviewer)<>'reviewer')) then
    delta:=sectalk_private.st_v8_residency_rollback_delta(baseline,current_snapshot);
    insert into sectalk_private.st_v8_residency_rollback_reviews(handoff,requester,digest,changes)
      values(transfer.handoff,actor_id,fingerprint,delta) returning * into latest;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor_id,'workspace.residency_rollback_review_captured',latest.id);
  elsif p_action='confirm' then
    if p_review is null or latest.id is distinct from p_review or latest.requester=actor_id
      or p_digest is distinct from latest.digest
      or sectalk_private.st_v8_offboarding_role(p_workspace,latest.requester)<>'owner'
      then raise insufficient_privilege; end if;
    if latest.digest is distinct from fingerprint then
      raise exception 'The destination changed after capture. Request a fresh review.' using errcode='PT409'; end if;
    if latest.reviewer is not null and latest.reviewer is distinct from actor_id then raise insufficient_privilege; end if;
    if latest.reviewer is null then
      update sectalk_private.st_v8_residency_rollback_reviews set reviewer=actor_id,reviewed_at=clock_timestamp()
        where id=latest.id returning * into latest;
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(p_workspace,actor_id,'workspace.residency_rollback_review_confirmed',latest.id);
    end if;
  end if;
  if latest.id is not null then
    review_state:=case when latest.digest<>fingerprint
        or sectalk_private.st_v8_offboarding_role(p_workspace,latest.requester)<>'owner'
        or latest.reviewer is not null and sectalk_private.st_v8_offboarding_role(p_workspace,latest.reviewer)<>'reviewer'
      then 'changed' when latest.reviewed_at is not null then 'reviewed' else 'pending' end;
  end if;
  return jsonb_build_object('state',review_state,'role',actor_role,'id',latest.id,'digest',latest.digest,
    'capturedAt',latest.captured_at,'reviewedAt',latest.reviewed_at,'changes',coalesce(latest.changes,'[]'::jsonb));
end $$;
revoke all on function public.st_v8_residency_rollback_reconcile(uuid,text,uuid,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_rollback_reconcile(uuid,text,uuid,text,text) to authenticated;

notify pgrst,'reload schema';
commit;
