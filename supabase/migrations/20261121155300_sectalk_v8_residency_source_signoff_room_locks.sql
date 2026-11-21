begin;

create or replace function public.st_v8_residency_source_evidence(p_workspace uuid,p_action text default 'status',
  p_confirmation text default null,p_review uuid default null,p_digest text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor_id uuid:=auth.uid();
  actor_role text;
  approval sectalk_private.st_v8_content_exports;
  manifest sectalk_private.st_v8_residency_rollback_manifests;
  recorded sectalk_private.st_v8_residency_source_evidence;
  scope_review jsonb;
  fingerprint text;
  coverage text;
  preserving boolean;
  held_handoff uuid;
  room_messages jsonb;
  room_tasks jsonb;
begin
  if p_action is null or p_action not in ('status','capture','confirm') then raise insufficient_privilege; end if;
  actor_role:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
  if actor_role not in ('owner','reviewer') or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    then raise insufficient_privilege; end if;

  if p_action<>'status' then
    if p_confirmation is distinct from p_workspace::text or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
      or actor_role is distinct from (case p_action when 'capture' then 'owner' else 'reviewer' end)
      then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
    perform pg_advisory_xact_lock(hashtextextended('sectalk-room-mode:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for share;
    perform 1 from public.st_v2_members m where m.workspace_id=p_workspace and m.user_id=actor_id for share;
    if actor_role='reviewer' then
      perform 1 from sectalk_private.st_v8_offboarding_reviewers r where (r.workspace,r.actor)=(p_workspace,actor_id) for share;
      if not found then raise insufficient_privilege; end if;
    end if;
    -- Recovery permits safety changes while writes are held. Lock exact recovered
    -- rooms and messages in the same order as native moderation before the snapshot.
    select h.handoff into held_handoff from sectalk_private.st_v8_residency_write_handoffs h
      where h.workspace=p_workspace and h.phase='held';
    select coalesce(b.records,'[]') into room_messages from sectalk_private.st_v8_residency_rollback_room_batches b
      where b.handoff=held_handoff and b.applied_at is not null;
    select coalesce(b.records,'[]') into room_tasks from sectalk_private.st_v8_residency_rollback_room_task_batches b
      where b.handoff=held_handoff and b.applied_at is not null;
    perform 1 from public.st_v6_rooms r where r.workspace_id=p_workspace and r.id in (
      select (e->>'room')::uuid from jsonb_array_elements(room_messages) e
      union select (e->>'room')::uuid from jsonb_array_elements(room_tasks) e
      union select c.room from sectalk_private.st_v8_residency_source_file_copies c
        where c.handoff=held_handoff and c.restored_at is not null and c.room is not null
    ) order by r.id for share;
    perform 1 from public.st_v6_room_posts p join public.st_v6_rooms r on r.id=p.room_id
      where r.workspace_id=p_workspace and exists(
        select 1 from jsonb_array_elements(room_messages) e
        where p.room_id=(e->>'room')::uuid and p.id in ((e->>'id')::uuid,(e->>'parent')::uuid)
      ) order by p.room_id,p.id for share of p;
    perform 1 from public.st_v6_tasks t join public.st_v6_rooms r on r.id=t.room_id
      where r.workspace_id=p_workspace and exists(
        select 1 from jsonb_array_elements(room_tasks) e where (t.room_id,t.id)=((e->>'room')::uuid,(e->>'id')::uuid)
      ) order by t.room_id,t.id for share of t;
    perform 1 from public.st_v6_task_audit a join public.st_v6_tasks t on t.id=a.task_id
      join public.st_v6_rooms r on r.id=t.room_id
      where r.workspace_id=p_workspace and exists(
        select 1 from jsonb_array_elements(room_tasks) e where (t.room_id,t.id)=((e->>'room')::uuid,(e->>'id')::uuid)
      ) order by a.task_id,a.id for share of a;
    -- Keep restored rows and their exact live Storage revisions stable while recording a sign-off.
    perform 1 from sectalk_private.st_v8_residency_source_file_copies c
      join sectalk_private.st_v8_residency_write_handoffs h using(handoff)
      join sectalk_private.st_v6_workspace_files f on (f.workspace,f.id)=(h.workspace,c.file)
      join storage.objects o on (o.id,o.version)=(c.restored_object,c.restored_version)
      join storage.buckets b on b.id=o.bucket_id
      where h.workspace=p_workspace and c.restored_at is not null
      order by c.file for share of c,f,o,b;
    perform 1 from sectalk_private.st_v8_residency_source_file_copies c
      join sectalk_private.st_v8_residency_write_handoffs h using(handoff)
      join sectalk_private.st_v6_room_files f on (f.workspace,f.room,f.id)=(h.workspace,c.room,c.file)
      join storage.objects o on (o.id,o.version)=(c.restored_object,c.restored_version)
      join storage.buckets b on b.id=o.bucket_id
      where h.workspace=p_workspace and c.restored_at is not null
      order by c.file for share of c,f,o,b;
    perform sectalk_private.limit_action('v8_residency_source_evidence',12);
  end if;

  scope_review:=public.st_v8_residency_source_replay_review(p_workspace);
  if scope_review->>'state' is distinct from 'held' then
    if p_action='status' then return scope_review; end if;
    raise insufficient_privilege;
  end if;
  select m.* into strict manifest from sectalk_private.st_v8_residency_rollback_manifests m
    join sectalk_private.st_v8_residency_write_handoffs f using(handoff,workspace)
    where m.workspace=p_workspace;
  select c.* into strict approval from sectalk_private.st_v8_content_exports c
    join sectalk_private.st_v8_residency_write_handoffs f on f.approval=c.id
    where f.handoff=manifest.handoff;
  if p_action<>'status' then
    perform 1 from sectalk_private.st_v8_content_exports c where c.id=approval.id and c.withdrawn_at is null for share;
    if not found then raise insufficient_privilege; end if;
  end if;

  preserving:=sectalk_private.st_v8_offboarding_holds(p_workspace);
  if preserving or exists(select 1 from jsonb_array_elements(scope_review->'records') item
    where item->>'result' is distinct from 'matched') then
    if p_action<>'status' then
      raise exception 'Source coverage must be current and clear of preservation holds.' using errcode='PT409';
    end if;
    return scope_review||jsonb_build_object('coverage',case when preserving then 'preservation_hold' else 'incomplete' end);
  end if;

  fingerprint:=encode(sha256(convert_to(jsonb_build_array('sectalk-residency-source-evidence-v1',
    p_workspace,manifest.handoff,manifest.review,manifest.review_sha256,manifest.packet_sha256,
    manifest.plan_sha256,approval.requester,approval.reviewer,scope_review->'records')::text,'UTF8')),'hex');
  select e.* into recorded from sectalk_private.st_v8_residency_source_evidence e
    where (e.handoff,e.digest)=(manifest.handoff,fingerprint);
  if p_action<>'status' and p_digest is distinct from fingerprint then
    raise exception 'Source evidence changed. Refresh the coverage before continuing.' using errcode='PT409';
  end if;
  if p_action='capture' and recorded.id is null then
    insert into sectalk_private.st_v8_residency_source_evidence(handoff,digest,requester)
      values(manifest.handoff,fingerprint,actor_id) returning * into recorded;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor_id,'workspace.residency_source_evidence_captured',recorded.id);
  elsif p_action='confirm' then
    if p_review is null or recorded.id is distinct from p_review or recorded.requester is distinct from approval.requester
      or actor_id is distinct from approval.reviewer or (recorded.reviewer is not null and recorded.reviewer<>actor_id) then
      raise insufficient_privilege;
    end if;
    if recorded.reviewed_at is null then
      update sectalk_private.st_v8_residency_source_evidence set reviewer=actor_id,reviewed_at=clock_timestamp()
        where id=recorded.id returning * into recorded;
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(p_workspace,actor_id,'workspace.residency_source_evidence_confirmed',recorded.id);
    end if;
  end if;
  coverage:=case when recorded.reviewed_at is not null then 'reviewed'
    when recorded.id is not null then 'pending' else 'ready' end;
  return scope_review||jsonb_build_object('coverage',coverage,'role',actor_role,'evidenceId',recorded.id,
    'evidenceDigest',fingerprint,'reviewedAt',recorded.reviewed_at);
end $$;

notify pgrst,'reload schema';
commit;
