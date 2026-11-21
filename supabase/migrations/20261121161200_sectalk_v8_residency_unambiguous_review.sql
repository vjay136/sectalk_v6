begin;

create function sectalk_private.st_v8_residency_manifest_keys_unique(p_changes jsonb)
returns boolean language sql immutable set search_path='' as $$
  select not exists(
    select 1 from jsonb_array_elements(p_changes) entry
    group by entry->>'kind', entry->>'id' having count(*)>1
  )
$$;
revoke all on function sectalk_private.st_v8_residency_manifest_keys_unique(jsonb) from public,anon,authenticated,service_role;

create or replace function public.st_v8_residency_rollback_reconcile(p_workspace uuid,p_action text default 'status',
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
  -- The v1 transfer format identifies records by kind and ID across the workspace.
  if exists(
    select 1 from (values (1,baseline),(2,current_snapshot)) snapshot(version,data)
    cross join lateral jsonb_each(snapshot.data) family
    cross join lateral jsonb_array_elements(family.value->'records') entry
    group by snapshot.version,family.key,entry->>0 having count(*)>1
  ) then
    if p_action='status' then return '{"state":"ambiguous_record_ids"}'::jsonb; end if;
    raise exception 'Record IDs repeat within a destination record type. Exact rollback review is unavailable.' using errcode='PT409';
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

create or replace function public.st_v8_residency_rollback_manifest(p_workspace uuid,p_action text default 'status',
  p_confirmation text default null,p_packet jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid();
  transfer sectalk_private.st_v8_residency_write_handoffs;
  admitted sectalk_private.st_v8_residency_rollback_manifest_admissions;
  known sectalk_private.st_v8_residency_rollback_manifests;
  review jsonb;
  claim jsonb;
  side text;
  wire text;
  signing_key bytea;
  received_digest text;
  now_epoch bigint;
  expires bigint;
begin
  if p_workspace is null or p_action is null or p_action not in ('status','issue','receive')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'owner'
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if p_confirmation is distinct from p_workspace::text or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
      then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces w where (w.id,w.owner)=(p_workspace,actor_id) for share;
    if not found then raise insufficient_privilege; end if;
  end if;

  side:=sectalk_private.st_v8_residency_rollback_side(p_workspace);
  if side is null then
    if p_action='status' then return '{"state":"inactive"}'::jsonb; end if;
    raise insufficient_privilege;
  end if;
  if p_action<>'status' and (p_action='issue') is distinct from (side='destination')
    then raise insufficient_privilege; end if;
  select f.* into transfer from sectalk_private.st_v8_residency_write_handoffs f where f.workspace=p_workspace;

  if p_action='receive' then
    if not coalesce(jsonb_typeof(p_packet)='object' and octet_length(p_packet::text)<=4194304,false)
      or not coalesce(p_packet->>'signature'~'^[0-9a-f]{64}$' and octet_length(p_packet->>'payload') between 50 and 4000000,false)
      or p_packet-array['payload','signature']<>'{}'::jsonb then raise insufficient_privilege; end if;
    received_digest:=encode(sha256(convert_to(p_packet::text,'UTF8')),'hex');
  end if;
  if side='source' then
    select k.* into known from sectalk_private.st_v8_residency_rollback_manifests k where k.handoff=transfer.handoff;
    if found then
      if p_action='receive' and received_digest is distinct from known.packet_sha256 then
        raise exception 'The rollback handoff already has a different verified manifest.' using errcode='PT409'; end if;
      return jsonb_build_object('state','received','side','source','review',known.review,'digest',known.review_sha256,
        'packetSha256',known.packet_sha256,'receivedAt',known.received_at,'changeCount',jsonb_array_length(known.changes));
    end if;
  end if;
  select a.* into admitted from sectalk_private.st_v8_residency_rollback_manifest_admissions a
    where a.handoff=transfer.handoff and a.expires_at>statement_timestamp();
  if not found then
    if p_action='status' then return jsonb_build_object('state','admission_required','side',side); end if;
    raise insufficient_privilege;
  end if;
  if side='destination' then
    review:=public.st_v8_residency_rollback_reconcile(p_workspace);
    if review->>'state' is distinct from 'reviewed' then
      if p_action='status' then return '{"state":"review_required","side":"destination"}'::jsonb; end if;
      raise exception 'The destination needs a current independent change review.' using errcode='PT409';
    end if;
  end if;
  if p_action='status' then return jsonb_build_object('state','ready','side',side); end if;
  perform sectalk_private.limit_action('v8_residency_rollback_manifest',12);
  select decode(v.decrypted_secret,'hex') into signing_key from vault.decrypted_secrets v
    where v.id=admitted.vault_id and v.decrypted_secret~'^[0-9a-f]{64}$';
  if not found then raise insufficient_privilege; end if;
  if p_action='issue' then
    wire:=jsonb_build_object('format','sectalk-residency-recovery-manifest-v1','workspace',p_workspace,
      'handoff',transfer.handoff,'approval',transfer.approval,'source',transfer.source_project,'destination',transfer.destination_project,
      'plan',admitted.plan_sha256,'review',review->>'id','digest',review->>'digest','changes',review->'changes',
      'expires',floor(extract(epoch from least(admitted.expires_at,statement_timestamp()+interval '5 minutes'))))::text;
    if octet_length(wire)>4000000 then raise exception 'The reviewed manifest exceeds the transfer limit.' using errcode='PT409'; end if;
    return jsonb_build_object('state','ready','side','destination','packet',jsonb_build_object('payload',wire,
      'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),'hex')));
  end if;
  wire:=p_packet->>'payload';
  if extensions.hmac(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),signing_key,'sha256')
    <>extensions.hmac(decode(p_packet->>'signature','hex'),signing_key,'sha256') then raise insufficient_privilege; end if;
  claim:=wire::jsonb;
  now_epoch:=floor(extract(epoch from clock_timestamp()));
  expires:=(claim->>'expires')::bigint;
  if (claim->>'format',claim->>'workspace',claim->>'handoff',claim->>'approval',claim->>'source',claim->>'destination',claim->>'plan')
    is distinct from ('sectalk-residency-recovery-manifest-v1',p_workspace::text,transfer.handoff::text,
      transfer.approval::text,transfer.source_project,transfer.destination_project,admitted.plan_sha256)
    or expires is null or expires<=now_epoch or expires>now_epoch+303
    or not coalesce(claim->>'digest'~'^[0-9a-f]{64}$' and claim->>'review'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$',false)
    or jsonb_typeof(claim->'changes') is distinct from 'array' then raise insufficient_privilege; end if;
  if jsonb_array_length(claim->'changes')>9000 or exists(
    select 1 from jsonb_array_elements(claim->'changes') entry
    where jsonb_typeof(entry) is distinct from 'object'
      or not coalesce(entry ?& array['kind','id','state','before','after'] and
        entry-array['kind','id','state','before','after']='{}'::jsonb
        and entry->>'kind' in ('channel','channel_message','workspace_task','room','room_message','room_task',
          'workspace_file','room_file','storage_object') and entry->>'id'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
        and case entry->>'state'
          when 'added' then entry->'before'='null'::jsonb and entry->>'after'~'^[0-9a-f]{64}$'
          when 'removed' then entry->>'before'~'^[0-9a-f]{64}$' and entry->'after'='null'::jsonb
          when 'changed' then entry->>'before'~'^[0-9a-f]{64}$' and entry->>'after'~'^[0-9a-f]{64}$'
            and entry->>'before'<>entry->>'after'
          else false end,false)
  ) then raise insufficient_privilege; end if;
  if not sectalk_private.st_v8_residency_manifest_keys_unique(claim->'changes') then raise insufficient_privilege; end if;
  insert into sectalk_private.st_v8_residency_rollback_manifests
    (handoff,workspace,review,review_sha256,packet_sha256,plan_sha256,changes)
    values(transfer.handoff,p_workspace,(claim->>'review')::uuid,claim->>'digest',received_digest,admitted.plan_sha256,claim->'changes')
    returning * into known;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor_id,'workspace.residency_rollback_manifest_received',transfer.handoff);
  return jsonb_build_object('state','received','side','source','review',known.review,'digest',known.review_sha256,
    'packetSha256',known.packet_sha256,'receivedAt',known.received_at,'changeCount',jsonb_array_length(known.changes));
end $$;

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
  if not sectalk_private.st_v8_residency_manifest_keys_unique(manifest.changes) then
    if p_action='status' then return scope_review||jsonb_build_object('coverage','incomplete'); end if;
    raise exception 'The admitted rollback manifest has ambiguous record IDs.' using errcode='PT409';
  end if;
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
