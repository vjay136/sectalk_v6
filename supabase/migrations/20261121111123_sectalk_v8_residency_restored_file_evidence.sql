begin;

alter table sectalk_private.st_v8_residency_source_file_copies
  add column destination_object uuid,
  add column destination_file_digest text check (destination_file_digest~'^[0-9a-f]{64}$'),
  add column destination_storage_digest text check (destination_storage_digest~'^[0-9a-f]{64}$'),
  add column local_file_digest text check (local_file_digest~'^[0-9a-f]{64}$'),
  add column local_storage_digest text check (local_storage_digest~'^[0-9a-f]{64}$'),
  add check ((destination_object is null)=(destination_file_digest is null)
    and (destination_object is null)=(destination_storage_digest is null)
    and (local_file_digest is null)=(local_storage_digest is null)),
  add unique (handoff,destination_object);

create or replace function public.st_v8_residency_source_file_stage(
  p_workspace uuid,p_file uuid,p_proof jsonb,p_sha256 text,p_bytes integer
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  admission jsonb;
  handoff_id uuid;
  review_id uuid;
  object_row storage.objects;
  receipt sectalk_private.st_v8_residency_source_file_copies;
  claim jsonb;
begin
  admission:=public.st_v8_residency_source_file_admission(p_workspace,p_file,p_proof,p_sha256,p_bytes);
  claim:=(p_proof->>'payload')::jsonb;
  handoff_id:=(admission->>'handoff')::uuid;
  review_id:=(admission->>'review')::uuid;

  select o.* into object_row from storage.objects o join storage.buckets b on b.id=o.bucket_id
    where (o.bucket_id,o.name)=('sectalk-residency-recovery',p_workspace::text||'/'||handoff_id::text||'/'||p_file::text||'/'||p_sha256)
      and not b.public and o.version is not null and o.metadata->>'size'=p_bytes::text
    for share of o,b;
  if not found then raise insufficient_privilege; end if;

  insert into sectalk_private.st_v8_residency_source_file_copies(handoff,file,review,sha256,bytes,object_id,object_version,filename,
    destination_object,destination_file_digest,destination_storage_digest)
    values (handoff_id,p_file,review_id,p_sha256,p_bytes,object_row.id,object_row.version,admission->>'filename',
      (claim->>'object')::uuid,claim->>'fileRevision',claim->>'objectRevision')
    on conflict (handoff,file) do nothing returning * into receipt;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,auth.uid(),'workspace.residency_file_replay_staged',p_file);
  else
    select c.* into receipt from sectalk_private.st_v8_residency_source_file_copies c
      where (c.handoff,c.file)=(handoff_id,p_file);
    if (receipt.review,receipt.sha256,receipt.bytes,receipt.object_id,receipt.object_version,coalesce(receipt.filename,admission->>'filename'))
      is distinct from (review_id,p_sha256,p_bytes,object_row.id,object_row.version,admission->>'filename') then
      raise exception 'The staged recovery copy differs from the verified receipt.' using errcode='PT409';
    end if;
    if receipt.destination_object is not null and (receipt.destination_object,receipt.destination_file_digest,receipt.destination_storage_digest)
      is distinct from ((claim->>'object')::uuid,claim->>'fileRevision',claim->>'objectRevision')
      then raise exception 'The signed destination revisions differ from the staged receipt.' using errcode='PT409'; end if;
    if receipt.destination_object is null then
      update sectalk_private.st_v8_residency_source_file_copies c set filename=admission->>'filename',
        destination_object=(claim->>'object')::uuid,destination_file_digest=claim->>'fileRevision',
        destination_storage_digest=claim->>'objectRevision'
        where (c.handoff,c.file)=(handoff_id,p_file);
    end if;
  end if;
  return jsonb_build_object('state','staged','file',p_file,'stagedAt',receipt.staged_at);
end $$;

create function sectalk_private.st_v8_pin_restored_file_evidence()
returns trigger language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  workspace_id uuid;
begin
  if new.restored_at is null or old.restored_at is not null then return new; end if;
  if new.destination_object is null then
    raise exception 'Stage a newly signed copy before restoring the file.' using errcode='PT409';
  end if;
  select h.workspace into strict workspace_id from sectalk_private.st_v8_residency_write_handoffs h where h.handoff=new.handoff;
  select encode(sha256(convert_to(to_jsonb(f)::text,'UTF8')),'hex') into strict new.local_file_digest
    from sectalk_private.st_v6_workspace_files f
    where (f.workspace,f.id,f.published_at)=(workspace_id,new.file,new.restored_at);
  select encode(sha256(convert_to((to_jsonb(o)-'last_accessed_at')::text,'UTF8')),'hex') into strict new.local_storage_digest
    from storage.objects o
    where (o.id,o.version,o.bucket_id,o.name)=(new.restored_object,new.restored_version,'sectalk-workspace-files',
      workspace_id::text||'/'||new.file::text);
  return new;
end $$;
revoke all on function sectalk_private.st_v8_pin_restored_file_evidence() from public,anon,authenticated,service_role;
create trigger st_v8_pin_restored_file_evidence before update of restored_at on sectalk_private.st_v8_residency_source_file_copies
  for each row execute function sectalk_private.st_v8_pin_restored_file_evidence();

create function sectalk_private.st_v8_restored_file_evidence(p_workspace uuid,p_handoff uuid,p_review uuid,
  p_owner uuid,p_reviewer uuid)
returns table(kind text,id uuid,revision text,receipt text,matched boolean) language sql stable
  set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  select e.kind,e.id,e.revision,
    encode(sha256(convert_to(jsonb_build_array('sectalk-restored-file-evidence-v1',p_workspace,c.handoff,c.file,
      c.destination_object,c.destination_file_digest,c.destination_storage_digest,c.approved_digest,
      c.restored_object,c.restored_version,c.local_file_digest,c.local_storage_digest)::text,'UTF8')),'hex'),
    coalesce(f.uploader=p_owner and f.published_at=c.restored_at and f.deleted_at is null and not b.public
      and encode(sha256(convert_to(to_jsonb(f)::text,'UTF8')),'hex')=c.local_file_digest
      and encode(sha256(convert_to((to_jsonb(o)-'last_accessed_at')::text,'UTF8')),'hex')=c.local_storage_digest,false)
  from sectalk_private.st_v8_residency_source_file_copies c
  cross join lateral (values ('workspace_file',c.file,c.destination_file_digest),
    ('storage_object',c.destination_object,c.destination_storage_digest)) e(kind,id,revision)
  left join sectalk_private.st_v6_workspace_files f on (f.workspace,f.id)=(p_workspace,c.file)
  left join storage.objects o on (o.id,o.version,o.bucket_id,o.name)=(c.restored_object,c.restored_version,
    'sectalk-workspace-files',p_workspace::text||'/'||c.file::text)
  left join storage.buckets b on b.id=o.bucket_id
  where (c.handoff,c.review,c.reviewer)=(p_handoff,p_review,p_reviewer) and c.restored_at is not null
    and c.local_file_digest is not null and c.destination_object is not null
$$;
revoke all on function sectalk_private.st_v8_restored_file_evidence(uuid,uuid,uuid,uuid,uuid)
  from public,anon,authenticated,service_role;

create or replace function public.st_v8_residency_source_replay_review(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  actor_id uuid:=auth.uid();
  actor_role text;
  transfer sectalk_private.st_v8_residency_write_handoffs;
  approval sectalk_private.st_v8_content_exports;
  manifest sectalk_private.st_v8_residency_rollback_manifests;
  results jsonb;
begin
  actor_role:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
  if p_workspace is null or actor_id is null or actor_role not in ('owner','reviewer')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false) then
    raise insufficient_privilege;
  end if;
  if sectalk_private.st_v8_residency_rollback_side(p_workspace) is distinct from 'source' then
    return '{"state":"inactive"}'::jsonb;
  end if;
  select f.* into strict transfer from sectalk_private.st_v8_residency_write_handoffs f where f.workspace=p_workspace;
  select c.* into approval from sectalk_private.st_v8_content_exports c
    where (c.id,c.workspace)=(transfer.approval,p_workspace)
      and c.approved_at is not null and c.withdrawn_at is null
      and sectalk_private.st_v8_offboarding_role(p_workspace,c.requester)='owner'
      and sectalk_private.st_v8_offboarding_role(p_workspace,c.reviewer)='reviewer';
  if not found or actor_id is distinct from (case actor_role when 'owner' then approval.requester else approval.reviewer end) then
    raise insufficient_privilege;
  end if;
  select m.* into manifest from sectalk_private.st_v8_residency_rollback_manifests m
    where m.handoff=transfer.handoff and m.workspace=p_workspace;
  if not found then return '{"state":"awaiting_manifest"}'::jsonb; end if;

  with board as (
    select (e->>'id')::uuid as id,e
    from sectalk_private.st_v8_residency_rollback_board_batches b
    cross join lateral jsonb_array_elements(b.tasks) e
    where b.handoff=transfer.handoff and b.applied_at is not null
      and (b.staged_by,b.applied_by)=(approval.requester,approval.reviewer)
  ), chat as (
    select (e->>'id')::uuid as id,e
    from sectalk_private.st_v8_residency_rollback_channel_batches b
    cross join lateral jsonb_array_elements(b.records) e
    where b.handoff=transfer.handoff and b.applied_at is not null
      and (b.staged_by,b.applied_by)=(approval.requester,approval.reviewer)
  ), recovered_files as (
    select * from sectalk_private.st_v8_restored_file_evidence(p_workspace,transfer.handoff,manifest.review,
      approval.requester,approval.reviewer)
  ), evidence as (
    select e->>'kind' as kind,(e->>'id')::uuid as id,e->>'state' as change,e->>'after' as revision
    from jsonb_array_elements(manifest.changes) e
  ), checked as (
    select d.kind,d.id,d.change,d.revision,r.receipt,
      case
        when b.id is not null then case when coalesce(
          case when d.change='added' then
            to_jsonb(i)=to_jsonb(sectalk_private.st_v8_rollback_board_added_row(
              p_workspace,coalesce((b.e->>'sourceAuthor')::uuid,approval.requester),b.e))
          else i.completed=(b.e->>'completed')::boolean and exists(
            select 1 from sectalk_private.st_v8_content_export_entries c
            join lateral sectalk_private.st_v8_content_export_records(p_workspace,approval.requester,approval.reviewer,
              'workspace_task',p_workspace,i.id) s on c.sha256=encode(sha256(convert_to(
                jsonb_set(s.item,'{completed}',to_jsonb(not i.completed))::text,'UTF8')),'hex')
            where (c.export_id,c.kind,c.scope_id,c.record_id)=(approval.id,'workspace_task',p_workspace,i.id))
          end,false) then 'matched' else 'source_changed' end
        when a.id is not null then case when coalesce(
          (case d.kind when 'channel' then to_jsonb(c) else to_jsonb(p) end)=
          sectalk_private.st_v8_rollback_channel_row(p_workspace,
            coalesce((a.e->>'sourceAuthor')::uuid,approval.requester),a.e)
          and (d.kind='channel' or p.channel_id=parent.id and parent.workspace_id=p_workspace
            and parent.visibility='workspace' and parent.encryption_mode='standard' and not parent.archived
            and not exists(select 1 from sectalk_private.st_v7_channel_reports r where r.post_id=p.id)
            and (not (a.e ? 'existingChannelName') or sectalk_private.st_v8_residency_source_channel_matches(
              p_workspace,approval.id,approval.requester,approval.reviewer,parent.id,a.e->>'existingChannelName'))),
          false) then 'matched' else 'source_changed' end
        when r.id is not null then case when r.matched then 'matched' else 'source_changed' end
        else 'not_replayed'
      end as result
    from evidence d
    left join recovered_files r on (r.kind,r.id,r.revision)=(d.kind,d.id,d.revision) and d.change='added'
    left join board b on d.kind='workspace_task' and d.id=b.id and d.revision=b.e->>'after'
      and d.change=(case when b.e->>'kind'='added' then 'added' else 'changed' end)
    left join public.st_v2_items i on i.id=b.id and i.workspace_id=p_workspace and i.kind='task'
    left join chat a on d.kind=a.e->>'kind' and d.id=a.id and d.revision=a.e->>'digest' and d.change='added'
    left join public.st_v2_channels c on d.kind='channel' and c.id=a.id and c.workspace_id=p_workspace
    left join public.st_v2_posts p on d.kind='channel_message' and p.id=a.id
    left join public.st_v2_channels parent on parent.id=p.channel_id
  )
  select coalesce(jsonb_agg(jsonb_build_object('kind',kind,'id',id,'change',change,'revision',revision,'result',result)
    ||case when receipt is null then '{}'::jsonb else jsonb_build_object('sourceReceipt',receipt) end
    order by kind,id),'[]'::jsonb) into results from checked;

  return jsonb_build_object('state','held','reviewDigest',manifest.review_sha256,'records',results);
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
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for share;
    perform 1 from public.st_v2_members m where m.workspace_id=p_workspace and m.user_id=actor_id for share;
    if actor_role='reviewer' then
      perform 1 from sectalk_private.st_v8_offboarding_reviewers r where (r.workspace,r.actor)=(p_workspace,actor_id) for share;
      if not found then raise insufficient_privilege; end if;
    end if;
    -- Keep restored rows and their exact live Storage revisions stable while recording a sign-off.
    perform 1 from sectalk_private.st_v8_residency_source_file_copies c
      join sectalk_private.st_v8_residency_write_handoffs h using(handoff)
      join sectalk_private.st_v6_workspace_files f on (f.workspace,f.id)=(h.workspace,c.file)
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
