begin;

alter table sectalk_private.st_v8_residency_source_file_copies
  add column filename text check (char_length(filename) between 1 and 140),
  add column restored_at timestamptz,
  add column restored_object uuid,
  add column restored_version text,
  add check ((restored_at is null)=(restored_object is null) and (restored_at is null)=(restored_version is null));

create or replace function public.st_v8_residency_source_file_stage(
  p_workspace uuid,p_file uuid,p_proof jsonb,p_sha256 text,p_bytes integer
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  admission jsonb;
  handoff_id uuid;
  review_id uuid;
  object_row storage.objects;
  receipt sectalk_private.st_v8_residency_source_file_copies;
begin
  admission:=public.st_v8_residency_source_file_admission(p_workspace,p_file,p_proof,p_sha256,p_bytes);
  handoff_id:=(admission->>'handoff')::uuid;
  review_id:=(admission->>'review')::uuid;

  select o.* into object_row from storage.objects o join storage.buckets b on b.id=o.bucket_id
    where (o.bucket_id,o.name)=('sectalk-residency-recovery',p_workspace::text||'/'||handoff_id::text||'/'||p_file::text||'/'||p_sha256)
      and not b.public and o.version is not null and o.metadata->>'size'=p_bytes::text
    for share of o,b;
  if not found then raise insufficient_privilege; end if;

  insert into sectalk_private.st_v8_residency_source_file_copies(handoff,file,review,sha256,bytes,object_id,object_version,filename)
    values (handoff_id,p_file,review_id,p_sha256,p_bytes,object_row.id,object_row.version,admission->>'filename')
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
    if receipt.filename is null then
      update sectalk_private.st_v8_residency_source_file_copies set filename=admission->>'filename'
        where (handoff,file)=(handoff_id,p_file);
    end if;
  end if;
  return jsonb_build_object('state','staged','file',p_file,'stagedAt',receipt.staged_at);
end $$;

create or replace function public.st_v8_residency_source_file_review(p_workspace uuid,p_file uuid default null,
  p_confirmation text default null,p_digest text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor_id uuid:=auth.uid();
  actor_role text;
  transfer sectalk_private.st_v8_residency_write_handoffs;
  approval sectalk_private.st_v8_content_exports;
  manifest sectalk_private.st_v8_residency_rollback_manifests;
  records jsonb;
  exact_digest text;
  changed boolean;
begin
  actor_role:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
  if p_workspace is null or not coalesce(actor_role in ('owner','reviewer'),false)
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    then raise insufficient_privilege; end if;

  if p_file is not null then
    if actor_role<>'reviewer' or p_confirmation is distinct from p_workspace::text
      or not coalesce(p_digest~'^[0-9a-f]{64}$',false)
      or not coalesce(sectalk_private.st_v7_admin_fresh(),false) then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for share;
    perform 1 from public.st_v2_members m where (m.workspace_id,m.user_id)=(p_workspace,actor_id) for share;
    if not found then raise insufficient_privilege; end if;
    perform 1 from sectalk_private.st_v8_offboarding_reviewers r where (r.workspace,r.actor)=(p_workspace,actor_id) for share;
    if not found or sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'reviewer'
      or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
    perform sectalk_private.limit_action('v8_residency_source_file_review',20);
  end if;

  if sectalk_private.st_v8_residency_rollback_side(p_workspace) is distinct from 'source' then
    if p_file is null then return '{"state":"inactive"}'::jsonb; end if;
    raise insufficient_privilege;
  end if;
  select f.* into transfer from sectalk_private.st_v8_residency_write_handoffs f where f.workspace=p_workspace;
  select c.* into approval from sectalk_private.st_v8_content_exports c
    where (c.id,c.workspace)=(transfer.approval,p_workspace) and c.approved_at is not null and c.withdrawn_at is null
      and c.requester is distinct from c.reviewer
      and sectalk_private.st_v8_offboarding_role(p_workspace,c.requester)='owner'
      and sectalk_private.st_v8_offboarding_role(p_workspace,c.reviewer)='reviewer'
    for share;
  if not found or actor_id is distinct from (case when actor_role='owner' then approval.requester else approval.reviewer end)
    then raise insufficient_privilege; end if;
  select m.* into manifest from sectalk_private.st_v8_residency_rollback_manifests m
    where (m.handoff,m.workspace)=(transfer.handoff,p_workspace);
  if not found then
    if p_file is null then return '{"state":"inactive"}'::jsonb; end if;
    raise insufficient_privilege;
  end if;

  if p_file is not null then
    -- The recovery object revision is immutable to workspace roles. Pin it for the confirmation transaction.
    perform 1 from sectalk_private.st_v8_residency_source_file_copies c
      join storage.objects o on o.id=c.object_id and o.version=c.object_version
      join storage.buckets b on b.id=o.bucket_id and not b.public
      where (c.handoff,c.file,c.review)=(manifest.handoff,p_file,manifest.review)
        and (o.bucket_id,o.name)=('sectalk-residency-recovery',p_workspace::text||'/'||
          c.handoff::text||'/'||c.file::text||'/'||c.sha256) and o.metadata->>'size'=c.bytes::text
      for share of o,b;
    if not found then raise exception 'The staged file is missing or changed.' using errcode='PT409'; end if;
  end if;

  select coalesce(jsonb_agg(jsonb_build_object('file',c.file,'sha256',c.sha256,'bytes',c.bytes,'filename',c.filename,
      'digest',d.value,'state',case when o.id is null then 'changed'
        when c.restored_at is not null and live.id is not null and published.id is not null then 'restored'
        when c.restored_at is not null then 'changed'
        when c.reviewer=approval.reviewer and c.approved_digest=d.value then 'approved' else 'staged' end)
      order by c.file),'[]'::jsonb) into records
    from sectalk_private.st_v8_residency_source_file_copies c
    left join (storage.objects o join storage.buckets b on b.id=o.bucket_id and not b.public)
      on (o.id,o.version)=(c.object_id,c.object_version) and o.metadata->>'size'=c.bytes::text
      and (o.bucket_id,o.name)=('sectalk-residency-recovery',p_workspace::text||'/'||c.handoff::text||'/'||c.file::text||'/'||c.sha256)
    left join storage.objects live on live.id=c.restored_object and live.version=c.restored_version
      and (live.bucket_id,live.name)=('sectalk-workspace-files',p_workspace::text||'/'||c.file::text)
    left join sectalk_private.st_v6_workspace_files published on (published.workspace,published.id)=(p_workspace,c.file)
      and published.deleted_at is null and published.published_at=c.restored_at and published.filename=c.filename
      and published.size_bytes=c.bytes and published.fingerprint=sectalk_private.st_v6_workspace_file_fingerprint(p_workspace,c.sha256)
    cross join lateral (select encode(sha256(convert_to(jsonb_build_array('sectalk-source-file-review-v1',
      p_workspace,c.handoff,c.file,c.review,manifest.review_sha256,manifest.packet_sha256,approval.id,approval.requester,approval.reviewer,
      c.sha256,c.bytes,c.object_id,c.object_version,c.filename)::text,'UTF8')),'hex') value) d
    where (c.handoff,c.review)=(manifest.handoff,manifest.review) and (p_file is null or c.file=p_file);

  if p_file is not null then
    exact_digest:=records->0->>'digest';
    if exact_digest is distinct from p_digest or records->0->>'state'='changed' then
      raise exception 'The staged file changed. Refresh the review before continuing.' using errcode='PT409';
    end if;
    update sectalk_private.st_v8_residency_source_file_copies c
      set reviewer=actor_id,reviewed_at=clock_timestamp(),approved_digest=exact_digest
      where (c.handoff,c.file)=(manifest.handoff,p_file) and (c.reviewer,c.approved_digest) is distinct from (actor_id,exact_digest);
    changed:=found;
    if changed then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(p_workspace,actor_id,'workspace.residency_file_replay_approved',p_file);
    end if;
    if records->0->>'state'<>'restored' then records:=jsonb_set(records,'{0,state}','"approved"'::jsonb); end if;
  end if;
  return jsonb_build_object('state','held','role',actor_role,'files',records);
end $$;

create table sectalk_private.st_v8_residency_file_write_permits (
  tx xid8 not null,
  workspace uuid not null,
  file uuid not null,
  revision bytea not null,
  primary key (tx,workspace,file)
);
alter table sectalk_private.st_v8_residency_file_write_permits enable row level security;
revoke all on sectalk_private.st_v8_residency_file_write_permits from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_guard_workspace_file_insert()
returns trigger language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
begin
  if not exists (select 1 from sectalk_private.st_v8_residency_file_write_permits p
    where (p.tx,p.workspace,p.file,p.revision)=(pg_current_xact_id_if_assigned(),new.workspace,new.id,
      sha256(convert_to(to_jsonb(new)::text,'UTF8')))) then
    perform sectalk_private.st_v7_require_workspace_write(new.workspace);
  end if;
  return new;
end $$;
revoke all on function sectalk_private.st_v8_guard_workspace_file_insert() from public,anon,authenticated,service_role;
drop trigger st_v7_payment_write on sectalk_private.st_v6_workspace_files;
create trigger st_v7_payment_write before update of workspace,published_at on sectalk_private.st_v6_workspace_files
  for each row execute function sectalk_private.st_v7_guard_workspace_write('workspace','direct','file');
create trigger st_v8_payment_file_insert before insert on sectalk_private.st_v6_workspace_files
  for each row execute function sectalk_private.st_v8_guard_workspace_file_insert();

create function public.st_v8_residency_source_file_restore(p_workspace uuid,p_file uuid,p_digest text,
  p_action text default 'prepare') returns jsonb language plpgsql security definer
  set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  actor_id uuid:=auth.uid();
  handoff_id uuid;
  review_row jsonb;
  copy sectalk_private.st_v8_residency_source_file_copies;
  object_row storage.objects;
  restored sectalk_private.st_v6_workspace_files;
begin
  if p_workspace is null or p_file is null or not coalesce(p_digest~'^[0-9a-f]{64}$',false)
    or not coalesce(p_action in ('prepare','publish'),false)
    or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
    or sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'owner'
    then raise insufficient_privilege; end if;

  perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform 1 from public.st_v2_workspaces w where (w.id,w.owner)=(p_workspace,actor_id) for share;
  if not found or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;

  select value into review_row from jsonb_array_elements(public.st_v8_residency_source_file_review(p_workspace)->'files')
    where value->>'file'=p_file::text;
  if (review_row->>'digest') is distinct from p_digest or not coalesce(review_row->>'state' in ('approved','restored'),false)
    then raise exception 'The current staged file needs independent approval.' using errcode='PT409'; end if;
  select f.handoff into handoff_id from sectalk_private.st_v8_residency_write_handoffs f where f.workspace=p_workspace;
  select c.* into copy from sectalk_private.st_v8_residency_source_file_copies c where (c.handoff,c.file)=(handoff_id,p_file);
  if not found or copy.filename is null or copy.filename ~ '[/[:cntrl:]]' or strpos(copy.filename,chr(92))>0
    or copy.approved_digest is distinct from p_digest then raise insufficient_privilege; end if;
  perform 1 from sectalk_private.st_v8_offboarding_reviewers r
    join public.st_v2_members m on (m.workspace_id,m.user_id)=(r.workspace,r.actor)
    where (r.workspace,r.actor)=(p_workspace,copy.reviewer) and m.suspended_at is null for share of r,m;
  if not found or sectalk_private.st_v8_offboarding_role(p_workspace,copy.reviewer) is distinct from 'reviewer'
    then raise insufficient_privilege; end if;
  perform 1 from storage.objects o join storage.buckets b on b.id=o.bucket_id and not b.public
    where (o.id,o.version)=(copy.object_id,copy.object_version) and o.metadata->>'size'=copy.bytes::text
      and (o.bucket_id,o.name)=('sectalk-residency-recovery',p_workspace::text||'/'||handoff_id::text||'/'||p_file::text||'/'||copy.sha256)
    for share of o,b;
  if not found then raise exception 'The staging object changed.' using errcode='PT409'; end if;
  perform sectalk_private.limit_action('v8_residency_source_file_restore',30);

  if copy.restored_at is not null then
    return jsonb_build_object('state','restored','file',p_file,'publishedAt',copy.restored_at);
  end if;
  if exists(select 1 from sectalk_private.st_v6_workspace_files f where (f.workspace,f.id)=(p_workspace,p_file)) or
    exists(select 1 from sectalk_private.st_v6_workspace_retired_file_ids f where (f.workspace,f.id)=(p_workspace,p_file)) then
    raise exception 'The source already contains this file identity.' using errcode='PT409';
  end if;
  if exists(select 1 from sectalk_private.st_v6_workspace_files f where f.workspace=p_workspace
    group by f.workspace having count(*)>=200 or sum(f.size_bytes)+copy.bytes>67108864) then
    raise exception 'The workspace file storage limit was reached.' using errcode='PT413';
  end if;
  if p_action='prepare' then
    return jsonb_build_object('state','ready','file',p_file,'handoff',handoff_id,'filename',copy.filename,'bytes',copy.bytes,'sha256',copy.sha256);
  end if;

  select o.* into object_row from storage.objects o join storage.buckets b on b.id=o.bucket_id and not b.public
    where (o.bucket_id,o.name)=('sectalk-workspace-files',p_workspace::text||'/'||p_file::text)
      and o.version is not null and o.metadata->>'size'=copy.bytes::text
      and o.user_metadata->>'sectalkRollbackApproval'=p_digest and o.user_metadata->>'sectalkRollbackSha256'=copy.sha256
    for share of o,b;
  if not found then raise exception 'The verified copy is missing from workspace Storage.' using errcode='PT409'; end if;

  restored.workspace:=p_workspace;
  restored.id:=p_file;
  restored.uploader:=actor_id;
  restored.filename:=copy.filename;
  restored.size_bytes:=copy.bytes;
  restored.fingerprint:=sectalk_private.st_v6_workspace_file_fingerprint(p_workspace,copy.sha256);
  restored.created_at:=clock_timestamp();
  restored.published_at:=restored.created_at;
  restored.maintenance_after:='-infinity';
  insert into sectalk_private.st_v8_residency_file_write_permits(tx,workspace,file,revision)
    values(pg_current_xact_id(),p_workspace,p_file,sha256(convert_to(to_jsonb(restored)::text,'UTF8')));
  insert into sectalk_private.st_v6_workspace_files select (restored).*;
  delete from sectalk_private.st_v8_residency_file_write_permits p
    where (p.tx,p.workspace,p.file)=(pg_current_xact_id(),p_workspace,p_file);
  insert into sectalk_private.st_v6_workspace_file_events(workspace,file_id,actor,event)
    values(p_workspace,p_file,actor_id,'published');
  update sectalk_private.st_v8_residency_source_file_copies c
    set restored_at=restored.published_at,restored_object=object_row.id,restored_version=object_row.version
    where (c.handoff,c.file)=(handoff_id,p_file);
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor_id,'workspace.residency_file_replay_restored',p_file);
  return jsonb_build_object('state','restored','file',p_file,'publishedAt',restored.published_at);
end $$;

revoke all on function public.st_v8_residency_source_file_restore(uuid,uuid,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_source_file_restore(uuid,uuid,text,text) to authenticated;
notify pgrst,'reload schema';
commit;
