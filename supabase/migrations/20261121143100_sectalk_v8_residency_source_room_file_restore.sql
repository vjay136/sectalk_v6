begin;

alter table sectalk_private.st_v8_residency_source_file_copies
  add column room uuid,
  add column room_name text check (char_length(room_name) between 1 and 64),
  add check ((room is null)=(room_name is null));

create function sectalk_private.st_v8_residency_restored_file_path(p_workspace uuid,p_room uuid,p_file uuid)
returns text language sql immutable set search_path='' as $$
  select p_workspace::text||'/'||coalesce('rooms/'||p_room::text||'/','')||p_file::text;
$$;
revoke all on function sectalk_private.st_v8_residency_restored_file_path(uuid,uuid,uuid)
  from public,anon,authenticated,service_role;


create or replace function public.st_v8_residency_source_file_admission(
  p_workspace uuid,p_file uuid,p_proof jsonb,p_sha256 text,p_bytes integer
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor_id uuid:=auth.uid();
  approved_export sectalk_private.st_v8_content_exports;
  room_id uuid;
  room_name text;
  transfer sectalk_private.st_v8_residency_write_handoffs;
  manifest sectalk_private.st_v8_residency_rollback_manifests;
  admission sectalk_private.st_v8_residency_rollback_manifest_admissions;
  wire text;
  claim jsonb;
  signing_key bytea;
  owner_email text;
  owner_tag bytea;
  expires bigint;
  now_epoch bigint:=floor(extract(epoch from statement_timestamp()));
begin
  if p_workspace is null or p_file is null
    or not coalesce(p_sha256~'^[0-9a-f]{64}$' and p_bytes between 1 and 4194304,false)
    or not coalesce(jsonb_typeof(p_proof)='object' and octet_length(p_proof::text)<=4096
      and p_proof-array['payload','signature']='{}'::jsonb and jsonb_typeof(p_proof->'payload')='string'
      and p_proof->>'signature'~'^[0-9a-f]{64}$',false)
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
    or sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'owner'
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    then raise insufficient_privilege; end if;

  perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-room-mode:'||p_workspace::text,0));
  perform 1 from public.st_v2_workspaces w where (w.id,w.owner)=(p_workspace,actor_id) for share;
  if not found or sectalk_private.st_v8_residency_rollback_side(p_workspace) is distinct from 'source'
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;

  select f.* into transfer from sectalk_private.st_v8_residency_write_handoffs f where f.workspace=p_workspace;
  select c.* into approved_export from sectalk_private.st_v8_content_exports c
    where (c.id,c.workspace,c.requester)=(transfer.approval,p_workspace,actor_id)
      and c.approved_at is not null and c.withdrawn_at is null
      and sectalk_private.st_v8_offboarding_role(p_workspace,c.reviewer)='reviewer' for share;
  if not found then raise insufficient_privilege; end if;
  select m.* into manifest from sectalk_private.st_v8_residency_rollback_manifests m
    where (m.handoff,m.workspace)=(transfer.handoff,p_workspace);
  if not found then raise insufficient_privilege; end if;
  select a.* into admission from sectalk_private.st_v8_residency_rollback_manifest_admissions a
    where (a.handoff,a.plan_sha256)=(manifest.handoff,manifest.plan_sha256) and a.expires_at>statement_timestamp();
  if not found then raise insufficient_privilege; end if;
  select decode(v.decrypted_secret,'hex') into signing_key from vault.decrypted_secrets v
    where v.id=admission.vault_id and v.decrypted_secret~'^[0-9a-f]{64}$';
  if not found then raise insufficient_privilege; end if;

  perform sectalk_private.limit_action('v8_residency_source_file_admission',30);
  wire:=p_proof->>'payload';
  if extensions.hmac(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),signing_key,'sha256')
    <>extensions.hmac(decode(p_proof->>'signature','hex'),signing_key,'sha256') then raise insufficient_privilege; end if;
  claim:=wire::jsonb;
  if claim->>'format'='sectalk-residency-room-file-copy-v1' then
    if not coalesce(claim->>'room'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
      and char_length(claim->>'roomName') between 1 and 64,false) then raise insufficient_privilege; end if;
    room_id:=(claim->>'room')::uuid;
    room_name:=claim->>'roomName';
    if not sectalk_private.st_v8_residency_source_room_matches(p_workspace,approved_export.id,actor_id,
      approved_export.reviewer,room_id,room_name)
      or public.st_v8_app_file_context('room',room_id)->>'access' is distinct from 'allowed'
      or sectalk_private.st_v7_workspace_payment_mode(p_workspace)->>'reason' is distinct from 'residency'
      then raise insufficient_privilege; end if;
  elsif claim ?| array['room','roomName'] then raise insufficient_privilege;
  end if;
  if (claim->>'format',claim->>'workspace',claim->>'handoff',claim->>'source',claim->>'destination',
      claim->>'approval',claim->>'plan',claim->>'review',claim->>'digest',claim->>'file',claim->>'sha256',claim->>'bytes')
      is distinct from (case when room_id is null then 'sectalk-residency-file-copy-v1' else 'sectalk-residency-room-file-copy-v1' end,p_workspace::text,transfer.handoff::text,
        transfer.source_project,transfer.destination_project,transfer.approval::text,manifest.plan_sha256,
        manifest.review::text,manifest.review_sha256,p_file::text,p_sha256,p_bytes::text)
    or not coalesce(claim->>'expires'~'^[0-9]{1,12}$' and claim->>'fileRevision'~'^[0-9a-f]{64}$'
      and claim->>'object'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
      and claim->>'objectRevision'~'^[0-9a-f]{64}$' and claim->>'ownerTag'~'^[0-9a-f]{64}$'
      and jsonb_typeof(claim->'filename')='string' and char_length(btrim(claim->>'filename')) between 1 and 140,false)
    then raise insufficient_privilege; end if;
  expires:=(claim->>'expires')::bigint;
  if expires<=now_epoch or expires>least(now_epoch+300,floor(extract(epoch from admission.expires_at)))
    or not manifest.changes @> jsonb_build_array(
      jsonb_build_object('kind',case when room_id is null then 'workspace_file' else 'room_file' end,'id',p_file,'state','added','after',claim->>'fileRevision'),
      jsonb_build_object('kind','storage_object','id',claim->>'object','state','added','after',claim->>'objectRevision'))
    then raise insufficient_privilege; end if;

  select lower(btrim(u.email)) into owner_email from auth.users u
    where u.id=actor_id and u.email_confirmed_at is not null and nullif(btrim(u.email),'') is not null
      and nullif(btrim(u.email_change),'') is null;
  if not found then raise insufficient_privilege; end if;
  owner_tag:=extensions.hmac(convert_to('sectalk-file-replay-owner-v1:'||transfer.handoff::text||':'||owner_email,'UTF8'),
    signing_key,'sha256');
  if extensions.hmac(owner_tag,signing_key,'sha256')
    <>extensions.hmac(decode(claim->>'ownerTag','hex'),signing_key,'sha256') then raise insufficient_privilege; end if;

  return jsonb_build_object('state','proof_verified','handoff',transfer.handoff,'file',p_file,
    'filename',claim->>'filename','room',room_id,'roomName',room_name,'sha256',p_sha256,'bytes',p_bytes,'review',manifest.review,
    'proofSha256',encode(sha256(convert_to(p_proof::text,'UTF8')),'hex'));
end $$;

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
    destination_object,destination_file_digest,destination_storage_digest,room,room_name)
    values (handoff_id,p_file,review_id,p_sha256,p_bytes,object_row.id,object_row.version,admission->>'filename',
      (claim->>'object')::uuid,claim->>'fileRevision',claim->>'objectRevision',(admission->>'room')::uuid,admission->>'roomName')
    on conflict (handoff,file) do nothing returning * into receipt;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,auth.uid(),'workspace.residency_file_replay_staged',p_file);
  else
    select c.* into receipt from sectalk_private.st_v8_residency_source_file_copies c
      where (c.handoff,c.file)=(handoff_id,p_file);
    if (receipt.review,receipt.sha256,receipt.bytes,receipt.object_id,receipt.object_version,coalesce(receipt.filename,admission->>'filename'),receipt.room,receipt.room_name)
      is distinct from (review_id,p_sha256,p_bytes,object_row.id,object_row.version,admission->>'filename',(admission->>'room')::uuid,admission->>'roomName') then
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
    perform pg_advisory_xact_lock(hashtextextended('sectalk-room-mode:'||p_workspace::text,0));
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

  select coalesce(jsonb_agg(jsonb_build_object('file',c.file,'sha256',c.sha256,'bytes',c.bytes,'filename',c.filename,'room',c.room,
      'digest',d.value,'state',case when o.id is null then 'changed'
        when c.room is not null and not sectalk_private.st_v8_residency_source_room_matches(
          p_workspace,approval.id,approval.requester,approval.reviewer,c.room,c.room_name) then 'changed'
        when c.restored_at is not null and live.id is not null
          and (published.id is not null or published_room.id is not null) then 'restored'
        when c.restored_at is not null then 'changed'
        when c.reviewer=approval.reviewer and c.approved_digest=d.value then 'approved' else 'staged' end)
      order by c.file),'[]'::jsonb) into records
    from sectalk_private.st_v8_residency_source_file_copies c
    left join (storage.objects o join storage.buckets b on b.id=o.bucket_id and not b.public)
      on (o.id,o.version)=(c.object_id,c.object_version) and o.metadata->>'size'=c.bytes::text
      and (o.bucket_id,o.name)=('sectalk-residency-recovery',p_workspace::text||'/'||c.handoff::text||'/'||c.file::text||'/'||c.sha256)
    left join storage.objects live on live.id=c.restored_object and live.version=c.restored_version
      and (live.bucket_id,live.name)=('sectalk-workspace-files',sectalk_private.st_v8_residency_restored_file_path(p_workspace,c.room,c.file))
    left join sectalk_private.st_v6_workspace_files published on (published.workspace,published.id)=(p_workspace,c.file)
      and c.room is null and published.deleted_at is null and published.published_at=c.restored_at and published.filename=c.filename
      and published.size_bytes=c.bytes and published.fingerprint=sectalk_private.st_v6_workspace_file_fingerprint(p_workspace,c.sha256)
    left join sectalk_private.st_v6_room_files published_room
      on (published_room.workspace,published_room.room,published_room.id)=(p_workspace,c.room,c.file)
      and published_room.deleted_at is null and published_room.published_at=c.restored_at and published_room.filename=c.filename
      and (published_room.size_bytes,published_room.sha256)=(c.bytes,c.sha256)
    cross join lateral (select encode(sha256(convert_to((jsonb_build_array('sectalk-source-file-review-v1',
      p_workspace,c.handoff,c.file,c.review,manifest.review_sha256,manifest.packet_sha256,approval.id,approval.requester,approval.reviewer,
      c.sha256,c.bytes,c.object_id,c.object_version,c.filename)||
      case when c.room is null then '[]'::jsonb else jsonb_build_array(c.room,c.room_name) end)::text,'UTF8')),'hex') value) d
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

drop trigger st_v7_payment_write on sectalk_private.st_v6_room_files;
create trigger st_v7_payment_write before update of workspace,published_at on sectalk_private.st_v6_room_files
  for each row execute function sectalk_private.st_v7_guard_workspace_write('workspace','direct','file');
create trigger st_v8_payment_file_insert before insert on sectalk_private.st_v6_room_files
  for each row execute function sectalk_private.st_v8_guard_workspace_file_insert();

create or replace function public.st_v8_residency_source_file_restore(p_workspace uuid,p_file uuid,p_digest text,
  p_action text default 'prepare') returns jsonb language plpgsql security definer
  set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  actor_id uuid:=auth.uid();
  handoff_id uuid;
  review_row jsonb;
  copy sectalk_private.st_v8_residency_source_file_copies;
  object_row storage.objects;
  restored sectalk_private.st_v6_workspace_files;
  restored_room sectalk_private.st_v6_room_files;
  published_at timestamptz;
begin
  if p_workspace is null or p_file is null or not coalesce(p_digest~'^[0-9a-f]{64}$',false)
    or not coalesce(p_action in ('prepare','publish'),false)
    or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
    or sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'owner'
    then raise insufficient_privilege; end if;

  perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-room-mode:'||p_workspace::text,0));
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
  if copy.room is not null then
    perform 1 from public.st_v6_rooms r where (r.id,r.workspace_id,r.name)=(copy.room,p_workspace,copy.room_name)
      and r.kind='public' and r.classification in ('public','internal') and r.encryption_mode='standard'
      and not r.archived and not r.locked for share;
    if not found or public.st_v8_app_file_context('room',copy.room)->>'access' is distinct from 'allowed'
      or sectalk_private.st_v7_workspace_payment_mode(p_workspace)->>'reason' is distinct from 'residency'
      or exists(select 1 from public.st_v6_room_timeouts t where (t.room_id,t.user_id)=(copy.room,actor_id)
        and t.until_at>statement_timestamp()) then raise insufficient_privilege; end if;
  end if;
  if exists(select 1 from sectalk_private.st_v6_malware_hashes m where m.sha256=decode(copy.sha256,'hex')) then
    raise exception 'The recovery copy was blocked by platform policy.' using errcode='PT422'; end if;
  perform sectalk_private.limit_action('v8_residency_source_file_restore',30);

  if copy.restored_at is not null then
    return jsonb_build_object('state','restored','file',p_file,'publishedAt',copy.restored_at);
  end if;
  if copy.room is null then
    if exists(select 1 from sectalk_private.st_v6_workspace_files f where (f.workspace,f.id)=(p_workspace,p_file)) or
      exists(select 1 from sectalk_private.st_v6_workspace_retired_file_ids f where (f.workspace,f.id)=(p_workspace,p_file)) then
      raise exception 'The source already contains this file identity.' using errcode='PT409';
    end if;
    if exists(select 1 from sectalk_private.st_v6_workspace_files f where f.workspace=p_workspace
      group by f.workspace having count(*)>=200 or sum(f.size_bytes)+copy.bytes>67108864) then
      raise exception 'The workspace file storage limit was reached.' using errcode='PT413';
    end if;
  else
    if exists(select 1 from sectalk_private.st_v6_room_files f where (f.room,f.id)=(copy.room,p_file))
      or exists(select 1 from sectalk_private.st_v8_offboarding_room_file_retirements f
        where (f.room,f.file)=(copy.room,p_file)) then
      raise exception 'The source already contains or retired this room file identity.' using errcode='PT409';
    end if;
    if exists(select 1 from sectalk_private.st_v6_room_files f where f.room=copy.room
      group by f.room having count(*)>=100 or sum(f.size_bytes)+copy.bytes>33554432) then
      raise exception 'The room file storage limit was reached.' using errcode='PT413';
    end if;
  end if;
  if p_action='prepare' then
    return jsonb_build_object('state','ready','file',p_file,'room',copy.room,'handoff',handoff_id,'filename',copy.filename,'bytes',copy.bytes,'sha256',copy.sha256);
  end if;

  select o.* into object_row from storage.objects o join storage.buckets b on b.id=o.bucket_id and not b.public
    where (o.bucket_id,o.name)=('sectalk-workspace-files',sectalk_private.st_v8_residency_restored_file_path(p_workspace,copy.room,p_file))
      and o.version is not null and o.metadata->>'size'=copy.bytes::text
      and o.user_metadata->>'sectalkRollbackApproval'=p_digest and o.user_metadata->>'sectalkRollbackSha256'=copy.sha256
    for share of o,b;
  if not found then raise exception 'The verified copy is missing from workspace Storage.' using errcode='PT409'; end if;

  published_at:=clock_timestamp();
  if copy.room is null then
    restored.workspace:=p_workspace;
    restored.id:=p_file;
    restored.uploader:=actor_id;
    restored.filename:=copy.filename;
    restored.size_bytes:=copy.bytes;
    restored.fingerprint:=sectalk_private.st_v6_workspace_file_fingerprint(p_workspace,copy.sha256);
    restored.created_at:=published_at;
    restored.published_at:=restored.created_at;
    restored.maintenance_after:='-infinity';
    insert into sectalk_private.st_v8_residency_file_write_permits(tx,workspace,file,revision)
      values(pg_current_xact_id(),p_workspace,p_file,sha256(convert_to(to_jsonb(restored)::text,'UTF8')));
    insert into sectalk_private.st_v6_workspace_files select (restored).*;
    delete from sectalk_private.st_v8_residency_file_write_permits p
      where (p.tx,p.workspace,p.file)=(pg_current_xact_id(),p_workspace,p_file);
    insert into sectalk_private.st_v6_workspace_file_events(workspace,file_id,actor,event)
      values(p_workspace,p_file,actor_id,'published');
  else
    restored_room.room:=copy.room;
    restored_room.workspace:=p_workspace;
    restored_room.id:=p_file;
    restored_room.uploader:=actor_id;
    restored_room.filename:=copy.filename;
    restored_room.size_bytes:=copy.bytes;
    restored_room.sha256:=copy.sha256;
    restored_room.created_at:=published_at;
    restored_room.published_at:=published_at;
    restored_room.retry_at:='-infinity';
    insert into sectalk_private.st_v8_residency_file_write_permits(tx,workspace,file,revision)
      values(pg_current_xact_id(),p_workspace,p_file,sha256(convert_to(to_jsonb(restored_room)::text,'UTF8')));
    insert into sectalk_private.st_v6_room_files select (restored_room).*;
    delete from sectalk_private.st_v8_residency_file_write_permits p
      where (p.tx,p.workspace,p.file)=(pg_current_xact_id(),p_workspace,p_file);
  end if;
  update sectalk_private.st_v8_residency_source_file_copies c
    set restored_at=published_at,restored_object=object_row.id,restored_version=object_row.version
    where (c.handoff,c.file)=(handoff_id,p_file);
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor_id,'workspace.residency_file_replay_restored',p_file);
  return jsonb_build_object('state','restored','file',p_file,'publishedAt',published_at);
end $$;

create or replace function sectalk_private.st_v8_pin_restored_file_evidence()
returns trigger language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  workspace_id uuid;
begin
  if new.restored_at is null or old.restored_at is not null then return new; end if;
  if new.destination_object is null then
    raise exception 'Stage a newly signed copy before restoring the file.' using errcode='PT409';
  end if;
  select h.workspace into strict workspace_id from sectalk_private.st_v8_residency_write_handoffs h where h.handoff=new.handoff;
  if new.room is null then
    select encode(sha256(convert_to(to_jsonb(f)::text,'UTF8')),'hex') into strict new.local_file_digest
      from sectalk_private.st_v6_workspace_files f
      where (f.workspace,f.id,f.published_at)=(workspace_id,new.file,new.restored_at);
  else
    select encode(sha256(convert_to(to_jsonb(f)::text,'UTF8')),'hex') into strict new.local_file_digest
      from sectalk_private.st_v6_room_files f
      where (f.workspace,f.room,f.id,f.published_at)=(workspace_id,new.room,new.file,new.restored_at);
  end if;
  select encode(sha256(convert_to((to_jsonb(o)-'last_accessed_at')::text,'UTF8')),'hex') into strict new.local_storage_digest
    from storage.objects o
    where (o.id,o.version,o.bucket_id,o.name)=(new.restored_object,new.restored_version,'sectalk-workspace-files',
      sectalk_private.st_v8_residency_restored_file_path(workspace_id,new.room,new.file));
  return new;
end $$;

create or replace function sectalk_private.st_v8_restored_file_evidence(p_workspace uuid,p_handoff uuid,p_review uuid,
  p_owner uuid,p_reviewer uuid)
returns table(kind text,id uuid,revision text,receipt text,matched boolean) language sql stable
  set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  select e.kind,e.id,e.revision,
    encode(sha256(convert_to((jsonb_build_array(case when c.room is null then 'sectalk-restored-file-evidence-v1' else 'sectalk-restored-room-file-evidence-v1' end,p_workspace,c.handoff,c.file,
      c.destination_object,c.destination_file_digest,c.destination_storage_digest,c.approved_digest,
      c.restored_object,c.restored_version,c.local_file_digest,c.local_storage_digest)||
      case when c.room is null then '[]'::jsonb else jsonb_build_array(c.room,c.room_name) end)::text,'UTF8')),'hex'),
    coalesce(not b.public and (
      (c.room is null and f.uploader=p_owner and f.published_at=c.restored_at and f.deleted_at is null
        and encode(sha256(convert_to(to_jsonb(f)::text,'UTF8')),'hex')=c.local_file_digest)
      or (c.room is not null and rf.uploader=p_owner and rf.published_at=c.restored_at and rf.deleted_at is null
        and sectalk_private.st_v8_residency_source_room_matches(p_workspace,h.approval,p_owner,p_reviewer,c.room,c.room_name)
        and encode(sha256(convert_to(to_jsonb(rf)::text,'UTF8')),'hex')=c.local_file_digest))
      and encode(sha256(convert_to((to_jsonb(o)-'last_accessed_at')::text,'UTF8')),'hex')=c.local_storage_digest,false)
  from sectalk_private.st_v8_residency_source_file_copies c
  join sectalk_private.st_v8_residency_write_handoffs h using(handoff)
  cross join lateral (values (case when c.room is null then 'workspace_file' else 'room_file' end,c.file,c.destination_file_digest),
    ('storage_object',c.destination_object,c.destination_storage_digest)) e(kind,id,revision)
  left join sectalk_private.st_v6_workspace_files f on (f.workspace,f.id)=(p_workspace,c.file)
  left join sectalk_private.st_v6_room_files rf on (rf.workspace,rf.room,rf.id)=(p_workspace,c.room,c.file)
  left join storage.objects o on (o.id,o.version,o.bucket_id,o.name)=(c.restored_object,c.restored_version,
    'sectalk-workspace-files',sectalk_private.st_v8_residency_restored_file_path(p_workspace,c.room,c.file))
  left join storage.buckets b on b.id=o.bucket_id
  where (c.handoff,c.review,c.reviewer)=(p_handoff,p_review,p_reviewer) and c.restored_at is not null
    and c.local_file_digest is not null and c.destination_object is not null
$$;

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
    perform pg_advisory_xact_lock(hashtextextended('sectalk-room-mode:'||p_workspace::text,0));
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
