begin;

alter table sectalk_private.st_v8_residency_source_file_copies
  add column reviewer uuid,
  add column reviewed_at timestamptz,
  add column approved_digest text check (approved_digest~'^[0-9a-f]{64}$'),
  add check ((reviewer is null)=(reviewed_at is null) and (reviewer is null)=(approved_digest is null));

create function public.st_v8_residency_source_file_review(p_workspace uuid,p_file uuid default null,
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

  select coalesce(jsonb_agg(jsonb_build_object('file',c.file,'sha256',c.sha256,'bytes',c.bytes,
      'digest',d.value,'state',case when o.id is null then 'changed'
        when c.reviewer=approval.reviewer and c.approved_digest=d.value then 'approved' else 'staged' end)
      order by c.file),'[]'::jsonb) into records
    from sectalk_private.st_v8_residency_source_file_copies c
    left join (storage.objects o join storage.buckets b on b.id=o.bucket_id and not b.public)
      on (o.id,o.version)=(c.object_id,c.object_version) and o.metadata->>'size'=c.bytes::text
      and (o.bucket_id,o.name)=('sectalk-residency-recovery',p_workspace::text||'/'||c.handoff::text||'/'||c.file::text||'/'||c.sha256)
    cross join lateral (select encode(sha256(convert_to(jsonb_build_array('sectalk-source-file-review-v1',
      p_workspace,c.handoff,c.file,c.review,manifest.review_sha256,manifest.packet_sha256,approval.id,approval.requester,approval.reviewer,
      c.sha256,c.bytes,c.object_id,c.object_version)::text,'UTF8')),'hex') value) d
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
    records:=jsonb_set(records,'{0,state}','"approved"'::jsonb);
  end if;
  return jsonb_build_object('state','held','role',actor_role,'files',records);
end $$;

revoke all on function public.st_v8_residency_source_file_review(uuid,uuid,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_source_file_review(uuid,uuid,text,text) to authenticated;
notify pgrst,'reload schema';
commit;
