begin;

-- Validate the signed copy against the held source. This does not publish a file
-- or grant access to the live workspace bucket.
create function public.st_v8_residency_source_file_admission(
  p_workspace uuid,p_file uuid,p_proof jsonb,p_sha256 text,p_bytes integer
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor_id uuid:=auth.uid();
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
  perform 1 from public.st_v2_workspaces w where (w.id,w.owner)=(p_workspace,actor_id) for share;
  if not found or sectalk_private.st_v8_residency_rollback_side(p_workspace) is distinct from 'source'
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;

  select f.* into transfer from sectalk_private.st_v8_residency_write_handoffs f where f.workspace=p_workspace;
  perform 1 from sectalk_private.st_v8_content_exports c
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
  if (claim->>'format',claim->>'workspace',claim->>'handoff',claim->>'source',claim->>'destination',
      claim->>'approval',claim->>'plan',claim->>'review',claim->>'digest',claim->>'file',claim->>'sha256',claim->>'bytes')
      is distinct from ('sectalk-residency-file-copy-v1',p_workspace::text,transfer.handoff::text,
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
      jsonb_build_object('kind','workspace_file','id',p_file,'state','added','after',claim->>'fileRevision'),
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
    'filename',claim->>'filename','sha256',p_sha256,'bytes',p_bytes,'review',manifest.review,
    'proofSha256',encode(sha256(convert_to(p_proof::text,'UTF8')),'hex'));
end $$;

revoke all on function public.st_v8_residency_source_file_admission(uuid,uuid,jsonb,text,integer)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_source_file_admission(uuid,uuid,jsonb,text,integer) to authenticated;
notify pgrst,'reload schema';
commit;
