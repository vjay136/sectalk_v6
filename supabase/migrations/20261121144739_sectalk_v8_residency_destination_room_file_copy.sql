begin;

create function public.st_v8_residency_rollback_room_file_copy(
  p_workspace uuid,p_review uuid,p_file uuid,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  actor_id uuid:=auth.uid();
  transfer sectalk_private.st_v8_residency_write_handoffs;
  admission sectalk_private.st_v8_residency_rollback_manifest_admissions;
  file_row sectalk_private.st_v6_room_files;
  room_row public.st_v6_rooms;
  object_row storage.objects;
  review jsonb;
  file_revision text;
  object_revision text;
  stamp text;
  wire text;
  signing_key bytea;
  owner_email text;
begin
  if p_workspace is null or p_review is null or p_file is null
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
    or sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'owner'
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    or sectalk_private.st_v8_residency_rollback_side(p_workspace) is distinct from 'destination'
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;

  review:=public.st_v8_residency_rollback_reconcile(p_workspace);
  if (review->>'state',review->>'id') is distinct from ('reviewed',p_review::text) then raise insufficient_privilege; end if;
  select f.* into transfer from sectalk_private.st_v8_residency_write_handoffs f
    where f.workspace=p_workspace and f.phase='activated';
  select a.* into admission from sectalk_private.st_v8_residency_rollback_manifest_admissions a
    where a.handoff=transfer.handoff and a.expires_at>statement_timestamp();
  if not found then raise insufficient_privilege; end if;

  select f.* into file_row from sectalk_private.st_v6_room_files f
    where (f.workspace,f.id,f.uploader)=(p_workspace,p_file,actor_id)
      and f.deleted_at is null and f.published_at>=transfer.changed_at
      and not exists(select 1 from sectalk_private.st_v6_room_files other
        where (other.workspace,other.id)=(f.workspace,f.id) and other.room<>f.room);
  if not found then raise insufficient_privilege; end if;
  select r.* into room_row from public.st_v6_rooms r
    where (r.id,r.workspace_id,r.creator)=(file_row.room,p_workspace,actor_id)
      and (r.kind,r.classification,r.encryption_mode)=('private','confidential','standard')
      and not r.archived and not r.locked
      and sectalk_private.st_v6_room_role(r.id,actor_id)='owner'
      and not exists(select 1 from jsonb_array_elements(review->'changes') diff
        where (diff->>'kind',diff->>'id')=('room',r.id::text))
      and exists(select 1 from sectalk_private.st_v8_residency_room_imports i
        where (i.workspace,i.source_project,i.approval,i.room,i.room_name,i.actor)=
          (p_workspace,transfer.source_project,transfer.approval,r.id,r.name,actor_id) and i.imported_at<=transfer.changed_at);
  if not found or public.st_v8_app_file_context('room',room_row.id)->>'access' is distinct from 'allowed'
    or not coalesce((public.st_v7_explain_file_egress('room',room_row.id,p_file,'download')->>'allowed')::boolean,false)
    then raise insufficient_privilege; end if;

  select o.* into object_row from storage.objects o
    join storage.buckets b on b.id=o.bucket_id and b.public is false
    where (o.bucket_id,o.name)=('sectalk-workspace-files',p_workspace::text||'/rooms/'||room_row.id::text||'/'||p_file::text)
      and o.version is not null and o.metadata->>'size'=file_row.size_bytes::text;
  if not found then raise insufficient_privilege; end if;

  file_revision:=encode(sha256(convert_to(to_jsonb(file_row)::text,'UTF8')),'hex');
  object_revision:=encode(sha256(convert_to((to_jsonb(object_row)-'last_accessed_at')::text,'UTF8')),'hex');
  if not (review->'changes') @> jsonb_build_array(
    jsonb_build_object('kind','room_file','id',p_file,'state','added','after',file_revision),
    jsonb_build_object('kind','storage_object','id',object_row.id,'state','added','after',object_revision)
  ) then raise insufficient_privilege; end if;

  stamp:=encode(sha256(convert_to(jsonb_build_array(transfer.handoff,p_review,review->>'digest',
    admission.plan_sha256,room_row.id,room_row.name,file_revision,object_revision)::text,'UTF8')),'hex');
  if p_sha256 is null then return jsonb_build_object('room',room_row.id,'stamp',stamp,'bytes',file_row.size_bytes); end if;
  if p_sha256 is distinct from file_row.sha256 then raise insufficient_privilege; end if;

  select lower(btrim(u.email)) into owner_email from auth.users u
    where u.id=actor_id and u.email_confirmed_at is not null and nullif(btrim(u.email),'') is not null
      and nullif(btrim(u.email_change),'') is null;
  if not found then raise insufficient_privilege; end if;

  perform sectalk_private.limit_action('v8_residency_rollback_file_copy',20);
  select decode(v.decrypted_secret,'hex') into signing_key from vault.decrypted_secrets v
    where v.id=admission.vault_id and v.decrypted_secret~'^[0-9a-f]{64}$';
  if not found then raise insufficient_privilege; end if;
  wire:=jsonb_build_object('format','sectalk-residency-room-file-copy-v1','workspace',p_workspace,
    'handoff',transfer.handoff,'source',transfer.source_project,'destination',transfer.destination_project,
    'approval',transfer.approval,'plan',admission.plan_sha256,'review',p_review,'digest',review->>'digest',
    'room',room_row.id,'roomName',room_row.name,
    'file',p_file,'fileRevision',file_revision,'object',object_row.id,'objectRevision',object_revision,
    'ownerTag',encode(extensions.hmac(convert_to('sectalk-file-replay-owner-v1:'||transfer.handoff::text||':'||owner_email,'UTF8'),
      signing_key,'sha256'),'hex'),
    'filename',file_row.filename,'bytes',file_row.size_bytes,'sha256',p_sha256,
    'expires',floor(extract(epoch from least(admission.expires_at,statement_timestamp()+interval '5 minutes'))))::text;
  return jsonb_build_object('room',room_row.id,'stamp',stamp,'bytes',file_row.size_bytes,'proof',jsonb_build_object(
    'payload',wire,'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),'hex')));
end $$;

revoke all on function public.st_v8_residency_rollback_room_file_copy(uuid,uuid,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_rollback_room_file_copy(uuid,uuid,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
