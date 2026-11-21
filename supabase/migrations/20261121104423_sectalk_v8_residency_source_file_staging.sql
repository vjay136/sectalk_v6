begin;

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values ('sectalk-residency-recovery','sectalk-residency-recovery',false,4194304,array['application/octet-stream']);

create policy st_v8_private_residency_recovery on storage.objects as restrictive for all to public
  using (bucket_id<>'sectalk-residency-recovery') with check (bucket_id<>'sectalk-residency-recovery');

create table sectalk_private.st_v8_residency_source_file_copies (
  handoff uuid references sectalk_private.st_v8_residency_write_handoffs(handoff) on delete cascade,
  file uuid,
  review uuid not null,
  sha256 text not null check (sha256~'^[0-9a-f]{64}$'),
  bytes integer not null check (bytes between 1 and 4194304),
  object_id uuid not null,
  object_version text not null,
  staged_at timestamptz not null default clock_timestamp(),
  primary key (handoff,file)
);
alter table sectalk_private.st_v8_residency_source_file_copies enable row level security;
revoke all on sectalk_private.st_v8_residency_source_file_copies from public,anon,authenticated,service_role;

create function public.st_v8_residency_source_file_stage(
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

  insert into sectalk_private.st_v8_residency_source_file_copies(handoff,file,review,sha256,bytes,object_id,object_version)
    values (handoff_id,p_file,review_id,p_sha256,p_bytes,object_row.id,object_row.version)
    on conflict (handoff,file) do nothing returning * into receipt;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,auth.uid(),'workspace.residency_file_replay_staged',p_file);
  else
    select c.* into receipt from sectalk_private.st_v8_residency_source_file_copies c
      where (c.handoff,c.file)=(handoff_id,p_file);
    if (receipt.review,receipt.sha256,receipt.bytes,receipt.object_id,receipt.object_version)
      is distinct from (review_id,p_sha256,p_bytes,object_row.id,object_row.version) then
      raise exception 'The staged recovery copy differs from the verified receipt.' using errcode='PT409';
    end if;
  end if;
  return jsonb_build_object('state','staged','file',p_file,'stagedAt',receipt.staged_at);
end $$;

revoke all on function public.st_v8_residency_source_file_stage(uuid,uuid,jsonb,text,integer)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_source_file_stage(uuid,uuid,jsonb,text,integer) to authenticated;
notify pgrst,'reload schema';
commit;
