begin;

create table sectalk_private.st_v6_attachment_uploads (
  file_id uuid primary key references public.st_v5_files on delete cascade,
  sha256 text not null check(sha256 ~ '^[0-9a-f]{64}$'),
  received integer not null default 0 check(received between 0 and 4194304),
  completed boolean not null default false
);
create table sectalk_private.st_v6_attachment_chunks (
  file_id uuid not null references sectalk_private.st_v6_attachment_uploads on delete cascade,
  offset_bytes integer not null check(offset_bytes>=0 and offset_bytes<4194304),
  contents bytea not null check(octet_length(contents) between 1 and 262144),
  digest bytea not null check(octet_length(digest)=32),
  primary key(file_id,offset_bytes)
);
alter table sectalk_private.st_v6_attachment_uploads enable row level security;
alter table sectalk_private.st_v6_attachment_chunks enable row level security;
revoke all on sectalk_private.st_v6_attachment_uploads, sectalk_private.st_v6_attachment_chunks
  from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v6_attachment_stage_alive(p_file uuid,p_created timestamptz)
returns boolean language sql stable set search_path='' as $$
  select p_created>statement_timestamp()-interval '15 minutes' or exists (
    select 1 from sectalk_private.st_v6_attachment_scans s where s.file_id=p_file and s.retain_until>statement_timestamp()
  ) or exists (
    select 1 from sectalk_private.st_v6_attachment_uploads u join public.st_v5_files f on f.id=u.file_id
    where u.file_id=p_file and u.completed and f.upload_lease_until>statement_timestamp()
  )
$$;

create or replace function public.st_v6_authorize_file_upload(p_file uuid,p_actor uuid,p_bytes integer)
returns jsonb language plpgsql security definer set search_path='' as $$
declare f public.st_v5_files; object_size text;
begin
  perform sectalk_private.st_v6_lock_attachment_owner(p_actor);
  select * into f from public.st_v5_files where id=p_file and uploader=p_actor for update;
  if not found or not sectalk_private.st_v2_chat_write(f.chat_id,p_actor)
    or (f.message_id is null and (f.deleted_at is not null or not sectalk_private.st_v6_attachment_stage_alive(f.id,f.created_at))) then return null; end if;
  if p_bytes is distinct from f.size_bytes then
    raise exception 'The uploaded size does not match the staged attachment.' using errcode='PT409';
  end if;
  if exists(select 1 from sectalk_private.st_v6_attachment_uploads u where u.file_id=p_file)
    then raise exception 'Resume the staged attachment upload.' using errcode='PT409'; end if;
  select metadata->>'size' into object_size from storage.objects
    where bucket_id='sectalk-chat-files' and name=p_file::text;
  if f.message_id is null then
    perform sectalk_private.st_v6_require_attachment_capacity(p_actor,p_bytes,0);
  end if;
  if object_size is not null then
    if object_size<>p_bytes::text then
      raise exception 'Start a new attachment upload.' using errcode='PT409';
    end if;
    return jsonb_build_object('filename',f.filename,'uploaded',true);
  end if;
  if f.message_id is not null then return null; end if;
  update public.st_v5_files set upload_lease_until=statement_timestamp()+interval '5 minutes' where id=p_file;
  return jsonb_build_object('filename',f.filename,'uploaded',false);
end $$;

create function public.st_v6_resumable_attachment(
  p_file uuid,p_actor uuid,p_action text,p_sha256 text,p_offset integer,p_chunk text,p_chunk_hash text
)
returns jsonb language plpgsql security definer set search_path='' as $$
declare f public.st_v5_files;
declare u sectalk_private.st_v6_attachment_uploads;
declare object_size text;
declare payload bytea;
declare part_digest bytea;
begin
  if p_sha256 is null or p_sha256 !~ '^[0-9a-f]{64}$' or p_action is null
    or p_action not in ('status','chunk','assemble','finish') then
    raise exception 'Invalid attachment upload request.' using errcode='22023';
  end if;
  perform sectalk_private.st_v6_lock_attachment_owner(p_actor);
  select * into f from public.st_v5_files where id=p_file and uploader=p_actor for update;
  if not found or f.deleted_at is not null or not sectalk_private.st_v2_chat_write(f.chat_id,p_actor) then return null; end if;
  if f.message_id is not null then
    if p_action='chunk' then raise exception 'The attachment was already uploaded.' using errcode='PT409'; end if;
    return jsonb_build_object('offset',f.size_bytes,'uploaded',true);
  end if;
  if not sectalk_private.st_v6_attachment_stage_alive(f.id,f.created_at)
    and (p_action<>'finish' or f.upload_lease_until is null or f.upload_lease_until<=clock_timestamp()) then return null; end if;

  select * into u from sectalk_private.st_v6_attachment_uploads s where s.file_id=p_file;
  if not found then
    if p_action<>'status' then return null; end if;
    select metadata->>'size' into object_size from storage.objects
      where bucket_id='sectalk-chat-files' and name=p_file::text;
    if object_size=f.size_bytes::text then
      return jsonb_build_object('offset',f.size_bytes,'uploaded',true,'verify_existing',true);
    end if;
    if object_size is not null or f.upload_lease_until>clock_timestamp() then
      raise exception 'A different upload is already in progress.' using errcode='PT409';
    end if;
    perform sectalk_private.st_v6_require_attachment_capacity(p_actor,f.size_bytes,0);
    insert into sectalk_private.st_v6_attachment_uploads(file_id,sha256) values(p_file,p_sha256) returning * into u;
  end if;
  if u.sha256<>p_sha256 then raise exception 'This upload belongs to different bytes.' using errcode='PT409'; end if;
  if u.completed then
    if p_action='chunk' then raise exception 'The attachment was already uploaded.' using errcode='PT409'; end if;
    return jsonb_build_object('offset',u.received,'uploaded',true);
  end if;

  if p_action='chunk' then
    if p_offset is null or p_offset<0 or p_offset>=f.size_bytes or p_offset%262144<>0
      or p_chunk is null or char_length(p_chunk)>349528 or p_chunk_hash is null or p_chunk_hash !~ '^[0-9a-f]{64}$' then
      raise exception 'Invalid attachment chunk.' using errcode='22023';
    end if;
    payload:=decode(p_chunk,'base64');
    part_digest:=sha256(payload);
    if octet_length(payload)<>least(262144,f.size_bytes-p_offset) or encode(part_digest,'hex')<>p_chunk_hash then
      raise exception 'The attachment chunk failed checksum or length verification.' using errcode='PT422';
    end if;
    if p_offset<u.received and exists(select 1 from sectalk_private.st_v6_attachment_chunks c
      where c.file_id=p_file and c.offset_bytes=p_offset and c.digest=part_digest) then
      return jsonb_build_object('offset',u.received,'uploaded',false);
    end if;
    if p_offset<>u.received then raise exception 'The attachment chunk offset does not match.' using errcode='PT409'; end if;
    insert into sectalk_private.st_v6_attachment_chunks(file_id,offset_bytes,contents,digest)
      values(p_file,p_offset,payload,part_digest);
    update sectalk_private.st_v6_attachment_uploads set received=received+octet_length(payload) where file_id=p_file returning * into u;
  elsif p_action in ('assemble','finish') then
    if u.received<>f.size_bytes then raise exception 'The attachment upload is incomplete.' using errcode='PT409'; end if;
    if p_action='assemble' then
      perform sectalk_private.st_v6_require_attachment_capacity(p_actor,f.size_bytes,0);
      select string_agg(c.contents,''::bytea order by c.offset_bytes) into payload
        from sectalk_private.st_v6_attachment_chunks c where c.file_id=p_file;
      if payload is null or octet_length(payload)<>f.size_bytes or encode(sha256(payload),'hex')<>u.sha256 then
        raise exception 'The full attachment failed checksum verification.' using errcode='PT422';
      end if;
      update public.st_v5_files set upload_lease_until=clock_timestamp()+interval '5 minutes' where id=p_file;
      return jsonb_build_object('offset',u.received,'uploaded',false,'filename',f.filename,'bytes',encode(payload,'base64'));
    end if;
    if f.upload_lease_until is null or f.upload_lease_until<=clock_timestamp() or not exists(
      select 1 from storage.objects o where o.bucket_id='sectalk-chat-files' and o.name=p_file::text
        and o.metadata->>'size'=f.size_bytes::text
    ) then raise exception 'The verified attachment is not in Storage.' using errcode='PT409'; end if;
    delete from sectalk_private.st_v6_attachment_chunks where file_id=p_file;
    update sectalk_private.st_v6_attachment_uploads set completed=true where file_id=p_file returning * into u;
  end if;
  return jsonb_build_object('offset',u.received,'uploaded',u.completed);
end
$$;

create function sectalk_private.st_v6_resumable_attachment_publish_guard()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if old.message_id is null and new.message_id is not null and exists(
    select 1 from sectalk_private.st_v6_attachment_uploads u where u.file_id=new.id
      and (not u.completed or u.sha256 is distinct from current_setting('sectalk.attachment_sha256',true))
  ) then raise exception 'Finish verifying the attachment upload.' using errcode='PT409'; end if;
  return new;
end
$$;
create trigger st_v6_resumable_attachment_publish_guard before update of message_id on public.st_v5_files
  for each row execute function sectalk_private.st_v6_resumable_attachment_publish_guard();

create function sectalk_private.st_v6_release_attachment_chunks()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if (old.message_id is null and new.message_id is not null) or (old.deleted_at is null and new.deleted_at is not null) then
    delete from sectalk_private.st_v6_attachment_uploads u where u.file_id=new.id;
  end if;
  return null;
end
$$;
create trigger st_v6_release_attachment_chunks after update of message_id,deleted_at on public.st_v5_files
  for each row execute function sectalk_private.st_v6_release_attachment_chunks();

create function public.st_v6_expire_resumable_attachments()
returns integer language sql security definer set search_path='' as $$
  with abandoned as (
    select f.id from public.st_v5_files f join sectalk_private.st_v6_attachment_uploads u on u.file_id=f.id
    where f.message_id is null and f.deleted_at is null and f.created_at<=clock_timestamp()-interval '15 minutes'
      and (f.upload_lease_until is null or f.upload_lease_until<=clock_timestamp())
      and not exists(select 1 from sectalk_private.st_v6_attachment_scans s where s.file_id=f.id)
    order by f.created_at,f.id limit 20 for update of f skip locked
  ), expired as (
    update public.st_v5_files f set deleted_at=clock_timestamp(),purge_after=clock_timestamp()
    from abandoned where f.id=abandoned.id returning f.id
  ) select count(*)::integer from expired
$$;

revoke all on function public.st_v6_resumable_attachment(uuid,uuid,text,text,integer,text,text),
  public.st_v6_expire_resumable_attachments(), sectalk_private.st_v6_resumable_attachment_publish_guard(),
  sectalk_private.st_v6_release_attachment_chunks() from public,anon,authenticated,service_role;
grant execute on function public.st_v6_resumable_attachment(uuid,uuid,text,text,integer,text,text),
  public.st_v6_expire_resumable_attachments() to service_role;

commit;
