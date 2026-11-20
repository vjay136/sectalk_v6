begin;

create table sectalk_private.st_v7_file_fingerprints (
  file_id uuid primary key references public.st_v5_files on delete cascade,
  fingerprint bytea not null check(octet_length(fingerprint)=32),
  duplicate boolean not null
);
create index st_v7_file_fingerprints_match on sectalk_private.st_v7_file_fingerprints(fingerprint);
alter table sectalk_private.st_v7_file_fingerprints enable row level security;
revoke all on sectalk_private.st_v7_file_fingerprints from public,anon,authenticated,service_role;

create or replace function public.st_v6_pending_file(p_file uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare f public.st_v5_files; actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_file_inspection',12);
  select * into f from public.st_v5_files where id=p_file and uploader=actor;
  if not found or not sectalk_private.st_v2_chat_write(f.chat_id,actor)
    or (f.message_id is null and f.created_at<=now()-interval '15 minutes') then return null; end if;
  return jsonb_build_object('filename',f.filename,'size',f.size_bytes,'published',f.message_id,
    'duplicate',coalesce((select duplicate from sectalk_private.st_v7_file_fingerprints where file_id=p_file),false));
end $$;

create function public.st_v7_publish_hashed_file(p_file uuid,p_actor uuid,p_caption text,p_hash text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare f public.st_v5_files; message uuid; scoped_hash bytea; matched boolean;
begin
  if p_hash is null or p_hash !~ '^[0-9a-f]{64}$' then raise exception 'Invalid attachment fingerprint'; end if;
  select * into f from public.st_v5_files where id=p_file and uploader=p_actor for update;
  if not found then raise exception 'Attachment unavailable'; end if;
  -- Publishing holds the chat row lock through commit, serializing simultaneous matching uploads.
  message:=public.st_v6_publish_validated_file(p_file,p_actor,p_caption);
  if f.message_id is not null then
    select duplicate into matched from sectalk_private.st_v7_file_fingerprints where file_id=p_file;
    return jsonb_build_object('id',message,'duplicate',coalesce(matched,false));
  end if;

  -- Direct attachments are personal. Scope the fingerprint to the exact chat and its uploader.
  scoped_hash:=sha256(convert_to(f.chat_id::text||':'||p_actor::text||':'||p_hash,'UTF8'));
  select exists(
    select 1 from sectalk_private.st_v7_file_fingerprints indexed
    join public.st_v5_files previous on previous.id=indexed.file_id
    join public.st_messages prior_message on prior_message.id=previous.message_id
    where indexed.fingerprint=scoped_hash and previous.chat_id=f.chat_id and previous.uploader=p_actor
      and prior_message.revoked_at is null
      and not exists(select 1 from public.st_v5_hidden_messages hidden
        where hidden.user_id=p_actor and hidden.message_id=prior_message.id)
  ) into matched;
  insert into sectalk_private.st_v7_file_fingerprints(file_id,fingerprint,duplicate)
    values(p_file,scoped_hash,matched);
  return jsonb_build_object('id',message,'duplicate',matched);
end $$;

revoke all on function public.st_v7_publish_hashed_file(uuid,uuid,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_publish_hashed_file(uuid,uuid,text,text) to service_role;

commit;
