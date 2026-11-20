begin;

alter table public.st_v5_files add column upload_lease_until timestamptz;

create table sectalk_private.st_v6_attachment_policy (
  account_id uuid primary key references public.st_profiles on delete cascade,
  max_file_bytes integer check(max_file_bytes between 0 and 4194304),
  max_storage_bytes bigint check(max_storage_bytes between 0 and 8589934592),
  check(max_file_bytes is not null or max_storage_bytes is not null)
);
alter table sectalk_private.st_v6_attachment_policy enable row level security;
revoke all on sectalk_private.st_v6_attachment_policy from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_attachment_entitlement(p_actor uuid)
returns table(plan text,max_file_bytes integer,max_storage_bytes bigint)
language sql stable set search_path='' as $$
  select tiers.plan,least(tiers.max_file_bytes,policy.max_file_bytes),
    least(tiers.max_storage_bytes,policy.max_storage_bytes)
  from (values
    ('free',1048576,33554432::bigint),
    ('basic',2097152,134217728::bigint),
    ('professional',3145728,536870912::bigint),
    ('business',4194304,2147483648::bigint),
    ('enterprise',4194304,8589934592::bigint)
  ) tiers(plan,max_file_bytes,max_storage_bytes)
  left join sectalk_private.st_v6_attachment_policy policy on policy.account_id=p_actor
  where tiers.plan=sectalk_private.st_v2_effective_plan(p_actor)
$$;

create function sectalk_private.st_v6_attachment_usage(p_actor uuid)
returns table(stored_bytes bigint,reserved_bytes bigint)
language sql stable set search_path='' as $$
  select coalesce(sum(greatest(f.size_bytes,case when o.metadata->>'size' ~ '^[0-9]{1,10}$'
      then (o.metadata->>'size')::bigint end))
      filter (where f.message_id is not null or o.id is not null),0)::bigint,
    coalesce(sum(f.size_bytes) filter (where f.message_id is null and o.id is null
      and greatest(f.created_at+interval '15 minutes',f.upload_lease_until)>statement_timestamp()),0)
  from public.st_v5_files f
  left join storage.objects o on o.bucket_id='sectalk-chat-files' and o.name=f.id::text
  where f.uploader=p_actor
$$;

create function sectalk_private.st_v6_lock_attachment_owner(p_actor uuid)
returns void language sql set search_path='' as $$
  select pg_advisory_xact_lock(hashtextextended('sectalk:attachment-quota:'||p_actor::text,0))
$$;

-- Additional bytes are zero when the existing reservation already counts towards quota.
create function sectalk_private.st_v6_require_attachment_capacity(p_actor uuid,p_bytes integer,p_additional integer)
returns void language plpgsql set search_path='' as $$
declare entitlement record;
declare usage record;
begin
  select * into entitlement from sectalk_private.st_v6_attachment_entitlement(p_actor);
  if p_bytes>entitlement.max_file_bytes then
    raise exception 'This file exceeds your per-attachment limit.' using errcode='PT413';
  end if;
  select * into usage from sectalk_private.st_v6_attachment_usage(p_actor);
  if usage.stored_bytes+usage.reserved_bytes+p_additional>entitlement.max_storage_bytes then
    raise exception 'You have reached your direct attachment storage limit.' using errcode='PT409';
  end if;
end
$$;

create function public.st_v6_attachment_capacity()
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('plan',e.plan,'max_file_bytes',e.max_file_bytes,'max_storage_bytes',e.max_storage_bytes,
    'stored_bytes',u.stored_bytes,'reserved_bytes',u.reserved_bytes)
  from sectalk_private.st_v6_attachment_entitlement(auth.uid()) e
  cross join sectalk_private.st_v6_attachment_usage(auth.uid()) u
  where auth.uid() is not null
$$;

create or replace function public.st_v5_stage_file(p_chat uuid,p_id uuid,p_filename text,p_bytes integer)
returns boolean language plpgsql security definer set search_path='' as $$
declare previous public.st_v5_files; clean_name text; actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v5_attachment_stage',8);
  if not sectalk_private.st_v2_chat_write(p_chat,actor) then raise exception 'Conversation unavailable'; end if;
  clean_name:=regexp_replace(btrim(p_filename),'[/[:cntrl:][:space:]]+',' ','g');
  if clean_name is null or char_length(clean_name) not between 1 and 140 or strpos(clean_name,chr(92))>0
    or clean_name !~* '[.](png|jpe?g|webp|gif|pdf|txt)$' or p_bytes is null or p_bytes not between 1 and 4194304
    then raise exception 'Choose a supported file up to 4 MiB'; end if;

  perform sectalk_private.st_v6_lock_attachment_owner(actor);
  select * into previous from public.st_v5_files where id=p_id;
  if found then
    if previous.uploader<>actor or previous.chat_id<>p_chat or previous.filename<>clean_name or previous.size_bytes<>p_bytes
      or (previous.message_id is null and previous.created_at<=now()-interval '15 minutes')
      then raise exception 'Start a new attachment upload'; end if;
    if previous.message_id is null then
      perform sectalk_private.st_v6_require_attachment_capacity(actor,p_bytes,0);
    end if;
  else
    perform sectalk_private.st_v6_require_attachment_capacity(actor,p_bytes,p_bytes);
    insert into public.st_v5_files(id,chat_id,uploader,filename,size_bytes)
      values(p_id,p_chat,actor,clean_name,p_bytes) on conflict(id) do nothing;
    if not found then raise exception 'Start a new attachment upload'; end if;
  end if;
  return exists(select 1 from storage.objects where bucket_id='sectalk-chat-files' and name=p_id::text);
end $$;

create function public.st_v6_authorize_file_upload(p_file uuid,p_actor uuid,p_bytes integer)
returns jsonb language plpgsql security definer set search_path='' as $$
declare f public.st_v5_files; object_size text;
begin
  perform sectalk_private.st_v6_lock_attachment_owner(p_actor);
  select * into f from public.st_v5_files where id=p_file and uploader=p_actor for update;
  if not found or not sectalk_private.st_v2_chat_write(f.chat_id,p_actor)
    or (f.message_id is null and f.created_at<=now()-interval '15 minutes') then return null; end if;
  if p_bytes is distinct from f.size_bytes then
    raise exception 'The uploaded size does not match the staged attachment.' using errcode='PT409';
  end if;
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

  -- Keep the reservation charged while the bounded server upload finishes, even near stage expiry.
  update public.st_v5_files set upload_lease_until=statement_timestamp()+interval '5 minutes' where id=p_file;
  return jsonb_build_object('filename',f.filename,'uploaded',false);
end $$;

create or replace function public.st_v6_publish_validated_file(p_file uuid,p_actor uuid,p_caption text)
returns uuid language plpgsql security definer set search_path='' as $$
declare f public.st_v5_files; body_text text; object_size text; outcome text;
begin
  perform sectalk_private.st_v6_lock_attachment_owner(p_actor);
  select * into f from public.st_v5_files where id=p_file and uploader=p_actor for update;
  if not found or not sectalk_private.st_v2_chat_write(f.chat_id,p_actor)
    then raise exception 'Attachment unavailable'; end if;
  if f.message_id is not null then return f.message_id; end if;
  if f.created_at<=now()-interval '15 minutes' then raise exception 'Start a new attachment upload'; end if;
  select metadata->>'size' into object_size from storage.objects where bucket_id='sectalk-chat-files' and name=p_file::text;
  if object_size is distinct from f.size_bytes::text then raise exception 'Attachment upload is incomplete'; end if;
  perform sectalk_private.st_v6_require_attachment_capacity(p_actor,f.size_bytes,0);
  body_text:=coalesce(nullif(btrim(p_caption),''),'Attachment: '||f.filename);
  outcome:=sectalk_private.st_v6_write_message(p_actor,f.chat_id,f.id,body_text);
  if outcome<>'sent' then raise exception 'Attachment could not be published'; end if;
  update public.st_v5_files set message_id=f.id,upload_lease_until=null where id=f.id;
  return f.id;
end $$;

create or replace function public.st_v7_publish_hashed_file(p_file uuid,p_actor uuid,p_caption text,p_hash text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare f public.st_v5_files; message uuid; scoped_hash bytea; matched boolean;
begin
  if p_hash is null or p_hash !~ '^[0-9a-f]{64}$' then raise exception 'Invalid attachment fingerprint'; end if;
  perform sectalk_private.st_v6_lock_attachment_owner(p_actor);
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

-- The Storage authorization probe runs before the actual upload size is known.
drop policy st_v5_attachment_insert on storage.objects;
alter policy st_v5_attachment_guard_insert on storage.objects
  with check (bucket_id<>'sectalk-chat-files');

revoke all on function sectalk_private.st_v6_attachment_entitlement(uuid),
  sectalk_private.st_v6_attachment_usage(uuid),sectalk_private.st_v6_lock_attachment_owner(uuid),
  sectalk_private.st_v6_require_attachment_capacity(uuid,integer,integer) from public,anon,authenticated,service_role;
revoke all on function public.st_v6_attachment_capacity(),public.st_v6_authorize_file_upload(uuid,uuid,integer)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_attachment_capacity() to authenticated;
grant execute on function public.st_v6_authorize_file_upload(uuid,uuid,integer) to service_role;

commit;
