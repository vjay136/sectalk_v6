begin;

alter table public.st_v5_files
  add column deleted_at timestamptz,
  add column purge_after timestamptz,
  add column purged_at timestamptz,
  add column purge_token uuid,
  add column purge_lease_until timestamptz,
  add column purge_next_at timestamptz,
  add column purge_attempts integer not null default 0,
  add constraint st_v6_attachment_retention_state check (
    (deleted_at is null)=(purge_after is null)
    and (purge_token is null)=(purge_lease_until is null)
    and (purged_at is null or deleted_at is not null)
  );
create index st_v6_attachment_purge_queue on public.st_v5_files(purge_after,id)
  where deleted_at is not null and purged_at is null;

alter policy st_v5_chat_files_read on public.st_v5_files using(
  deleted_at is null and exists(select 1 from public.st_messages m where m.id=message_id and m.revoked_at is null)
);

-- Direct legal-hold admission must use the attachment row lock and decline an active purge lease.
-- Approved report evidence is the first retention hold source.
create function sectalk_private.st_v6_attachment_retention_held(p_file uuid)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v5_attachment_reports r where r.file_id=p_file)
$$;

create function sectalk_private.st_v6_guard_new_attachment_evidence()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform 1 from public.st_v5_files f where f.id=new.file_id and f.deleted_at is null for update;
  -- Still allow filing the report independently of the now-deleted attachment.
  return case when found then new else null end;
end
$$;
create trigger st_v6_guard_new_attachment_evidence before insert on sectalk_private.st_v5_attachment_reports
  for each row execute function sectalk_private.st_v6_guard_new_attachment_evidence();

create function public.st_v6_delete_attachment(p_file uuid)
returns timestamptz language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare attachment public.st_v5_files;
begin
  if not sectalk_private.st_v2_active(actor) then
    raise exception 'Attachment unavailable' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v6_attachment_delete',20);
  select * into attachment from public.st_v5_files f where f.id=p_file and f.uploader=actor
    and f.message_id is not null for update;
  if not found then raise exception 'Attachment unavailable' using errcode='42501'; end if;
  if attachment.deleted_at is not null then return attachment.purge_after; end if;
  update public.st_v5_files f set deleted_at=clock_timestamp(),purge_after=clock_timestamp()+interval '24 hours'
    where f.id=p_file returning f.purge_after into attachment.purge_after;
  perform realtime.send(jsonb_build_object('chat_id',attachment.chat_id),'inbox','st:account:'||participants.user_id,true)
  from public.st_chats c cross join lateral(values(c.member_a),(c.member_b)) participants(user_id)
    where c.id=attachment.chat_id;
  return attachment.purge_after;
end
$$;

create function public.st_v6_deleted_attachments()
returns table(filename text,deleted_at timestamptz,purge_after timestamptz,purged_at timestamptz)
language sql stable security definer set search_path='' as $$
  select f.filename,f.deleted_at,f.purge_after,f.purged_at from public.st_v5_files f
    where f.uploader=auth.uid() and f.deleted_at is not null and sectalk_private.st_v2_active(auth.uid())
    order by f.deleted_at desc,f.id limit 50
$$;

create function public.st_v6_claim_attachment_purge(p_limit integer default 20)
returns table(file_id uuid,lease uuid)
language sql security definer set search_path='' as $$
  with due as (
    select f.id from public.st_v5_files f where f.deleted_at is not null and f.purged_at is null
      and f.purge_after<=clock_timestamp() and coalesce(f.purge_next_at,f.purge_after)<=clock_timestamp()
      and (f.purge_lease_until is null or f.purge_lease_until<=clock_timestamp())
      and not sectalk_private.st_v6_attachment_retention_held(f.id)
    order by f.purge_after,f.id limit greatest(1,least(20,p_limit)) for update skip locked
  )
  update public.st_v5_files f set purge_token=gen_random_uuid(),purge_lease_until=clock_timestamp()+interval '5 minutes',
    purge_attempts=least(f.purge_attempts+1,30)
  from due where f.id=due.id returning f.id,f.purge_token
$$;

create function public.st_v6_confirm_attachment_purge(p_file uuid,p_lease uuid)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  perform 1 from public.st_v5_files f where f.id=p_file and f.purge_token=p_lease and f.purged_at is null
    and f.purge_lease_until>clock_timestamp() for update;
  return found and not sectalk_private.st_v6_attachment_retention_held(p_file);
end
$$;

create function public.st_v6_finish_attachment_purge(p_file uuid,p_lease uuid,p_removed boolean)
returns boolean language plpgsql security definer set search_path='' as $$
declare attempts integer;
begin
  select f.purge_attempts into attempts from public.st_v5_files f where f.id=p_file and f.purge_token=p_lease
    and f.purged_at is null and f.purge_lease_until>clock_timestamp() for update;
  if not found then return false; end if;
  if p_removed is true and not sectalk_private.st_v6_attachment_retention_held(p_file)
    and not exists(select 1 from storage.objects o where o.bucket_id='sectalk-chat-files' and o.name=p_file::text)
  then
    update public.st_v5_files f set purged_at=clock_timestamp(),purge_token=null,purge_lease_until=null,purge_next_at=null
      where f.id=p_file;
    return true;
  end if;
  update public.st_v5_files f set purge_token=null,purge_lease_until=null,
    purge_next_at=clock_timestamp()+make_interval(mins=>power(2,least(attempts,8))::integer)
    where f.id=p_file;
  return false;
end
$$;

create or replace function public.st_v6_file_can_read(p_file uuid)
returns boolean language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_file_download',80);
  return sectalk_private.st_v2_active(actor) and exists(
    select 1 from public.st_v5_files f where f.id=p_file and (
      (f.deleted_at is null and sectalk_private.member(f.chat_id,actor) and exists(select 1 from public.st_messages m
        where m.id=f.message_id and m.revoked_at is null and not exists(select 1 from public.st_v5_hidden_messages h
          where h.user_id=actor and h.message_id=m.id)))
      or (f.purged_at is null and public.st_staff_status()='verified' and exists(select 1 from sectalk_private.st_v5_attachment_reports e where e.file_id=f.id))
    )
  );
end $$;


create or replace function public.st_v6_view_file_details(p_file uuid)
returns table(filename text,size_bytes integer,shared_at timestamptz,can_view_history boolean)
language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare details record;
begin
  if actor is null or not sectalk_private.st_v2_active(actor) then return; end if;
  perform sectalk_private.limit_action('v6_file_detail_view',30);
  select f.filename,f.size_bytes,m.created_at as shared_at,f.uploader=actor as owner
    into details from public.st_v5_files f join public.st_messages m on m.id=f.message_id
    where f.id=p_file and f.deleted_at is null and m.revoked_at is null and sectalk_private.member(f.chat_id,actor)
      and not exists(select 1 from public.st_v5_hidden_messages h
        where h.user_id=actor and h.message_id=m.id);
  if not found then return; end if;
  insert into sectalk_private.st_v6_file_downloads(file_id,actor_id,event)
    values(p_file,actor,'view') on conflict do nothing;
  return query select details.filename,details.size_bytes,details.shared_at,details.owner;
end
$$;

create or replace function sectalk_private.st_v6_shareable_file(p_file uuid,p_owner uuid)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from public.st_v5_files f join public.st_messages m on m.id=f.message_id
    where f.id=p_file and f.deleted_at is null and (p_owner is null or f.uploader=p_owner) and m.revoked_at is null
      and sectalk_private.st_v2_chat_write(f.chat_id,f.uploader))
$$;

create or replace function public.st_v6_pending_file(p_file uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare f public.st_v5_files; actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_file_inspection',12);
  select * into f from public.st_v5_files where id=p_file and uploader=actor and deleted_at is null;
  if not found or not sectalk_private.st_v2_chat_write(f.chat_id,actor)
    or (f.message_id is null and f.created_at<=now()-interval '15 minutes') then return null; end if;
  return jsonb_build_object('filename',f.filename,'size',f.size_bytes,'published',f.message_id,
    'duplicate',coalesce((select duplicate from sectalk_private.st_v7_file_fingerprints where file_id=p_file),false));
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
      and previous.deleted_at is null and prior_message.revoked_at is null
      and not exists(select 1 from public.st_v5_hidden_messages hidden
        where hidden.user_id=p_actor and hidden.message_id=prior_message.id)
  ) into matched;
  insert into sectalk_private.st_v7_file_fingerprints(file_id,fingerprint,duplicate)
    values(p_file,scoped_hash,matched);
  return jsonb_build_object('id',message,'duplicate',matched);
end $$;

create or replace function sectalk_private.st_v6_attachment_usage(p_actor uuid)
returns table(stored_bytes bigint,reserved_bytes bigint)
language sql stable set search_path='' as $$
  select coalesce(sum(greatest(f.size_bytes,case when o.metadata->>'size' ~ '^[0-9]{1,10}$'
      then (o.metadata->>'size')::bigint end))
      filter (where f.message_id is not null or o.id is not null),0)::bigint,
    coalesce(sum(f.size_bytes) filter (where f.message_id is null and o.id is null
      and greatest(f.created_at+interval '15 minutes',f.upload_lease_until)>statement_timestamp()),0)
  from public.st_v5_files f
  left join storage.objects o on o.bucket_id='sectalk-chat-files' and o.name=f.id::text
  where f.uploader=p_actor and f.purged_at is null
$$;

revoke all on function sectalk_private.st_v6_attachment_retention_held(uuid),
  sectalk_private.st_v6_guard_new_attachment_evidence() from public,anon,authenticated,service_role;
revoke all on function public.st_v6_delete_attachment(uuid),public.st_v6_deleted_attachments(),
  public.st_v6_claim_attachment_purge(integer),public.st_v6_confirm_attachment_purge(uuid,uuid),
  public.st_v6_finish_attachment_purge(uuid,uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_delete_attachment(uuid),public.st_v6_deleted_attachments() to authenticated;
grant execute on function public.st_v6_claim_attachment_purge(integer),public.st_v6_confirm_attachment_purge(uuid,uuid),
  public.st_v6_finish_attachment_purge(uuid,uuid,boolean) to service_role;

commit;
