begin;

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('sectalk-encrypted-group-files','sectalk-encrypted-group-files',false,4194332,array['application/octet-stream']);
create policy st_v7_group_file_storage_isolated on storage.objects as restrictive for all to public
  using(bucket_id<>'sectalk-encrypted-group-files') with check(bucket_id<>'sectalk-encrypted-group-files');

create table sectalk_private.st_v7_group_files (
  id uuid primary key,
  group_id uuid not null,
  epoch integer not null check(epoch>0),
  uploader uuid not null,
  device_id uuid not null,
  cipher_bytes integer not null check(cipher_bytes between 29 and 4194332),
  expires_at timestamptz not null,
  message_id uuid,
  cleanup_claim uuid,
  cleanup_until timestamptz,
  unique(group_id,message_id),
  check((cleanup_claim is null)=(cleanup_until is null))
);
create index st_v7_group_file_usage on sectalk_private.st_v7_group_files(uploader);
create index st_v7_group_file_expiry on sectalk_private.st_v7_group_files(expires_at) where message_id is null;
alter table sectalk_private.st_v7_group_files enable row level security;
revoke all on sectalk_private.st_v7_group_files from public,anon,authenticated,service_role;

alter function sectalk_private.st_v6_attachment_usage(uuid) rename to st_v7_direct_attachment_usage;
create function sectalk_private.st_v6_attachment_usage(p_actor uuid)
returns table(stored_bytes bigint,reserved_bytes bigint)
language sql stable set search_path='' as $$
  select direct.stored_bytes+coalesce(groups.stored,0),direct.reserved_bytes+coalesce(groups.reserved,0)
  from sectalk_private.st_v7_direct_attachment_usage(p_actor) direct cross join lateral (
    select sum(f.cipher_bytes-28) filter(where f.message_id is not null or o.id is not null) stored,
      sum(f.cipher_bytes-28) filter(where f.message_id is null and o.id is null and f.expires_at>statement_timestamp()) reserved
    from sectalk_private.st_v7_group_files f
    left join storage.objects o on o.bucket_id='sectalk-encrypted-group-files' and o.name=f.id::text
    where f.uploader=p_actor
  ) groups;
$$;
revoke all on function sectalk_private.st_v6_attachment_usage(uuid),sectalk_private.st_v7_direct_attachment_usage(uuid)
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_group_file_device(p_group uuid,p_epoch integer)
returns uuid language sql stable security definer set search_path='' as $$
  select d.id from sectalk_private.st_v7_device_sessions s
  join sectalk_private.st_v7_devices d on (d.owner,d.id)=(s.owner,s.device_id)
  join sectalk_private.st_group_members m on m.group_id=p_group and m.actor=d.owner
  join sectalk_private.st_group_envelopes e on (e.group_id,e.epoch,e.device)=(m.group_id,p_epoch,d.id)
  where s.owner=(select auth.uid()) and s.session_id::text=auth.jwt()->>'session_id' and d.state in ('trusted','managed')
    and sectalk_private.st_v7_manage_sessions();
$$;

create function public.st_v7_stage_group_file(p_group uuid,p_file uuid,p_epoch integer,p_cipher_bytes integer)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); device uuid; limits record; usage record; reserved sectalk_private.st_v7_group_files;
begin
  if p_file is null or p_cipher_bytes is null or p_cipher_bytes not between 29 and 4194332 then
    raise exception using errcode='22023',message='Invalid encrypted attachment';
  end if;
  device:=sectalk_private.st_v7_group_file_device(p_group,p_epoch);
  if device is null or not exists(select 1 from sectalk_private.st_group_chats where id=p_group and epoch=p_epoch) then
    raise exception using errcode='42501',message='An approved group device and current group key are required';
  end if;
  perform sectalk_private.st_v6_lock_attachment_owner(actor);
  select * into reserved from sectalk_private.st_v7_group_files where id=p_file;
  if found then
    if (reserved.group_id,reserved.epoch,reserved.uploader,reserved.device_id,reserved.cipher_bytes)
       is not distinct from (p_group,p_epoch,actor,device,p_cipher_bytes)
      and (reserved.message_id is not null or reserved.expires_at>now()) then return; end if;
    raise exception using errcode='PT409',message='The attachment reservation is unavailable';
  end if;
  perform sectalk_private.limit_action('v7_group_file',12);
  select * into limits from sectalk_private.st_v6_attachment_entitlement(actor);
  if p_cipher_bytes-28>coalesce(limits.max_file_bytes,0) then
    raise exception using errcode='PT413',message='This file exceeds your plan’s attachment limit';
  end if;
  select * into usage from sectalk_private.st_v6_attachment_usage(actor);
  if usage.stored_bytes+usage.reserved_bytes+p_cipher_bytes-28 > coalesce(limits.max_storage_bytes,0) then
    raise exception using errcode='PT409',message='Your attachment storage allowance is full';
  end if;
  insert into sectalk_private.st_v7_group_files(id,group_id,epoch,uploader,device_id,cipher_bytes,expires_at)
    values(p_file,p_group,p_epoch,actor,device,p_cipher_bytes,now()+interval '20 minutes');
end $$;

create function public.st_v7_group_file_access(p_file uuid,p_action text,p_message uuid default null)
returns integer language sql stable security definer set search_path='' as $$
  select f.cipher_bytes from sectalk_private.st_v7_group_files f
  join sectalk_private.st_group_chats g on g.id=f.group_id
  cross join lateral (select sectalk_private.st_v7_group_file_device(f.group_id,f.epoch) current_device) approval
  where f.id=p_file and approval.current_device is not null and case p_action
    when 'upload' then g.epoch=f.epoch and f.uploader=(select auth.uid()) and approval.current_device=f.device_id
      and f.message_id is null and f.expires_at>now() and f.cleanup_claim is null
    when 'read' then f.message_id is not null and f.message_id=p_message and not exists(
      select 1 from sectalk_private.st_v7_group_quarantine t where t.group_id=f.group_id and t.message_id=f.message_id)
    else false end;
$$;

create function public.st_v7_lease_group_file_upload(p_file uuid,p_cipher_bytes integer)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  perform 1 from sectalk_private.st_v7_group_files where id=p_file for update;
  if not found or p_cipher_bytes is null or public.st_v7_group_file_access(p_file,'upload') is distinct from p_cipher_bytes then
    return false;
  end if;
  update sectalk_private.st_v7_group_files set expires_at=greatest(expires_at,now()+interval '2 minutes') where id=p_file;
  return true;
end $$;

create function public.st_v7_publish_group_file(p_file uuid,p_encrypted jsonb)
returns uuid language plpgsql security definer set search_path='' as $$
declare file sectalk_private.st_v7_group_files; authorized integer; target uuid;
begin
  if jsonb_typeof(p_encrypted) is distinct from 'object' or coalesce(p_encrypted->>'id','') !~
    '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' then raise exception using errcode='22023',message='Invalid encrypted message'; end if;
  target:=(p_encrypted->>'id')::uuid;
  select f.* into file from sectalk_private.st_v7_group_files f where f.id=p_file;
  if not found or file.uploader is distinct from auth.uid() or
    sectalk_private.st_v7_group_file_device(file.group_id,file.epoch) is distinct from file.device_id then
    raise exception using errcode='42501',message='Encrypted attachment unavailable';
  end if;
  perform 1 from sectalk_private.st_group_chats where id=file.group_id for update;
  select * into file from sectalk_private.st_v7_group_files where id=p_file for update;
  if file.message_id is not null and file.message_id=target and exists(select 1 from sectalk_private.st_group_messages m
    where (m.group_id,m.id)=(file.group_id,target) and m.payload=p_encrypted->>'payload' and m.signature=p_encrypted->>'signature') then
    return target;
  end if;
  authorized:=public.st_v7_group_file_access(p_file,'upload');
  if authorized is null or not exists(select 1 from storage.objects o where o.bucket_id='sectalk-encrypted-group-files'
    and o.name=p_file::text and o.metadata->>'size'=authorized::text) then
    raise exception using errcode='PT409',message='The encrypted attachment upload is incomplete or has expired';
  end if;
  perform public.st_group_chat('send',file.group_id,p_encrypted);
  update sectalk_private.st_v7_group_files set message_id=target where id=p_file;
  perform realtime.send(jsonb_build_object('group',file.group_id),'group_file_published','st:account:'||m.actor,true)
    from sectalk_private.st_group_members m where m.group_id=file.group_id and m.actor<>auth.uid();
  return target;
end $$;

create function public.st_v7_claim_group_file_cleanup()
returns table(id uuid,lease uuid) language sql security definer set search_path='' as $$
  with eligible as (
    select f.id from sectalk_private.st_v7_group_files f
    where (f.cleanup_until is null or f.cleanup_until<now()) and (
      (f.message_id is null and f.expires_at<now())
      or not exists(select 1 from sectalk_private.st_group_chats g where g.id=f.group_id))
    order by f.expires_at limit 20 for update skip locked
  ) update sectalk_private.st_v7_group_files f set cleanup_claim=gen_random_uuid(),cleanup_until=now()+interval '5 minutes'
    from eligible where f.id=eligible.id returning f.id,f.cleanup_claim;
$$;

create function public.st_v7_finish_group_file_cleanup(p_file uuid,p_lease uuid)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  delete from sectalk_private.st_v7_group_files f where f.id=p_file and f.cleanup_claim=p_lease
    and not exists(select 1 from storage.objects o where o.bucket_id='sectalk-encrypted-group-files' and o.name=f.id::text);
  return found;
end $$;

revoke all on function sectalk_private.st_v7_group_file_device(uuid,integer),
  public.st_v7_stage_group_file(uuid,uuid,integer,integer),public.st_v7_group_file_access(uuid,text,uuid),
  public.st_v7_lease_group_file_upload(uuid,integer),
  public.st_v7_publish_group_file(uuid,jsonb),public.st_v7_claim_group_file_cleanup(),public.st_v7_finish_group_file_cleanup(uuid,uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_stage_group_file(uuid,uuid,integer,integer),
  public.st_v7_group_file_access(uuid,text,uuid),public.st_v7_lease_group_file_upload(uuid,integer),
  public.st_v7_publish_group_file(uuid,jsonb) to authenticated;
grant execute on function public.st_v7_claim_group_file_cleanup(),public.st_v7_finish_group_file_cleanup(uuid,uuid) to service_role;

commit;
