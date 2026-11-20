\set ON_ERROR_STOP on
begin;

insert into auth.users(id,email) values
  ('6f040000-0000-4000-8000-000000000001','attachment-quota-owner@example.invalid'),
  ('6f040000-0000-4000-8000-000000000002','attachment-quota-peer@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('6f040000-0000-4000-8000-000000000001','attachment_quota_owner','Attachment quota owner'),
  ('6f040000-0000-4000-8000-000000000002','attachment_quota_peer','Attachment quota peer');
insert into public.st_chats(id,member_a,member_b,requester,status) values
  ('6f040000-0001-4000-8000-000000000001','6f040000-0000-4000-8000-000000000001',
  '6f040000-0000-4000-8000-000000000002','6f040000-0000-4000-8000-000000000001','accepted');
insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values
  ('6f040000-0000-4000-8000-000000000001','basic','active',now()+interval '1 day');

set local role authenticated;
select set_config('request.jwt.claims','{"sub":"6f040000-0000-4000-8000-000000000001","role":"authenticated"}',true);
do $$
begin
  if public.st_v6_attachment_capacity() is distinct from
    '{"plan":"basic","max_file_bytes":2097152,"max_storage_bytes":134217728,"stored_bytes":0,"reserved_bytes":0}'::jsonb
    then raise exception 'Paid plan did not set the expected attachment limits'; end if;
  if has_function_privilege('public.st_v6_authorize_file_upload(uuid,uuid,integer)','execute') then
    raise exception 'Authenticated caller could obtain an untrusted upload authorization';
  end if;
end
$$;
reset role;

insert into sectalk_private.st_v6_attachment_policy(account_id,max_file_bytes,max_storage_bytes) values
  ('6f040000-0000-4000-8000-000000000001',25,30);
set local role authenticated;
do $$
declare
  chat constant uuid := '6f040000-0001-4000-8000-000000000001';
  first_file constant uuid := '6f040000-0002-4000-8000-000000000001';
  next_file constant uuid := '6f040000-0002-4000-8000-000000000002';
  extra_file constant uuid := '6f040000-0002-4000-8000-000000000003';
begin
  if public.st_v5_stage_file(chat,first_file,'proof.txt',12)
    or public.st_v5_stage_file(chat,first_file,'proof.txt',12) then
    raise exception 'Raw upload was unexpectedly present';
  end if;
  if public.st_v6_attachment_capacity() is distinct from
    '{"plan":"basic","max_file_bytes":25,"max_storage_bytes":30,"stored_bytes":0,"reserved_bytes":12}'::jsonb
    then raise exception 'Policy caps or idempotent storage reservation failed'; end if;
  begin
    perform public.st_v5_stage_file(chat,next_file,'overfile.txt',26);
    raise exception 'File-size override was bypassed';
  exception when sqlstate 'PT413' then null; end;
  begin
    perform public.st_v5_stage_file(chat,next_file,'overflow.txt',19);
    raise exception 'Account storage override was bypassed';
  exception when sqlstate 'PT409' then null; end;

  perform public.st_v5_stage_file(chat,next_file,'fits.txt',18);
  begin
    perform public.st_v5_stage_file(chat,extra_file,'overflow.txt',1);
    raise exception 'An extra byte was reserved beyond capacity';
  exception when sqlstate 'PT409' then null; end;
  begin
    insert into storage.objects(bucket_id,name,metadata)
      values('sectalk-chat-files',first_file::text,'{"size":12}');
    raise exception 'An authenticated caller bypassed the server-side byte gate';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims','{"sub":"6f040000-0000-4000-8000-000000000002","role":"authenticated"}',true);
  if public.st_v6_attachment_capacity() is distinct from
    '{"plan":"free","max_file_bytes":1048576,"max_storage_bytes":33554432,"stored_bytes":0,"reserved_bytes":0}'::jsonb
    then raise exception 'A recipient was charged for another member’s attachments'; end if;
end
$$;
reset role;

set local role service_role;
do $$
declare
  actor constant uuid := '6f040000-0000-4000-8000-000000000001';
  peer constant uuid := '6f040000-0000-4000-8000-000000000002';
  file_id constant uuid := '6f040000-0002-4000-8000-000000000001';
begin
  if public.st_v6_authorize_file_upload(file_id,peer,12) is not null then
    raise exception 'Trusted upload authorization crossed attachment ownership';
  end if;
  begin
    perform public.st_v6_authorize_file_upload(file_id,actor,13);
    raise exception 'Byte mismatch was accepted';
  exception when sqlstate 'PT409' then null; end;
  if public.st_v6_authorize_file_upload(file_id,actor,12)
    is distinct from '{"filename":"proof.txt","uploaded":false}'::jsonb then
    raise exception 'A valid server-measured upload was rejected';
  end if;
  insert into storage.objects(bucket_id,name,metadata) values('sectalk-chat-files',file_id::text,'{"size":12}');
  if public.st_v6_authorize_file_upload(file_id,actor,12)
    is distinct from '{"filename":"proof.txt","uploaded":true}'::jsonb then
    raise exception 'An upload retry ignored a completed object';
  end if;
  if (public.st_v7_publish_hashed_file(file_id,actor,'Quota fixture',repeat('a',64))->>'id')::uuid
    is distinct from file_id then raise exception 'Valid reserved attachment did not publish'; end if;
end
$$;
reset role;

-- An abandoned reservation without an object is released. A legacy mismatched object remains charged at actual size.
update public.st_v5_files set created_at=now()-interval '16 minutes'
  where id='6f040000-0002-4000-8000-000000000002';
insert into public.st_v5_files(id,chat_id,uploader,filename,size_bytes,created_at) values
  ('6f040000-0002-4000-8000-000000000004','6f040000-0001-4000-8000-000000000001',
  '6f040000-0000-4000-8000-000000000001','legacy.txt',1,now()-interval '16 minutes');
insert into storage.objects(bucket_id,name,metadata) values
  ('sectalk-chat-files','6f040000-0002-4000-8000-000000000004','{"size":7}');
update public.st_v2_subscriptions set status='canceled'
  where user_id='6f040000-0000-4000-8000-000000000001';
set local role authenticated;
select set_config('request.jwt.claims','{"sub":"6f040000-0000-4000-8000-000000000001","role":"authenticated"}',true);
do $$
begin
  if public.st_v6_attachment_capacity() is distinct from
    '{"plan":"free","max_file_bytes":25,"max_storage_bytes":30,"stored_bytes":19,"reserved_bytes":0}'::jsonb
    then raise exception 'Downgrade, stranded objects, or reservation expiry did not count correctly'; end if;
end
$$;
reset role;
select 'passed: plan and policy caps, bounded idempotent reservations, byte authorization, owner isolation, expiry and legacy accounting' as result;
rollback;
