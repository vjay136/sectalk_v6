\set ON_ERROR_STOP on
begin;

do $$
declare
  owner_id uuid:=gen_random_uuid();
  peer_id uuid:=gen_random_uuid();
  staff_id uuid:=gen_random_uuid();
  chat_id uuid:=gen_random_uuid();
  original uuid:=gen_random_uuid();
  protected uuid:=gen_random_uuid();
  report uuid:=gen_random_uuid();
  late_report uuid:=gen_random_uuid();
  early_link text;
  job uuid;
  retry uuid;
  grace timestamptz;
begin
  insert into auth.users(id,email) values(owner_id,owner_id||'@example.invalid'),
    (peer_id,peer_id||'@example.invalid'),(staff_id,staff_id||'@example.invalid');
  insert into public.st_profiles(id,handle,name) values
    (owner_id,'retq_'||left(owner_id::text,8),'Retention uploader'),
    (peer_id,'retq_'||left(peer_id::text,8),'Retention recipient'),
    (staff_id,'retq_'||left(staff_id::text,8),'Evidence reviewer');
  insert into sectalk_private.staff values(staff_id);
  insert into public.st_chats(id,member_a,member_b,requester,status)
    values(chat_id,least(owner_id,peer_id),greatest(owner_id,peer_id),owner_id,'accepted');
  insert into public.st_messages(id,chat_id,sender,body) values
    (original,chat_id,owner_id,'Unheld attachment'),(protected,chat_id,owner_id,'Approved attachment evidence');
  insert into public.st_v5_files(id,chat_id,uploader,message_id,filename,size_bytes) values
    (original,chat_id,owner_id,original,'ordinary.txt',10),(protected,chat_id,owner_id,protected,'evidence.txt',20);
  insert into storage.objects(bucket_id,name,metadata) values
    ('sectalk-chat-files',original::text,'{"size":10}'),('sectalk-chat-files',protected::text,'{"size":20}');
  insert into public.st_reports(id,reporter,subject,chat_id,message_id,category,details) values
    (report,peer_id,owner_id,chat_id,protected,'threat','Approved evidence'),
    (late_report,peer_id,owner_id,chat_id,original,'threat','Report without reusable attachment');
  insert into sectalk_private.st_v5_attachment_reports values(report,protected);

  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',peer_id,'aal','aal1')::text,true);
  begin
    perform public.st_v6_delete_attachment(original);
    raise exception 'A recipient deleted the uploader attachment';
  exception when insufficient_privilege then null; end;
  if has_function_privilege('public.st_v6_claim_attachment_purge(integer)','execute')
    then raise exception 'Ordinary callers can claim a purge job'; end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'aal','aal1')::text,true);
  early_link:=public.st_v6_create_file_share(original,'synthetic-retention-password',900,1);
  grace:=public.st_v6_delete_attachment(original);
  perform public.st_v6_delete_attachment(protected);
  if grace < now()+interval '23 hours' or public.st_v6_delete_attachment(original) is distinct from grace
    or (select count(*) from public.st_v6_deleted_attachments())<>2
    or (public.st_v6_attachment_capacity()->>'stored_bytes')::integer<>30
  then raise exception 'Retention grace, private receipt, idempotency or quota reservation failed'; end if;
  if public.st_v6_file_can_read(original) or exists(select 1 from public.st_v6_view_file_details(original))
    or exists(select 1 from public.st_v5_files where id in (original,protected))
  then raise exception 'A deleted attachment remains available to the uploader'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',staff_id,'aal','aal2')::text,true);
  if public.st_v6_file_can_read(original) or not public.st_v6_file_can_read(protected)
    then raise exception 'Approved evidence exception was not scoped to its attachment'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',peer_id,'aal','aal1')::text,true);
  if public.st_v6_file_can_read(protected) or exists(select 1 from public.st_v6_deleted_attachments())
    then raise exception 'Recipient read retained evidence or uploader deletion receipts'; end if;
  reset role;

  insert into sectalk_private.st_v5_attachment_reports values(late_report,original);
  if found then raise exception 'A new attachment evidence record slipped in after deletion'; end if;
  set local role service_role;
  if public.st_v6_access_file_share(early_link,'synthetic-retention-password','peek') is not null
    or exists(select 1 from public.st_v6_claim_attachment_purge(20) c where c.file_id in (original,protected))
  then raise exception 'A share survived deletion or purge bypassed grace'; end if;
  reset role;

  update public.st_v5_files set purge_after=now()-interval '1 minute' where id in (original,protected);
  set local role service_role;
  select c.lease into job from public.st_v6_claim_attachment_purge(20) c where c.file_id=original;
  if job is null or not public.st_v6_confirm_attachment_purge(original,job)
    or exists(select 1 from public.st_v6_claim_attachment_purge(20) c where c.file_id in (original,protected))
  then raise exception 'Purge did not claim exactly the unheld attachment once'; end if;
  if public.st_v6_finish_attachment_purge(original,job,true)
    or exists(select 1 from public.st_v6_claim_attachment_purge(20) c where c.file_id=original)
  then raise exception 'Purge succeeded without removing Storage metadata or without retry backoff'; end if;
  reset role;

  update public.st_v5_files set purge_next_at=now()-interval '1 minute' where id=original;
  set local role service_role;
  select c.lease into retry from public.st_v6_claim_attachment_purge(20) c where c.file_id=original;
  if retry is null or retry=job or public.st_v6_finish_attachment_purge(original,job,true)
    then raise exception 'Retry did not issue a new lease or stale lease settled a job'; end if;
  if public.st_v6_finish_attachment_purge(original,retry,false)
    then raise exception 'A failed removal was marked as purged'; end if;
  reset role;
  if (select stored_bytes from sectalk_private.st_v6_attachment_usage(owner_id))<>30
    or not exists(select 1 from storage.objects where bucket_id='sectalk-chat-files' and name=protected::text)
  then raise exception 'Quota or protected evidence accounting changed unexpectedly'; end if;
end
$$;
select 'passed: owner deletion, 24-hour grace, scoped evidence protection, versioned purge leases and retry' as result;
rollback;
