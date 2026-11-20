\set ON_ERROR_STOP on
begin;

do $$
declare
  owner_id uuid:=gen_random_uuid();
  peer_id uuid:=gen_random_uuid();
  first_officer uuid:=gen_random_uuid();
  second_officer uuid:=gen_random_uuid();
  chat_id uuid:=gen_random_uuid();
  attachment uuid:=gen_random_uuid();
  unrelated uuid:=gen_random_uuid();
  first_hold uuid;
  second_hold uuid;
  lease uuid;
begin
  insert into auth.users(id,email)
    select id,id||'@example.invalid' from unnest(array[owner_id,peer_id,first_officer,second_officer]) id;
  insert into public.st_profiles(id,handle,name)
    select id,'filehold_'||left(id::text,8),'Attachment hold QA'
      from unnest(array[owner_id,peer_id,first_officer,second_officer]) id;
  insert into sectalk_private.staff values(first_officer),(second_officer);
  insert into public.st_chats(id,member_a,member_b,requester,status)
    values(chat_id,least(owner_id,peer_id),greatest(owner_id,peer_id),owner_id,'accepted');
  insert into public.st_messages(id,chat_id,sender,body) values
    (attachment,chat_id,owner_id,'Held attachment'),(unrelated,chat_id,owner_id,'Unassigned attachment');
  insert into public.st_v5_files(id,chat_id,uploader,message_id,filename,size_bytes) values
    (attachment,chat_id,owner_id,attachment,'private-hold.txt',12),
    (unrelated,chat_id,owner_id,unrelated,'private-other.txt',12);
  insert into storage.objects(bucket_id,name,metadata) values
    ('sectalk-chat-files',attachment::text,'{"size":12}'),('sectalk-chat-files',unrelated::text,'{"size":12}');
  insert into sectalk_private.st_v6_direct_file_hold_scope(operator_id,file_id,authorization_reference) values
    (first_officer,attachment,'QA legal reference 1'),(second_officer,attachment,'QA legal reference 2');

  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',first_officer,'aal','aal1')::text,true);
  if exists(select 1 from public.st_v6_direct_hold_targets()) then raise exception 'AAL1 scope leaked'; end if;
  begin
    perform public.st_v6_place_direct_file_hold(attachment,'AAL1 must fail');
    raise exception 'AAL1 placed legal hold';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',first_officer,'aal','aal2')::text,true);
  if (select array_agg(t.file_id) from public.st_v6_direct_hold_targets() t) is distinct from array[attachment]
    or public.st_v6_file_can_read(attachment) or exists(select 1 from public.st_v6_view_file_details(attachment))
  then raise exception 'Exact assignment or no-content-access contract failed'; end if;
  begin
    perform public.st_v6_place_direct_file_hold(unrelated,'Unassigned must fail');
    raise exception 'Staff could hold unassigned attachment';
  exception when insufficient_privilege then null; end;
  first_hold:=public.st_v6_place_direct_file_hold(attachment,'First legal directive');
  if public.st_v6_place_direct_file_hold(attachment,'Retry directive') is distinct from first_hold
    then raise exception 'Hold placement was not idempotent'; end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',second_officer,'aal','aal2')::text,true);
  second_hold:=public.st_v6_place_direct_file_hold(attachment,'Second legal directive');
  if first_hold=second_hold or (select array_agg(h.id) from public.st_v6_direct_hold_history(attachment) h)
    is distinct from array[second_hold] then raise exception 'Separate legal holds did not overlap privately'; end if;
  begin
    perform public.st_v6_release_direct_file_hold(attachment,first_hold,'Another officer may not release');
    raise exception 'Another officer released an independently placed hold';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'aal','aal1')::text,true);
  perform public.st_v5_message_action(attachment,'revoke');
  perform public.st_v6_delete_attachment(attachment);
  if public.st_v6_file_can_read(attachment) then raise exception 'Uploader still read withdrawn attachment'; end if;
  reset role;
  update public.st_v5_files set purge_after=now()-interval '1 minute' where id=attachment;
  begin
    delete from public.st_v5_files where id=attachment;
    raise exception 'Database row cascade could erase an active legal hold';
  exception when insufficient_privilege then null; end;

  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',first_officer,'aal','aal2')::text,true);
  perform public.st_v6_release_direct_file_hold(attachment,first_hold,'First directive terminated');
  reset role;
  delete from sectalk_private.st_v6_direct_file_hold_scope where operator_id=second_officer and file_id=attachment;
  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',second_officer,'aal','aal2')::text,true);
  if exists(select 1 from public.st_v6_direct_hold_targets()) then raise exception 'Revoked grant retained visibility'; end if;
  begin
    perform public.st_v6_release_direct_file_hold(attachment,second_hold,'Revoked operator cannot release');
    raise exception 'Removed scope still authorizes release';
  exception when insufficient_privilege then null; end;
  set local role service_role;
  if exists(select 1 from public.st_v6_claim_attachment_purge(20) c where c.file_id=attachment)
    then raise exception 'Remaining independent hold did not block purge after grant revocation'; end if;
  reset role;

  insert into sectalk_private.st_v6_direct_file_hold_scope(operator_id,file_id,authorization_reference)
    values(second_officer,attachment,'QA legal release authority');
  set local role authenticated;
  perform public.st_v6_release_direct_file_hold(attachment,second_hold,'Final directive terminated');
  set local role service_role;
  select c.lease into lease from public.st_v6_claim_attachment_purge(20) c where c.file_id=attachment;
  if lease is null then raise exception 'Released attachment did not become eligible for purge'; end if;
  set local role authenticated;
  begin
    perform public.st_v6_place_direct_file_hold(attachment,'Purge lease bars hold admission');
    raise exception 'A hold raced into an already leased external deletion';
  exception when sqlstate 'PT409' then null; end;
  reset role;
end
$$;
select 'passed: MFA and exact scope, no content rights, independent holds, assignment revoke and purge serialization' as result;
rollback;
