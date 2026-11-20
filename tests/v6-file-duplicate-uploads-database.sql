begin;

do $$
declare
  sender uuid:=gen_random_uuid();
  recipient uuid:=gen_random_uuid();
  outsider uuid:=gen_random_uuid();
  chat uuid:=gen_random_uuid();
  other_chat uuid:=gen_random_uuid();
  file_id uuid;
  first_file uuid:=gen_random_uuid();
  hidden_file uuid:=gen_random_uuid();
  revoked_file uuid:=gen_random_uuid();
  result jsonb;
  fixture record;
begin
  if has_function_privilege('anon','public.st_v7_publish_hashed_file(uuid,uuid,text,text)','EXECUTE')
    or has_function_privilege('authenticated','public.st_v7_publish_hashed_file(uuid,uuid,text,text)','EXECUTE')
    or has_table_privilege('authenticated','sectalk_private.st_v7_file_fingerprints','SELECT')
    or has_table_privilege('service_role','sectalk_private.st_v7_file_fingerprints','SELECT')
    then raise exception 'Fingerprint data is directly accessible'; end if;

  insert into auth.users(id,email) values(sender,'duplicate-sender@example.invalid'),
    (recipient,'duplicate-recipient@example.invalid'),(outsider,'duplicate-outsider@example.invalid');
  insert into public.st_profiles(id,name,handle) values(sender,'Duplicate sender','duplicate_sql_sender'),
    (recipient,'Duplicate recipient','duplicate_sql_recipient'),(outsider,'Duplicate outsider','duplicate_sql_outsider');
  insert into public.st_chats(id,member_a,member_b,requester,status) values
    (chat,least(sender,recipient),greatest(sender,recipient),sender,'accepted'),
    (other_chat,least(sender,outsider),greatest(sender,outsider),sender,'accepted');

  for fixture in
    select * from (values
      (1,first_file,chat,sender,'a','original.txt',false),
      (2,gen_random_uuid(),chat,sender,'a','renamed.txt',true),
      (3,gen_random_uuid(),chat,recipient,'a','original.txt',false),
      (4,gen_random_uuid(),other_chat,sender,'a','original.txt',false),
      (5,gen_random_uuid(),chat,sender,'b','original.txt',false),
      (6,hidden_file,chat,sender,'c','hidden.txt',false),
      (7,gen_random_uuid(),chat,sender,'c','hidden.txt',false),
      (8,revoked_file,chat,sender,'d','revoked.txt',false),
      (9,gen_random_uuid(),chat,sender,'d','revoked.txt',false)
    ) cases(position,id,conversation,uploader,hash,filename,expected) order by position
  loop
    file_id:=fixture.id;
    insert into public.st_v5_files(id,chat_id,uploader,filename,size_bytes)
      values(file_id,fixture.conversation,fixture.uploader,fixture.filename,8);
    insert into storage.objects(bucket_id,name,metadata)
      values('sectalk-chat-files',file_id::text,'{"size":8}');

    set local role service_role;
    result:=public.st_v7_publish_hashed_file(file_id,fixture.uploader,'Fixture',repeat(fixture.hash,64));
    if result is distinct from jsonb_build_object('id',file_id,'duplicate',fixture.expected)
      then raise exception 'Unexpected duplicate result for %: %',fixture.filename,result; end if;
    if public.st_v7_publish_hashed_file(file_id,fixture.uploader,'Retry',repeat('f',64)) is distinct from result
      then raise exception 'Successful publication should preserve its response on retry'; end if;
    reset role;

    if file_id in (hidden_file,revoked_file) then
      set local role authenticated;
      perform set_config('request.jwt.claim.sub',sender::text,true);
      perform public.st_v5_message_action(file_id,case when file_id=hidden_file then 'hide' else 'revoke' end);
      reset role;
    end if;
  end loop;

  if (select count(*) from sectalk_private.st_v7_file_fingerprints fingerprint
      join public.st_v5_files attachment on attachment.id=fingerprint.file_id
      where attachment.uploader in (sender,recipient)) <> 9
    then raise exception 'Every published attachment must have its own fingerprint'; end if;

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',outsider::text,true);
  if public.st_v6_pending_file(first_file) is not null
    then raise exception 'An outsider must not see another upload result'; end if;
end $$;

rollback;
