begin;

insert into auth.users(id,email,aud,role) values
 ('50000000-0000-4000-8000-000000000001','st-v5-alex@example.invalid','authenticated','authenticated'),
 ('50000000-0000-4000-8000-000000000002','st-v5-billie@example.invalid','authenticated','authenticated'),
 ('50000000-0000-4000-8000-000000000003','st-v5-casey@example.invalid','authenticated','authenticated'),
 ('50000000-0000-4000-8000-000000000004','st-v5-staff@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
 ('50000000-0000-4000-8000-000000000001','sectalk_v5_alex','Alex fixture'),
 ('50000000-0000-4000-8000-000000000002','sectalk_v5_billie','Billie fixture'),
 ('50000000-0000-4000-8000-000000000003','sectalk_v5_casey','Casey fixture'),
 ('50000000-0000-4000-8000-000000000004','sectalk_v5_staff','Safety staff fixture');
insert into sectalk_private.staff(user_id) values('50000000-0000-4000-8000-000000000004');

set local role authenticated;
do $$
declare
  alex constant uuid:='50000000-0000-4000-8000-000000000001';
  billie constant uuid:='50000000-0000-4000-8000-000000000002';
  casey constant uuid:='50000000-0000-4000-8000-000000000003';
  staffer constant uuid:='50000000-0000-4000-8000-000000000004';
  file_key constant uuid:=gen_random_uuid();
  text_key constant uuid:=gen_random_uuid();
  chat uuid;
  report uuid;
  counts jsonb;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',alex,'role','authenticated','aal','aal1')::text,true);
  perform public.st_v5_save_discovery('college',array['study-cybersecurity'],true,true);
  perform public.st_v5_profile_details_save('Studying secure design',false);
  insert into storage.objects(bucket_id,name) values('sectalk-avatars',alex::text||'.jpg');
  perform public.st_v5_profile_details_save(null,true);

  perform set_config('request.jwt.claims',json_build_object('sub',casey,'role','authenticated','aal','aal1')::text,true);
  begin
    perform public.st_v5_save_discovery('student',array['study-cybersecurity'],true,false);
    raise exception 'Discovery omitted age attestation' using errcode='P0004';
  exception when raise_exception then null;
  end;
  perform public.st_v5_save_discovery('professional',array['study-cybersecurity'],true,true);
  if not exists(select 1 from public.st_v5_find_friends('','college','study-cybersecurity') where handle='sectalk_v5_alex')
    then raise exception 'Opted-in profile missing from filtered discovery'; end if;
  if exists(select 1 from public.st_v5_profile_details where user_id=alex)
    or exists(select 1 from storage.objects where bucket_id='sectalk-avatars' and name=alex::text||'.jpg')
    then raise exception 'Discovery exposed private status or photo'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',alex,'role','authenticated','aal','aal1')::text,true);
  chat:=public.st_request('sectalk_v5_billie');
  perform set_config('request.jwt.claims',json_build_object('sub',billie,'role','authenticated','aal','aal1')::text,true);
  if public.st_v5_last_seen(chat) is not null then raise exception 'Pending request could see activity'; end if;
  perform public.st_respond(chat,true);
  if not exists(select 1 from public.st_v5_profile_details where user_id=alex and status_message='Studying secure design' and photo_revision is not null)
    or not exists(select 1 from storage.objects where bucket_id='sectalk-avatars' and name=alex::text||'.jpg')
    then raise exception 'Accepted contact could not see shared profile'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',alex,'role','authenticated','aal','aal1')::text,true);
  perform public.st_v3_set_presence('online');
  perform public.st_v5_set_last_seen(true);
  perform public.st_send(chat,text_key,'Initial private text');
  perform public.st_v2_edit_message(text_key,'Edited private text');
  if public.st_v5_stage_file(chat,file_key,'test.txt',10) then raise exception 'New attachment already uploaded'; end if;
  insert into storage.objects(bucket_id,name,metadata) values('sectalk-chat-files',file_key::text,'{"size":10}'::jsonb);
  if public.st_v6_pending_file(file_key)->>'filename' is distinct from 'test.txt'
    then raise exception 'Pending owner could not resolve validation metadata'; end if;
  if has_function_privilege('public.st_v5_send_file(uuid,text)','EXECUTE')
    or has_function_privilege('public.st_v6_publish_validated_file(uuid,uuid,text)','EXECUTE')
    then raise exception 'An ordinary caller could publish unvalidated bytes'; end if;
  set local role service_role;
  if public.st_v6_publish_validated_file(file_key,alex,'Fixture caption') is distinct from file_key
    then raise exception 'Trusted attachment was not sent'; end if;
  set local role authenticated;

  perform set_config('request.jwt.claims',json_build_object('sub',billie,'role','authenticated','aal','aal1')::text,true);
  if public.st_v5_last_seen(chat) is null then raise exception 'Shared activity not visible to accepted contact'; end if;
  if not exists(select 1 from public.st_v5_files where id=file_key)
    or not public.st_v6_file_can_read(file_key)
    or exists(select 1 from storage.objects where bucket_id='sectalk-chat-files' and name=file_key::text)
    then raise exception 'Recipient cannot download the attachment'; end if;
  begin
    perform public.st_v5_message_action(text_key,'revoke');
    raise exception 'Recipient revoked a sender message' using errcode='P0004';
  exception when raise_exception then null;
  end;
  perform public.st_v5_message_action(text_key,'hide');
  perform public.st_v2_react(file_key,'👍',true);
  perform public.st_v2_react(file_key,'[[st:😀|👓]]',true);
  perform public.st_v2_react(file_key,'[[st:😀|👓]]',true);
  if (select count(*) from public.st_v2_reactions where message_id=file_key)<>2 then raise exception 'Expected native and custom reactions'; end if;
  perform public.st_v2_react(file_key,'👍',false);
  begin
    perform public.st_v2_react(file_key,'plain text',true);
    raise exception 'Invalid reaction accepted' using errcode='P0004';
  exception when raise_exception then null;
  end;
  counts:=public.st_v5_profile_activity();
  if (counts->>'received')::int<>1 then raise exception 'Hidden message counted in profile'; end if;
  report:=public.st_v5_report(chat,file_key,'sexual_content','Fixture concern',true);

  perform set_config('request.jwt.claims',json_build_object('sub',casey,'role','authenticated','aal','aal1')::text,true);
  if public.st_v6_file_can_read(file_key)
    or exists(select 1 from storage.objects where bucket_id='sectalk-chat-files' and name=file_key::text)
    or exists(select 1 from public.st_v5_report_timeline(report)) then raise exception 'Outside account accessed evidence or timeline'; end if;
  begin
    perform public.st_v5_moderate(report,'warn','Unauthorized example');
    raise exception 'Unverified account could moderate' using errcode='P0004';
  exception when raise_exception then null;
  end;

  perform set_config('request.jwt.claims',json_build_object('sub',alex,'role','authenticated','aal','aal1')::text,true);
  if exists(select 1 from public.st_v5_hidden_messages where message_id=text_key) then raise exception 'Private hide leaked to sender'; end if;
  perform public.st_v5_message_action(text_key,'revoke');
  perform public.st_v5_message_action(file_key,'revoke');
  if exists(select 1 from public.st_v2_reactions where message_id=file_key) then raise exception 'Reaction remained on a revoked message'; end if;
  if exists(select 1 from public.st_v2_message_edits where message_id=text_key) then raise exception 'Revoked edit content remained'; end if;
  if public.st_v6_file_can_read(file_key)
    or exists(select 1 from storage.objects where bucket_id='sectalk-chat-files' and name=file_key::text)
    then raise exception 'Sender could still download revoked file'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',staffer,'role','authenticated','aal','aal2')::text,true);
  if (public.st_v5_case(report)->'attachment'->>'id') is distinct from file_key::text
    or not public.st_v6_file_can_read(file_key)
    or exists(select 1 from storage.objects where bucket_id='sectalk-chat-files' and name=file_key::text)
    then raise exception 'Explicitly shared evidence unavailable to MFA staff'; end if;
  perform public.st_v5_moderate(report,'escalated','Escalation fixture');
  perform public.st_v5_moderate(report,'warn','Warning fixture');
  perform public.st_v5_moderate(report,'remove','Indefinite restriction fixture');
  perform public.st_v5_moderate(report,'resolved','Resolution fixture');

  perform set_config('request.jwt.claims',json_build_object('sub',billie,'role','authenticated','aal','aal1')::text,true);
  if not exists(select 1 from public.st_v5_report_timeline(report) where action='remove')
    or exists(select 1 from public.st_v5_report_timeline(report) where action='viewed')
    or exists(select 1 from public.st_v5_account_notices) then raise exception 'Timeline scope or outcome wrong'; end if;
  if public.st_v5_last_seen(chat) is not null then raise exception 'Restricted contact activity exposed'; end if;
  perform public.st_set_block(chat,true);
  if exists(select 1 from public.st_v5_profile_details where user_id=alex)
    then raise exception 'Blocked contact profile remained visible'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',alex,'role','authenticated','aal','aal1')::text,true);
  if not exists(select 1 from public.st_v5_account_notices where action='remove' and until_at='infinity'::timestamptz)
    or exists(select 1 from public.st_v5_report_timeline(report)) then raise exception 'Private account notices or report scope failed'; end if;
  begin
    perform public.st_send(chat,gen_random_uuid(),'A restricted send');
    raise exception 'Restricted account sent a new message' using errcode='P0004';
  exception when raise_exception then null;
  end;
end $$;
reset role;
select 'passed: attachment privacy, revoke, moderator MFA, report tracking, discovery, profiles, and blocking' as result;
rollback;
