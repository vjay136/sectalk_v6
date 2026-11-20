begin;
do $$
declare
  first_person uuid:=gen_random_uuid();
  peer uuid:=gen_random_uuid();
  outsider uuid:=gen_random_uuid();
  conversation uuid;
  room_mismatch uuid:=gen_random_uuid();
  clip uuid:=gen_random_uuid();
  opted uuid:=gen_random_uuid();
  cipher text:=encode(decode(repeat('4a',2400),'hex'),'base64');
  output jsonb;
begin
  insert into auth.users(id,email) values
    (first_person,'voice-rollback-one@example.invalid'),(peer,'voice-rollback-two@example.invalid'),(outsider,'voice-rollback-outside@example.invalid');
  insert into public.st_profiles(id,handle,name) values
    (first_person,'voice_fixture_one','Voice one'),(peer,'voice_fixture_two','Voice two'),(outsider,'voice_fixture_out','Voice outside');
  insert into public.st_chats(member_a,member_b,requester,status)
    values(least(first_person,peer),greatest(first_person,peer),first_person,'accepted') returning id into conversation;
  if has_function_privilege('authenticated','public.st_v6_voice_note_command(text,uuid,uuid,uuid,text,boolean,integer)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v6_voice_note','select')
    then raise exception 'Voice ciphertext bypasses application authorization'; end if;
  output:=public.st_v6_voice_note_command('create',first_person,conversation,clip,cipher,false,60);
  if output->>'ok'<>'true' or not exists(select 1 from public.st_messages where id=clip and voice_note and expires_at is not null)
    then raise exception 'Atomic timed voice message failed'; end if;
  if public.st_v6_voice_note_command('read',outsider,conversation,clip) is not null
    or public.st_v6_voice_note_command('read',peer,room_mismatch,clip) is not null
    or public.st_v6_voice_note_command('begin_speech',first_person,conversation,clip) is not null
    then raise exception 'Cross-chat access or absent speech consent accepted'; end if;
  if public.st_v6_voice_note_command('read',peer,conversation,clip) is null
    then raise exception 'Peer could not read note'; end if;
  perform public.st_v6_voice_note_command('create',first_person,conversation,opted,cipher,true,0);
  if public.st_v6_voice_note_command('begin_speech',peer,conversation,opted) is not null
    or public.st_v6_voice_note_command('begin_speech',first_person,conversation,opted) is null
    or public.st_v6_voice_note_command('save_speech',first_person,conversation,opted,cipher) is null
    then raise exception 'Per-author transcript consent failed'; end if;
  if not exists(select 1 from public.st_messages where id=opted and voice_transcript) then raise exception 'Transcript live update marker missing'; end if;
  insert into public.st_v5_hidden_messages(message_id,user_id) values(opted,peer);
  if public.st_v6_voice_note_command('read',peer,conversation,opted) is not null then raise exception 'Hidden note remained readable'; end if;
  insert into public.st_blocks(actor,target) values(peer,first_person);
  if public.st_v6_voice_note_command('read',first_person,conversation,opted) is not null then raise exception 'Block did not deny voice media'; end if;
  delete from public.st_blocks where actor=peer and target=first_person;
  update public.st_messages set created_at=now()-interval '2 minutes',expires_at=now()-interval '1 minute' where id=clip;
  if public.st_v6_voice_note_command('read',peer,conversation,clip) is not null then raise exception 'Expired note remained readable'; end if;
  update public.st_messages set revoked_at=clock_timestamp(),body='Message removed' where id in (clip,opted);
  if exists(select 1 from sectalk_private.st_v6_voice_note where message in (clip,opted)) then
    raise exception 'Revocation did not purge encrypted note payloads';
  end if;
end
$$;
rollback;
