begin;

insert into auth.users(id,email) values
  ('79500000-0000-4000-8000-000000000001','typing-owner@example.invalid'),
  ('79500000-0000-4000-8000-000000000002','typing-peer@example.invalid'),
  ('79500000-0000-4000-8000-000000000003','typing-outsider@example.invalid');
insert into public.st_profiles(id,name,handle)
select id,split_part(email,'@',1),replace(split_part(email,'@',1),'-','_')
  from auth.users where id::text like '79500000-0000-4000-8000-%';

do $$
declare
  owner_id constant uuid:='79500000-0000-4000-8000-000000000001';
  peer_id constant uuid:='79500000-0000-4000-8000-000000000002';
  outsider_id constant uuid:='79500000-0000-4000-8000-000000000003';
  room constant uuid:=gen_random_uuid();
  first_root constant uuid:=gen_random_uuid();
  second_root constant uuid:=gen_random_uuid();
  conversation uuid;
  workspace uuid;
  expiry text;
  hint_count bigint;
begin
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  workspace:=public.st_v2_create_workspace('Typing fixture workspace');
  perform public.st_v6_room_create(room,workspace,'Typing fixture room','public','blank');
  perform public.st_v6_room_post(room,first_root,'First root');
  perform public.st_v6_room_post(room,second_root,'Second root');
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,peer_id,'member'),(workspace,outsider_id,'member');
  insert into public.st_v6_room_members(room_id,user_id,role) values(room,peer_id,'member');

  set local role authenticated;
  conversation:=public.st_request('typing_peer');
  perform public.st_v2_typing(conversation,true);
  perform set_config('request.jwt.claim.sub',peer_id::text,true);
  perform public.st_respond(conversation,true);
  if public.st_v2_chat_status(conversation)->>'typing_until' is not null
    then raise exception 'Pending chat emitted typing'; end if;
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform public.st_v2_typing(conversation,true);
  perform public.st_v6_room_typing(room,first_root,true);
  if public.st_v2_chat_status(conversation)->>'typing_until' is not null
    or public.st_v6_room_typing_status(room,first_root)->>'typing_until' is not null
    then raise exception 'Own pulse was returned as peer activity'; end if;

  perform set_config('request.jwt.claim.sub',peer_id::text,true);
  expiry:=public.st_v2_chat_status(conversation)->>'typing_until';
  if expiry is null or public.st_v6_room_typing_status(room,first_root)->>'typing_until' is null
    or public.st_v6_room_typing_status(room,null)->>'typing_until' is not null
    or public.st_v6_room_typing_status(room,second_root)->>'typing_until' is not null
    then raise exception 'Typing was missing or crossed room thread scopes'; end if;
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform public.st_v2_typing(conversation,true);
  perform public.st_v6_room_typing(room,null,true);
  perform set_config('request.jwt.claim.sub',peer_id::text,true);
  if public.st_v2_chat_status(conversation)->>'typing_until' is distinct from expiry
    or public.st_v6_room_typing_status(room,null)->>'typing_until' is not null
    then raise exception 'A rapid pulse bypassed the server cooldown'; end if;

  perform set_config('request.jwt.claim.sub',outsider_id::text,true);
  perform public.st_v2_typing(conversation,true);
  perform public.st_v6_room_typing(room,first_root,true);
  if public.st_v2_chat_status(conversation)<>'{}'::jsonb
    or public.st_v6_room_typing_status(room,first_root)<>'{}'::jsonb
    then raise exception 'A nonparticipant read typing status'; end if;
  begin
    perform public.st_v6_set_typing_policy(conversation,false);
    raise exception 'A nonparticipant changed typing policy' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform public.st_v6_set_typing_policy(conversation,false);
  perform public.st_v6_set_room_typing_policy(room,false);
  if public.st_v2_chat_status(conversation)->>'share_own_typing' is distinct from 'false'
    or public.st_v6_room_typing_status(room,first_root)->>'share_own_typing' is distinct from 'false'
    then raise exception 'Opt-out was not applied'; end if;
  reset role;
  select count(*) into hint_count from realtime.messages where event='chat_activity' and payload->>'chat_id'=conversation::text;
  set local role authenticated;
  perform public.st_v2_typing(conversation,true);
  perform public.st_v6_room_typing(room,first_root,true);
  perform set_config('request.jwt.claim.sub',peer_id::text,true);
  if public.st_v2_chat_status(conversation)->>'typing_until' is not null
    or public.st_v6_room_typing_status(room,first_root)->>'typing_until' is not null
    or public.st_v2_chat_status(conversation)->>'share_own_typing' is distinct from 'true'
    then raise exception 'Opt-out exposed typing or disabled the other participant'; end if;
  reset role;
  if (select count(*) from realtime.messages where event='chat_activity' and payload->>'chat_id'=conversation::text)<>hint_count
    then raise exception 'A suppressed pulse emitted a Realtime hint'; end if;

  -- Advance past the pulse floor without sleeping, then enable sharing and verify it is usable again.
  update public.st_v2_typing set last_started_at=clock_timestamp()-interval '3 seconds' where chat_id=conversation;
  update sectalk_private.room_typing set last_started_at=clock_timestamp()-interval '3 seconds' where room_id=room;
  set local role authenticated;
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform public.st_v6_set_typing_policy(conversation,true);
  perform public.st_v6_set_room_typing_policy(room,true);
  perform public.st_v2_typing(conversation,true);
  perform public.st_v6_room_typing(room,null,true);
  perform set_config('request.jwt.claim.sub',peer_id::text,true);
  if public.st_v2_chat_status(conversation)->>'typing_until' is null
    or public.st_v6_room_typing_status(room,null)->>'typing_until' is null
    then raise exception 'Re-enabled typing did not emit'; end if;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform public.st_v2_typing(conversation,false);
  perform public.st_v2_typing(conversation,true);
  perform public.st_v6_room_typing(room,null,false);
  perform public.st_v6_room_typing(room,null,true);
  perform set_config('request.jwt.claim.sub',peer_id::text,true);
  if public.st_v2_chat_status(conversation)->>'typing_until' is not null
    or public.st_v6_room_typing_status(room,null)->>'typing_until' is not null
    then raise exception 'A clear/restart cycle bypassed the pulse floor'; end if;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  for counter in 1..75 loop
    begin
      perform public.st_v2_typing(conversation,true);
      if counter=75 then raise exception 'No direct typing request limit'; end if;
    exception when sqlstate 'PT429' then exit; end;
  end loop;
  for counter in 1..75 loop
    begin
      perform public.st_v6_room_typing(room,null,true);
      if counter=75 then raise exception 'No room typing request limit'; end if;
    exception when sqlstate 'PT429' then exit; end;
  end loop;
  reset role;
  update public.st_v2_typing set expires_at=clock_timestamp()+interval '5 seconds' where chat_id=conversation;
  update sectalk_private.room_typing set expires_at=clock_timestamp()+interval '5 seconds' where room_id=room;
  insert into public.st_blocks(actor,target) values(peer_id,owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claim.sub',peer_id::text,true);
  if public.st_v2_chat_status(conversation)->>'typing_until' is not null
    or public.st_v6_room_typing_status(room,null)->>'typing_until' is not null
    then raise exception 'A block did not hide already active typing'; end if;
  reset role;

  delete from public.st_blocks where actor=peer_id and target=owner_id;
  insert into public.st_v6_room_timeouts(room_id,user_id,until_at) values(room,owner_id,clock_timestamp()+interval '1 minute');
  set local role authenticated;
  if public.st_v6_room_typing_status(room,null)->>'typing_until' is not null
    then raise exception 'A posting timeout did not hide already active typing'; end if;
  reset role;

  update public.st_v2_typing set expires_at=statement_timestamp()-interval '1 second' where chat_id=conversation;
  update sectalk_private.room_typing set expires_at=statement_timestamp()-interval '1 second' where room_id=room;
  set local role authenticated;
  if public.st_v2_chat_status(conversation)->>'typing_until' is not null
    or public.st_v6_room_typing_status(room,null)->>'typing_until' is not null
    then raise exception 'Expired typing was returned'; end if;
  reset role;
end $$;

do $$
begin
  if has_function_privilege('anon','public.st_v6_room_typing_status(uuid,uuid)','EXECUTE')
    or has_function_privilege('anon','public.st_v2_chat_status(uuid)','EXECUTE')
    or has_table_privilege('authenticated','sectalk_private.room_typing','SELECT')
    or has_table_privilege('authenticated','public.st_v2_typing','SELECT')
    then raise exception 'Typing data or RPC was exposed to an unauthorized role'; end if;
end $$;

rollback;
