begin;

insert into auth.users(id,email) values
  ('7b000000-0000-4000-8000-000000000001','forward-alex@example.invalid'),
  ('7b000000-0000-4000-8000-000000000002','forward-billie@example.invalid'),
  ('7b000000-0000-4000-8000-000000000003','forward-casey@example.invalid');
insert into public.st_profiles(id,name,handle) values
  ('7b000000-0000-4000-8000-000000000001','Forward Alex','forward_alex'),
  ('7b000000-0000-4000-8000-000000000002','Forward Billie','forward_billie'),
  ('7b000000-0000-4000-8000-000000000003','Forward Casey','forward_casey');

do $$
declare
  alex constant uuid:='7b000000-0000-4000-8000-000000000001';
  billie constant uuid:='7b000000-0000-4000-8000-000000000002';
  casey constant uuid:='7b000000-0000-4000-8000-000000000003';
  origin_msg uuid:=gen_random_uuid();
  copy_msg uuid:=gen_random_uuid();
  following_msg uuid:=gen_random_uuid();
  hidden_msg uuid:=gen_random_uuid();
  revoked_msg uuid:=gen_random_uuid();
  attached_msg uuid:=gen_random_uuid();
  room_msg uuid:=gen_random_uuid();
  room_copy uuid:=gen_random_uuid();
  private_msg uuid:=gen_random_uuid();
  announcement_msg uuid:=gen_random_uuid();
  removed_msg uuid:=gen_random_uuid();
  source_room uuid:=gen_random_uuid();
  dest_room uuid:=gen_random_uuid();
  private_room uuid:=gen_random_uuid();
  other_room uuid:=gen_random_uuid();
  origin_chat uuid;
  dest_chat uuid;
  outside_chat uuid;
  workspace uuid;
  other_workspace uuid;
  test_case record;
begin
  if has_function_privilege('anon','public.st_v6_forward_direct(uuid,uuid,uuid,uuid)','EXECUTE')
    or has_function_privilege('anon','public.st_v6_forward_room(uuid,uuid,uuid,uuid)','EXECUTE')
    or has_function_privilege('authenticated','sectalk_private.st_v6_write_room_post(uuid,uuid,text,text,uuid,boolean)','EXECUTE')
    or has_column_privilege('authenticated','public.st_messages','forwarded','UPDATE')
    then raise exception 'Unexpected forwarding permission'; end if;

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',alex::text,true);
  origin_chat:=public.st_request('forward_billie');
  dest_chat:=public.st_request('forward_casey');
  workspace:=public.st_v2_create_workspace('Forwarding workspace');
  perform public.st_v6_room_create(source_room,workspace,'Forward origin','public','blank');
  perform public.st_v6_room_create(dest_room,workspace,'Forward target','public','blank');
  perform public.st_v6_room_create(private_room,workspace,'Private target','private','blank');
  perform set_config('request.jwt.claim.sub',casey::text,true);
  other_workspace:=public.st_v2_create_workspace('Other forwarding tenant');
  perform public.st_v6_room_create(other_room,other_workspace,'Other room','public','blank');
  perform set_config('request.jwt.claim.sub',billie::text,true);
  perform public.st_respond(origin_chat,true);
  outside_chat:=public.st_request('forward_casey');
  perform public.st_send(origin_chat,origin_msg,'Original direct text');
  perform public.st_send(origin_chat,hidden_msg,'Hidden direct text');
  perform public.st_send(origin_chat,revoked_msg,'Revoked direct text');
  perform public.st_v5_message_action(revoked_msg,'revoke');
  perform public.st_send(origin_chat,attached_msg,'Attachment caption');
  perform set_config('request.jwt.claim.sub',casey::text,true);
  perform public.st_respond(dest_chat,true);
  perform public.st_respond(outside_chat,true);

  reset role;
  insert into public.st_v5_files(id,chat_id,uploader,message_id,filename,size_bytes)
    values(gen_random_uuid(),origin_chat,billie,attached_msg,'proof.txt',10);
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,casey,'member');
  insert into public.st_v2_members(workspace_id,user_id,role) values(other_workspace,alex,'member');
  insert into public.st_v6_room_members(room_id,user_id,role) values(dest_room,casey,'member'),(other_room,alex,'member');

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',alex::text,true);
  perform public.st_v5_message_action(hidden_msg,'hide');
  perform public.st_v6_forward_direct(origin_chat,origin_msg,dest_chat,copy_msg);
  perform public.st_v6_forward_direct(origin_chat,origin_msg,dest_chat,copy_msg);
  perform public.st_send(dest_chat,following_msg,'Message after retry');
  for test_case in select * from (values
      (origin_chat,origin_msg,outside_chat),
      (outside_chat,origin_msg,dest_chat),
      (origin_chat,hidden_msg,dest_chat),
      (origin_chat,revoked_msg,dest_chat),
      (origin_chat,attached_msg,dest_chat),
      (origin_chat,origin_msg,source_room)
    ) attempts(source_chat,source_message,destination)
  loop
    begin
      perform public.st_v6_forward_direct(test_case.source_chat,test_case.source_message,test_case.destination,gen_random_uuid());
      raise exception 'Ineligible direct forwarding was accepted' using errcode='P0004';
    exception when raise_exception then
      if sqlerrm<>'Forwarding is unavailable' then raise; end if;
    end;
  end loop;
  perform set_config('request.jwt.claim.sub',casey::text,true);
  if not exists(select 1 from public.st_messages where id=copy_msg and chat_id=dest_chat and sender=alex
      and body='Original direct text' and forwarded and sequence=1 and reply_to is null)
    or not exists(select 1 from public.st_messages where id=following_msg and sequence=2 and not forwarded)
    or exists(select 1 from public.st_messages where id=origin_msg) then
    raise exception 'Wrong direct copy, recipient visibility, or message sequence';
  end if;
  perform public.st_set_block(dest_chat,true);
  perform set_config('request.jwt.claim.sub',alex::text,true);
  begin
    perform public.st_v6_forward_direct(origin_chat,origin_msg,dest_chat,gen_random_uuid());
    raise exception 'Blocked direct forwarding was accepted' using errcode='P0004';
  exception when raise_exception then
    if sqlerrm<>'Forwarding is unavailable' then raise; end if;
  end;

  perform public.st_v6_room_post(source_room,room_msg,'Room copy @forward_casey @channel');
  perform public.st_v6_room_post(source_room,announcement_msg,'Announcement','announcement');
  perform public.st_v6_room_post(source_room,removed_msg,'Removed room text');
  perform public.st_v6_room_post_action(source_room,removed_msg,'delete');
  perform public.st_v6_room_post(private_room,private_msg,'Private room text');
  if (select array_agg(id) from public.st_v6_forward_room_destinations(source_room)) is distinct from array[dest_room]
    then raise exception 'Incorrect room forwarding choices'; end if;
  perform public.st_v6_forward_room(source_room,room_msg,dest_room,room_copy);
  perform public.st_v6_forward_room(source_room,room_msg,dest_room,room_copy);
  for test_case in select * from (values
      (source_room,room_msg,other_room),
      (source_room,room_msg,private_room),
      (private_room,private_msg,dest_room),
      (source_room,announcement_msg,dest_room),
      (source_room,removed_msg,dest_room),
      (source_room,room_msg,dest_chat)
    ) attempts(room_id,post_id,destination)
  loop
    begin
      perform public.st_v6_forward_room(test_case.room_id,test_case.post_id,test_case.destination,gen_random_uuid());
      raise exception 'Ineligible room forwarding was accepted' using errcode='P0004';
    exception when raise_exception then
      if sqlerrm<>'Forwarding is unavailable' then raise; end if;
    end;
  end loop;
  perform set_config('request.jwt.claim.sub',casey::text,true);
  if not exists(select 1 from public.st_v6_room_posts where room_id=dest_room and id=room_copy
    and sender=alex and forwarded and body='Room copy @forward_casey @channel' and parent_id is null)
    or exists(select 1 from public.st_v6_room_posts where room_id=source_room and id=room_msg)
    or exists(select 1 from public.st_v3_notifications where room_post_id=room_copy) then
    raise exception 'Wrong room copy, recipient visibility, or mention alert';
  end if;
  begin
    perform public.st_v6_set_room_forwarding(dest_room,false);
    raise exception 'Room member changed forwarding policy' using errcode='P0004';
  exception when raise_exception then
    if sqlerrm<>'Room settings unavailable' then raise; end if;
  end;
  perform set_config('request.jwt.claim.sub',alex::text,true);
  perform public.st_v6_set_room_forwarding(dest_room,false);
  if exists(select 1 from public.st_v6_forward_room_destinations(source_room))
    or not exists(select 1 from public.st_v6_room_audit where room_id=dest_room and action='room.forwarding_disabled')
    then raise exception 'The room policy did not update choices and audit'; end if;
  begin
    perform public.st_v6_forward_room(source_room,room_msg,dest_room,gen_random_uuid());
    raise exception 'Disabled destination accepted a forward' using errcode='P0004';
  exception when raise_exception then
    if sqlerrm<>'Forwarding is unavailable' then raise; end if;
  end;
  perform public.st_v6_set_room_forwarding(dest_room,true);
  perform public.st_v6_set_room_forwarding(source_room,false);
  begin
    perform public.st_v6_forward_room(source_room,room_msg,dest_room,gen_random_uuid());
    raise exception 'Disabled source accepted a forward' using errcode='P0004';
  exception when raise_exception then
    if sqlerrm<>'Forwarding is unavailable' then raise; end if;
  end;
end $$;

rollback;
