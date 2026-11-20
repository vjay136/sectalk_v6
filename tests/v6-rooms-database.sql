begin;

insert into auth.users(id,email,aud,role) values
 ('61000000-0000-4000-8000-000000000001','room-owner@example.invalid','authenticated','authenticated'),
 ('61000000-0000-4000-8000-000000000002','room-member@example.invalid','authenticated','authenticated'),
 ('61000000-0000-4000-8000-000000000003','room-outside@example.invalid','authenticated','authenticated'),
 ('61000000-0000-4000-8000-000000000004','room-guest@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
 ('61000000-0000-4000-8000-000000000001','room_fixture_owner','Room owner'),
 ('61000000-0000-4000-8000-000000000002','room_fixture_member','Room member'),
 ('61000000-0000-4000-8000-000000000003','room_fixture_outside','Outside account'),
 ('61000000-0000-4000-8000-000000000004','room_fixture_guest','Room guest');
insert into auth.sessions(id,user_id,aal) values
 ('61000000-0000-4000-8000-000000000011','61000000-0000-4000-8000-000000000001','aal1');
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
 (gen_random_uuid(),'61000000-0000-4000-8000-000000000011','password',now(),now());

set local role authenticated;
do $$
declare
  owner_id constant uuid:='61000000-0000-4000-8000-000000000001';
  owner_claims constant text:=json_build_object('sub',owner_id,'role','authenticated','aal','aal1',
    'session_id','61000000-0000-4000-8000-000000000011')::text;
  member_id constant uuid:='61000000-0000-4000-8000-000000000002';
  outside_id constant uuid:='61000000-0000-4000-8000-000000000003';
  guest_id constant uuid:='61000000-0000-4000-8000-000000000004';
  public_room constant uuid:=gen_random_uuid();
  private_room constant uuid:=gen_random_uuid();
  admin_room constant uuid:=gen_random_uuid();
  announcements constant uuid:=gen_random_uuid();
  broadcast constant uuid:=gen_random_uuid();
  root_message constant uuid:=gen_random_uuid();
  reply_message constant uuid:=gen_random_uuid();
  room_task constant uuid:=gen_random_uuid();
  workspace uuid;
  invitation uuid;
begin
  perform set_config('request.jwt.claims',owner_claims,true);
  workspace:=public.st_v2_create_workspace('Room acceptance');
  perform public.st_v2_invite(workspace,'room_fixture_member');
  perform public.st_v2_invite(workspace,'room_fixture_guest');
  perform public.st_v6_room_create(public_room,workspace,'Public room','public','project');
  perform public.st_v6_room_create(public_room,workspace,'Public room','public','project');
  perform public.st_v6_room_create(private_room,workspace,'Private room','private','family');
  perform public.st_v6_room_create(admin_room,workspace,'Admin room','admin','incident');
  perform public.st_v6_room_create(announcements,workspace,'Announcements','announcement','blank');
  perform public.st_v6_room_create(broadcast,workspace,'Broadcast','broadcast','blank');
  perform public.st_v6_room_post(public_room,root_message,'Root message');
  perform public.st_v6_room_post(private_room,gen_random_uuid(),'Private fixture');
  perform public.st_v6_task_create(room_task,private_room,null,'Private fixture task');
  if (select count(*) from public.st_v6_search('Private fixture','room',jsonb_build_object('room',private_room)))<>1
    or exists(select 1 from public.st_v6_search('Private fixture','room',jsonb_build_object('room',public_room)))
    or (select count(*) from public.st_v6_search('','task',jsonb_build_object('room',private_room,'status','todo')))<>1
    or exists(select 1 from public.st_v6_search('','task',jsonb_build_object('room',private_room,'status','done')))
    then raise exception 'Room or task status filter failed'; end if;
  perform public.st_v6_room_post(admin_room,gen_random_uuid(),'Admin fixture');
  perform public.st_v6_room_post(announcements,gen_random_uuid(),'Announcement fixture','announcement');
  perform public.st_v6_room_post(broadcast,gen_random_uuid(),'Broadcast fixture');

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  select id into invitation from public.st_v2_invites where invitee=member_id;
  perform public.st_v2_reply_invite(invitation,true);
  if exists(select 1 from public.st_v6_search('Private fixture',null,jsonb_build_object('room',private_room)))
    then raise exception 'Room filter leaked private posts or tasks'; end if;
  if (select count(*) from public.st_v6_rooms where workspace_id=workspace)<>3
    or exists(select 1 from public.st_v6_room_posts) then raise exception 'Directory or pre-join visibility failed'; end if;
  perform public.st_v6_room_membership(public_room,'join');
  perform public.st_v6_room_membership(announcements,'join');
  perform public.st_v6_room_membership(broadcast,'join');
  perform public.st_v6_room_membership(private_room,'request');
  perform public.st_v6_room_post(public_room,reply_message,'Reply message','message',root_message);
  perform public.st_v6_room_post(public_room,reply_message,'Reply message','message',root_message);
  if (select count(*) from public.st_v6_room_posts where room_id=public_room and parent_id=root_message)<>1
    then raise exception 'Thread write was duplicated or unavailable'; end if;
  insert into public.st_v6_thread_follows(room_id,post_id) values(public_room,root_message);
  insert into public.st_v6_thread_follows(room_id,post_id) values(public_room,root_message)
    on conflict(room_id,post_id,user_id) do nothing;
  if not exists(select 1 from public.st_v6_room_thread_state(public_room,array[root_message]) where replies=1 and following)
    then raise exception 'Reply count or private follow failed'; end if;
  begin
    insert into public.st_v6_thread_follows(room_id,post_id) values(public_room,reply_message);
    raise exception 'Reply could be followed as a root' using errcode='P0004';
  exception when insufficient_privilege then null; end;
  if public.st_v6_room_my_role(broadcast) is distinct from 'read_only' then raise exception 'Broadcast join did not constrain permissions'; end if;
  begin
    perform public.st_v6_room_post(announcements,gen_random_uuid(),'Unauthorized announcement','announcement');
    raise exception 'Participant posted announcement' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_room_post(broadcast,gen_random_uuid(),'Unauthorized broadcast');
    raise exception 'Subscriber posted to broadcast' using errcode='P0004';
  exception when raise_exception then null; end;
  if exists(select 1 from public.st_v6_room_audit) then raise exception 'Room audit leaked to a member'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',guest_id,'role','authenticated')::text,true);
  select id into invitation from public.st_v2_invites where invitee=guest_id;
  perform public.st_v2_reply_invite(invitation,true);
  perform set_config('request.jwt.claims',owner_claims,true);
  if exists(select 1 from public.st_v6_room_thread_state(public_room,array[root_message]) where following)
    or exists(select 1 from public.st_v6_thread_follows) then raise exception 'Another participant saw a private follow'; end if;
  perform public.st_v6_room_membership(private_room,'approve',member_id);
  perform public.st_v6_room_membership(private_room,'invite',guest_id,'guest');
  perform public.st_v6_room_membership(public_room,'role',member_id,'moderator');
  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if public.st_v6_room_my_role(public_room) is distinct from 'moderator'
    or not exists(select 1 from public.st_v6_room_audit where room_id=public_room)
    then raise exception 'Promoted moderator permissions not applied'; end if;
  perform set_config('request.jwt.claims',owner_claims,true);
  perform public.st_v6_room_membership(public_room,'role',member_id,'member');
  perform public.st_v6_room_settings(public_room,'pin',root_message);
  perform public.st_v6_room_settings(public_room,'slow',null,5);
  perform public.st_v6_room_membership(private_room,'mute',member_id);

  perform set_config('request.jwt.claims',json_build_object('sub',guest_id,'role','authenticated')::text,true);
  if not exists(select 1 from public.st_v6_rooms where id=private_room)
    or exists(select 1 from public.st_v6_room_posts where room_id=private_room) then raise exception 'Invitation did not scope metadata only'; end if;
  perform public.st_v6_room_membership(private_room,'accept');
  if public.st_v6_room_my_role(private_room) is distinct from 'guest'
    or (select count(*) from public.st_v6_room_members where room_id=private_room)<>1 then raise exception 'Guest role isolation failed'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  delete from public.st_v6_thread_follows where room_id=public_room and post_id=root_message;
  if exists(select 1 from public.st_v6_room_thread_state(public_room,array[root_message]) where following)
    then raise exception 'Unfollow did not remove user preference'; end if;
  if not exists(select 1 from public.st_v6_room_posts where room_id=private_room)
    or not exists(select 1 from public.st_v6_room_pins where room_id=public_room and post_id=root_message)
    then raise exception 'Approved room or pin unavailable'; end if;
  begin
    perform public.st_v6_room_settings(public_room,'pin',root_message);
    raise exception 'A regular member changed a room pin' using errcode='P0004';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_room_post(private_room,gen_random_uuid(),'Muted post');
    raise exception 'Muted account wrote a message' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_room_post(public_room,gen_random_uuid(),'Slow mode violation');
    raise exception 'Slow mode was bypassed' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v6_room_membership(private_room,'unmute',member_id);
  perform public.st_v6_room_membership(private_room,'timeout',member_id);
  if not exists(select 1 from public.st_v6_room_timeouts where room_id=private_room and user_id=member_id
    and until_at>now() and until_at<=now()+interval '15 minutes') then raise exception 'Finite timeout was not saved'; end if;
  perform public.st_v6_room_membership(private_room,'unmute',member_id);
  perform public.st_v6_room_membership(private_room,'ban',guest_id);
  perform public.st_v6_room_settings(private_room,'lock');
  perform public.st_v6_room_settings(public_room,'archive');
  if not exists(select 1 from public.st_v6_search('Root message','room',jsonb_build_object('room',public_room)) s where s.id=root_message)
    then raise exception 'Archiving hid accessible room history from Search'; end if;
  perform public.st_v6_room_settings(public_room,'restore');
  if not exists(select 1 from public.st_v6_room_audit where room_id=private_room and action='membership.ban' and target=guest_id)
    then raise exception 'Room audit did not record moderation'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',guest_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_rooms where id=private_room) or exists(select 1 from public.st_v6_room_posts where room_id=private_room)
    then raise exception 'Banned member retained room access'; end if;
  if exists(select 1 from public.st_v6_search('',null,jsonb_build_object('room',private_room)))
    then raise exception 'Banned user retained filtered search access'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  begin
    perform public.st_v6_room_post(private_room,gen_random_uuid(),'Locked room write');
    raise exception 'Lock did not stop posting' using errcode='P0004';
  exception when raise_exception then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v6_room_membership(private_room,'unban',guest_id);
  if exists(select 1 from public.st_v6_room_bans where room_id=private_room and user_id=guest_id)
    then raise exception 'Ban was not lifted'; end if;
  perform public.st_v6_room_membership(private_room,'remove',member_id);
  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_room_posts where room_id=private_room) then raise exception 'Removed room member kept access'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',outside_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_rooms where workspace_id=workspace) or exists(select 1 from public.st_v6_room_posts)
    then raise exception 'Cross-tenant room access'; end if;
  begin
    perform public.st_v6_room_membership(private_room,'request');
    raise exception 'Outsider requested access by code' using errcode='P0004';
  exception when raise_exception then null; end;
end $$;
reset role;
select 'passed: room types, roles, invites, approval, posting, threads, pins, moderation, audit and tenant isolation' as result;
rollback;
