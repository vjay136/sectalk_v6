begin;

insert into auth.users(id,email,aud,role) values
  ('69600000-0000-4000-8000-000000000001','read-owner@example.invalid','authenticated','authenticated'),
  ('69600000-0000-4000-8000-000000000002','read-member@example.invalid','authenticated','authenticated'),
  ('69600000-0000-4000-8000-000000000003','read-outsider@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('69600000-0000-4000-8000-000000000001','read_owner','Owner'),
  ('69600000-0000-4000-8000-000000000002','read_member','Member'),
  ('69600000-0000-4000-8000-000000000003','read_outsider','Outsider');

set local role authenticated;
do $$
declare
  author constant uuid:='69600000-0000-4000-8000-000000000001';
  reader constant uuid:='69600000-0000-4000-8000-000000000002';
  outsider constant uuid:='69600000-0000-4000-8000-000000000003';
  room constant uuid:=gen_random_uuid();
  other_room constant uuid:=gen_random_uuid();
  room_post constant uuid:=gen_random_uuid();
  reply constant uuid:=gen_random_uuid();
  foreign_post constant uuid:=gen_random_uuid();
  first_dm constant uuid:=gen_random_uuid();
  private_dm constant uuid:=gen_random_uuid();
  later_dm constant uuid:=gen_random_uuid();
  workspace uuid; chat uuid; invitation uuid;
begin
  perform set_config('request.jwt.claim.sub',author::text,true);
  workspace:=public.st_v2_create_workspace('Read receipt fixtures');
  perform public.st_v2_invite(workspace,'read_member');
  perform public.st_v6_room_create(room,workspace,'Read receipts','public','blank');
  perform public.st_v6_room_create(other_room,workspace,'Other room','private','blank');
  perform public.st_v6_room_post(room,room_post,'Message');
  perform public.st_v6_room_post(room,reply,'Reply','message',room_post);
  perform public.st_v6_room_post(other_room,foreign_post,'Foreign message');
  perform public.st_v6_share_room_reads(room,array[room_post]);
  if exists(select 1 from public.st_v6_room_read_counts(room,array[room_post]))
    then raise exception 'Author counted as a reader'; end if;
  chat:=public.st_request('read_member');

  perform set_config('request.jwt.claim.sub',outsider::text,true);
  perform public.st_v6_share_room_reads(room,array[room_post]);
  if public.st_v6_read_receipt_settings(null,room)<>'{}' or public.st_v2_chat_status(chat)<>'{}'
    then raise exception 'Outsider could query receipt settings or direct chat status'; end if;

  perform set_config('request.jwt.claim.sub',reader::text,true);
  select id into invitation from public.st_v2_invites where workspace_id=workspace and invitee=reader;
  perform public.st_v2_reply_invite(invitation,true);
  perform public.st_v6_room_membership(room,'join');
  perform public.st_respond(chat,true);
  begin
    perform public.st_v6_set_read_receipt_policy(false,p_workspace=>workspace);
    raise exception 'Member changed workspace policy' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_set_read_receipt_policy(false,p_room=>room);
    raise exception 'Member changed room policy' using errcode='P0004';
  exception when raise_exception then null; end;
  perform public.st_v6_share_room_reads(room,array[room_post,room_post,reply,foreign_post]);
  if exists(select 1 from public.st_v6_room_read_counts(room,array[room_post,reply]))
    then raise exception 'Member obtained another author''s receipts'; end if;

  perform set_config('request.jwt.claim.sub',author::text,true);
  if (select count(*) from public.st_v6_room_read_counts(room,array[room_post,reply]) where amount=1)<>2
    or exists(select 1 from public.st_v6_room_read_counts(other_room,array[foreign_post]))
    then raise exception 'Room receipt counts were not deduplicated and scoped'; end if;
  perform public.st_v6_set_read_receipt_policy(false,p_workspace=>workspace);
  perform set_config('request.jwt.claim.sub',reader::text,true);
  perform public.st_v6_share_room_reads(room,array[room_post]);
  perform set_config('request.jwt.claim.sub',author::text,true);
  if exists(select 1 from public.st_v6_room_read_counts(room,array[room_post,reply]))
    then raise exception 'Workspace disabled receipts were disclosed'; end if;
  perform public.st_v6_set_read_receipt_policy(true,p_workspace=>workspace);
  if exists(select 1 from public.st_v6_room_read_counts(room,array[room_post,reply]))
    then raise exception 'Re-enabling workspace receipts restored earlier activity'; end if;
  perform public.st_v6_set_read_receipt_policy(false,p_room=>room);
  perform set_config('request.jwt.claim.sub',reader::text,true);
  perform public.st_v6_share_room_reads(room,array[room_post]);
  perform set_config('request.jwt.claim.sub',author::text,true);
  if exists(select 1 from public.st_v6_room_read_counts(room,array[room_post]))
    then raise exception 'Room disabled receipts were disclosed'; end if;
  perform public.st_v6_set_read_receipt_policy(true,p_room=>room);
  perform public.st_send(chat,first_dm,'Shared direct read');

  perform set_config('request.jwt.claim.sub',reader::text,true);
  perform public.st_v2_read(chat,first_dm);
  perform public.st_v6_share_room_reads(room,array[room_post]);
  perform set_config('request.jwt.claim.sub',author::text,true);
  if public.st_v2_chat_status(chat)->>'read_id' is distinct from first_dm::text
    or (select amount from public.st_v6_room_read_counts(room,array[room_post])) is distinct from 1::bigint
    then raise exception 'Shared direct or new room receipts missing'; end if;
  perform public.st_send(chat,private_dm,'Read privately');

  perform set_config('request.jwt.claim.sub',reader::text,true);
  perform public.st_v6_set_read_receipt_policy(false);
  perform public.st_v6_ack_message_delivery(chat,array[private_dm]);
  perform public.st_v2_read(chat,private_dm);
  perform public.st_v6_share_room_reads(room,array[room_post]);
  if (select last_read_id from public.st_v2_chat_state where chat_id=chat) is distinct from private_dm
    then raise exception 'Personal opt-out stopped private unread tracking'; end if;
  perform set_config('request.jwt.claim.sub',author::text,true);
  if public.st_v2_chat_status(chat)->>'read_id' is not null
    or exists(select 1 from public.st_v6_room_read_counts(room,array[room_post]))
    or (select delivered_at from public.st_messages where id=private_dm) is null
    then raise exception 'Personal opt-out disclosed a read or stopped delivery'; end if;
  perform set_config('request.jwt.claim.sub',reader::text,true);
  perform public.st_v6_set_read_receipt_policy(true);
  perform public.st_v2_read(chat,private_dm);
  perform set_config('request.jwt.claim.sub',author::text,true);
  if public.st_v2_chat_status(chat)->>'read_id' is not null
    or exists(select 1 from public.st_v6_room_read_counts(room,array[room_post]))
    then raise exception 'Personal re-enable restored prior reads'; end if;
  perform public.st_send(chat,later_dm,'New shared read');
  perform set_config('request.jwt.claim.sub',reader::text,true);
  perform public.st_v2_read(chat,later_dm);
  perform set_config('request.jwt.claim.sub',author::text,true);
  if public.st_v2_chat_status(chat)->>'read_id' is distinct from later_dm::text
    or (public.st_v2_chat_status(chat)->>'read_since_sequence')::bigint is distinct from
      (select sequence from public.st_messages where id=later_dm)
    then raise exception 'Personal re-enable did not allow future reads'; end if;
end $$;
reset role;
select 'passed: policy precedence, authorized setters, scoped counts, private cursor, delivery and future reads' as result;
rollback;
