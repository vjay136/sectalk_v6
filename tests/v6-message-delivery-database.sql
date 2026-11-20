begin;

insert into auth.users(id,email,aud,role) values
  ('68000000-0000-4000-8000-000000000001','delivery-sender@example.invalid','authenticated','authenticated'),
  ('68000000-0000-4000-8000-000000000002','delivery-peer@example.invalid','authenticated','authenticated'),
  ('68000000-0000-4000-8000-000000000003','delivery-outsider@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('68000000-0000-4000-8000-000000000001','delivery_sender','Sender'),
  ('68000000-0000-4000-8000-000000000002','delivery_peer','Peer'),
  ('68000000-0000-4000-8000-000000000003','delivery_outsider','Outsider');

set local role authenticated;
do $$
declare
  author_id constant uuid:='68000000-0000-4000-8000-000000000001';
  peer_id constant uuid:='68000000-0000-4000-8000-000000000002';
  outsider_id constant uuid:='68000000-0000-4000-8000-000000000003';
  normal constant uuid:=gen_random_uuid();
  hidden constant uuid:=gen_random_uuid();
  revoked constant uuid:=gen_random_uuid();
  blocked constant uuid:=gen_random_uuid();
  conversation uuid;
  other_conversation uuid;
  timestamp_before timestamptz;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',author_id,'role','authenticated')::text,true);
  conversation:=public.st_request('delivery_peer');
  other_conversation:=public.st_request('delivery_outsider');
  perform set_config('request.jwt.claims',json_build_object('sub',peer_id,'role','authenticated')::text,true);
  perform public.st_respond(conversation,true);
  perform set_config('request.jwt.claims',json_build_object('sub',author_id,'role','authenticated')::text,true);
  perform public.st_send(conversation,normal,'Stable retry');
  perform public.st_send(conversation,normal,'Stable retry');
  perform public.st_send(conversation,hidden,'Hidden from the receiver');
  perform public.st_send(conversation,revoked,'Revoked before delivery');
  perform public.st_send(conversation,blocked,'Blocked before delivery');
  perform public.st_v5_message_action(revoked,'revoke');
  if exists(select 1 from public.st_v6_ack_message_delivery(conversation,array[normal]))
    then raise exception 'Sender marked their own message delivered'; end if;
  if (select count(*) from public.st_messages m where m.id=normal)<>1 then raise exception 'Retry duplicated the message'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',outsider_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_ack_message_delivery(conversation,array[normal]))
    or exists(select 1 from public.st_v6_ack_message_delivery(other_conversation,array[normal]))
    then raise exception 'Outsider changed delivery in another or pending conversation'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',peer_id,'role','authenticated')::text,true);
  perform public.st_v5_message_action(hidden,'hide');
  if (select array_agg(ack) from public.st_v6_ack_message_delivery(conversation,array[normal,normal,hidden,revoked]) ack)
    is distinct from array[normal] then raise exception 'Delivery was not limited to permitted messages'; end if;
  select m.delivered_at into timestamp_before from public.st_messages m where m.id=normal;
  if timestamp_before is null then raise exception 'Recipient acknowledgment did not record delivery'; end if;
  perform public.st_v6_ack_message_delivery(conversation,array[normal]);
  if (select m.delivered_at from public.st_messages m where m.id=normal) is distinct from timestamp_before
    then raise exception 'Duplicate acknowledgment rewrote delivery time'; end if;
  perform public.st_v2_read(conversation,normal);
  perform public.st_set_block(conversation,true);
  if exists(select 1 from public.st_v6_ack_message_delivery(conversation,array[blocked]))
    then raise exception 'Blocked conversation could acknowledge new delivery'; end if;
  perform public.st_set_block(conversation,false);
  perform set_config('request.jwt.claims',json_build_object('sub',author_id,'role','authenticated')::text,true);
  if public.st_v2_chat_status(conversation)->>'read_id' is distinct from normal::text
    then raise exception 'Delivery changed existing read receipts'; end if;
end $$;
reset role;
select 'passed: recipient-only acknowledgment, unavailable messages, block enforcement, stable retries and read receipts' as result;
rollback;
