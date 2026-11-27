begin;

insert into auth.users(id,email) values
  ('7d200000-0000-4000-8000-000000000001','call-push-sender@example.invalid'),
  ('7d200000-0000-4000-8000-000000000002','call-push-recipient@example.invalid'),
  ('7d200000-0000-4000-8000-000000000003','call-push-outsider@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('7d200000-0000-4000-8000-000000000001','call_push_sender','Sender'),
  ('7d200000-0000-4000-8000-000000000002','call_push_recipient','Recipient'),
  ('7d200000-0000-4000-8000-000000000003','call_push_outsider','Outsider');
insert into auth.sessions(id,user_id) values
  ('7d300000-0000-4000-8000-000000000001','7d200000-0000-4000-8000-000000000001'),
  ('7d300000-0000-4000-8000-000000000002','7d200000-0000-4000-8000-000000000002'),
  ('7d300000-0000-4000-8000-000000000003','7d200000-0000-4000-8000-000000000003'),
  ('7d300000-0000-4000-8000-000000000004','7d200000-0000-4000-8000-000000000001');

do $$
declare
  sender constant uuid:='7d200000-0000-4000-8000-000000000001';
  recipient constant uuid:='7d200000-0000-4000-8000-000000000002';
  outsider constant uuid:='7d200000-0000-4000-8000-000000000003';
  sender_session constant uuid:='7d300000-0000-4000-8000-000000000001';
  recipient_session constant uuid:='7d300000-0000-4000-8000-000000000002';
  outsider_session constant uuid:='7d300000-0000-4000-8000-000000000003';
  other_sender_session constant uuid:='7d300000-0000-4000-8000-000000000004';
  chat constant uuid:=gen_random_uuid();
  device constant uuid:=gen_random_uuid();
  recipient_endpoint constant text:='https://fcm.googleapis.com/fcm/send/incoming-test';
  outgoing uuid;
  item record;
begin
  if has_function_privilege('anon','public.st_v6_claim_incoming_call_push(uuid,uuid,uuid)','execute')
    or has_function_privilege('authenticated','public.st_v6_claim_incoming_call_push(uuid,uuid,uuid)','execute')
    or not has_function_privilege('service_role','public.st_v6_claim_incoming_call_push(uuid,uuid,uuid)','execute') then
    raise exception 'Unexpected incoming-call claim permissions';
  end if;
  insert into public.st_chats(id,member_a,member_b,requester,status) values(chat,sender,recipient,sender,'accepted');
  if not public.st_v6_push_subscription(recipient,recipient_session,'save',recipient_endpoint,repeat('A',87),repeat('A',22)) then
    raise exception 'Could not prepare a recipient subscription';
  end if;
  perform set_config('request.jwt.claim.sub',sender::text,true);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',sender,'session_id',sender_session)::text,true);
  perform public.st_send(chat,gen_random_uuid(),'preceding message fixture');
  outgoing:=public.st_v6_start_call(chat,true,device);
  if exists(select 1 from public.st_v6_claim_incoming_call_push(outgoing,recipient,recipient_session))
    or exists(select 1 from public.st_v6_claim_incoming_call_push(outgoing,outsider,outsider_session))
    or exists(select 1 from public.st_v6_claim_incoming_call_push(outgoing,sender,other_sender_session)) then
    raise exception 'Unauthorized call claim yielded a recipient subscription';
  end if;
  select * into item from public.st_v6_claim_incoming_call_push(outgoing,sender,sender_session);
  if item.endpoint is distinct from recipient_endpoint or item.terminal is not null
    or item.ttl not between 1 and 30
    or exists(select 1 from public.st_v6_claim_incoming_call_push(outgoing,sender,sender_session))
    or not exists(select 1 from sectalk_private.st_v6_push_jobs where kind='dm.message' and attempts=0) then
    raise exception 'Call push must be timely, recipient-only, single-lease, and independent of message backlog';
  end if;
  perform public.st_v6_finish_web_push(item.job,item.lease,'sent');
  perform public.st_v6_call_action(outgoing,'end',device);
  outgoing:=public.st_v6_start_call(chat,false,device);
  perform set_config('request.jwt.claim.sub',recipient::text,true);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',recipient,'session_id',recipient_session)::text,true);
  perform public.st_v6_set_notification_preference('call',false);
  select * into item from public.st_v6_claim_incoming_call_push(outgoing,sender,sender_session);
  if item.terminal is distinct from 'discard' or item.endpoint is not null or item.p256dh is not null or item.auth_secret is not null then
    raise exception 'Claim did not recheck callee preferences before revealing credentials';
  end if;
  perform public.st_v6_finish_web_push(item.job,item.lease,'discard');
  perform public.st_v6_set_notification_preference('call',true);
  perform set_config('request.jwt.claim.sub',sender::text,true);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',sender,'session_id',sender_session)::text,true);
  perform public.st_v6_call_action(outgoing,'end',device);
  outgoing:=public.st_v6_start_call(chat,false,device);
  perform public.st_v6_call_action(outgoing,'end',device);
  if exists(select 1 from public.st_v6_claim_incoming_call_push(outgoing,sender,sender_session)) then
    raise exception 'Ended call yielded a push lease';
  end if;
end $$;

select 'passed: browser call push is immediate, session-bound, and respects current recipient settings' as result;
rollback;
