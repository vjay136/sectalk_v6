begin;

insert into auth.users(id,email) values
  ('7e000000-0000-4000-8000-000000000001','delivery-sender@example.invalid'),
  ('7e000000-0000-4000-8000-000000000002','delivery-recipient@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('7e000000-0000-4000-8000-000000000001','delivery_sender','Sender'),
  ('7e000000-0000-4000-8000-000000000002','delivery_recipient','Recipient');
insert into auth.sessions(id,user_id) values
  ('7e100000-0000-4000-8000-000000000001','7e000000-0000-4000-8000-000000000002'),
  ('7e100000-0000-4000-8000-000000000002','7e000000-0000-4000-8000-000000000002');

do $$
<<fixture>>
declare
  sender constant uuid:='7e000000-0000-4000-8000-000000000001';
  recipient constant uuid:='7e000000-0000-4000-8000-000000000002';
  device_a constant uuid:='7e100000-0000-4000-8000-000000000001';
  device_b constant uuid:='7e100000-0000-4000-8000-000000000002';
  endpoint_a constant text:='https://fcm.googleapis.com/fcm/send/delivery-test-a';
  endpoint_b constant text:='https://fcm.googleapis.com/fcm/send/delivery-test-b';
  chat constant uuid:=gen_random_uuid();
  accepted_message constant uuid:=gen_random_uuid();
  failed_message constant uuid:=gen_random_uuid();
  delivery_id uuid;
  item record;
  delivery record;
  round integer;
begin
  if has_function_privilege('authenticated','public.st_v6_notification_dead_letter_summary()','execute')
    or has_function_privilege('authenticated','public.st_v6_claim_web_push()','execute')
    or has_function_privilege('anon','public.st_v6_notification_fallbacks()','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v6_notification_delivery_events','select,insert,update,delete') then
    raise exception 'The delivery ledger or operator queue is too broadly accessible';
  end if;
  insert into public.st_chats(id,member_a,member_b,requester,status) values(chat,sender,recipient,sender,'accepted');
  perform public.st_v6_push_subscription(recipient,device_a,'save',endpoint_a,repeat('A',87),repeat('A',22));
  perform public.st_v6_push_subscription(recipient,device_b,'save',endpoint_b,repeat('B',87),repeat('B',22));

  perform set_config('request.jwt.claim.sub',sender::text,true);
  perform public.st_send(chat,accepted_message,'private message body');
  perform sectalk_private.st_v6_queue_web_push(recipient,'dm.message',null,chat,null,'dm:'||accepted_message);
  select e.id into delivery_id from sectalk_private.st_v6_notification_delivery_events e where event_key='dm:'||accepted_message;
  if (select count(*) from sectalk_private.st_v6_push_jobs q where q.event_id=delivery_id)<>2 then
    raise exception 'Duplicate source event created more than one delivery per browser';
  end if;
  for item in select * from public.st_v6_claim_web_push() where endpoint in (endpoint_a,endpoint_b) order by endpoint loop
    perform public.st_v6_finish_web_push(item.job,gen_random_uuid(),'sent');
    if exists(select 1 from sectalk_private.st_v6_push_jobs where id=item.job and state<>'pending') then
      raise exception 'A nonmatching lease completed a browser job';
    end if;
    perform public.st_v6_finish_web_push(item.job,item.lease,case when item.endpoint=endpoint_a then 'rejected' else 'sent' end);
  end loop;
  if (select state from sectalk_private.st_v6_notification_delivery_events where id=delivery_id)<>'sent' then
    raise exception 'A successful browser acceptance still produced an in-app fallback';
  end if;
  perform sectalk_private.st_v6_queue_web_push(recipient,'dm.message',null,chat,null,'dm:'||accepted_message);
  if exists(select 1 from public.st_v6_claim_web_push() where endpoint in (endpoint_a,endpoint_b)) then
    raise exception 'A completed event was queued again during its deduplication window';
  end if;

  perform public.st_send(chat,failed_message,'second private body');
  for round in 1..3 loop
    for item in select * from public.st_v6_claim_web_push() where endpoint in (endpoint_a,endpoint_b) loop
      perform public.st_v6_finish_web_push(item.job,item.lease,case when item.endpoint=endpoint_a then 'gone' else 'retry' end);
    end loop;
    update sectalk_private.st_v6_push_jobs set next_attempt_at=now() where state='pending'
      and event_id in (select e.id from sectalk_private.st_v6_notification_delivery_events e where e.recipient=fixture.recipient);
  end loop;
  if (select count(*) from sectalk_private.st_v6_notification_dead_letters l
    join sectalk_private.st_v6_push_jobs q on q.id=l.job_id
    join sectalk_private.st_v6_notification_delivery_events e on e.id=q.event_id
    where e.recipient=fixture.recipient and l.reason in ('subscription_gone','retry_exhausted','provider_rejected'))<>3 then
    raise exception 'Expected classified terminal provider outcomes in the dead-letter ledger';
  end if;

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',recipient::text,true);
  select * into delivery from public.st_v6_notification_fallbacks();
  if delivery.id is null or delivery.kind<>'dm.message' or delivery.read_at is not null then
    raise exception 'All failed browser deliveries did not produce a recipient fallback';
  end if;
  perform set_config('request.jwt.claim.sub',sender::text,true);
  perform public.st_v6_read_notification_fallback(delivery.id);
  if exists(select 1 from public.st_v6_notification_fallbacks()) then
    raise exception 'A sender could inspect a recipient fallback';
  end if;
  perform set_config('request.jwt.claim.sub',recipient::text,true);
  if (select read_at from public.st_v6_notification_fallbacks() where id=delivery.id) is not null then
    raise exception 'Another account marked the fallback as read';
  end if;
  perform public.st_v6_read_notification_fallback(delivery.id);
  if (select read_at from public.st_v6_notification_fallbacks() where id=delivery.id) is null then
    raise exception 'The recipient could not mark their fallback as read';
  end if;
  perform public.st_v6_set_notification_preference('dm',false);
  if exists(select 1 from public.st_v6_notification_fallbacks()) then
    raise exception 'The fallback bypassed an optional category preference';
  end if;

  perform public.st_v6_set_notification_preference('dm',true);
  reset role;
  perform set_config('request.jwt.claim.sub',sender::text,true);
  perform public.st_send(chat,gen_random_uuid(),'Expired delivery');
  update sectalk_private.st_v6_push_jobs set expires_at=now() where state='pending'
    and event_id in (select e.id from sectalk_private.st_v6_notification_delivery_events e where e.recipient=fixture.recipient);
  select c.* into item from public.st_v6_claim_web_push() c
  join sectalk_private.st_v6_push_jobs q on q.id=c.job
  join sectalk_private.st_v6_notification_delivery_events e on e.id=q.event_id where e.recipient=fixture.recipient;
  if item.terminal is distinct from 'expired' or item.endpoint is not null then
    raise exception 'Expired jobs were still available for provider delivery';
  end if;
  perform public.st_v6_finish_web_push(item.job,item.lease,item.terminal);
  if not exists(select 1 from sectalk_private.st_v6_notification_dead_letters where job_id=item.job and reason='expired') then
    raise exception 'Expired delivery did not enter the dead-letter ledger';
  end if;
end $$;

select 'passed: durable deduplication, bounded retry, dead letters, and recipient-only fallback' as result;
rollback;
