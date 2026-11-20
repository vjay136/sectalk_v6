begin;

insert into auth.users(id,email,aud,role) values
  ('65000000-0000-4000-8000-000000000001','schedule-sender@example.invalid','authenticated','authenticated'),
  ('65000000-0000-4000-8000-000000000002','schedule-recipient@example.invalid','authenticated','authenticated'),
  ('65000000-0000-4000-8000-000000000003','schedule-other@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('65000000-0000-4000-8000-000000000001','schedule_sender','Scheduled sender'),
  ('65000000-0000-4000-8000-000000000002','schedule_recipient','Scheduled recipient'),
  ('65000000-0000-4000-8000-000000000003','schedule_other','Other recipient');
insert into public.st_chats(id,member_a,member_b,requester,status) values
  ('65000000-0001-4000-8000-000000000001','65000000-0000-4000-8000-000000000001','65000000-0000-4000-8000-000000000002',
    '65000000-0000-4000-8000-000000000001','accepted'),
  ('65000000-0001-4000-8000-000000000002','65000000-0000-4000-8000-000000000001','65000000-0000-4000-8000-000000000003',
    '65000000-0000-4000-8000-000000000001','accepted');

set local role authenticated;
do $$
declare
  sender_id constant uuid:='65000000-0000-4000-8000-000000000001';
  recipient_id constant uuid:='65000000-0000-4000-8000-000000000002';
  other_id constant uuid:='65000000-0000-4000-8000-000000000003';
  chat constant uuid:='65000000-0001-4000-8000-000000000001';
  other_chat constant uuid:='65000000-0001-4000-8000-000000000002';
  scheduled constant uuid:='65000000-0002-4000-8000-000000000001';
  blocked constant uuid:='65000000-0002-4000-8000-000000000002';
  cancelled constant uuid:='65000000-0002-4000-8000-000000000003';
  planned_at constant timestamptz:=now()+interval '1 hour';
begin
  perform set_config('request.jwt.claims',json_build_object('sub',sender_id,'role','authenticated')::text,true);
  if public.st_v6_schedule_message(chat,scheduled,'Future message',planned_at)<>'pending'
    or public.st_v6_schedule_message(chat,scheduled,'Future message',planned_at)<>'pending'
    then raise exception 'Identical retry did not return the queued schedule'; end if;
  perform public.st_v6_schedule_message(other_chat,blocked,'Blocked after scheduling',planned_at);
  perform public.st_v6_schedule_message(chat,cancelled,'Cancelled before delivery',planned_at);
  if public.st_v6_cancel_scheduled_message(cancelled)<>'cancelled'
    or public.st_v6_cancel_scheduled_message(cancelled)<>'cancelled'
    then raise exception 'Cancellation did not remain idempotent'; end if;
  begin
    perform public.st_v6_schedule_message(chat,gen_random_uuid(),'Invalid date',now()-interval '5 minutes');
    raise exception 'Past schedule was accepted' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',recipient_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_scheduled_messages)
    or exists(select 1 from public.st_messages where id=scheduled)
    then raise exception 'Recipient saw unsent message content'; end if;
  begin
    perform public.st_v6_cancel_scheduled_message(scheduled);
    raise exception 'Recipient cancelled a different account schedule' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform sectalk_private.st_v6_dispatch_scheduled_messages();
    raise exception 'Authenticated clients can run the dispatcher' using errcode='P0004';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',other_id,'role','authenticated')::text,true);
  perform public.st_set_block(other_chat,true);
end $$;
reset role;

select sectalk_private.st_v6_dispatch_scheduled_messages();
update public.st_v6_scheduled_messages set send_at=now()-interval '1 second'
where sender='65000000-0000-4000-8000-000000000001';
select sectalk_private.st_v6_dispatch_scheduled_messages();
select sectalk_private.st_v6_dispatch_scheduled_messages();

do $$
begin
  if (select count(*) from public.st_messages where id='65000000-0002-4000-8000-000000000001'
       and body='Future message' and sender='65000000-0000-4000-8000-000000000001')<>1
    or exists(select 1 from public.st_messages where id in
      ('65000000-0002-4000-8000-000000000002','65000000-0002-4000-8000-000000000003'))
    then raise exception 'The dispatcher duplicated a message or ignored current permissions or cancellation'; end if;
  if (select array_agg(state order by id) from public.st_v6_scheduled_messages
      where sender='65000000-0000-4000-8000-000000000001')<>array['sent','failed','cancelled']
    or exists(select 1 from public.st_v6_scheduled_messages
      where sender='65000000-0000-4000-8000-000000000001' and body is not null)
    then raise exception 'Terminal outbox status was incorrect or retained message text'; end if;
end $$;

select 'passed: scheduled message isolation, cancellation, block after scheduling, terminal privacy and one-time delivery' as result;
rollback;
