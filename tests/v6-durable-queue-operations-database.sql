begin;

insert into auth.users(id,email,email_confirmed_at) values
  ('7f200000-0000-4000-8000-000000000001','queue-sender@example.invalid',now()),
  ('7f200000-0000-4000-8000-000000000002','queue-recipient@example.invalid',now()),
  ('7f200000-0000-4000-8000-000000000003','queue-other@example.invalid',now()),
  ('7f200000-0000-4000-8000-000000000004','queue-operator@example.invalid',now());
insert into public.st_profiles(id,handle,name) values
  ('7f200000-0000-4000-8000-000000000001','queue_test_sender','Sender'),
  ('7f200000-0000-4000-8000-000000000002','queue_test_peer','Recipient'),
  ('7f200000-0000-4000-8000-000000000003','queue_test_other','Other'),
  ('7f200000-0000-4000-8000-000000000004','queue_test_operator','Operator');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
  ('7f220000-0000-4000-8000-000000000004','7f200000-0000-4000-8000-000000000004','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
  ('7f210000-0000-4000-8000-000000000002','7f200000-0000-4000-8000-000000000002','aal1',null),
  ('7f210000-0000-4000-8000-000000000003','7f200000-0000-4000-8000-000000000003','aal1',null),
  ('7f210000-0000-4000-8000-000000000004','7f200000-0000-4000-8000-000000000004','aal2','7f220000-0000-4000-8000-000000000004');
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
  ('7f230000-0000-4000-8000-000000000004','7f210000-0000-4000-8000-000000000004','totp',now(),now()-interval '15 minutes');
insert into sectalk_private.staff(user_id) values
  ('7f200000-0000-4000-8000-000000000004'),('7f200000-0000-4000-8000-000000000003');
insert into sectalk_private.st_v6_queue_operators(account_id) values ('7f200000-0000-4000-8000-000000000004');

do $$
declare
  sender_id constant uuid:='7f200000-0000-4000-8000-000000000001';
  recipient_id constant uuid:='7f200000-0000-4000-8000-000000000002';
  other_id constant uuid:='7f200000-0000-4000-8000-000000000003';
  operator_id constant uuid:='7f200000-0000-4000-8000-000000000004';
  recipient_session constant uuid:='7f210000-0000-4000-8000-000000000002';
  other_session constant uuid:='7f210000-0000-4000-8000-000000000003';
  operator_session constant uuid:='7f210000-0000-4000-8000-000000000004';
  endpoint_a constant text:='https://fcm.googleapis.com/fcm/send/ordered-queue-a';
  endpoint_b constant text:='https://fcm.googleapis.com/fcm/send/ordered-queue-b';
  chat_a constant uuid:=gen_random_uuid();
  chat_b constant uuid:=gen_random_uuid();
  first_message constant uuid:=gen_random_uuid();
  second_message constant uuid:=gen_random_uuid();
  task constant uuid:=gen_random_uuid();
  acquisition constant uuid:=gen_random_uuid();
  first_event uuid;
  second_event uuid;
  email_event uuid;
  failed uuid;
  email_failed uuid;
  pending record;
  other_count integer:=0;
  ordered_count integer:=0;
  scan_after_failure timestamptz;
begin
  if has_function_privilege('authenticated','public.st_v6_claim_web_push(uuid)','execute')
    or has_function_privilege('authenticated','public.st_v6_claim_notification_email(uuid)','execute')
    or has_function_privilege('anon','public.st_v6_replay_queue_dead_letter(uuid)','execute') then
    raise exception 'Queue worker claims or replay are too broadly exposed';
  end if;
  insert into public.st_chats(id,member_a,member_b,requester,status) values
    (chat_a,sender_id,recipient_id,sender_id,'accepted'),(chat_b,sender_id,other_id,sender_id,'accepted');
  perform public.st_v6_push_subscription(recipient_id,recipient_session,'save',endpoint_a,repeat('A',87),repeat('A',22));
  perform public.st_v6_push_subscription(other_id,other_session,'save',endpoint_b,repeat('B',87),repeat('B',22));
  perform set_config('request.jwt.claim.sub',sender_id::text,true);
  perform public.st_send(chat_a,first_message,'Confidential first message');
  perform public.st_send(chat_a,second_message,'Confidential second message');
  perform public.st_send(chat_b,gen_random_uuid(),'Confidential separate ordering key');
  select id into first_event from sectalk_private.st_v6_notification_delivery_events where event_key='dm:'||first_message;
  select id into second_event from sectalk_private.st_v6_notification_delivery_events where event_key='dm:'||second_message;
  for pending in
    select claim.*,q.event_id from public.st_v6_claim_web_push(acquisition) claim
    join sectalk_private.st_v6_push_jobs q on q.id=claim.job where claim.endpoint in (endpoint_a,endpoint_b)
  loop
    if pending.endpoint=endpoint_a then
      if pending.event_id is distinct from first_event then raise exception 'Later event overtook its ordering key'; end if;
      ordered_count:=ordered_count+1;
      perform public.st_v6_finish_web_push(pending.job,pending.lease,'retry');
    else
      other_count:=other_count+1;
      perform public.st_v6_finish_web_push(pending.job,pending.lease,'sent');
    end if;
  end loop;
  if ordered_count<>1 or other_count<>1
    or exists(select 1 from public.st_v6_claim_web_push() claim where claim.endpoint=endpoint_a) then
    raise exception 'A retry failed to block its key or blocked an independent key';
  end if;
  update sectalk_private.st_v6_push_jobs set next_attempt_at=now() where event_id=first_event;
  if exists(select 1 from public.st_v6_claim_web_push(acquisition) claim where claim.endpoint=endpoint_a) then
    raise exception 'A duplicate consumer acquisition claimed a second batch';
  end if;
  select claim.* into pending from public.st_v6_claim_web_push() claim where claim.endpoint=endpoint_a;
  perform public.st_v6_finish_web_push(pending.job,pending.lease,'expired');
  select id into failed from sectalk_private.st_v6_notification_dead_letters where job_id=pending.job;
  select claim.*,q.event_id into pending from public.st_v6_claim_web_push() claim
    join sectalk_private.st_v6_push_jobs q on q.id=claim.job where claim.endpoint=endpoint_a;
  if pending.event_id is distinct from second_event then raise exception 'Second event did not follow terminal delivery'; end if;
  perform public.st_v6_finish_web_push(pending.job,pending.lease,'sent');

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',other_id::text,true);
  if public.st_v6_queue_operations_status()<>'none' then raise exception 'Ordinary staff gained queue operations'; end if;
  perform set_config('request.jwt.claim.sub',operator_id::text,true);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',operator_id,'aal','aal2','session_id',operator_session)::text,true);
  begin
    perform public.st_v6_replay_queue_dead_letter(failed);
    raise exception 'Stale MFA authorized replay' using errcode='P0100';
  exception when sqlstate '42501' then null; end;
  reset role;
  update auth.mfa_amr_claims set updated_at=now() where session_id=operator_session;
  perform set_config('request.jwt.claim.sub',recipient_id::text,true);
  perform public.st_v6_set_notification_preference('dm',false);
  set local role authenticated;
  perform set_config('request.jwt.claim.sub',operator_id::text,true);
  if public.st_v6_queue_operations_status()<>'verified'
    or not exists(select 1 from public.st_v6_queue_dead_letters() entry where entry.id=failed and not entry.replayable) then
    raise exception 'Fresh role or eligibility was not enforced';
  end if;
  begin
    perform public.st_v6_replay_queue_dead_letter(failed);
    raise exception 'A revoked preference allowed replay' using errcode='P0100';
  exception when sqlstate 'P0001' then null; end;
  perform set_config('request.jwt.claim.sub',recipient_id::text,true);
  perform public.st_v6_set_notification_preference('dm',true);
  reset role;
  insert into public.st_v5_hidden_messages(message_id,user_id) values(first_message,recipient_id);
  set local role authenticated;
  perform set_config('request.jwt.claim.sub',operator_id::text,true);
  begin
    perform public.st_v6_replay_queue_dead_letter(failed);
    raise exception 'A hidden source still allowed replay' using errcode='P0100';
  exception when sqlstate 'P0001' then null; end;
  reset role;
  delete from public.st_v5_hidden_messages where message_id=first_message and user_id=recipient_id;
  set local role authenticated;
  perform public.st_v6_replay_queue_dead_letter(failed);
  reset role;
  select claim.* into pending from public.st_v6_claim_web_push() claim where claim.endpoint=endpoint_a;
  perform public.st_v6_finish_web_push(pending.job,pending.lease,'sent');
  if not exists(select 1 from sectalk_private.st_v6_queue_replays where event_id=first_event and actor=operator_id)
    or (select state from sectalk_private.st_v6_notification_delivery_events where id=first_event)<>'sent' then
    raise exception 'Replayed browser delivery did not enter the existing worker or audit ledger';
  end if;
  set local role authenticated;
  begin
    perform public.st_v6_replay_queue_dead_letter(failed);
    raise exception 'A terminal success could be replayed' using errcode='P0100';
  exception when sqlstate 'P0001' then null; end;
  reset role;

  perform public.st_v6_push_subscription(recipient_id,recipient_session,'delete',endpoint_a);
  perform set_config('request.jwt.claim.sub',recipient_id::text,true);
  perform public.st_v6_set_notification_email(true,'prompt',array['task']);
  insert into public.st_v6_tasks(id,chat_id,author_id,title) values(task,chat_a,sender_id,'Private task');
  insert into public.st_v6_task_notices(recipient,task_id,kind,due_at,created_at)
    values(recipient_id,task,'due',now(),now()-interval '1 minute');
  update sectalk_private.st_v6_notification_email set scanned_at=now()-interval '1 hour' where recipient=recipient_id;
  select * into pending from public.st_v6_claim_notification_email(acquisition) claim where claim.recipient=recipient_id;
  email_event:=pending.delivery_id;
  if email_event is null then raise exception 'A browser worker key interfered with the email worker'; end if;
  for retry in 1..3 loop
    perform public.st_v6_finish_notification_email(recipient_id,pending.lease,'retry');
    if retry<3 then
      update sectalk_private.st_v6_notification_email set next_at=now() where recipient=recipient_id;
      if exists(select 1 from public.st_v6_claim_notification_email(acquisition) claim where claim.recipient=recipient_id) then
        raise exception 'A repeated email worker claim consumed another lease';
      end if;
      select * into pending from public.st_v6_claim_notification_email() claim where claim.recipient=recipient_id;
    end if;
  end loop;
  select l.id into email_failed from sectalk_private.st_v6_notification_dead_letters l where l.email_event_id=email_event;
  update sectalk_private.st_v6_notification_email set scanned_at=now()+interval '1 minute' where recipient=recipient_id
    returning scanned_at into scan_after_failure;
  set local role authenticated;
  perform set_config('request.jwt.claim.sub',operator_id::text,true);
  perform public.st_v6_replay_queue_dead_letter(email_failed);
  reset role;
  select * into pending from public.st_v6_claim_notification_email() claim where claim.recipient=recipient_id;
  if pending.delivery_id is distinct from email_event or pending.tasks<>1 then
    raise exception 'Email replay did not reuse its scoped original window';
  end if;
  perform public.st_v6_finish_notification_email(recipient_id,pending.lease,'sent');
  if (select scanned_at from sectalk_private.st_v6_notification_email where recipient=recipient_id) is distinct from scan_after_failure then
    raise exception 'An older email replay rewound the live scanner';
  end if;
end $$;

select 'passed: ordered channel workers, acquisition idempotency, fresh MFA, safe replay and no terminal success replay' as result;
rollback;
