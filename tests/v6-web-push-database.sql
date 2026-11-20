begin;

insert into auth.users(id,email) values
  ('7d000000-0000-4000-8000-000000000001','push-sender@example.invalid'),
  ('7d000000-0000-4000-8000-000000000002','push-recipient@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('7d000000-0000-4000-8000-000000000001','web_push_sender','Sender'),
  ('7d000000-0000-4000-8000-000000000002','web_push_recipient','Recipient');
insert into auth.sessions(id,user_id) values
  ('7d100000-0000-4000-8000-000000000001','7d000000-0000-4000-8000-000000000001'),
  ('7d100000-0000-4000-8000-000000000002','7d000000-0000-4000-8000-000000000002');

do $$
declare
  sender constant uuid:='7d000000-0000-4000-8000-000000000001';
  recipient constant uuid:='7d000000-0000-4000-8000-000000000002';
  sender_session constant uuid:='7d100000-0000-4000-8000-000000000001';
  recipient_session constant uuid:='7d100000-0000-4000-8000-000000000002';
  chat constant uuid:=gen_random_uuid();
  sender_endpoint constant text:='https://fcm.googleapis.com/fcm/send/sender-test';
  recipient_endpoint constant text:='https://fcm.googleapis.com/fcm/send/recipient-test';
  item record;
begin
  if has_function_privilege('authenticated','public.st_v6_claim_web_push()','execute')
    or has_function_privilege('authenticated','public.st_v6_push_subscription(uuid,uuid,text,text,text,text)','execute')
    or has_table_privilege('service_role','sectalk_private.st_v6_push_subscriptions','select') then
    raise exception 'Browser subscriptions or dispatch credentials are exposed';
  end if;
  insert into public.st_chats(id,member_a,member_b,requester,status) values(chat,sender,recipient,sender,'accepted');
  if not public.st_v6_push_subscription(sender,sender_session,'save',sender_endpoint,repeat('A',87),repeat('A',22))
    or not public.st_v6_push_subscription(recipient,recipient_session,'save',recipient_endpoint,repeat('A',87),repeat('A',22))
    or public.st_v6_push_subscription(sender,recipient_session,'save',recipient_endpoint,repeat('B',87),repeat('B',22))
    or public.st_v6_push_subscription(sender,sender_session,'save',recipient_endpoint,repeat('B',87),repeat('B',22)) then
    raise exception 'Subscription identity is not bound to its original session';
  end if;
  perform set_config('request.jwt.claim.sub',sender::text,true);
  perform public.st_send(chat,gen_random_uuid(),'sensitive body fixture');
  select * into item from public.st_v6_claim_web_push();
  if item.endpoint is distinct from recipient_endpoint or item.p256dh is distinct from repeat('A',87)
    or exists(select 1 from public.st_v6_claim_web_push()) then
    raise exception 'Dispatch leaked an endpoint or accepted a concurrent duplicate claim';
  end if;
  perform public.st_v6_finish_web_push(item.job,item.lease,'retry');
  if not exists(select 1 from sectalk_private.st_v6_push_jobs where id=item.job and attempts=1 and lease_id is null) then
    raise exception 'Transient failures were not rescheduled';
  end if;
  update sectalk_private.st_v6_push_jobs set next_attempt_at=now() where id=item.job;
  perform set_config('request.jwt.claim.sub',recipient::text,true);
  perform public.st_v6_set_notification_preference('dm',false);
  select * into item from public.st_v6_claim_web_push();
  if item.job is null or item.endpoint is not null or item.p256dh is not null or item.auth_secret is not null then
    raise exception 'A preference change did not suppress already queued alerts';
  end if;
  perform public.st_v6_finish_web_push(item.job,item.lease,'discard');
  perform public.st_v6_set_quiet_mute(null,true);
  perform set_config('request.jwt.claim.sub',sender::text,true);
  perform public.st_send(chat,gen_random_uuid(),'optional alert content');
  if exists(select 1 from public.st_v6_claim_web_push()) then
    raise exception 'A muted optional alert was queued';
  end if;

  insert into public.st_v5_account_notices(user_id,action) values(recipient,'warn');
  select * into item from public.st_v6_claim_web_push();
  if item.endpoint is distinct from recipient_endpoint then raise exception 'Missing opted-in critical account alert'; end if;
  perform public.st_v6_finish_web_push(item.job,item.lease,'gone');
  if public.st_v6_push_subscription(recipient,recipient_session,'status') then
    raise exception 'Gone provider subscription remained usable';
  end if;
  perform public.st_v6_push_subscription(recipient,recipient_session,'save',recipient_endpoint,repeat('A',87),repeat('A',22));
  insert into public.st_v5_account_notices(user_id,action) values(recipient,'restore');
  delete from auth.sessions where id=recipient_session;
  if exists(select 1 from public.st_v6_claim_web_push() q where q.endpoint is not null) then
    raise exception 'Session revocation retained a dispatchable notification';
  end if;
end $$;

select 'passed: recipient-only, preference-aware Web Push and session-revocation cleanup' as result;
rollback;
