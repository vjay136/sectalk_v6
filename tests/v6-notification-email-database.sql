begin;

insert into auth.users(id,email,email_confirmed_at) values
  ('7f000000-0000-4000-8000-000000000001','email-owner@example.invalid',now()),
  ('7f000000-0000-4000-8000-000000000002','email-recipient@example.invalid',now()),
  ('7f000000-0000-4000-8000-000000000003','email-unverified@example.invalid',null);
insert into public.st_profiles(id,handle,name) values
  ('7f000000-0000-4000-8000-000000000001','email_owner','Owner'),
  ('7f000000-0000-4000-8000-000000000002','email_recipient','Recipient'),
  ('7f000000-0000-4000-8000-000000000003','email_unverified','Unverified');

do $$
declare
  owner_id constant uuid:='7f000000-0000-4000-8000-000000000001';
  recipient_id constant uuid:='7f000000-0000-4000-8000-000000000002';
  unverified_id constant uuid:='7f000000-0000-4000-8000-000000000003';
  room constant uuid:=gen_random_uuid();
  chat constant uuid:=gen_random_uuid();
  post constant uuid:=gen_random_uuid();
  task constant uuid:=gen_random_uuid();
  workspace uuid;
  delivery record;
begin
  if has_function_privilege('authenticated','public.st_v6_claim_notification_email()','execute')
    or has_function_privilege('authenticated','public.st_v6_unsubscribe_notification_email(uuid)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v6_notification_email','select,insert,update,delete') then
    raise exception 'Email recipients or unsubscribe credentials are exposed';
  end if;
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  workspace:=public.st_v2_create_workspace('Email notification workspace');
  perform public.st_v6_room_create(room,workspace,'Email private room','private','blank');
  insert into public.st_v2_members(workspace_id,user_id) values(workspace,recipient_id);
  insert into public.st_v6_room_members(room_id,user_id,role) values(room,recipient_id,'member');
  insert into public.st_chats(id,member_a,member_b,requester,status) values(chat,owner_id,recipient_id,owner_id,'accepted');
  insert into public.st_v6_tasks(id,room_id,author_id,title) values(task,room,owner_id,'Private task details');

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',unverified_id::text,true);
  begin
    perform public.st_v6_set_notification_email(true,'daily',array['mention']);
    raise exception 'An unverified address was subscribed' using errcode='P0100';
  exception when sqlstate 'P0001' then null; end;
  perform set_config('request.jwt.claim.sub',recipient_id::text,true);
  if public.st_v6_notification_email_settings()->>'enabled' is distinct from 'false' then
    raise exception 'Email notifications default to opted in';
  end if;
  perform public.st_v6_set_notification_email(true,'daily',array['call','task','mention']);
  reset role;
  if exists(select 1 from public.st_v6_claim_notification_email() job where job.recipient=recipient_id) then
    raise exception 'A daily digest was claimable before its scheduled time';
  end if;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform public.st_v6_room_post(room,post,'Confidential @email_recipient');
  update public.st_v3_notifications set created_at=now()-interval '2 minutes' where room_post_id=post;
  insert into public.st_v6_task_notices(recipient,task_id,kind,due_at,created_at)
    values(recipient_id,task,'due',now(),now()-interval '1 minute');
  insert into public.st_calls(chat_id,caller,callee,status,video,created_at,expires_at)
    values(chat,owner_id,recipient_id,'ringing',false,now()-interval '6 minutes',now()-interval '5 minutes');
  update sectalk_private.st_v6_notification_email set scanned_at=now()-interval '1 hour',next_at=now()
    where recipient=recipient_id;
  select * into delivery from public.st_v6_claim_notification_email() job where job.recipient=recipient_id;
  if delivery.email is distinct from 'email-recipient@example.invalid' or delivery.cadence<>'daily'
    or (delivery.mentions,delivery.tasks,delivery.calls) is distinct from (1::bigint,1::bigint,1::bigint)
    or exists(select 1 from public.st_v6_claim_notification_email() job where job.recipient=recipient_id) then
    raise exception 'Digest counts, recipient, or lease were incorrect';
  end if;
  perform public.st_v6_unsubscribe_notification_email(gen_random_uuid());
  if not public.st_v6_confirm_notification_email(delivery.recipient,delivery.lease) then
    raise exception 'An invalid unsubscribe key affected an existing job';
  end if;
  perform public.st_v6_finish_notification_email(delivery.recipient,delivery.lease,false);
  update sectalk_private.st_v6_notification_email set next_at=now() where recipient=recipient_id;
  select * into delivery from public.st_v6_claim_notification_email() job where job.recipient=recipient_id;
  if delivery.email is null then raise exception 'A transient delivery failure did not retry'; end if;
  perform public.st_v6_finish_notification_email(delivery.recipient,delivery.lease,true);
  update sectalk_private.st_v6_notification_email set next_at=now() where recipient=recipient_id;
  if exists(select 1 from public.st_v6_claim_notification_email() job where job.recipient=recipient_id) then
    raise exception 'A delivered window was sent again';
  end if;

  perform set_config('request.jwt.claim.sub',recipient_id::text,true);
  perform public.st_v6_set_notification_email(true,'weekly',array['mention']);
  perform public.st_v6_unsubscribe_notification_email(delivery.unsubscribe_key);
  if public.st_v6_notification_email_settings()->>'enabled' is distinct from 'true' then
    raise exception 'An old link changed renewed consent';
  end if;
  update auth.users set email='changed-recipient@example.invalid' where id=recipient_id;
  update sectalk_private.st_v6_notification_email set next_at=now() where recipient=recipient_id;
  if exists(select 1 from public.st_v6_claim_notification_email() job where job.recipient=recipient_id)
    or public.st_v6_notification_email_settings()->>'enabled' is distinct from 'false' then
    raise exception 'Consent transferred to a different address';
  end if;
end $$;

select 'passed: email opt-in, category counts, cadence, lease, renewal, verified address and unsubscribe isolation' as result;
rollback;
