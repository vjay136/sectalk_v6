begin;

insert into auth.users(id,email) values
  ('7a000000-0000-4000-8000-000000000001','category-sender@example.invalid'),
  ('7a000000-0000-4000-8000-000000000002','category-recipient@example.invalid'),
  ('7a000000-0000-4000-8000-000000000003','category-outsider@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('7a000000-0000-4000-8000-000000000001','category_sender','Sender'),
  ('7a000000-0000-4000-8000-000000000002','category_recipient','Recipient'),
  ('7a000000-0000-4000-8000-000000000003','category_outsider','Outsider');

do $$
<<fixture>>
declare
  sender constant uuid:='7a000000-0000-4000-8000-000000000001';
  recipient constant uuid:='7a000000-0000-4000-8000-000000000002';
  outsider constant uuid:='7a000000-0000-4000-8000-000000000003';
  chat constant uuid:=gen_random_uuid();
  room constant uuid:=gen_random_uuid();
  admin_room constant uuid:=gen_random_uuid();
  root constant uuid:=gen_random_uuid();
  task constant uuid:=gen_random_uuid();
  report constant uuid:=gen_random_uuid();
  workspace uuid;
  preference text;
  enabled boolean;
  alert_summary jsonb;
begin
  if has_function_privilege('anon','public.st_v6_notification_preferences()','execute')
    or has_function_privilege('anon','public.st_v6_set_notification_preference(text,boolean)','execute')
    or has_function_privilege('authenticated','sectalk_private.st_v6_deliver_account_alert(uuid,text,boolean,uuid)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v6_notification_preferences','select,insert,update,delete') then
    raise exception 'Notification preference grants are too broad';
  end if;

  insert into public.st_chats(id,member_a,member_b,requester,status)
  values(chat,sender,recipient,sender,'accepted');
  perform set_config('request.jwt.claim.sub',sender::text,true);
  workspace:=public.st_v2_create_workspace('Notification preference workspace');
  insert into public.st_v2_members(workspace_id,user_id,role)
    values(workspace,recipient,'admin'),(workspace,outsider,'member');
  perform public.st_v6_room_create(room,workspace,'Shared room','public','blank');
  perform public.st_v6_room_create(admin_room,workspace,'Admin room','admin','blank');
  perform public.st_v6_room_post(room,root,'Thread root');
  insert into public.st_v6_room_members(room_id,user_id,role)
    values(room,recipient,'member'),(room,outsider,'member');
  insert into public.st_v6_thread_follows(room_id,post_id,user_id) values(room,root,recipient);
  insert into public.st_v6_tasks(id,chat_id,author_id,title) values(task,chat,sender,'A task');
  insert into public.st_reports(id,reporter,subject,chat_id,category,details)
    values(report,recipient,sender,chat,'other','A report');

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',recipient::text,true);
  if public.st_v6_notification_preferences() is distinct from
    '{"dm":true,"mention":true,"thread":true,"task":true,"call":true,"security":true,"billing":true,"admin":true}'::jsonb then
    raise exception 'Unexpected notification defaults';
  end if;
  begin
    perform public.st_v6_set_notification_preference('invalid',true);
    raise exception 'An unknown category was accepted' using errcode='P0100';
  exception when sqlstate 'P0001' then null; end;
  perform public.st_v6_set_notification_preference('dm',false);
  if not public.st_v6_direct_alert_quiet(chat,'dm') or public.st_v6_direct_alert_quiet(chat,'call') then
    raise exception 'DM preference affected the call category';
  end if;
  perform public.st_v6_set_notification_preference('dm',true);
  perform public.st_v6_set_notification_preference('call',false);
  if public.st_v6_direct_alert_quiet(chat,'dm') or not public.st_v6_direct_alert_quiet(chat,'call') then
    raise exception 'Call preference affected the DM category';
  end if;
  perform set_config('request.jwt.claim.sub',outsider::text,true);
  if public.st_v6_notification_preferences()->'call'<>'true'::jsonb
    or not public.st_v6_direct_alert_quiet(chat,'dm') then
    raise exception 'A user could see another account preference or another chat alert decision';
  end if;
  reset role;

  foreach enabled in array array[false,true] loop
    perform set_config('request.jwt.claim.sub',recipient::text,true);
    foreach preference in array array['mention','thread','task','security','billing','admin'] loop
      perform public.st_v6_set_notification_preference(preference,enabled);
    end loop;
    perform set_config('request.jwt.claim.sub',sender::text,true);
    perform public.st_v6_room_post(room,gen_random_uuid(),'Hi @category_recipient');
    perform public.st_v6_room_post(room,gen_random_uuid(),'Thread reply',p_parent=>root);
    perform public.st_v6_room_post(admin_room,gen_random_uuid(),'Admin update');
    insert into public.st_v6_task_notices(recipient,task_id,kind,due_at)
      values(recipient,task,'due',case when enabled then now() else now()+interval '1 day' end);
    update public.st_reports set status=case when enabled then 'resolved' else 'reviewing' end where id=report;
    insert into public.st_v2_subscriptions(user_id,plan,status)
      values(recipient,'basic',case when enabled then 'active' else 'trialing' end)
      on conflict (user_id) do update set status=excluded.status;
    if not enabled then
      perform set_config('request.jwt.claim.sub',recipient::text,true);
      perform public.st_v6_set_quiet_mute(null,true);
      insert into public.st_v5_account_notices(user_id,action) values(recipient,'warn');
      perform public.st_v6_set_quiet_mute(null,false);
    end if;
  end loop;

  perform set_config('request.jwt.claim.sub',recipient::text,true);
  perform public.st_v6_set_quiet_mute(null,true);
  perform set_config('request.jwt.claim.sub',sender::text,true);
  perform public.st_v6_room_post(room,gen_random_uuid(),'Quiet @category_recipient');
  insert into public.st_v6_task_notices(recipient,task_id,kind,due_at)
    values(recipient,task,'due',now()+interval '2 days');
  update public.st_reports set status='dismissed' where id=report;

  select jsonb_object_agg(kind,frequency) into alert_summary
  from (select payload->>'kind' as kind,count(*) as frequency from realtime.messages
    where event='category_alert' and topic='st:account:'||recipient and private group by 1) alerts;
  if alert_summary is distinct from
    '{"thread.reply":1,"task.due":1,"security.report":1,"security.account":1,"billing.subscription":1,"admin.room":1}'::jsonb then
    raise exception 'Unexpected category alerts: %',alert_summary;
  end if;
  if (select count(*) from realtime.messages where event='room_activity' and private
      and topic='st:account:'||recipient and payload->>'mention_kind'='mention.user'
      and payload->>'priority'='high')<>1
    or (select count(*) from public.st_v3_notifications where room_id=room and st_v3_notifications.recipient=fixture.recipient)<>2
    or (select count(*) from public.st_v6_task_notices where task_id=task)<>3
    or exists(select 1 from realtime.messages where event='category_alert' and topic='st:account:'||outsider)
    or exists(select 1 from realtime.messages where event='category_alert' and topic='st:account:'||recipient
      and (not private or payload-'id'-'kind'-'priority'-'receipt_id'<>'{}'::jsonb
        or (payload ? 'receipt_id') is distinct from (payload->>'kind'='admin.room')
        or payload->>'priority' is distinct from case payload->>'kind'
          when 'security.account' then 'critical' when 'task.due' then 'high' else 'normal' end)) then
    raise exception 'Incorrect mention delivery, durable notices, recipients, payloads or priorities';
  end if;
end $$;

select 'passed: notification preferences, delivery, durable records, isolation and critical bypass' as result;
rollback;
