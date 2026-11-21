begin;

insert into auth.users(id,email) values
  ('7c000000-0000-4000-8000-000000000001','notify-policy-owner@example.invalid'),
  ('7c000000-0000-4000-8000-000000000002','notify-policy-admin@example.invalid'),
  ('7c000000-0000-4000-8000-000000000003','notify-policy-other@example.invalid'),
  ('7c000000-0000-4000-8000-000000000004','notify-policy-member@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('7c000000-0000-4000-8000-000000000001','notify_policy_owner','Owner'),
  ('7c000000-0000-4000-8000-000000000002','notify_policy_admin','Admin'),
  ('7c000000-0000-4000-8000-000000000003','notify_policy_other','Other owner'),
  ('7c000000-0000-4000-8000-000000000004','notify_policy_member','Member');

do $$
<<fixture>>
declare
  owner_id constant uuid:='7c000000-0000-4000-8000-000000000001';
  admin_id constant uuid:='7c000000-0000-4000-8000-000000000002';
  other_id constant uuid:='7c000000-0000-4000-8000-000000000003';
  member_id constant uuid:='7c000000-0000-4000-8000-000000000004';
  room_id constant uuid:=gen_random_uuid();
  admin_room constant uuid:=gen_random_uuid();
  other_room constant uuid:=gen_random_uuid();
  thread_root constant uuid:=gen_random_uuid();
  task_id constant uuid:=gen_random_uuid();
  chat_id constant uuid:=gen_random_uuid();
  workspace uuid;
  other_workspace uuid;
  channel uuid;
  other_channel uuid;
  alert_counts jsonb;
begin
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  workspace:=public.st_v2_create_workspace('Workspace notification policy');
  perform public.st_v6_room_create(room_id,workspace,'Members room','public','blank');
  perform public.st_v6_room_create(admin_room,workspace,'Admin room','admin','blank');
  perform public.st_v6_room_post(room_id,thread_root,'Follow this thread');
  perform set_config('request.jwt.claim.sub',other_id::text,true);
  other_workspace:=public.st_v2_create_workspace('Other notification policy');
  perform public.st_v6_room_create(other_room,other_workspace,'Other room','public','blank');
  select id into channel from public.st_v2_channels where workspace_id=workspace and name='general';
  select id into other_channel from public.st_v2_channels where workspace_id=other_workspace and name='general';
  insert into public.st_v2_members(workspace_id,user_id,role) values
    (workspace,admin_id,'admin'),(workspace,member_id,'member'),(other_workspace,admin_id,'member');
  insert into public.st_v6_room_members(room_id,user_id,role) values
    (room_id,admin_id,'member'),(other_room,admin_id,'member');
  insert into public.st_v6_thread_follows(room_id,post_id,user_id) values(room_id,thread_root,admin_id);
  insert into public.st_v6_tasks(id,room_id,author_id,title) values(task_id,room_id,owner_id,'Required task');
  insert into public.st_chats(id,member_a,member_b,requester,status)
    values(chat_id,owner_id,admin_id,owner_id,'accepted');

  if has_function_privilege('anon','public.st_v6_set_workspace_notification_policy(uuid,text[],integer)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v6_workspace_notification_policy','select,insert,update,delete') then
    raise exception 'Policy grants are too broad';
  end if;
  set local role authenticated;
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  if public.st_v6_workspace_notification_settings(workspace)->'mandatory_categories' is distinct from '[]'::jsonb
    then raise exception 'Default policy is incorrect'; end if;
  begin
    perform public.st_v6_set_workspace_notification_policy(workspace,array['mention'],60);
    raise exception 'A member changed the workspace policy' using errcode='P0100';
  exception when sqlstate 'P0001' then null; end;
  begin
    perform public.st_v6_workspace_notification_settings(other_workspace);
    raise exception 'An outsider read a workspace policy' using errcode='P0100';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  begin
    perform public.st_v6_set_workspace_notification_policy(workspace,array['dm'],60);
    raise exception 'The workspace changed direct-message policy' using errcode='P0100';
  exception when sqlstate 'P0001' then null; end;
  begin
    perform public.st_v6_set_workspace_notification_policy(workspace,array['mention'],1441);
    raise exception 'An invalid quiet limit was accepted' using errcode='P0100';
  exception when sqlstate 'P0001' then null; end;
  perform public.st_v6_set_workspace_notification_policy(workspace,array['mention','thread','task','admin'],60);
  perform public.st_v6_set_notification_preference('mention',false);
  perform public.st_v6_set_notification_preference('thread',false);
  perform public.st_v6_set_notification_preference('task',false);
  perform public.st_v6_set_notification_preference('admin',false);
  perform public.st_v6_set_quiet_mute(null,true);
  if not public.st_v6_direct_alert_quiet(chat_id,'dm')
    or public.st_v6_workspace_notification_settings(workspace)->>'max_quiet_minutes' is distinct from '60' then
    raise exception 'Policy persistence or direct-message quiet isolation failed';
  end if;
  reset role;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform public.st_v6_room_post(room_id,gen_random_uuid(),'Required @notify_policy_admin');
  perform public.st_v6_room_post(room_id,gen_random_uuid(),'Required thread reply',p_parent=>thread_root);
  perform public.st_v6_room_post(admin_room,gen_random_uuid(),'Admin room post');
  insert into public.st_v6_task_notices(recipient,task_id,kind,due_at) values(admin_id,task_id,'due',now());
  perform public.st_v2_post(channel,gen_random_uuid(),'Quiet window is active');
  perform set_config('request.jwt.claim.sub',other_id::text,true);
  perform public.st_v6_room_post(other_room,gen_random_uuid(),'Still quiet @notify_policy_admin');

  update sectalk_private.st_v6_quiet_rules set mute_started_at=now()-interval '61 minutes'
  where user_id=admin_id and st_v6_quiet_rules.chat_id is null;
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform public.st_v2_post(channel,gen_random_uuid(),'Quiet cap elapsed');
  perform set_config('request.jwt.claim.sub',other_id::text,true);
  perform public.st_v2_post(other_channel,gen_random_uuid(),'No policy here');
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  if not public.st_v6_direct_alert_quiet(chat_id,'dm') then
    raise exception 'Workspace cap shortened direct-message quiet hours';
  end if;

  select jsonb_object_agg(kind,frequency) into alert_counts
  from (select payload->>'kind' as kind,count(*) as frequency from realtime.messages
    where event='category_alert' and topic='st:account:'||admin_id and private group by 1) alerts;
  if alert_counts is distinct from '{"thread.reply":1,"task.due":1,"admin.room":1}'::jsonb
    or (select count(*) from realtime.messages where event='room_activity' and private
      and topic='st:account:'||admin_id and payload->>'mention_kind'='mention.user'
      and payload->>'room_id'=room_id::text)<>1
    or exists(select 1 from realtime.messages where event='room_activity'
      and topic='st:account:'||admin_id and payload->>'room_id'=other_room::text)
    or (select count(*) from realtime.messages where event='channel_activity'
      and topic='st:account:'||admin_id and payload->>'channel_id'=channel::text)<>1
    or exists(select 1 from realtime.messages where event='channel_activity'
      and topic='st:account:'||admin_id and payload->>'channel_id'=other_channel::text) then
    raise exception 'Unexpected workspace alert routing or quiet cap: %',alert_counts;
  end if;

  perform public.st_v6_set_quiet_mute(null,false);
  perform public.st_v6_set_room_quiet(room_id,'snooze',p_minutes=>120);
  if not (public.st_v6_room_quiet_settings(room_id)->>'active')::boolean then
    raise exception 'The quiet limit ended a new snooze immediately';
  end if;
  update sectalk_private.st_v6_room_quiet_rules q set snooze_started_at=now()-interval '61 minutes'
    where q.room_id=fixture.room_id and q.user_id=admin_id;
  perform public.st_v6_set_room_quiet(room_id,'snooze',p_minutes=>180);
  if (public.st_v6_room_quiet_settings(room_id)->>'active')::boolean then
    raise exception 'Extending an active snooze restarted its quiet cap';
  end if;

  if not sectalk_private.st_v6_workspace_quiet_schedule(array[1]::smallint[],time '23:30',time '02:00',
      'UTC','2026-11-17 00:15+00',interval '60 minutes')
    or sectalk_private.st_v6_workspace_quiet_schedule(array[1]::smallint[],time '23:30',time '02:00',
      'UTC','2026-11-17 00:30+00',interval '60 minutes')
    or not sectalk_private.st_v6_workspace_quiet_schedule(array[7]::smallint[],time '01:15',time '04:00',
      'America/New_York','2026-11-01 05:55+00',interval '45 minutes')
    or sectalk_private.st_v6_workspace_quiet_schedule(array[7]::smallint[],time '01:15',time '04:00',
      'America/New_York','2026-11-01 06:20+00',interval '45 minutes') then
    raise exception 'Overnight or daylight-saving schedule cap is incorrect';
  end if;
end $$;

select 'passed: notification policy permissions, tenant isolation, mandatory delivery and quiet caps' as result;
rollback;
