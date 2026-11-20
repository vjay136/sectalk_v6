begin;
insert into auth.users(id,email,aud,role) values
 ('62000000-0000-4000-8000-000000000001','task-owner@example.invalid','authenticated','authenticated'),
 ('62000000-0000-4000-8000-000000000002','task-member@example.invalid','authenticated','authenticated'),
 ('62000000-0000-4000-8000-000000000003','task-outside@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
 ('62000000-0000-4000-8000-000000000001','task_fixture_owner','Task owner'),
 ('62000000-0000-4000-8000-000000000002','task_fixture_member','Task member'),
 ('62000000-0000-4000-8000-000000000003','task_fixture_outside','Task outsider');
set local role authenticated;
do $$
declare
  actor constant uuid:='62000000-0000-4000-8000-000000000001';
  member_id constant uuid:='62000000-0000-4000-8000-000000000002';
  outsider constant uuid:='62000000-0000-4000-8000-000000000003';
  room constant uuid:=gen_random_uuid();
  room_task constant uuid:=gen_random_uuid();
  chat_task constant uuid:=gen_random_uuid();
  standalone_chat_task constant uuid:=gen_random_uuid();
  msg constant uuid:=gen_random_uuid();
  room_post constant uuid:=gen_random_uuid();
  chat uuid;
  workspace uuid;
  invitation uuid;
  latest_event bigint;
  snapshot jsonb;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',actor,'role','authenticated')::text,true);
  workspace:=public.st_v2_create_workspace('Scoped task fixture');
  perform public.st_v2_invite(workspace,'task_fixture_member');
  perform public.st_v6_room_create(room,workspace,'Private tasks','private','project');
  perform public.st_v6_room_post(room,room_post,'Room source');
  perform public.st_v6_task_create(room_task,room,null,'Private room task',p_due_at=>now()+interval '1 hour');
  chat:=public.st_request('task_fixture_member');

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  select id into invitation from public.st_v2_invites where invitee=member_id;
  perform public.st_v2_reply_invite(invitation,true);
  perform public.st_respond(chat,true);
  if exists(select 1 from public.st_v6_tasks where id=room_task) then raise exception 'Workspace member saw private room task'; end if;
  perform public.st_v6_room_membership(room,'request');

  perform set_config('request.jwt.claims',json_build_object('sub',actor,'role','authenticated')::text,true);
  perform public.st_v6_room_membership(room,'approve',member_id);
  perform public.st_v6_task_create(standalone_chat_task,null,chat,'Standalone direct task');
  if not exists(select 1 from public.st_v6_tasks where id=standalone_chat_task and chat_id=chat)
    or public.st_v6_task_source(standalone_chat_task) is not null
    then raise exception 'Standalone direct task did not retain its scope'; end if;
  perform public.st_v6_task_create(gen_random_uuid(),room,null,'Task from room post',room_post);
  perform public.st_send(chat,msg,'Original message body');
  perform public.st_v6_task_create(chat_task,null,chat,'Direct task',msg,now()-interval '1 minute','high',array['Review','review']);
  perform public.st_v6_task_create(chat_task,null,chat,'Direct task',msg,now()-interval '1 minute','high',array['review']);
  if (select count(*) from public.st_v6_task_audit where task_id=chat_task)<>1 then raise exception 'Creation retry duplicated the audit event'; end if;
  if not exists(select 1 from public.st_v6_tasks where id=chat_task and labels=array['review'] and due_at<now())
    then raise exception 'Task metadata was not retained'; end if;
  perform public.st_v2_edit_message(msg,'Updated source message');
  snapshot:=public.st_v6_task_source(chat_task);
  if snapshot->>'snapshot' is distinct from 'Original message body' or snapshot->>'currentText' is distinct from 'Updated source message'
    then raise exception 'Original snapshot or live reference was incorrect'; end if;
  begin
    perform public.st_v6_task_create(gen_random_uuid(),room,null,'Cross-scope task',msg);
    raise exception 'Direct source crossed a room boundary' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_task_update(chat_task,'assign',p_person=>outsider,p_enabled=>true);
    raise exception 'Outsider received task assignment' using errcode='P0004';
  exception when raise_exception then null; end;
  perform public.st_v6_task_update(chat_task,'assign',p_person=>actor,p_enabled=>true);
  perform public.st_v6_task_update(chat_task,'assign',p_person=>member_id,p_enabled=>true);
  if (select count(*) from public.st_v6_task_people where task_id=chat_task and kind='assignee')<>2
    then raise exception 'Multiple assignees were not retained'; end if;
  perform public.st_v6_task_update(chat_task,'watch',p_enabled=>true);

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if not exists(select 1 from public.st_v6_tasks where id=room_task) then raise exception 'Approved room member cannot see task'; end if;
  if exists(select 1 from public.st_v6_task_people where task_id=chat_task and kind='watcher') then raise exception 'Private watcher list leaked'; end if;
  perform public.st_v6_task_update(chat_task,'status','in_progress');
  perform public.st_v6_task_update(chat_task,'status','blocked');
  perform public.st_v6_task_update(chat_task,'status','done');
  perform public.st_v6_task_update(chat_task,'status','done');
  if exists(select 1 from public.st_v6_task_notices where task_id=chat_task) then raise exception 'Other recipient notice leaked'; end if;
  begin
    perform public.st_v6_task_update(chat_task,'status','todo');
    raise exception 'Assignee reopened a terminal task' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',actor,'role','authenticated')::text,true);
  select id into latest_event from public.st_v6_task_notices where task_id=chat_task and kind='completed';
  if latest_event is null or (select count(*) from public.st_v6_task_notices where task_id=chat_task)<>1
    then raise exception 'Task completion notice missing or duplicated'; end if;
  perform public.st_v6_task_notice_read(latest_event);
  if not exists(select 1 from public.st_v6_task_notices where id=latest_event and read_at is not null)
    then raise exception 'Read receipt was not saved'; end if;
  perform public.st_v6_task_update(chat_task,'status','todo');
  perform public.st_v6_task_update(chat_task,'status','cancelled');
  perform public.st_v5_message_action(msg,'revoke');
  snapshot:=public.st_v6_task_source(chat_task);
  if snapshot is distinct from '{"available":false}'::jsonb
    or not exists(select 1 from public.st_v6_tasks where id=chat_task and status='cancelled')
    then raise exception 'Revoke broke the task or exposed the snapshot'; end if;
  if not exists(select 1 from public.st_v6_task_audit where task_id=chat_task and action='status' and detail->>'to'='done')
    then raise exception 'Missing task completion audit event'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',outsider,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_tasks) or exists(select 1 from public.st_v6_task_audit)
    or exists(select 1 from public.st_v6_task_people) or exists(select 1 from public.st_v6_task_notices)
    then raise exception 'Outsider read task data'; end if;
end $$;
reset role;
delete from public.st_v6_room_posts where body='Room source' and sender='62000000-0000-4000-8000-000000000001';
select sectalk_private.st_v6_task_send_reminders();
select sectalk_private.st_v6_task_send_reminders();
set local role authenticated;
do $$
begin
  perform set_config('request.jwt.claims',json_build_object(
    'sub','62000000-0000-4000-8000-000000000001','role','authenticated')::text,true);
  if not exists(select 1 from public.st_v6_tasks t where t.title='Task from room post'
    and public.st_v6_task_source(t.id)='{"available":false}'::jsonb)
    then raise exception 'Hard-deleted source broke the room task or exposed its snapshot'; end if;
  if (select count(*) from public.st_v6_task_notices n join public.st_v6_tasks t on t.id=n.task_id
      where n.kind='due' and t.title='Private room task')<>1 then raise exception 'Deadline reminder unavailable or duplicated'; end if;
  perform set_config('request.jwt.claims',json_build_object(
    'sub','62000000-0000-4000-8000-000000000002','role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_task_notices n join public.st_v6_tasks t on t.id=n.task_id
      where n.kind='due' and t.title='Private room task') then raise exception 'Deadline reminder leaked to another room participant'; end if;
end $$;
reset role;
select 'passed: scoped tasks, source edits and revoke, labels, multi-assign, private watchers, audited status, notices and reminders' as result;
rollback;
