begin;

insert into auth.users(id,email,aud,role) values
  ('69100000-0000-4000-8000-000000000001','thread-owner@example.invalid','authenticated','authenticated'),
  ('69100000-0000-4000-8000-000000000002','thread-member@example.invalid','authenticated','authenticated'),
  ('69100000-0000-4000-8000-000000000003','thread-outsider@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('69100000-0000-4000-8000-000000000001','thread_fixture_owner','Thread owner'),
  ('69100000-0000-4000-8000-000000000002','thread_fixture_member','Thread member'),
  ('69100000-0000-4000-8000-000000000003','thread_fixture_outsider','Thread outsider');

set local role authenticated;
do $$
declare
  owner_id constant uuid:='69100000-0000-4000-8000-000000000001';
  member_id constant uuid:='69100000-0000-4000-8000-000000000002';
  outsider_id constant uuid:='69100000-0000-4000-8000-000000000003';
  room constant uuid:=gen_random_uuid();
  root constant uuid:=gen_random_uuid();
  deleted_root constant uuid:=gen_random_uuid();
  reply constant uuid:=gen_random_uuid();
  retained_reply constant uuid:=gen_random_uuid();
  task constant uuid:=gen_random_uuid();
  workspace uuid;
  invite_id uuid;
  original_at timestamptz;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  workspace:=public.st_v2_create_workspace('Thread integrity fixture');
  perform public.st_v2_invite(workspace,'thread_fixture_member');
  perform public.st_v6_room_create(room,workspace,'Thread integrity room','public','blank');

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  select id into invite_id from public.st_v2_invites where workspace_id=workspace and invitee=member_id;
  perform public.st_v2_reply_invite(invite_id,true);
  perform public.st_v6_room_membership(room,'join');
  perform public.st_v6_room_post(room,root,'Sensitive original text');
  perform public.st_v6_room_post(room,deleted_root,'Author-deleted original');
  select created_at into original_at from public.st_v6_room_posts where room_id=room and id=root;
  insert into public.st_v6_thread_follows(room_id,post_id) values(room,root),(room,deleted_root);
  perform public.st_v6_task_create(task,room,null,'Task sourced to parent',root);

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v6_room_post(room,reply,'An existing reply','message',root);
  perform public.st_v6_room_post(room,retained_reply,'Reply on deleted root','message',deleted_root);
  perform public.st_v6_room_settings(room,'pin',root);
  perform public.st_v6_room_membership(room,'role',member_id,'moderator');

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  begin
    perform public.st_v6_room_post_action(room,reply,'redact');
    raise exception 'Moderator redacted an owner post' using errcode='P0004';
  exception when raise_exception then null; end;
  perform public.st_v6_room_post_action(room,root,'edit','Edited topic');
  perform public.st_v6_room_post_action(room,root,'edit','Edited topic');
  if not exists(select 1 from public.st_v6_room_thread_state(room,array[root]) where post_id=root and replies=1
    and following and excerpt='Edited topic')
    or not exists(select 1 from public.st_v6_room_posts where room_id=room and id=root and created_at=original_at and edited_at is not null)
    or public.st_v6_task_source(task)->>'currentText' is distinct from 'Edited topic'
    then raise exception 'Edited topic changed identity, replies, follows or live task source'; end if;
  perform public.st_v6_room_post_action(room,deleted_root,'delete');
  if not exists(select 1 from public.st_v6_room_thread_state(room,array[deleted_root])
    where post_id=deleted_root and replies=1 and following and excerpt='Message removed')
    then raise exception 'Author deletion removed thread identity or exposed the original'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v6_room_post_action(room,root,'redact');
  perform public.st_v6_room_post_action(room,root,'redact');
  if (select count(*) from public.st_v6_room_audit where room_id=room and target=root and action='post.edited')<>1
    or (select count(*) from public.st_v6_room_audit where room_id=room and target=root and action='post.redacted')<>1
    or exists(select 1 from public.st_v6_room_pins where room_id=room and post_id=root)
    then raise exception 'Retry duplicated audit events or redaction retained the existing pin'; end if;
  begin
    perform public.st_v6_room_settings(room,'pin',root);
    raise exception 'A redacted root could be pinned' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if not exists(select 1 from public.st_v6_room_thread_state(room,array[root])
    where post_id=root and replies=1 and following and excerpt='Message removed')
    or not exists(select 1 from public.st_v6_room_posts where room_id=room and id=reply and parent_id=root)
    or exists(select 1 from public.st_v6_room_posts where room_id=room and body in ('Sensitive original text','Edited topic'))
    or public.st_v6_task_source(task) is distinct from '{"available":false}'::jsonb
    or not exists(select 1 from public.st_v6_tasks where id=task)
    then raise exception 'Redaction drifted the thread or exposed the task source'; end if;
  begin
    perform public.st_v6_room_post_action(room,root,'edit','Restore removed text');
    raise exception 'A redacted root could be restored through edit' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_task_create(gen_random_uuid(),room,null,'Task from removed message',root);
    raise exception 'A removed root could be used as a new task source' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',outsider_id,'role','authenticated')::text,true);
  begin
    perform public.st_v6_room_post_action(room,root,'redact');
    raise exception 'An outside account redacted a room post' using errcode='P0004';
  exception when raise_exception then null; end;
  if exists(select 1 from public.st_v6_room_thread_state(room,array[root]))
    then raise exception 'An outside account could read the tombstoned thread'; end if;
end $$;

reset role;
select 'passed: thread edits, deletion and redaction retain replies and follows, scrub task sources and enforce authorization' as result;
rollback;
