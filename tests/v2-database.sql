begin;

insert into auth.users(id,email,aud,role) values
 ('20000000-0000-4000-8000-000000000001','st-v2-owner@example.invalid','authenticated','authenticated'),
 ('20000000-0000-4000-8000-000000000002','st-v2-member@example.invalid','authenticated','authenticated'),
 ('20000000-0000-4000-8000-000000000003','st-v2-unrelated@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
 ('20000000-0000-4000-8000-000000000001','sectalk_v2_owner','Workspace owner'),
 ('20000000-0000-4000-8000-000000000002','sectalk_v2_member','Workspace tester'),
 ('20000000-0000-4000-8000-000000000003','sectalk_v2_other','Unrelated tester');

set local role authenticated;
do $$
declare owner_id uuid:='20000000-0000-4000-8000-000000000001';
        member_id uuid:='20000000-0000-4000-8000-000000000002';
        other_id uuid:='20000000-0000-4000-8000-000000000003';
        space uuid; channel uuid; invite uuid; task uuid; chat uuid; test_message uuid:=gen_random_uuid(); test_reply uuid:=gen_random_uuid();
        refused boolean:=false;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated','aal','aal1')::text,true);
  space:=public.st_v2_create_workspace('Scope test');
  if (select count(*) from public.st_v2_workspaces where id=space)<>1 then raise exception 'Owner cannot read workspace'; end if;
  begin perform public.st_v2_create_workspace('Second free workspace'); exception when raise_exception then refused:=true; end;
  if not refused then raise exception 'Free workspace cap did not apply'; end if;
  if not public.st_v2_invite(space,'sectalk_v2_member') then raise exception 'Invitation failed'; end if;
  select id into invite from public.st_v2_invites where workspace_id=space and invitee=member_id;
  channel:=public.st_v2_create_channel(space,'project-updates');
  perform public.st_v2_post(channel,gen_random_uuid(),'Workspace policy test');
  task:=public.st_v2_add_item(space,'task','Check role access','',null);
  chat:=public.st_request('sectalk_v2_member');

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated','aal','aal1')::text,true);
  if exists(select 1 from public.st_v2_channels where id=channel) then raise exception 'Pending invite exposed channel'; end if;
  if public.st_v2_reply_invite(invite,true) is distinct from space then raise exception 'Accepting invite failed'; end if;
  if not exists(select 1 from public.st_v2_posts where channel_id=channel) then raise exception 'Member cannot read post'; end if;
  perform public.st_v2_complete_task(task,true);
  if not exists(select 1 from public.st_v2_items where id=task and completed) then raise exception 'Could not complete task'; end if;
  refused:=false;
  begin perform public.st_v2_set_member(space,owner_id,'remove'); exception when raise_exception then refused:=true; end;
  if not refused then raise exception 'Member changed workspace roles'; end if;
  perform public.st_respond(chat,true);

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated','aal','aal1')::text,true);
  perform public.st_send(chat,test_message,'First version');
  perform public.st_v2_edit_message(test_message,'Revised body');
  if (select count(*) from public.st_v2_search_messages(chat,'Revised'))<>1 then raise exception 'Search did not find edit'; end if;
  perform public.st_v2_pin(chat,test_message);
  perform public.st_v2_set_member(space,member_id,'remove');

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated','aal','aal1')::text,true);
  if exists(select 1 from public.st_v2_posts where channel_id=channel) then raise exception 'Removed member retained access'; end if;
  if not exists(select 1 from public.st_v2_message_edits where st_v2_message_edits.message_id=test_message and body='First version') then raise exception 'Edit history missing'; end if;
  perform public.st_v2_react(test_message,'✅',true);
  if not exists(select 1 from public.st_v2_inbox_status() where chat_id=chat and unread) then raise exception 'Unread chat marker missing'; end if;
  perform public.st_v2_read(chat,test_message);
  if exists(select 1 from public.st_v2_inbox_status() where chat_id=chat and unread) then raise exception 'Read cursor did not clear unread marker'; end if;
  perform public.st_v2_send_reply(chat,test_reply,'Reply from the member',test_message);
  perform public.st_v2_send_reply(chat,test_reply,'Reply from the member',test_message);
  if (select count(*) from public.st_messages where id=test_reply and reply_to=test_message)<>1 then raise exception 'Reply idempotency failed'; end if;
  perform public.st_v2_typing(chat,true);
  perform public.st_v2_mute(chat,true);

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated','aal','aal1')::text,true);
  if (public.st_v2_chat_status(chat)->>'read_id') is distinct from test_message::text then raise exception 'Read receipt missing'; end if;
  if (public.st_v2_chat_status(chat)->>'typing_until') is null then raise exception 'Typing state missing'; end if;
  if exists(select 1 from public.st_v2_chat_state where user_id=member_id) then raise exception 'Private mute exposed'; end if;
  if not exists(select 1 from public.st_v2_pins where chat_id=chat) then raise exception 'Pin missing'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',other_id,'role','authenticated','aal','aal1')::text,true);
  if exists(select 1 from public.st_v2_posts where channel_id=channel) or exists(select 1 from public.st_v2_search_messages(chat,'Revised')) then
    raise exception 'Unrelated account could read scoped content';
  end if;
  if has_function_privilege('authenticated','public.st_v2_sync_billing(text,uuid,text,text,text,text,timestamptz,boolean,timestamptz)','execute')
    or has_function_privilege('authenticated','public.st_v2_reserve_checkout(uuid,text)','execute') then raise exception 'Client can write billing state'; end if;
end $$;
reset role;
set local role service_role;
select public.st_v2_sync_billing('evt_v2_fixture','20000000-0000-4000-8000-000000000001','cus_v2_fixture','sub_v2_fixture','basic','active',now()+interval '1 day',false,now());
select public.st_v2_sync_billing('evt_v2_fixture','20000000-0000-4000-8000-000000000001','cus_v2_fixture','sub_v2_fixture','business','active',now()+interval '1 day',false,now());
reset role;
do $$
begin
  if (select plan from public.st_v2_subscriptions where user_id='20000000-0000-4000-8000-000000000001') is distinct from 'basic'
    then raise exception 'Billing update was not idempotent'; end if;
end $$;
select 'passed: consent, tenant isolation, roles, workspace limits, chat controls, billing isolation and event replay' as result;
rollback;
