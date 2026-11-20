begin;

insert into auth.users(id,email,aud,role) values
  ('64500000-0000-4000-8000-000000000001','collab-host@example.invalid','authenticated','authenticated'),
  ('64500000-0000-4000-8000-000000000002','collab-guest@example.invalid','authenticated','authenticated'),
  ('64500000-0000-4000-8000-000000000003','collab-wait@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('64500000-0000-4000-8000-000000000001','collaboration_host','Meeting host'),
  ('64500000-0000-4000-8000-000000000002','collaboration_guest','Meeting guest'),
  ('64500000-0000-4000-8000-000000000003','collaboration_wait','Waiting member');

set local role authenticated;
do $$
declare
  host constant uuid:='64500000-0000-4000-8000-000000000001';
  attendee constant uuid:='64500000-0000-4000-8000-000000000002';
  waiting constant uuid:='64500000-0000-4000-8000-000000000003';
  meeting constant uuid:='64500000-0001-4000-8000-000000000001';
  another constant uuid:='64500000-0001-4000-8000-000000000002';
  message constant uuid:='64500000-0002-4000-8000-000000000001';
  space uuid;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',host,'role','authenticated')::text,true);
  space:=public.st_v2_create_workspace('Collaboration checks');
  perform public.st_v2_invite(space,'collaboration_guest');
  perform public.st_v2_invite(space,'collaboration_wait');
  perform public.st_v6_start_instant_meeting(meeting,space,'Collaboration meeting',15);
  perform public.st_v6_start_instant_meeting(another,space,'Other collaboration meeting',15);
  perform public.st_v6_send_meeting_chat(another,message,'Private separate meeting');
  perform public.st_v6_send_meeting_chat(meeting,message,' Welcome ');

  perform set_config('request.jwt.claims',json_build_object('sub',waiting,'role','authenticated')::text,true);
  perform public.st_v2_reply_invite((select id from public.st_v2_invites where workspace_id=space and invitee=waiting),true);
  perform public.st_v3_request_admission(meeting);
  if exists(select 1 from public.st_v6_meeting_chat) or exists(select 1 from public.st_v6_meeting_controls)
    then raise exception 'Waiting user read in-call information'; end if;
  begin
    perform public.st_v6_meeting_roster(meeting);
    raise exception 'Waiting user read roster';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_send_meeting_chat(meeting,gen_random_uuid(),'before admission');
    raise exception 'Waiting user sent chat';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',attendee,'role','authenticated')::text,true);
  perform public.st_v2_reply_invite((select id from public.st_v2_invites where workspace_id=space and invitee=attendee),true);
  perform public.st_v3_request_admission(meeting);
  perform set_config('request.jwt.claims',json_build_object('sub',host,'role','authenticated')::text,true);
  perform public.st_v3_admit(meeting,attendee,true);
  begin
    perform public.st_v6_set_meeting_spotlight(meeting,waiting);
    raise exception 'Host spotlighted a waiting user';
  exception when invalid_parameter_value then null; end;
  perform public.st_v6_set_meeting_spotlight(meeting,attendee);

  perform set_config('request.jwt.claims',json_build_object('sub',attendee,'role','authenticated')::text,true);
  if (select count(*) from public.st_v6_meeting_roster(meeting))<>2 or
    not exists(select 1 from public.st_v6_meeting_roster(meeting) where user_id=host and is_host and name='Meeting host')
    then raise exception 'Admitted roster was inaccurate'; end if;
  if (select count(*) from public.st_v6_meeting_chat)<>1 or not exists(
    select 1 from public.st_v6_meeting_chat where body='Welcome' and user_id=host and author_name='Meeting host'
  ) then raise exception 'Shared chat body, sender or isolation failed'; end if;
  if not exists(select 1 from public.st_v6_meeting_controls where meeting_id=meeting and spotlight=attendee)
    or exists(select 1 from public.st_v6_meeting_controls where meeting_id=another)
    then raise exception 'Shared spotlight visibility or isolation failed'; end if;
  begin
    perform public.st_v6_set_meeting_spotlight(meeting,host);
    raise exception 'Attendee changed the room spotlight';
  exception when insufficient_privilege then null; end;
  begin
    update public.st_v6_meeting_controls set spotlight=null where meeting_id=meeting;
    raise exception 'Attendee directly updated controls';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_send_meeting_chat(meeting,message,'Forged replacement');
    raise exception 'Attendee took over a host message identifier';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_v6_send_meeting_chat(meeting,gen_random_uuid(),repeat('x',1001));
    raise exception 'Oversized chat passed validation';
  exception when invalid_parameter_value then null; end;
  perform public.st_v6_send_meeting_chat(meeting,gen_random_uuid(),'Message from guest');
  perform public.st_v3_leave(meeting);
  if exists(select 1 from public.st_v6_meeting_chat) or exists(select 1 from public.st_v6_meeting_controls)
    then raise exception 'Departed user retained chat or control access'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',host,'role','authenticated')::text,true);
  if not exists(select 1 from public.st_v6_meeting_controls where meeting_id=meeting and spotlight is null)
    or (select count(*) from public.st_v6_meeting_roster(meeting))<>1
    then raise exception 'Departure did not remove the attendee and spotlight'; end if;
  perform public.st_v6_send_meeting_chat(meeting,message,'Welcome');
  if (select count(*) from public.st_v6_meeting_chat where meeting_id=meeting)<>2
    then raise exception 'Snapped author chat or idempotent resend failed'; end if;
  perform public.st_v3_meeting_state(meeting,'ended');
  if exists(select 1 from public.st_v6_meeting_chat where meeting_id=meeting)
    then raise exception 'Ended meeting chat was readable'; end if;
end $$;
reset role;

select 'passed: admitted roster and chat, author and meeting isolation, write permissions, and spotlight lifecycle' as result;
rollback;
