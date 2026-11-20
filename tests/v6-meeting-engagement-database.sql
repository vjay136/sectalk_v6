begin;

insert into auth.users(id,email,aud,role) values
  ('64400000-0000-4000-8000-000000000001','hand-host@example.invalid','authenticated','authenticated'),
  ('64400000-0000-4000-8000-000000000002','hand-attendee@example.invalid','authenticated','authenticated'),
  ('64400000-0000-4000-8000-000000000003','hand-waiting@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('64400000-0000-4000-8000-000000000001','engagement_host','Hand host'),
  ('64400000-0000-4000-8000-000000000002','engagement_attendee','Hand guest'),
  ('64400000-0000-4000-8000-000000000003','engagement_waiting','Hand waiting');

set local role authenticated;
do $$
declare
  host constant uuid:='64400000-0000-4000-8000-000000000001';
  attendee constant uuid:='64400000-0000-4000-8000-000000000002';
  waiting constant uuid:='64400000-0000-4000-8000-000000000003';
  meeting constant uuid:='64400000-0001-4000-8000-000000000001';
  another constant uuid:='64400000-0001-4000-8000-000000000002';
  space uuid;
  started timestamptz;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',host,'role','authenticated')::text,true);
  space:=public.st_v2_create_workspace('Hand checks');
  perform public.st_v2_invite(space,'engagement_attendee');
  perform public.st_v2_invite(space,'engagement_waiting');
  perform public.st_v6_start_instant_meeting(meeting,space,'Hand meeting',15);
  perform public.st_v6_start_instant_meeting(another,space,'Other meeting',15);
  perform public.st_v6_set_meeting_hand(another,true);

  perform set_config('request.jwt.claims',json_build_object('sub',attendee,'role','authenticated')::text,true);
  perform public.st_v2_reply_invite((select id from public.st_v2_invites where workspace_id=space and invitee=attendee),true);
  perform public.st_v3_request_admission(meeting);
  perform set_config('request.jwt.claims',json_build_object('sub',waiting,'role','authenticated')::text,true);
  perform public.st_v2_reply_invite((select id from public.st_v2_invites where workspace_id=space and invitee=waiting),true);
  perform public.st_v3_request_admission(meeting);
  begin
    perform public.st_v6_set_meeting_hand(meeting,true);
    raise exception 'Waiting member raised a hand';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',host,'role','authenticated')::text,true);
  perform public.st_v3_admit(meeting,attendee,true);
  perform set_config('request.jwt.claims',json_build_object('sub',attendee,'role','authenticated')::text,true);
  perform public.st_v6_set_meeting_hand(meeting,true);
  select raised_at into started from public.st_v6_meeting_hands where meeting_id=meeting and user_id=attendee;
  perform public.st_v6_set_meeting_hand(meeting,true);
  if started is null or started is distinct from (select raised_at from public.st_v6_meeting_hands where meeting_id=meeting and user_id=attendee)
    or exists(select 1 from public.st_v6_meeting_hands where meeting_id=another) then
    raise exception 'Hand queue order or isolation failed';
  end if;
  begin
    perform public.st_v6_send_meeting_reaction(meeting,'unsupported');
    raise exception 'Unsupported reaction was accepted';
  exception when invalid_parameter_value then null; end;
  perform public.st_v6_send_meeting_reaction(meeting,'clap');
  perform public.st_v6_send_meeting_reaction(meeting,'heart');

  perform set_config('request.jwt.claims',json_build_object('sub',waiting,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_meeting_hands) or exists(select 1 from public.st_v6_meeting_reactions)
    then raise exception 'Waiting member saw participation'; end if;
  begin
    perform public.st_v6_send_meeting_reaction(meeting,'clap');
    raise exception 'Waiting member reacted';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',host,'role','authenticated')::text,true);
  if (select count(*) from public.st_v6_meeting_reactions where meeting_id=meeting and user_id=attendee)<>1
    or not exists(select 1 from public.st_v6_meeting_reactions where meeting_id=meeting and reaction='heart'
      and expires_at-reacted_at=interval '8 seconds') then raise exception 'Reaction storage was not bounded'; end if;
end $$;
reset role;

update public.st_v6_meeting_reactions
set reacted_at=statement_timestamp()-interval '9 seconds',expires_at=statement_timestamp()-interval '1 second'
where meeting_id='64400000-0001-4000-8000-000000000001';
set local role authenticated;
do $$
declare
  host constant uuid:='64400000-0000-4000-8000-000000000001';
  attendee constant uuid:='64400000-0000-4000-8000-000000000002';
  meeting constant uuid:='64400000-0001-4000-8000-000000000001';
begin
  perform set_config('request.jwt.claims',json_build_object('sub',host,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_meeting_reactions where meeting_id=meeting) then raise exception 'Expired reaction was readable'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',attendee,'role','authenticated')::text,true);
  perform public.st_v3_leave(meeting);
  perform public.st_v3_request_admission(meeting);
  perform set_config('request.jwt.claims',json_build_object('sub',host,'role','authenticated')::text,true);
  perform public.st_v3_admit(meeting,attendee,true);
  if exists(select 1 from public.st_v6_meeting_hands where meeting_id=meeting and user_id=attendee)
    then raise exception 'Readmission restored the old hand state'; end if;
  perform public.st_v3_meeting_state(meeting,'ended');
  begin
    perform public.st_v6_set_meeting_hand(meeting,true);
    raise exception 'Ended meeting accepted interaction';
  exception when insufficient_privilege then null; end;
end $$;
reset role;
select 'passed: admitted-only meeting gestures, durable hand order, expiration, and leave/readmission isolation' as result;
rollback;
