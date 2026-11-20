begin;

insert into auth.users(id,email,aud,role) values
 ('30000000-0000-4000-8000-000000000001','st-v3-owner@example.invalid','authenticated','authenticated'),
 ('30000000-0000-4000-8000-000000000002','st-v3-member@example.invalid','authenticated','authenticated'),
 ('30000000-0000-4000-8000-000000000003','st-v3-outside@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
 ('30000000-0000-4000-8000-000000000001','sectalk_v3_owner','v3 owner'),
 ('30000000-0000-4000-8000-000000000002','sectalk_v3_member','v3 member'),
 ('30000000-0000-4000-8000-000000000003','sectalk_v3_outside','v3 outside');

set local role authenticated;
do $$
declare
  owner_id constant uuid:='30000000-0000-4000-8000-000000000001';
  member_id constant uuid:='30000000-0000-4000-8000-000000000002';
  outside_id constant uuid:='30000000-0000-4000-8000-000000000003';
  meeting_id constant uuid:=gen_random_uuid();
  object_name constant text:=owner_id::text||'/'||gen_random_uuid()::text||'.stvault';
  space uuid;
  invite uuid;
  chat uuid;
  channel uuid;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  space:=public.st_v2_create_workspace('v3 scope test');
  perform public.st_v2_invite(space,'sectalk_v3_member');
  select id into invite from public.st_v2_invites where workspace_id=space and invitee=member_id;
  chat:=public.st_request('sectalk_v3_member');
  channel:=public.st_v2_create_channel(space,'release-tests');
  perform public.st_v2_post(channel,gen_random_uuid(),'fixture_nebula_v3');
  perform public.st_v2_add_item(space,'task','fixture_nebula_v3','',null);
  perform public.st_v3_set_presence('online');
  insert into storage.objects(bucket_id,name) values('sectalk-vault',object_name);
  if not exists(select 1 from storage.objects where bucket_id='sectalk-vault' and name=object_name)
    then raise exception 'Owner cannot access own vault object'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  perform public.st_v2_reply_invite(invite,true);
  perform public.st_respond(chat,true);
  if not exists(select 1 from public.st_v3_presence where user_id=owner_id)
    then raise exception 'Accepted contact cannot see opted-in presence'; end if;
  if exists(select 1 from storage.objects where bucket_id='sectalk-vault' and name=object_name)
    then raise exception 'Contact accessed another user vault'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_send(chat,gen_random_uuid(),'fixture_nebula_v3');
  perform public.st_v3_schedule(space,'fixture_nebula_v3','Agenda',now(),now()+interval '1 hour',meeting_id);
  perform public.st_v3_schedule(space,'fixture_nebula_v3','Agenda',now(),now()+interval '1 hour',meeting_id);

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if (select count(*) from public.st_v3_search('fixture_nebula_v3',null))<>4
    then raise exception 'Search did not return all four permitted sources'; end if;
  if public.st_v3_request_admission(meeting_id) is distinct from 'waiting' or public.st_v3_media_access(meeting_id)
    then raise exception 'Waiting-room gate failed'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v3_meeting_state(meeting_id,'live');
  perform public.st_v3_admit(meeting_id,member_id,true);
  if (select count(*) from public.st_v3_attendance where status='admitted')<>2
    then raise exception 'Host admission did not update roster'; end if;
  if exists(select 1 from public.st_v3_notifications where recipient=member_id)
    then raise exception 'Host accessed a member notification'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if not public.st_v3_media_access(meeting_id) then raise exception 'Admitted member lacks media access'; end if;
  if (select count(*) from public.st_v3_notifications where read_at is null)<>2
    then raise exception 'Meeting schedule/admission notifications missing or duplicated'; end if;
  perform public.st_v3_mark_notification(null);
  if exists(select 1 from public.st_v3_notifications where read_at is null)
    then raise exception 'Bulk read failed'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',outside_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v3_meetings where id=meeting_id)
    or exists(select 1 from public.st_v3_attendance)
    or exists(select 1 from public.st_v3_notifications)
    or exists(select 1 from public.st_v3_presence where user_id=owner_id)
    or exists(select 1 from public.st_v3_search('fixture_nebula_v3',null))
    or public.st_v3_media_access(meeting_id)
    then raise exception 'Outside account accessed scoped data'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v3_meeting_state(meeting_id,'ended');
  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if public.st_v3_media_access(meeting_id) then raise exception 'Ended meeting still issues access'; end if;
end $$;
reset role;
select 'passed: meeting admission, tenant isolation, presence, search, notifications, vault access' as result;
rollback;
