begin;

insert into auth.users(id,email,aud,role) values
  ('65000000-0000-4000-8000-000000000001','instant-owner@example.invalid','authenticated','authenticated'),
  ('65000000-0000-4000-8000-000000000002','instant-admin@example.invalid','authenticated','authenticated'),
  ('65000000-0000-4000-8000-000000000003','instant-member@example.invalid','authenticated','authenticated'),
  ('65000000-0000-4000-8000-000000000004','instant-outsider@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('65000000-0000-4000-8000-000000000001','instant_fixture_owner','Instant owner'),
  ('65000000-0000-4000-8000-000000000002','instant_fixture_admin','Instant admin'),
  ('65000000-0000-4000-8000-000000000003','instant_fixture_member','Instant member'),
  ('65000000-0000-4000-8000-000000000004','instant_fixture_outsider','Instant outsider');
insert into public.st_v2_workspaces(id,name,owner) values
  ('65000000-0001-4000-8000-000000000001','Instant meeting fixture','65000000-0000-4000-8000-000000000001');
insert into public.st_v2_members(workspace_id,user_id,role) values
  ('65000000-0001-4000-8000-000000000001','65000000-0000-4000-8000-000000000001','owner'),
  ('65000000-0001-4000-8000-000000000001','65000000-0000-4000-8000-000000000002','admin'),
  ('65000000-0001-4000-8000-000000000001','65000000-0000-4000-8000-000000000003','member');

set local role authenticated;
do $$
declare
  owner_id constant uuid:='65000000-0000-4000-8000-000000000001';
  admin_id constant uuid:='65000000-0000-4000-8000-000000000002';
  member_id constant uuid:='65000000-0000-4000-8000-000000000003';
  outside_id constant uuid:='65000000-0000-4000-8000-000000000004';
  space constant uuid:='65000000-0001-4000-8000-000000000001';
  instant_id uuid:=gen_random_uuid();
  scheduled_id uuid:=gen_random_uuid();
begin
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  if public.st_v6_start_instant_meeting(instant_id,space,'  ',30) is distinct from instant_id
    or public.st_v6_start_instant_meeting(instant_id,space,'Instant meeting',30) is distinct from instant_id
    then raise exception 'Starting or retrying an instant meeting failed'; end if;
  if not exists(select 1 from public.st_v3_meetings where id=instant_id and is_instant
    and status='live' and host_id=owner_id and title='Instant meeting'
    and starts_at<=clock_timestamp() and ends_at-starts_at=interval '30 minutes')
    or not public.st_v3_media_access(instant_id)
    then raise exception 'Instant meeting did not start with the host admitted'; end if;
  if (select count(*) from public.st_v2_workspace_audit where workspace_id=space and target=instant_id and event='meeting.live')<>1
    then raise exception 'Retry duplicated the live audit event'; end if;
  perform public.st_v3_schedule(space,'Legacy scheduled meeting','',now(),now()+interval '1 hour',scheduled_id);
  if not exists(select 1 from public.st_v3_meetings where id=scheduled_id and not is_instant and status='scheduled')
    then raise exception 'Scheduled meeting behavior changed'; end if;
  begin
    perform public.st_v6_start_instant_meeting(scheduled_id,space,'Legacy scheduled meeting',60);
    raise exception 'Instant retry reused a scheduled meeting ID' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_start_instant_meeting(instant_id,space,'Instant meeting',60);
    raise exception 'A different instant request reused the same meeting ID' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_start_instant_meeting(gen_random_uuid(),space,'Too short',1);
    raise exception 'Instant meeting accepted an invalid duration' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if (select count(*) from public.st_v3_notifications where meeting_id=instant_id and kind='meeting.started')<>1
    then raise exception 'Member did not receive exactly one instant meeting notice'; end if;
  if public.st_v3_request_admission(instant_id) is distinct from 'waiting' or public.st_v3_media_access(instant_id)
    then raise exception 'Instant meeting bypassed its waiting room'; end if;
  begin
    perform public.st_v6_start_instant_meeting(gen_random_uuid(),space,'Member attempt',30);
    raise exception 'Member created an instant meeting' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',outside_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v3_meetings where id=instant_id)
    or exists(select 1 from public.st_v3_notifications where meeting_id=instant_id)
    then raise exception 'Instant meeting leaked across workspaces'; end if;
  begin
    perform public.st_v6_start_instant_meeting(gen_random_uuid(),space,'Outsider attempt',30);
    raise exception 'Outsider created an instant meeting' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v3_meeting_state(instant_id,'ended');
  if public.st_v6_start_instant_meeting(instant_id,space,'Instant meeting',30) is distinct from instant_id
    or exists(select 1 from public.st_v3_meetings where id=instant_id and status<>'ended')
    then raise exception 'Retry reopened an ended meeting'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',admin_id,'role','authenticated')::text,true);
  if public.st_v6_start_instant_meeting(gen_random_uuid(),space,'Admin instant meeting',15) is null
    then raise exception 'Workspace admin could not start an instant meeting'; end if;
end $$;
reset role;

select 'passed: atomic instant start, host admission, waiting room, replay and audit, notifications and workspace authorization' as result;
rollback;
