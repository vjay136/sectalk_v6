begin;

insert into auth.users(id,email,aud,role) values
  ('67000000-0000-4000-8000-000000000001','series-owner@example.invalid','authenticated','authenticated'),
  ('67000000-0000-4000-8000-000000000002','series-guest@example.invalid','authenticated','authenticated'),
  ('67000000-0000-4000-8000-000000000003','series-outsider@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('67000000-0000-4000-8000-000000000001','series_owner','Host'),
  ('67000000-0000-4000-8000-000000000002','series_guest','Guest'),
  ('67000000-0000-4000-8000-000000000003','series_outside','Outside');
insert into public.st_v2_workspaces(id,name,owner) values
  ('67000000-0001-4000-8000-000000000001','Series fixture','67000000-0000-4000-8000-000000000001');
insert into public.st_v2_members(workspace_id,user_id,role) values
  ('67000000-0001-4000-8000-000000000001','67000000-0000-4000-8000-000000000001','owner'),
  ('67000000-0001-4000-8000-000000000001','67000000-0000-4000-8000-000000000002','member');

set local role authenticated;
do $$
declare
  owner_id constant uuid:='67000000-0000-4000-8000-000000000001';
  attendee constant uuid:='67000000-0000-4000-8000-000000000002';
  outsider constant uuid:='67000000-0000-4000-8000-000000000003';
  series constant uuid:='67000000-0002-4000-8000-000000000001';
  space constant uuid:='67000000-0001-4000-8000-000000000001';
  zone constant text:='America/New_York';
  base timestamp:=date_trunc('day',now() at time zone zone)+interval '10 hours';
  transition timestamp;
  first_start timestamptz;
begin
  select min(d.day_at) into transition from generate_series(1,335) n
    cross join lateral (select base+make_interval(days=>n) as day_at) d
    where (((d.day_at+interval '1 day') at time zone zone)-(d.day_at at time zone zone))<>interval '24 hours';
  if transition is null then raise exception 'Could not find a daylight transition for the fixture'; end if;
  first_start:=transition at time zone zone;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  if public.st_v6_schedule_series(space,series,'Recurring fixture','Agenda',first_start,first_start+interval '1 hour','daily',3,zone)
    is distinct from series then raise exception 'Series creation returned an unexpected ID'; end if;
  perform public.st_v6_schedule_series(space,series,'Recurring fixture','Agenda',first_start,first_start+interval '1 hour','daily',3,zone);
  if (select count(*) from public.st_v3_meetings m where m.series_id=series and
      m.starts_at at time zone zone=transition+make_interval(days=>m.series_index-1)
      and m.ends_at-m.starts_at=interval '1 hour')<>3 then raise exception 'Series lost local time or duplicated'; end if;
  begin
    perform public.st_v6_schedule_series(space,series,'Different meeting','Agenda',first_start,first_start+interval '1 hour','daily',3,zone);
    raise exception 'Series ID conflict was accepted' using errcode='P0004';
  exception when raise_exception then null; end;
  if (select count(*) from public.st_v2_workspace_audit where workspace_id=space and event='meeting.series_scheduled')<>1
    then raise exception 'Series creation was not audited once'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',attendee,'role','authenticated')::text,true);
  if (select count(*) from public.st_v3_notifications where meeting_id=series and kind='meeting.scheduled')<>1
    then raise exception 'The member did not receive one series notification'; end if;
  begin
    perform public.st_v6_schedule_series(space,gen_random_uuid(),'Unauthorised','',first_start,first_start+interval '1 hour','weekly',2,zone);
    raise exception 'A regular member scheduled a series' using errcode='P0004';
  exception when raise_exception then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',outsider,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v3_meetings m where m.series_id=series)
    then raise exception 'Outsider could read meeting series through a join ID'; end if;
end $$;
reset role;
select 'passed: day and timezone recurrence, idempotent retries, notifications, host authorization and join-link isolation' as result;
rollback;
