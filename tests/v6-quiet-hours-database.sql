begin;

insert into auth.users(id,email,aud,role) values
  ('660a0000-0000-4000-8000-000000000001','quiet-owner@example.invalid','authenticated','authenticated'),
  ('660a0000-0000-4000-8000-000000000002','quiet-peer@example.invalid','authenticated','authenticated'),
  ('660a0000-0000-4000-8000-000000000003','quiet-other@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('660a0000-0000-4000-8000-000000000001','quiet_owner','Quiet owner'),
  ('660a0000-0000-4000-8000-000000000002','quiet_peer','Quiet peer'),
  ('660a0000-0000-4000-8000-000000000003','quiet_other','Quiet other');
insert into public.st_chats(id,member_a,member_b,requester,status) values
  ('660a0000-0001-4000-8000-000000000001','660a0000-0000-4000-8000-000000000001',
    '660a0000-0000-4000-8000-000000000002','660a0000-0000-4000-8000-000000000001','accepted');

do $$
declare rule sectalk_private.st_v6_quiet_rules;
begin
  if has_table_privilege('authenticated','sectalk_private.st_v6_quiet_rules','SELECT')
    or has_function_privilege('anon','public.st_v6_effective_availability(uuid)','EXECUTE') then
    raise exception 'Quiet hours were granted to an unintended role';
  end if;
  rule.days:=array[1]::smallint[];
  rule.starts_at:=time '22:00';
  rule.ends_at:=time '07:00';
  rule.zone:='Asia/Kolkata';
  if sectalk_private.st_v6_quiet_window(rule,'2026-11-16 16:29:59Z')
    or not sectalk_private.st_v6_quiet_window(rule,'2026-11-16 16:30Z')
    or not sectalk_private.st_v6_quiet_window(rule,'2026-11-17 01:29:59Z')
    or sectalk_private.st_v6_quiet_window(rule,'2026-11-17 01:30Z')
    or sectalk_private.st_v6_quiet_window(rule,'2026-11-17 17:00Z') then
    raise exception 'Overnight quiet hours did not carry across the selected weekday';
  end if;
  rule.days:=array[7]::smallint[];
  rule.starts_at:=time '01:30';
  rule.ends_at:=time '03:30';
  rule.zone:='America/New_York';
  if not sectalk_private.st_v6_quiet_window(rule,'2026-03-08 06:45Z')
    or not sectalk_private.st_v6_quiet_window(rule,'2026-03-08 07:15Z')
    or sectalk_private.st_v6_quiet_window(rule,'2026-03-08 07:30Z')
    or not sectalk_private.st_v6_quiet_window(rule,'2026-11-01 05:45Z')
    or not sectalk_private.st_v6_quiet_window(rule,'2026-11-01 06:45Z') then
    raise exception 'Local quiet hours did not follow DST';
  end if;
end $$;

set local role authenticated;
do $$
declare
  owner_id constant uuid:='660a0000-0000-4000-8000-000000000001';
  peer_id constant uuid:='660a0000-0000-4000-8000-000000000002';
  outsider constant uuid:='660a0000-0000-4000-8000-000000000003';
  chat_id constant uuid:='660a0000-0001-4000-8000-000000000001';
  active_days constant smallint[]:=array[1,2,3,4,5,6,7]::smallint[];
  local_time constant time:=(now() at time zone 'UTC')::time;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v5_profile_details_save('Available for questions',false);
  perform public.st_v6_set_quiet_snooze(chat_id,30);
  if not public.st_v6_quiet_active(chat_id) or public.st_v6_quiet_active(null)
    or (public.st_v6_quiet_settings(chat_id)->>'snooze_until')::timestamptz<=now() then
    raise exception 'Chat snooze was not confined to the chat';
  end if;
  perform public.st_v6_set_quiet_snooze(chat_id,0);
  if public.st_v6_quiet_active(chat_id) then raise exception 'Chat snooze did not clear'; end if;
  perform public.st_v2_mute(chat_id,true);
  if not public.st_v6_quiet_active(chat_id)
    or (public.st_v6_quiet_settings(chat_id)->>'muted')::boolean is distinct from true then
    raise exception 'Legacy mute was ignored';
  end if;
  perform public.st_v6_set_quiet_mute(chat_id,false);
  perform public.st_v6_set_quiet_schedule(chat_id,active_days,
    local_time-interval '1 hour',local_time+interval '1 hour','UTC',null);
  if not public.st_v6_quiet_active(chat_id) or public.st_v6_quiet_active(null) then
    raise exception 'Chat schedule was not confined to the chat';
  end if;
  perform public.st_v6_set_quiet_schedule(chat_id,null,null,null,null,null);
  perform public.st_v6_set_quiet_mute(null,true);
  if not public.st_v6_quiet_active(chat_id) then raise exception 'Account mute did not apply to chat'; end if;
  perform public.st_v6_set_quiet_mute(null,false);
  perform public.st_v6_set_quiet_schedule(null,active_days,
    local_time-interval '1 hour',local_time+interval '1 hour','UTC','Focus time');
  if not public.st_v6_quiet_active(chat_id) then raise exception 'Account schedule did not apply to chat'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',peer_id,'role','authenticated')::text,true);
  if public.st_v6_quiet_active(chat_id)
    or public.st_v6_effective_availability(owner_id) is distinct from '{"busy":false,"status":"Available for questions"}'::jsonb then
    raise exception 'Quiet settings leaked across chat members or ignored presence opt-out';
  end if;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v3_set_presence('online');
  perform set_config('request.jwt.claims',json_build_object('sub',peer_id,'role','authenticated')::text,true);
  if public.st_v6_effective_availability(owner_id) is distinct from '{"busy":true,"status":"Focus time"}'::jsonb then
    raise exception 'Scheduled status and Busy not visible to opted-in accepted contacts';
  end if;
  perform set_config('request.jwt.claims',json_build_object('sub',outsider,'role','authenticated')::text,true);
  if public.st_v6_effective_availability(owner_id) is not null then raise exception 'Outsider saw status'; end if;
  begin
    perform public.st_v6_quiet_settings(chat_id);
    raise exception 'Outsider saw chat settings';
  exception when raise_exception then
    if sqlerrm<>'Notification settings unavailable' then raise; end if;
  end;
  begin
    perform public.st_v6_set_quiet_snooze(chat_id,1);
    raise exception 'Outsider wrote chat settings';
  exception when raise_exception then
    if sqlerrm<>'Invalid notification snooze' then raise; end if;
  end;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  begin
    perform public.st_v6_set_quiet_schedule(null,active_days,time '21:00',time '07:00','Invalid/Zone',null);
    raise exception 'Invalid time zone was saved';
  exception when raise_exception then
    if sqlerrm<>'Choose valid quiet hours, days and time zone' then raise; end if;
  end;
  perform public.st_v6_set_quiet_schedule(null,null,null,null,null,null);
  perform set_config('request.jwt.claims',json_build_object('sub',peer_id,'role','authenticated')::text,true);
  if public.st_v6_effective_availability(owner_id) is distinct from '{"busy":false,"status":"Available for questions"}'::jsonb then
    raise exception 'Removing schedule did not restore custom status';
  end if;
  perform public.st_set_block(chat_id,true);
  if public.st_v6_effective_availability(owner_id) is not null then raise exception 'Blocked contact saw status'; end if;
end $$;

reset role;
select 'passed: account and chat quiet settings, schedule boundaries, DST, mute, snooze, and status visibility' as result;
rollback;
