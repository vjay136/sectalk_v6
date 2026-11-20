begin;

insert into auth.users(id,email,aud,role) values
  ('64200000-0000-4000-8000-000000000001','ice-caller@example.invalid','authenticated','authenticated'),
  ('64200000-0000-4000-8000-000000000002','ice-callee@example.invalid','authenticated','authenticated'),
  ('64200000-0000-4000-8000-000000000003','ice-outsider@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('64200000-0000-4000-8000-000000000001','ice_fixture_caller','ICE caller'),
  ('64200000-0000-4000-8000-000000000002','ice_fixture_callee','ICE callee'),
  ('64200000-0000-4000-8000-000000000003','ice_fixture_outsider','ICE outsider');
insert into public.st_chats(id,member_a,member_b,requester,status) values
  ('64200000-0001-4000-8000-000000000001',
   '64200000-0000-4000-8000-000000000001','64200000-0000-4000-8000-000000000002',
   '64200000-0000-4000-8000-000000000001','accepted');
insert into public.st_calls(id,chat_id,caller,callee,video,status,expires_at) values
  ('64200000-0002-4000-8000-000000000001','64200000-0001-4000-8000-000000000001',
   '64200000-0000-4000-8000-000000000001','64200000-0000-4000-8000-000000000002',
   false,'active',now()-interval '1 minute');

set local role authenticated;
do $$
declare
  caller constant uuid:='64200000-0000-4000-8000-000000000001';
  callee constant uuid:='64200000-0000-4000-8000-000000000002';
  outsider constant uuid:='64200000-0000-4000-8000-000000000003';
  chat constant uuid:='64200000-0001-4000-8000-000000000001';
  expired constant uuid:='64200000-0002-4000-8000-000000000001';
  real_call uuid;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',caller,'role','authenticated')::text,true);
  if public.st_v6_call_ice_session(expired) is not null then raise exception 'Expired call got ICE access'; end if;
  real_call:=public.st_place_call(chat,false);
  if public.st_v6_call_ice_session(real_call) is not null then raise exception 'Ringing call got ICE access'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',callee,'role','authenticated')::text,true);
  perform public.st_call_status(real_call,true);
  if public.st_v6_call_ice_session(real_call) is distinct from now()+interval '2 hours' then
    raise exception 'Participant could not read the active call expiry';
  end if;
  perform set_config('request.jwt.claims',json_build_object('sub',outsider,'role','authenticated')::text,true);
  for n in 1..12 loop
    if public.st_v6_call_ice_session(real_call) is not null then raise exception 'Outsider got ICE access'; end if;
  end loop;
  begin
    perform public.st_v6_call_ice_session(real_call);
    raise exception 'Repeated requests exceeded the issuance rate limit';
  exception when sqlstate 'PT429' then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',callee,'role','authenticated')::text,true);
  perform public.st_set_block(chat,true);
  if public.st_v6_call_ice_session(real_call) is not null then raise exception 'Blocked call retained ICE access'; end if;
end $$;

reset role;
select 'passed: call ICE denies expired, ringing, blocked, and outsider requests, and rate limits credential reads' as result;
rollback;
