begin;

insert into auth.users(id,email,aud,role) values
  ('64300000-0000-4000-8000-000000000001','ring-caller@example.invalid','authenticated','authenticated'),
  ('64300000-0000-4000-8000-000000000002','ring-callee@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('64300000-0000-4000-8000-000000000001','ring_fixture_caller','Ring caller'),
  ('64300000-0000-4000-8000-000000000002','ring_fixture_callee','Ring callee');
insert into public.st_chats(id,member_a,member_b,requester,status) values
  ('64300000-0001-4000-8000-000000000001',
   '64300000-0000-4000-8000-000000000001','64300000-0000-4000-8000-000000000002',
   '64300000-0000-4000-8000-000000000001','accepted');

set local role authenticated;
do $$
declare
  caller constant uuid:='64300000-0000-4000-8000-000000000001';
  callee constant uuid:='64300000-0000-4000-8000-000000000002';
  chat constant uuid:='64300000-0001-4000-8000-000000000001';
  caller_session constant uuid:='64300000-0002-4000-8000-000000000001';
  callee_session constant uuid:='64300000-0002-4000-8000-000000000002';
  second_session constant uuid:='64300000-0002-4000-8000-000000000003';
  caller_device constant uuid:='64300000-0003-4000-8000-000000000001';
  callee_device constant uuid:='64300000-0003-4000-8000-000000000002';
  second_device constant uuid:='64300000-0003-4000-8000-000000000003';
  ring uuid;
  decision text;
  outcome text;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',caller,'role','authenticated','session_id',caller_session)::text,true);
  ring:=public.st_v6_start_call(chat,false,caller_device);
  if public.st_v6_call_action(ring,'end',second_device)<>'unavailable' then raise exception 'Wrong caller tab could cancel'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',callee,'role','authenticated','session_id',callee_session)::text,true);
  if public.st_v6_call_action(ring,'accept',callee_device)<>'accepted' or
     public.st_v6_call_action(ring,'accept',callee_device)<>'accepted' then
    raise exception 'Winning acceptance was not idempotent';
  end if;
  if public.st_v6_call_action(ring,'accept',second_device)<>'answered_elsewhere'
    or public.st_v6_call_action(ring,'end',second_device)<>'answered_elsewhere' then
    raise exception 'Sibling tab could change ownership or end the active call';
  end if;
  begin
    perform public.st_v6_call_signal(ring,'answer','{"type":"answer","sdp":"fixture"}'::jsonb,second_device);
    raise exception 'Sibling tab sent a signal without ownership' using errcode='P0004';
  exception when raise_exception then null; end;
  perform public.st_v6_call_signal(ring,'answer','{"type":"answer","sdp":"fixture"}'::jsonb,callee_device);

  perform set_config('request.jwt.claims',json_build_object('sub',callee,'role','authenticated','session_id',second_session)::text,true);
  perform public.st_call_status(ring,false);
  if public.st_v6_call_action(ring,'busy',callee_device)<>'answered_elsewhere'
    or public.st_v6_call_ice_session(ring) is not null
    or exists(select 1 from public.st_signals where call_id=ring) then
    raise exception 'Sibling session accessed or interrupted the winning endpoint';
  end if;
  if not exists(select 1 from public.st_calls where id=ring and status='active') then
    raise exception 'Legacy status request ended the owned call';
  end if;

  perform set_config('request.jwt.claims',json_build_object('sub',callee,'role','authenticated','session_id',callee_session)::text,true);
  if public.st_v6_call_action(ring,'end',callee_device)<>'ended' then raise exception 'Winning device could not hang up'; end if;

  foreach decision in array array['busy','decline','end'] loop
    perform set_config('request.jwt.claims',json_build_object('sub',caller,'role','authenticated','session_id',caller_session)::text,true);
    ring:=public.st_v6_start_call(chat,false,caller_device);
    if decision='end' then
      outcome:=public.st_v6_call_action(ring,decision,caller_device);
      if outcome<>'ended'
        or not exists(select 1 from public.st_calls where id=ring and end_reason='cancelled') then
        raise exception 'Ringing caller could not cancel';
      end if;
    else
      perform set_config('request.jwt.claims',json_build_object('sub',callee,'role','authenticated','session_id',second_session)::text,true);
      outcome:=public.st_v6_call_action(ring,decision,second_device);
      if outcome<>'ended'
        or not exists(select 1 from public.st_calls where id=ring and end_reason=case when decision='busy' then 'busy' else 'declined' end) then
        raise exception 'Recipient decision was not persisted';
      end if;
    end if;
  end loop;

  perform set_config('request.jwt.claims',json_build_object('sub',caller,'role','authenticated','session_id',caller_session)::text,true);
  ring:=public.st_place_call(chat,false);
  perform set_config('request.jwt.claims',json_build_object('sub',callee,'role','authenticated','session_id',callee_session)::text,true);
  perform public.st_call_status(ring,true);
  perform public.st_signal(ring,'answer','{"type":"answer","sdp":"legacy fixture"}'::jsonb);
  if public.st_v6_call_ice_session(ring) is null then raise exception 'Legacy answer lost its ICE path'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',callee,'role','authenticated','session_id',second_session)::text,true);
  perform public.st_call_status(ring,false);
  if public.st_v6_call_ice_session(ring) is not null
    or exists(select 1 from public.st_signals where call_id=ring)
    or not exists(select 1 from public.st_calls where id=ring and status='active') then
    raise exception 'Legacy acceptance did not bind the winning auth session';
  end if;
end $$;

reset role;
select 'passed: device-owned accept, sibling restrictions, ICE/signals, busy, decline and cancel' as result;
rollback;
