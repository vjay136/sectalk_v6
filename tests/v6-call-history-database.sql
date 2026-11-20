begin;

insert into auth.users(id,email,aud,role) values
  ('64000000-0000-4000-8000-000000000001','history-caller@example.invalid','authenticated','authenticated'),
  ('64000000-0000-4000-8000-000000000002','history-callee@example.invalid','authenticated','authenticated'),
  ('64000000-0000-4000-8000-000000000003','history-outsider@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('64000000-0000-4000-8000-000000000001','history_fixture_caller','History caller'),
  ('64000000-0000-4000-8000-000000000002','history_fixture_callee','History callee'),
  ('64000000-0000-4000-8000-000000000003','history_fixture_outsider','History outsider');
insert into public.st_chats(id,member_a,member_b,requester,status) values
  ('64000000-0001-4000-8000-000000000001',
   '64000000-0000-4000-8000-000000000001','64000000-0000-4000-8000-000000000002',
   '64000000-0000-4000-8000-000000000001','accepted');
insert into public.st_calls(id,chat_id,caller,callee,video,expires_at,created_at) values
  ('64000000-0002-4000-8000-000000000001','64000000-0001-4000-8000-000000000001',
   '64000000-0000-4000-8000-000000000001','64000000-0000-4000-8000-000000000002',
   true,now()-interval '1 minute',now()-interval '2 minutes');

set local role authenticated;
do $$
declare
  caller_id constant uuid:='64000000-0000-4000-8000-000000000001';
  callee_id constant uuid:='64000000-0000-4000-8000-000000000002';
  outsider_id constant uuid:='64000000-0000-4000-8000-000000000003';
  chat constant uuid:='64000000-0001-4000-8000-000000000001';
  timed_out constant uuid:='64000000-0002-4000-8000-000000000001';
  cancelled uuid;
  declined uuid;
  answered uuid;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',caller_id,'role','authenticated')::text,true);
  perform public.st_call_status(timed_out,false);
  cancelled:=public.st_place_call(chat,false);
  perform public.st_call_status(cancelled,false);
  declined:=public.st_place_call(chat,true);

  perform set_config('request.jwt.claims',json_build_object('sub',callee_id,'role','authenticated')::text,true);
  perform public.st_call_status(declined,false);
  perform public.st_call_status(declined,false);
  if (select end_reason from public.st_calls where id=timed_out) is distinct from 'missed'
    or (select end_reason from public.st_calls where id=declined) is distinct from 'declined'
    or (select end_reason from public.st_calls where id=cancelled) is distinct from 'cancelled'
    then raise exception 'Call outcomes were incorrectly recorded'; end if;
  answered:=public.st_place_call(chat,true);

  perform set_config('request.jwt.claims',json_build_object('sub',outsider_id,'role','authenticated')::text,true);
  perform public.st_call_status(answered,false);
  if exists(select 1 from public.st_calls where chat_id=chat) then raise exception 'Call history leaked to an outsider'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',caller_id,'role','authenticated')::text,true);
  perform public.st_call_status(answered,true);
  perform public.st_call_status(answered,false);
  if exists(select 1 from public.st_calls where id=answered and (status<>'ended' or end_reason is not null))
    then raise exception 'An answered call was incorrectly marked as missed'; end if;
end $$;

reset role;
select 'passed: missed, declined, cancelled and answered call outcomes, callback and participant-only history' as result;
rollback;
