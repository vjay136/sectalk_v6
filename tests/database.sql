begin;

insert into auth.users(id,email,aud,role) values
  ('10000000-0000-4000-8000-000000000001','st-transaction-check-a@example.invalid','authenticated','authenticated'),
  ('10000000-0000-4000-8000-000000000002','st-transaction-check-b@example.invalid','authenticated','authenticated'),
  ('10000000-0000-4000-8000-000000000003','st-transaction-check-c@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('10000000-0000-4000-8000-000000000001','st_tx_test_a','Test A'),
  ('10000000-0000-4000-8000-000000000002','st_tx_test_b','Test B'),
  ('10000000-0000-4000-8000-000000000003','st_tx_test_c','Test C');
insert into sectalk_private.staff values('10000000-0000-4000-8000-000000000003');
set local role authenticated;
do $$
declare a uuid:='10000000-0000-4000-8000-000000000001';
b uuid:='10000000-0000-4000-8000-000000000002';
c uuid:='10000000-0000-4000-8000-000000000003';
m uuid:=gen_random_uuid();
chat uuid; call_id uuid; report_id uuid; failed boolean;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',a,'role','authenticated','aal','aal1')::text,true);
  chat:=public.st_request('st_tx_test_b');
  if chat is null then raise exception 'Request creation failed'; end if;
  failed:=false;
  begin perform public.st_send(chat,m,'Consent check'); exception when raise_exception then failed:=true; end;
  if not failed then raise exception 'Pending request accepted a message'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',b,'role','authenticated','aal','aal1')::text,true);
  perform public.st_respond(chat,true);

  perform set_config('request.jwt.claims',json_build_object('sub',a,'role','authenticated','aal','aal1')::text,true);
  perform public.st_send(chat,m,'Test message');
  perform public.st_send(chat,m,'Test message');
  if (select count(*) from public.st_messages where id=m)<>1 then raise exception 'Send was not idempotent'; end if;
  call_id:=public.st_place_call(chat,true);

  perform set_config('request.jwt.claims',json_build_object('sub',b,'role','authenticated','aal','aal1')::text,true);
  if (select count(*) from public.st_messages where id=m)<>1 then raise exception 'Recipient cannot read message'; end if;
  perform public.st_call_status(call_id,true);
  perform public.st_signal(call_id,'answer','{"type":"answer","sdp":"test fixture"}');
  report_id:=public.st_report(chat,m,'harassment','Test notes');
  if (select count(id) from public.st_reports where id=report_id)<>1 then raise exception 'Reporter cannot see status'; end if;
  perform public.st_set_block(chat,true);
  if (select status from public.st_calls where id=call_id)<>'ended' then raise exception 'Blocking did not end call'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',a,'role','authenticated','aal','aal1')::text,true);
  failed:=false;
  begin perform public.st_send(chat,gen_random_uuid(),'Blocked check'); exception when raise_exception then failed:=true; end;
  if not failed then raise exception 'Blocked conversation accepted a message'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',c,'role','authenticated','aal','aal1')::text,true);
  if exists(select 1 from public.st_messages where id=m) then raise exception 'Unrelated staff can read chat'; end if;
  failed:=false;
  begin perform public.st_case(report_id); exception when raise_exception then failed:=true; end;
  if not failed then raise exception 'Evidence readable before MFA'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',c,'role','authenticated','aal','aal2')::text,true);
  if exists(select 1 from public.st_messages where id=m) then raise exception 'Verified staff can read chat'; end if;
  if (public.st_case(report_id)->>'evidence') is distinct from 'Test message' then raise exception 'Evidence unavailable'; end if;
  perform public.st_moderate(report_id,'resolved','Verified by test');
end $$;
reset role;
select 'passed: consent, participant RLS, idempotency, call signaling, blocking, evidence isolation, MFA, moderation' as result;
rollback;
