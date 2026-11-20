begin;

insert into auth.users(id,email,aud,role)
select format('6a000000-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  format('usage-%s@example.invalid',n),'authenticated','authenticated' from generate_series(1,12) n;
insert into public.st_profiles(id,handle,name)
select id,'usage_'||split_part(split_part(email,'@',1),'-',2),'Usage fixture' from auth.users
where email like 'usage-%@example.invalid';
insert into sectalk_private.staff(user_id) values('6a000000-0000-4000-8000-000000000001');
insert into public.st_chats(id,member_a,member_b,requester,status)
select format('6a000000-0001-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  '6a000000-0000-4000-8000-000000000001',format('6a000000-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  '6a000000-0000-4000-8000-000000000001','accepted' from generate_series(2,12) n;

-- Isolate previous sums in this rollback-only fixture.
update public.st_messages set created_at=date_trunc('day',now(),'UTC')-interval '45 days';
update public.st_calls set created_at=date_trunc('day',now(),'UTC')-interval '45 days';
update public.st_v3_meetings set created_at=date_trunc('day',now(),'UTC')-interval '45 days';
update public.st_v6_task_audit set created_at=date_trunc('day',now(),'UTC')-interval '45 days';
insert into public.st_messages(id,chat_id,sender,body,created_at)
select gen_random_uuid(),format('6a000000-0001-4000-8000-%s',lpad((2+n%11)::text,12,'0'))::uuid,
  format('6a000000-0000-4000-8000-%s',lpad((2+n%11)::text,12,'0'))::uuid,
  'Private message body',date_trunc('day',now(),'UTC')-interval '2 days' from generate_series(0,22) n;
insert into public.st_calls(chat_id,caller,callee,video,status,created_at,expires_at)
select '6a000000-0001-4000-8000-000000000002','6a000000-0000-4000-8000-000000000002',
  '6a000000-0000-4000-8000-000000000001',false,'ended',
  date_trunc('day',now(),'UTC')-interval '2 days',date_trunc('day',now(),'UTC')-interval '2 days'+interval '1 minute'
from generate_series(1,20);

set local role authenticated;
do $$
declare
  staffer constant uuid:='6a000000-0000-4000-8000-000000000001';
  metrics jsonb;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',staffer,'role','authenticated','aal','aal1')::text,true);
  begin
    perform public.st_v6_usage_metrics('7d');
    raise exception 'Staff usage access accepted without MFA';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',staffer,'role','authenticated','aal','aal2')::text,true);
  metrics:=public.st_v6_usage_metrics('7d');
  if metrics-'through' is distinct from '{"metrics":{"accounts":10,"messages":20}}'::jsonb
    then raise exception 'Usage results were not rounded or suppressed as expected'; end if;
  if public.st_v6_usage_metrics('30d')-'through' is distinct from metrics-'through'
    then raise exception 'Fixed date windows failed to include eligible rows'; end if;
  begin
    perform public.st_v6_usage_metrics('1m');
    raise exception 'Unapproved usage window accepted';
  exception when invalid_parameter_value then null; end;
end $$;
reset role;
select 'passed: product aggregates, rounding, single-actor suppression, coarse periods and staff MFA' as result;
rollback;
