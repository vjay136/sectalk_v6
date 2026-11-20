begin;

insert into auth.users(id,email,aud,role)
select format('69000000-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  format('latency-%s@example.invalid',n),'authenticated','authenticated' from generate_series(1,6) n;
insert into public.st_profiles(id,handle,name)
select id,'latency_'||split_part(split_part(email,'@',1),'-',2),'Latency fixture' from auth.users
where email like 'latency-%@example.invalid';
insert into sectalk_private.staff(user_id) values('69000000-0000-4000-8000-000000000001');
insert into public.st_chats(id,member_a,member_b,requester,status)
select format('69000000-0001-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  '69000000-0000-4000-8000-000000000001',format('69000000-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  '69000000-0000-4000-8000-000000000001','accepted' from generate_series(2,6) n;

-- Exclude preceding browser fixture data in this rollback-only transaction.
update public.st_messages set delivered_at=null where delivered_at is not null;
insert into public.st_messages(id,chat_id,sender,body,created_at,delivered_at)
select gen_random_uuid(),format('69000000-0001-4000-8000-%s',lpad((2+(n-1)%5)::text,12,'0'))::uuid,
  '69000000-0000-4000-8000-000000000001','Private fixture text',
  date_trunc('hour',now(),'UTC')-interval '2 hours',
  date_trunc('hour',now(),'UTC')-interval '2 hours'+n*interval '100 milliseconds'
from generate_series(1,20) n;

set local role authenticated;
do $$
declare
  staffer constant uuid:='69000000-0000-4000-8000-000000000001';
  member_id constant uuid:='69000000-0000-4000-8000-000000000002';
  metrics jsonb;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated','aal','aal2')::text,true);
  begin
    perform public.st_v6_delivery_latency('24h');
    raise exception 'Non-staff access accepted';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',staffer,'role','authenticated','aal','aal1')::text,true);
  begin
    perform public.st_v6_delivery_latency('24h');
    raise exception 'Staff access accepted without MFA';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',staffer,'role','authenticated','aal','aal2')::text,true);
  metrics:=public.st_v6_delivery_latency('24h');
  if metrics-'through' is distinct from '{"available":true,"p50":1050,"p95":1905,"p99":1981}'::jsonb
    then raise exception 'Incorrect delivery percentiles or unexpected response fields'; end if;
  begin
    perform public.st_v6_delivery_latency('1m');
    raise exception 'Unapproved cohort window accepted';
  exception when invalid_parameter_value then null; end;
end $$;

reset role;
update public.st_messages set delivered_at=null
where chat_id='69000000-0001-4000-8000-000000000006';
set local role authenticated;
do $$
begin
  if public.st_v6_delivery_latency('24h')-'through' is distinct from '{"available":false}'::jsonb
    then raise exception 'An undersized cohort disclosed delivery statistics'; end if;
end $$;
reset role;

select 'passed: delivery percentiles, cohort suppression, range checks, staff MFA and no message content' as result;
rollback;
