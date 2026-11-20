begin;

insert into auth.users(id,email)
select format('7f400000-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  format('security-report-%s@example.invalid',n) from generate_series(1,13) n;
insert into public.st_profiles(id,handle,name)
select id,'security_report_'||split_part(split_part(email,'@',1),'-',3),'Private report fixture account'
from auth.users where email like 'security-report-%@example.invalid';
insert into sectalk_private.staff(user_id) values('7f400000-0000-4000-8000-000000000001');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
values('7f410000-0000-4000-8000-000000000001','7f400000-0000-4000-8000-000000000001','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id)
values('7f420000-0000-4000-8000-000000000001','7f400000-0000-4000-8000-000000000001','aal2','7f410000-0000-4000-8000-000000000001');
insert into public.st_chats(id,member_a,member_b,requester,status)
select format('7f400000-0001-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  format('7f400000-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  format('7f400000-0000-4000-8000-%s',lpad((n+6)::text,12,'0'))::uuid,
  format('7f400000-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,'accepted'
from generate_series(2,7) n;

insert into public.st_reports(reporter,subject,chat_id,category,details,evidence,status,created_at)
select c.member_a,c.member_b,c.id,i.category,'Private report notes','Private evidence excerpt','resolved',i.at
from public.st_chats c cross join (values ('threat','2020-03-04 08:00+00'::timestamptz),
  ('scam','2020-03-04 09:00+00'),('spam','2020-03-04 10:00+00'),('other','2020-03-05 00:00+00')) i(category,at)
where c.id::text like '7f400000-0001-%'
  and (i.category<>'spam' or c.id<'7f400000-0001-4000-8000-000000000006');

insert into sectalk_private.audit(actor,report_id,action,note,created_at)
select '7f400000-0000-4000-8000-000000000001',r.id,a.action,'Private audit reason',
  case when a.action='remove' then '2020-03-05 00:00+00'::timestamptz else r.created_at+interval '1 hour' end
from public.st_reports r cross join (values('warn'),('suspend'),('restore'),('remove')) a(action)
where r.chat_id::text like '7f400000-0001-%' and (
  r.category in ('scam','spam') or (r.category='threat'
    and (a.action in ('restore','remove') or r.chat_id<'7f400000-0001-4000-8000-000000000006')));

do $$
declare
  staffer constant uuid:='7f400000-0000-4000-8000-000000000001';
  staff_session constant uuid:='7f420000-0000-4000-8000-000000000001';
  member_id constant uuid:='7f400000-0000-4000-8000-000000000002';
  sample jsonb;
  daily jsonb;
  weekly jsonb;
begin
  if has_function_privilege('anon','public.st_v6_security_report(text)','execute')
    or has_function_privilege('authenticated','sectalk_private.st_v6_security_report_cohort(timestamptz,timestamptz)','execute') then
    raise exception 'The security report is publicly accessible or accepts arbitrary dates';
  end if;
  select jsonb_object_agg(c.category,to_jsonb(c)-'category') into sample
  from sectalk_private.st_v6_security_report_cohort('2020-03-04 00:00+00','2020-03-05 00:00+00') c;
  if sample->'threat' is distinct from '{"reports":5,"actioned":null}'::jsonb
    or sample->'scam' is distinct from '{"reports":5,"actioned":5}'::jsonb
    or sample->'spam' is distinct from '{"reports":null,"actioned":null}'::jsonb
    or sample->'other' is distinct from '{"reports":null,"actioned":null}'::jsonb
    or sample::text like '%Private%' then
    raise exception 'Daily suppression, rounding, enforcement deduplication or UTC cutoff failed';
  end if;

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',member_id,'aal','aal2','session_id',staff_session)::text,true);
  begin
    perform public.st_v6_security_report('daily');
    raise exception 'A nonstaff account read security reports';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claim.sub',staffer::text,true);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',staffer,'aal','aal2','session_id',gen_random_uuid())::text,true);
  begin
    perform public.st_v6_security_report('weekly');
    raise exception 'A stale staff session read security reports';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',staffer,'aal','aal2','session_id',staff_session)::text,true);
  begin
    perform public.st_v6_security_report('2020-03-04');
    raise exception 'An arbitrary date period was accepted';
  exception when invalid_parameter_value then null; end;
  daily:=public.st_v6_security_report('daily');
  weekly:=public.st_v6_security_report('weekly');
  if (daily->>'period_end')::date is distinct from (now() at time zone 'UTC')::date
    or (daily->>'period_end')::date-(daily->>'period_start')::date<>1
    or (weekly->>'period_end')::date is distinct from date_trunc('week',now() at time zone 'UTC')::date
    or (weekly->>'period_end')::date-(weekly->>'period_start')::date<>7
    or jsonb_array_length(daily->'rows')<>7 or jsonb_array_length(weekly->'rows')<>7
    or exists(select 1 from jsonb_array_elements(daily->'rows') as r(row)
      where r.row-'category'-'reports'-'actioned'<>'{}'::jsonb) then
    raise exception 'The report period or privacy-safe response shape is incorrect';
  end if;
end $$;

select 'passed: verified staff reporting, fixed daily and weekly UTC windows, and suppressed aggregates' as result;
rollback;
