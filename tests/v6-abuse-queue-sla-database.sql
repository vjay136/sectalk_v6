begin;

insert into auth.users(id,email) values
  ('baaaa471-cc00-41d5-a34c-000000000001','sla-reporter@example.invalid'),
  ('baaaa471-cc00-41d5-a34c-000000000002','sla-subject@example.invalid'),
  ('baaaa471-cc00-41d5-a34c-000000000003','sla-reviewer@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('baaaa471-cc00-41d5-a34c-000000000001','sla_fixture_reporter','Fixture reporter'),
  ('baaaa471-cc00-41d5-a34c-000000000002','sla_fixture_subject','Fixture subject'),
  ('baaaa471-cc00-41d5-a34c-000000000003','sla_fixture_reviewer','Fixture reviewer');
insert into sectalk_private.staff(user_id) values ('baaaa471-cc00-41d5-a34c-000000000003');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
  ('baaaa471-cc00-41d5-a34c-000000000011','baaaa471-cc00-41d5-a34c-000000000003','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
  ('baaaa471-cc00-41d5-a34c-000000000021','baaaa471-cc00-41d5-a34c-000000000003','aal2','baaaa471-cc00-41d5-a34c-000000000011');
insert into public.st_chats(id,member_a,member_b,requester,status) values
  ('baaaa471-cc00-41d5-a34c-000000000010','baaaa471-cc00-41d5-a34c-000000000001',
    'baaaa471-cc00-41d5-a34c-000000000002','baaaa471-cc00-41d5-a34c-000000000001','accepted');
insert into public.st_reports(id,reporter,subject,chat_id,created_at,category,status,details,evidence)
select ('baaaa471-cc00-41d5-a34c-0000000000'||key)::uuid,
  'baaaa471-cc00-41d5-a34c-000000000001','baaaa471-cc00-41d5-a34c-000000000002',
  'baaaa471-cc00-41d5-a34c-000000000010',now()-elapsed,category,status,'Synthetic notes','Synthetic evidence'
from (values ('31',interval '3 hours','threat','open'),('32',interval '6 hours','spam','open'),
  ('33',interval '80 hours','harassment','reviewing'),('34',interval '1 day','scam','resolved')) fixture(key,elapsed,category,status);
insert into sectalk_private.audit(actor,report_id,action,created_at,note) values
  ('baaaa471-cc00-41d5-a34c-000000000003','baaaa471-cc00-41d5-a34c-000000000031','viewed',now()-interval '2 hours',''),
  ('baaaa471-cc00-41d5-a34c-000000000003','baaaa471-cc00-41d5-a34c-000000000033','reviewing',now()-interval '75 hours','Working report'),
  ('baaaa471-cc00-41d5-a34c-000000000003','baaaa471-cc00-41d5-a34c-000000000034','resolved',now()-interval '20 hours','Resolved report');

set local role authenticated;
do $$
declare
  reporter_id constant uuid:='baaaa471-cc00-41d5-a34c-000000000001';
  staff_id constant uuid:='baaaa471-cc00-41d5-a34c-000000000003';
  session_id constant uuid:='baaaa471-cc00-41d5-a34c-000000000021';
begin
  perform set_config('request.jwt.claims',json_build_object('sub',reporter_id,'role','authenticated','aal','aal2','session_id',session_id)::text,true);
  begin
    perform public.st_v6_abuse_queue();
    raise exception 'Nonstaff account opened the moderation queue';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',staff_id,'role','authenticated','aal','aal2','session_id',gen_random_uuid())::text,true);
  begin
    perform public.st_v6_abuse_queue();
    raise exception 'A stale staff session opened the moderation queue';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',staff_id,'role','authenticated','aal','aal2','session_id',session_id)::text,true);
  if not exists(select 1 from public.st_v6_abuse_queue('threat','active','overdue')
    where id='baaaa471-cc00-41d5-a34c-000000000031' and acknowledged_at is null
      and next_due=acknowledge_by and acknowledge_by-created_at=interval '2 hours')
    or not exists(select 1 from public.st_v6_abuse_queue('spam','open','next_day')
      where id='baaaa471-cc00-41d5-a34c-000000000032' and not overdue)
    or not exists(select 1 from public.st_v6_abuse_queue('harassment','reviewing','overdue')
      where id='baaaa471-cc00-41d5-a34c-000000000033' and next_due=resolve_by
        and resolve_by-created_at=interval '72 hours')
    or not exists(select 1 from public.st_v6_abuse_queue('scam','closed','any')
      where id='baaaa471-cc00-41d5-a34c-000000000034' and closed_at is not null and next_due is null and not overdue)
  then raise exception 'Staff acknowledgment, action or closure timers were incorrect'; end if;
  if exists(select 1 from public.st_v6_abuse_queue('spam','open','next_day') q
      where to_jsonb(q) ?| array['evidence','details','reporter','note'])
  then raise exception 'Evidence leaked through the queue list'; end if;
  begin
    perform public.st_v6_abuse_queue(null,'active','any',10001);
    raise exception 'An invalid pagination request was accepted';
  exception when invalid_parameter_value then null; end;
end $$;
select 'passed: genuine staff assurance, distinct response clocks, filters and no evidence in list' as result;
rollback;
