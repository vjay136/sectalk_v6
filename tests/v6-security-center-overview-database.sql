begin isolation level repeatable read;

insert into auth.users(id,email)
select format('7f500000-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  format('security-overview-%s@example.invalid',n) from generate_series(1,13) n;
insert into public.st_profiles(id,handle,name)
select id,'security_overview_'||split_part(split_part(email,'@',1),'-',3),'Private overview fixture account'
from auth.users where email like 'security-overview-%@example.invalid';
insert into sectalk_private.staff(user_id) values('7f500000-0000-4000-8000-000000000001');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
values('7f510000-0000-4000-8000-000000000001','7f500000-0000-4000-8000-000000000001','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id)
values('7f520000-0000-4000-8000-000000000001','7f500000-0000-4000-8000-000000000001','aal2','7f510000-0000-4000-8000-000000000001');
insert into public.st_chats(id,member_a,member_b,requester,status)
select format('7f500000-0001-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  format('7f500000-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  format('7f500000-0000-4000-8000-%s',lpad((n+6)::text,12,'0'))::uuid,
  format('7f500000-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,'accepted'
from generate_series(2,7) n;

insert into public.st_reports(reporter,subject,chat_id,category,details,evidence,status,created_at)
select c.member_a,c.member_b,c.id,'threat','Private notes','Private evidence',
  case when c.id='7f500000-0001-4000-8000-000000000006' then 'reviewing'
    when c.id='7f500000-0001-4000-8000-000000000007' then 'open' else 'resolved' end,
  '2020-03-04 00:00+00'
from public.st_chats c where c.id::text like '7f500000-0001-%';
insert into public.st_reports(reporter,subject,chat_id,category,details,status,created_at)
select c.member_a,c.member_b,c.id,'spam','Private sparse cohort','dismissed','2020-02-28 00:00+00'
from public.st_chats c cross join generate_series(1,8)
where c.id='7f500000-0001-4000-8000-000000000002';
insert into sectalk_private.audit(actor,report_id,action,note,created_at)
select '7f500000-0000-4000-8000-000000000001',r.id,a.action,'Private action detail',
  r.created_at+make_interval(mins=>a.minutes)
from public.st_reports r cross join (values('viewed',2),('restore',5),('reviewing',30),
  ('escalated',60),('resolved',90),('dismissed',120)) a(action,minutes)
where r.chat_id::text like '7f500000-0001-%' and r.category='threat'
  and (a.action not in ('resolved','dismissed') or r.chat_id<>'7f500000-0001-4000-8000-000000000007');

do $$
declare
  staffer constant uuid:='7f500000-0000-4000-8000-000000000001';
  member_id constant uuid:='7f500000-0000-4000-8000-000000000002';
  staff_session constant uuid:='7f520000-0000-4000-8000-000000000001';
  sample jsonb;
  overview jsonb;
  original_incidents bigint;
  expected_open bigint;
  expected_depth bigint;
begin
  if has_function_privilege('anon','public.st_v6_security_center_overview()','execute')
    or has_function_privilege('authenticated','sectalk_private.st_v6_case_response_averages(timestamptz,timestamptz)','execute') then
    raise exception 'The overview or raw duration window was exposed';
  end if;

  sample:=sectalk_private.st_v6_case_response_averages('2020-03-04 00:00+00','2020-03-05 00:00+00');
  if sample->'acknowledgement' is distinct from '{"minutes":30,"samples":6}'::jsonb
    or sample->'resolution' is distinct from '{"minutes":90,"samples":5}'::jsonb then
    raise exception 'A view, restore, duplicate or incomplete action changed the duration: %',sample;
  end if;
  sample:=sectalk_private.st_v6_case_response_averages('2020-03-04 00:45+00','2020-03-05 00:00+00');
  if sample->'acknowledgement' is distinct from 'null'::jsonb
    or sample->'resolution' is distinct from '{"minutes":90,"samples":5}'::jsonb then
    raise exception 'Timing was based on report creation or second acknowledgement rather than completion windows';
  end if;
  sample:=sectalk_private.st_v6_overview_report_trend('2020-03-09');
  if jsonb_array_length(sample)<>8
    or sample->7 is distinct from '{"week_start":"2020-03-02","reports":5}'::jsonb
    or sample->6 is distinct from '{"week_start":"2020-02-24","reports":null}'::jsonb then
    raise exception 'Weekly suppression or rounding did not preserve distinct cohorts: %',sample;
  end if;

  select count(*) into original_incidents from sectalk_private.st_v6_security_incidents where status<>'resolved';
  select count(*) filter(where status='open'),count(*) filter(where status in ('open','reviewing'))
    into expected_open,expected_depth from public.st_reports;
  insert into sectalk_private.st_v6_security_incidents(id,title,severity,status,created_by,assigned_to)
    values(gen_random_uuid(),'Private assigned incident','critical','contained',member_id,staffer),
      (gen_random_uuid(),'Private unrelated incident','high','investigating',member_id,member_id),
      (gen_random_uuid(),'Private resolved incident','high','resolved',staffer,staffer);

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',member_id,'aal','aal2','session_id',staff_session)::text,true);
  begin
    perform public.st_v6_security_center_overview();
    raise exception 'A nonstaff account read the security overview';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claim.sub',staffer::text,true);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',staffer,'aal','aal2','session_id',gen_random_uuid())::text,true);
  begin
    perform public.st_v6_security_center_overview();
    raise exception 'A stale staff session read the security overview';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',staffer,'aal','aal2','session_id',staff_session)::text,true);
  overview:=public.st_v6_security_center_overview();
  if (overview->>'open_cases')::bigint is distinct from expected_open or (overview->>'queue_depth')::bigint is distinct from expected_depth
    or overview->'open_incidents' is distinct from 'null'::jsonb or overview::text like '%Private%'
    or (overview#>>'{response_times,until}')::timestamptz-(overview#>>'{response_times,since}')::timestamptz<>interval '7 days' then
    raise exception 'Case counts, incident privilege or response period is inaccurate';
  end if;
  reset role;
  insert into sectalk_private.st_v6_incident_responders(user_id,role) values(staffer,'responder');
  set local role authenticated;
  overview:=public.st_v6_security_center_overview();
  if overview->>'incident_scope' is distinct from 'assigned_or_created' or (overview->>'open_incidents')::bigint is distinct from 1 then
    raise exception 'Responder incident count disclosed other staff work or included resolved incidents';
  end if;
  reset role;
  update sectalk_private.st_v6_incident_responders set role='lead' where user_id=staffer;
  set local role authenticated;
  overview:=public.st_v6_security_center_overview();
  if overview->>'incident_scope' is distinct from 'all'
    or (overview->>'open_incidents')::bigint is distinct from original_incidents+2 then
    raise exception 'Lead incident count was inaccurate';
  end if;
end $$;

select 'passed: genuine assurance, scoped incident and case counts, suppressed risk and completed moderation timing' as result;
rollback;
