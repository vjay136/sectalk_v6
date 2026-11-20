begin;
insert into auth.users(id,email)
select ('7f700000-0000-4000-8000-00000000000'||n)::uuid,'route-'||n||'@example.invalid' from generate_series(1,6) n;
insert into public.st_profiles(id,handle,name)
select id, 'route_'||split_part(split_part(email,'@',1),'-',2),'Case fixture'
from auth.users where email ~ '^route-[1-6]@example\.invalid$';
insert into sectalk_private.staff(user_id)
select id from public.st_profiles where handle in ('route_1','route_2','route_3','route_4','route_5','route_6');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
select ('7f710000-0000-4000-8000-00000000000'||n)::uuid, ('7f700000-0000-4000-8000-00000000000'||n)::uuid,
'totp','verified',now(),now() from generate_series(1,6) n;
insert into auth.sessions(id,user_id,aal,factor_id)
select ('7f720000-0000-4000-8000-00000000000'||n)::uuid,('7f700000-0000-4000-8000-00000000000'||n)::uuid,
'aal2',('7f710000-0000-4000-8000-00000000000'||n)::uuid from generate_series(1,6) n;

insert into public.st_chats(id,member_a,member_b,requester,status)
values('7f730000-0000-4000-8000-000000000001','7f700000-0000-4000-8000-000000000004',
 '7f700000-0000-4000-8000-000000000005','7f700000-0000-4000-8000-000000000004','accepted');
insert into public.st_reports(id,reporter,subject,chat_id,category,details,evidence)
select ('7f740000-0000-4000-8000-00000000000'||n)::uuid,c.member_a,c.member_b,c.id,
 'threat','Private reporter details',case when n=1 then 'Private shared excerpt' end
from public.st_chats c cross join generate_series(1,2)n where c.id='7f730000-0000-4000-8000-000000000001';
insert into sectalk_private.st_v6_case_on_call(user_id,tier,starts_at,ends_at) values
 ('7f700000-0000-4000-8000-000000000001',1,now(),now()+interval '1 hour'),
 ('7f700000-0000-4000-8000-000000000002',2,now(),now()+interval '1 hour'),
 ('7f700000-0000-4000-8000-000000000003',3,now(),now()+interval '1 hour'),
 ('7f700000-0000-4000-8000-000000000004',2,now()-interval '1 minute',now()+interval '1 hour'),
 ('7f700000-0000-4000-8000-000000000006',1,now()-interval '2 hours',now()-interval '1 hour');

create function pg_temp.route_actor(n integer,assurance text default 'aal2') returns void
language sql as $$
 select set_config('request.jwt.claims',jsonb_build_object(
  'sub','7f700000-0000-4000-8000-00000000000'||n,'aal',assurance,
  'session_id','7f720000-0000-4000-8000-00000000000'||n)::text,true)::text::void
$$;

set local role authenticated;
do $$
declare
 report uuid:='7f740000-0000-4000-8000-000000000001';
 snapshot jsonb;
begin
 perform pg_temp.route_actor(1,'aal1');
 begin perform public.st_v6_update_case_escalation(report,'route',0::smallint,'Low assurance');
   raise exception 'Low assurance accepted'; exception when insufficient_privilege then null; end;
 perform pg_temp.route_actor(4);
 begin perform public.st_v6_case_escalation(report);
   raise exception 'Case participant could read escalation'; exception when insufficient_privilege then null; end;
 perform pg_temp.route_actor(6);
 if public.st_v6_case_escalation(report)->>'can_route' is distinct from 'false' then
   raise exception 'Off-shift staff gained routing controls'; end if;
 begin perform public.st_v6_update_case_escalation(report,'route',0::smallint,'Off shift');
   raise exception 'Off-shift staff could route'; exception when insufficient_privilege then null; end;
 perform pg_temp.route_actor(1);
 perform public.st_v6_update_case_escalation(report,'route',0::smallint,'L1 triage');
 snapshot:=public.st_v6_case_escalation(report);
 if snapshot->>'tier' is distinct from '1' or snapshot->>'can_acknowledge' is distinct from 'true'
 or (snapshot->>'acknowledge_by')::timestamptz-(snapshot->>'assigned_at')::timestamptz<>interval '2 hours'
 or (snapshot->>'action_by')::timestamptz-(snapshot->>'assigned_at')::timestamptz<>interval '24 hours' then
   raise exception 'Missing stage state and deadlines: %',snapshot; end if;
 begin perform public.st_v6_update_case_escalation(report,'route',0::smallint,'Stale route');
   raise exception 'Stale route accepted'; exception when serialization_failure then null; end;
 begin perform public.st_v6_update_case_escalation(report,'route',1::smallint,'Premature route');
   raise exception 'Premature route accepted'; exception when invalid_parameter_value then null; end;
 perform pg_temp.route_actor(2);
 if exists(select from public.st_v6_case_escalation_assignments()) then raise exception 'Unassigned staff saw assignment'; end if;
 begin perform public.st_v6_update_case_escalation(report,'acknowledge',1::smallint,'Wrong assignee');
   raise exception 'Another tier acknowledged'; exception when insufficient_privilege then null; end;
 perform pg_temp.route_actor(1);
 perform public.st_v6_update_case_escalation(report,'acknowledge',1::smallint,'L1 accepted');
 perform public.st_v6_update_case_escalation(report,'acknowledge',1::smallint,'Duplicate');
 perform public.st_v6_update_case_escalation(report,'route',1::smallint,'Send to L2');
 begin perform public.st_v6_update_case_escalation(report,'route',2::smallint,'Unauthorized promotion');
   raise exception 'L1 promoted L2 stage'; exception when insufficient_privilege then null; end;
 if exists(select from public.st_v6_case_escalation_assignments()) then raise exception 'Old L1 assignment remained active'; end if;
 perform pg_temp.route_actor(2);
 if (select count(*) from public.st_v6_case_escalation_assignments() where tier=2)<>1 then
   raise exception 'Assignment did not skip the conflicted reporter'; end if;
end $$;
reset role;

update sectalk_private.st_v6_case_escalations set acknowledge_by=now()-interval '1 second' where
 report_id='7f740000-0000-4000-8000-000000000001' and tier=2;
set local role authenticated;
do $$
declare report uuid:='7f740000-0000-4000-8000-000000000001';
begin
 perform pg_temp.route_actor(2);
 perform public.st_v6_update_case_escalation(report,'route',2::smallint,'L2 acknowledgment is overdue');
 perform pg_temp.route_actor(3);
 if (select count(*) from public.st_v6_case_escalation_assignments() where tier=3)<>1 then
   raise exception 'Platform assignment missing'; end if;
 perform public.st_v6_update_case_escalation(report,'acknowledge',3::smallint,'Platform accepted');
 begin perform public.st_v6_update_case_escalation(report,'route',3::smallint,'Out of scope');
   raise exception 'Platform disclosed outside personal scope'; exception when invalid_parameter_value then null; end;
 perform pg_temp.route_actor(4);
 if exists(select from public.st_v5_report_timeline(report) where action like 'case_%')
 or exists(select from public.st_v6_case_escalation_assignments()) then raise exception 'Reporter saw routing metadata'; end if;
end $$;
reset role;

do $$
begin
 if (select count(*) from sectalk_private.audit where report_id='7f740000-0000-4000-8000-000000000001'
     and action in ('case_routed','case_route_acknowledged'))<>5 then
   raise exception 'Missing or duplicate audit records'; end if;
 if (select count(*) from realtime.messages where event='case_escalation'
     and topic in ('st:account:7f700000-0000-4000-8000-000000000001',
       'st:account:7f700000-0000-4000-8000-000000000002','st:account:7f700000-0000-4000-8000-000000000003')
     and private and payload-'id'='{}')<>3
 or exists(select from realtime.messages where event='case_escalation'
     and topic='st:account:7f700000-0000-4000-8000-000000000004') then
   raise exception 'Unexpected private notification delivery'; end if;
 if has_table_privilege('authenticated','sectalk_private.st_v6_case_on_call','insert')
 or has_function_privilege('anon','public.st_v6_case_escalation(uuid)','execute') then
   raise exception 'Roster or stage state is exposed'; end if;
end $$;
rollback;
