begin;
insert into auth.users(id,email)
select ('dc1def00-9999-4261-a553-'||lpad(n::text,12,'0'))::uuid,'incident-'||n||'@example.invalid'
from generate_series(1,5) n;
insert into public.st_profiles(id,name,handle)
select ('dc1def00-9999-4261-a553-'||lpad(n::text,12,'0'))::uuid,'Incident fixture '||n,'incident_fixture_'||n
from generate_series(1,5) n;
insert into sectalk_private.staff(user_id)
select ('dc1def00-9999-4261-a553-'||lpad(n::text,12,'0'))::uuid from generate_series(1,3) n;
insert into sectalk_private.st_v6_incident_responders(user_id,role) values
  ('dc1def00-9999-4261-a553-000000000001','lead'),('dc1def00-9999-4261-a553-000000000002','responder');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
select ('dc1def00-9999-4261-a553-'||lpad((n+10)::text,12,'0'))::uuid,
  ('dc1def00-9999-4261-a553-'||lpad(n::text,12,'0'))::uuid,'totp','verified',now(),now()
from generate_series(1,3) n;
insert into auth.sessions(id,user_id,aal,factor_id)
select ('dc1def00-9999-4261-a553-'||lpad((n+20)::text,12,'0'))::uuid,
  ('dc1def00-9999-4261-a553-'||lpad(n::text,12,'0'))::uuid,'aal2',
  ('dc1def00-9999-4261-a553-'||lpad((n+10)::text,12,'0'))::uuid
from generate_series(1,3) n;
insert into public.st_chats(id,member_a,member_b,requester,status) values
  ('dc1def00-9999-4261-a553-000000000030','dc1def00-9999-4261-a553-000000000004','dc1def00-9999-4261-a553-000000000005',
    'dc1def00-9999-4261-a553-000000000004','accepted');
insert into public.st_reports(id,reporter,subject,chat_id,category,details,evidence) values
  ('dc1def00-9999-4261-a553-000000000031','dc1def00-9999-4261-a553-000000000004','dc1def00-9999-4261-a553-000000000005',
    'dc1def00-9999-4261-a553-000000000030','scam','Private report notes','Private report evidence');

set local role authenticated;
do $$
declare
  lead_id uuid:='dc1def00-9999-4261-a553-000000000001';
  responder_id uuid:='dc1def00-9999-4261-a553-000000000002';
  unrelated_staff uuid:='dc1def00-9999-4261-a553-000000000003';
  report uuid:='dc1def00-9999-4261-a553-000000000031';
  incident uuid:=gen_random_uuid();
  lead_claims text:=json_build_object('sub',lead_id,'role','authenticated','aal','aal2',
    'session_id','dc1def00-9999-4261-a553-000000000021')::text;
  responder_claims text:=json_build_object('sub',responder_id,'role','authenticated','aal','aal2',
    'session_id','dc1def00-9999-4261-a553-000000000022')::text;
  snapshot jsonb;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',unrelated_staff,'role','authenticated','aal','aal2',
    'session_id','dc1def00-9999-4261-a553-000000000023')::text,true);
  if public.st_v6_incident_access()<>'none' then raise exception 'General staff received an incident role'; end if;
  begin
    perform public.st_v6_incident_dashboard();
    raise exception 'General staff opened the incident dashboard';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',lead_claims,true);
  perform public.st_v6_write_incident(incident,'create','{"title":"Scoped fixture incident","severity":"high"}');
  perform public.st_v6_write_incident(incident,'create','{"title":"Scoped fixture incident","severity":"high"}');
  begin
    perform public.st_v6_write_incident(incident,'update','{"status":"resolved","severity":"high","note":"Attempt invalid jump"}');
    raise exception 'Invalid state transition passed' using errcode='P0100';
  exception when raise_exception then null; end;
  perform public.st_v6_write_incident(incident,'link',jsonb_build_object('entity',report,'note','Verified report association'));
  perform public.st_v6_write_incident(incident,'link',jsonb_build_object('entity',report,'note','Verified report association'));
  perform set_config('request.jwt.claims',responder_claims,true);
  begin
    perform public.st_v6_incident_dashboard(incident);
    raise exception 'Unassigned responder read incident details';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',lead_claims,true);
  perform public.st_v6_write_incident(incident,'assign',jsonb_build_object('entity',responder_id,'note','Assign scoped responder'));
  perform set_config('request.jwt.claims',responder_claims,true);
  perform public.st_v6_write_incident(incident,'update','{"status":"investigating","severity":"critical","note":"Investigation started"}');
  perform public.st_v6_write_incident(incident,'note','{"note":"Untrusted narrative stored as plain text"}');
  perform public.st_v6_write_incident(incident,'update','{"status":"contained","severity":"critical","note":"Contained fixture impact"}');
  perform public.st_v6_write_incident(incident,'update','{"status":"resolved","severity":"high","note":"Resolved fixture"}');
  perform public.st_v6_write_incident(incident,'postmortem','{"note":"Resolved incident postmortem"}');
  snapshot:=public.st_v6_incident_dashboard(incident);
  if snapshot->'incident'->>'postmortem'<>'Resolved incident postmortem'
    or snapshot->'incident'->>'status'<>'resolved'
    or snapshot->'reports'<>jsonb_build_array(report)
    or jsonb_array_length(snapshot->'timeline')<>8
    or snapshot::text like '%Private report evidence%' or snapshot::text like '%Private report notes%'
  then raise exception 'Incident scope, timeline, association or postmortem was invalid'; end if;
end $$;
select 'passed: real session binding, scoped responders, assignment, transition, linked evidence boundary and postmortem' as result;
rollback;
