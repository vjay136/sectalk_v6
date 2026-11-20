\set ON_ERROR_STOP on
begin;

insert into auth.users(id,email,aud,role) values
  ('6f000001-0000-4000-8000-000000000001','qos-caller@example.invalid','authenticated','authenticated'),
  ('6f000001-0000-4000-8000-000000000002','qos-callee@example.invalid','authenticated','authenticated'),
  ('6f000001-0000-4000-8000-000000000003','qos-staff@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('6f000001-0000-4000-8000-000000000001','qos_caller','QoS caller'),
  ('6f000001-0000-4000-8000-000000000002','qos_callee','QoS callee'),
  ('6f000001-0000-4000-8000-000000000003','qos_staff','QoS staff');
insert into sectalk_private.staff(user_id) values ('6f000001-0000-4000-8000-000000000003');

insert into public.st_chats(id,member_a,member_b,requester,status) values
  ('6f000001-0001-4000-8000-000000000001','6f000001-0000-4000-8000-000000000001',
   '6f000001-0000-4000-8000-000000000002','6f000001-0000-4000-8000-000000000001','accepted');
insert into public.st_calls(id,chat_id,caller,callee,video,status,expires_at)
select format('6f000001-0002-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  '6f000001-0001-4000-8000-000000000001','6f000001-0000-4000-8000-000000000001',
  '6f000001-0000-4000-8000-000000000002',false,'active',now()+interval '5 minutes'
from generate_series(1,26) n;
insert into sectalk_private.st_v6_call_endpoints values
  ('6f000001-0002-4000-8000-000000000001','6f000001-0000-4000-8000-000000000001',
   'fixture-session','6f000001-0003-4000-8000-000000000001');

-- All earlier cohort changes are rolled back. Seed only known daily aggregates.
delete from sectalk_private.st_v6_call_qos where day < (now() at time zone 'UTC')::date;
insert into sectalk_private.st_v6_call_qos(day,event_key,reporter_key,mode,metric,bucket)
select (now() at time zone 'UTC')::date - age, extensions.gen_random_bytes(32),
  extensions.digest(convert_to('synthetic-daily-person-' || (n % people), 'UTF8'),'sha256'), mode,metric,bucket
from (values
  (1,'meeting','setup','fast',19,6),
  (1,'meeting','relay','relayed',20,1),
  (1,'direct','recovery','recovered',9,5),
  (8,'direct','relay','non_relayed',13,5),
  (0,'direct','setup','fast',13,5)
) as cases(age,mode,metric,bucket,sample_count,people)
cross join lateral generate_series(1,sample_count) n;

set local role authenticated;
do $$
declare
  caller constant uuid := '6f000001-0000-4000-8000-000000000001';
  staffer constant uuid := '6f000001-0000-4000-8000-000000000003';
  first_call constant uuid := '6f000001-0002-4000-8000-000000000001';
  endpoint constant uuid := '6f000001-0003-4000-8000-000000000001';
  reports jsonb;
  meeting uuid := gen_random_uuid();
  workspace uuid;
  resource uuid;
begin
  perform set_config('request.jwt.claims',jsonb_build_object('sub',caller,'session_id','wrong-session','aal','aal2')::text,true);
  if public.st_v6_report_call_qos('direct',first_call,endpoint,'setup','fast')
    then raise exception 'A different device session entered call quality instrumentation'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',staffer,'aal','aal1')::text,true);
  if public.st_v6_report_call_qos('direct',first_call,endpoint,'setup','fast')
    then raise exception 'A user outside the call entered instrumentation'; end if;
  begin
    perform public.st_v6_usage_metrics('7d',true);
    raise exception 'Staff without MFA read call quality';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims','{"sub":"6f000001-0000-4000-8000-000000000002"}',true);
  if public.st_v6_report_call_qos('direct',first_call,null,'ice_restart','requested')
    then raise exception 'The non-initiating endpoint could report a restart offer'; end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',caller,'session_id','fixture-session','aal','aal2')::text,true);
  if public.st_v6_report_call_qos('direct',first_call,gen_random_uuid(),'setup','fast')
    or public.st_v6_report_call_qos('direct',first_call,endpoint,'setup','opaque free form')
    then raise exception 'Invalid device or unbounded value was accepted'; end if;
  if not public.st_v6_report_call_qos('direct',first_call,endpoint,'setup','fast')
    or public.st_v6_report_call_qos('direct',first_call,endpoint,'setup','slow')
    then raise exception 'Call setup deduplication failed'; end if;
  if not public.st_v6_report_call_qos('direct',first_call,endpoint,'join','started')
    or not public.st_v6_report_call_qos('direct',first_call,endpoint,'ice_restart','not_requested')
    then raise exception 'Join or ICE restart denominator failed'; end if;
  workspace := public.st_v2_create_workspace('Call QoS fixture');
  perform public.st_v6_start_instant_meeting(meeting,workspace,'Quality meeting',15);
  if not public.st_v6_report_call_qos('meeting',meeting,null,'recovery','recovered')
    then raise exception 'Admitted meeting attendee could not report'; end if;
  for n in 2..21 loop
    resource := format('6f000001-0002-4000-8000-%s',lpad(n::text,12,'0'))::uuid;
    if not public.st_v6_report_call_qos('direct',resource,null,'setup','fast')
      then raise exception 'Daily budget was exhausted too soon'; end if;
  end loop;
  if public.st_v6_report_call_qos('direct','6f000001-0002-4000-8000-000000000024',null,'setup','fast')
    then raise exception 'Daily budget exceeded 24 samples'; end if;
  if not public.st_v6_report_call_qos('direct',first_call,endpoint,'join','connected')
    or not public.st_v6_report_call_qos('direct',first_call,endpoint,'ice_restart','requested')
    or public.st_v6_report_call_qos('direct',first_call,endpoint,'join','started')
    then raise exception 'The daily cap or out-of-order updates corrupted the paired denominators'; end if;
  begin
    perform 1 from sectalk_private.st_v6_call_qos;
    raise exception 'Individual call samples were exposed';
  exception when insufficient_privilege then null; end;
  begin
    perform 1 from sectalk_private.st_v6_call_qos_key;
    raise exception 'The call quality key was exposed';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_usage_metrics('7d',true);
    raise exception 'A non-staff account read call quality';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',staffer,'aal','aal2')::text,true);
  reports := public.st_v6_usage_metrics('7d',true)->'qos';
  if reports->'metrics' is distinct from '{"meeting:setup:fast":10}'::jsonb then
    raise exception 'Call quality thresholds, rounding, or completed-day cutoff failed';
  end if;
  reports := public.st_v6_usage_metrics('30d',true)->'qos';
  if reports->'metrics' is distinct from '{"meeting:setup:fast":10,"direct:relay:non_relayed":10}'::jsonb then
    raise exception 'Call quality reporting window did not include only qualifying daily buckets';
  end if;
end $$;
reset role;

insert into sectalk_private.st_v6_call_qos(day,event_key,reporter_key,mode,metric,bucket)
select (now() at time zone 'UTC')::date-1, extensions.gen_random_bytes(32),
  extensions.digest('synthetic-rate-person-' || (n%people),'sha256'), mode,metric,bucket
from (values
  ('meeting','join','connected',20,5), ('meeting','join','started',10,5),
  ('direct','ice_restart','requested',20,5), ('direct','ice_restart','not_requested',10,5),
  ('direct','relay','relayed',20,5), ('direct','relay','non_relayed',10,5),
  ('meeting','mos','4_or_more',12,5),
  ('direct','join','connected',12,5), ('direct','join','started',1,1)
) as cases(mode,metric,bucket,sample_count,people)
cross join lateral generate_series(1,sample_count) n;

set local role authenticated;
do $$
declare quality jsonb := public.st_v6_usage_metrics('7d',true)->'qos';
begin
  if quality->'rates' is distinct from '{
    "meeting:join":{"sampled":30,"positive":20,"percent":60},
    "direct:ice_restart":{"sampled":30,"positive":20,"percent":60},
    "direct:relay":{"sampled":30,"positive":20,"percent":60}
  }'::jsonb or quality->'metrics'->'meeting:mos:4_or_more' is distinct from '10'::jsonb then
    raise exception 'Rate denominators, rare outcome suppression, or MOS aggregation failed';
  end if;
end $$;
reset role;

rollback;
