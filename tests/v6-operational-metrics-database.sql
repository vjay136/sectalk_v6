\set ON_ERROR_STOP on
begin;

insert into auth.users(id,email) values
  ('6a010000-0000-4000-8000-000000000001','ops-fixture-staff@example.invalid'),
  ('6a010000-0000-4000-8000-000000000002','ops-fixture-member@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('6a010000-0000-4000-8000-000000000001','ops_fixture_staff','Operational metric staff'),
  ('6a010000-0000-4000-8000-000000000002','ops_fixture_member','Operational metric member');
insert into sectalk_private.staff values('6a010000-0000-4000-8000-000000000001');
delete from sectalk_private.st_v6_operation_rollups where operation='file_upload';
insert into sectalk_private.st_v6_operation_rollups values
  (date_bin(interval '5 minutes',statement_timestamp(),'2000-01-01Z'::timestamptz)-interval '25 hours',
   'file_upload',1,0,0,0,0,1,array[1,0,0,0,0,0,0,0,0]);

set local role service_role;
select public.st_v6_record_operational_metrics('[
  {"operation":"file_upload","duration_ms":20,"status":200,"in_flight":1},
  {"operation":"file_upload","duration_ms":40,"status":429,"in_flight":3},
  {"operation":"file_upload","duration_ms":80,"status":503,"in_flight":2},
  {"operation":"call_ice","duration_ms":250,"status":400,"in_flight":2}
]');
select public.st_v6_record_operational_metrics('[
  {"operation":"file_upload","duration_ms":12000,"status":500,"in_flight":5}
]');
do $$
begin
  begin
    perform public.st_v6_record_operational_metrics('[
      {"operation":"unrecognized-operation","duration_ms":20,"status":200,"in_flight":1}
    ]');
    raise exception 'An unapproved dimension was recorded';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_v6_record_operational_metrics((select jsonb_agg(jsonb_build_object(
      'operation','call_ice','duration_ms',20,'status',200,'in_flight',1)) from generate_series(1,129)));
    raise exception 'An oversized batch was recorded';
  exception when invalid_parameter_value then null; end;
end
$$;
reset role;

do $$
begin
  if has_function_privilege('anon','public.st_v6_operational_metrics(text)','execute')
    or has_function_privilege('authenticated','public.st_v6_record_operational_metrics(jsonb)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v6_operation_rollups','select') then
    raise exception 'Operational data or recording permissions bypass the staff/ingestion RPCs';
  end if;
end
$$;

set local role authenticated;
do $$
declare
  staffer constant uuid := '6a010000-0000-4000-8000-000000000001';
  member constant uuid := '6a010000-0000-4000-8000-000000000002';
  result jsonb;
begin
  perform set_config('request.jwt.claims',jsonb_build_object('sub',member,'aal','aal2')::text,true);
  begin
    perform public.st_v6_operational_metrics('1h');
    raise exception 'An ordinary MFA member viewed operational data';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',staffer,'aal','aal1')::text,true);
  begin
    perform public.st_v6_operational_metrics('1h');
    raise exception 'Staff without MFA viewed operational data';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',staffer,'aal','aal2')::text,true);
  select to_jsonb(r) into result from public.st_v6_operational_metrics('1h') r where r.operation='file_upload';
  if result is distinct from '{"operation":"file_upload","requests":4,"client_errors":1,"server_errors":2,
    "throttled":1,"unavailable":1,"peak_in_flight":5,"p50_band":2,"p95_band":9}'::jsonb
    then raise exception 'Operational counters, histogram quantiles or window failed: %',result; end if;
  if (select r.requests from public.st_v6_operational_metrics('24h') r where r.operation='file_upload')<>4
    or (select r.requests from public.st_v6_operational_metrics('7d') r where r.operation='file_upload')<>5
    then raise exception 'Reporting windows failed to bound old telemetry'; end if;
  begin
    perform public.st_v6_operational_metrics('30d');
    raise exception 'Unbounded history was requested';
  exception when invalid_parameter_value then null; end;
end
$$;
reset role;

insert into sectalk_private.suspensions values('6a010000-0000-4000-8000-000000000001',now()+interval '1 day');
set local role authenticated;
do $$
begin
  perform public.st_v6_operational_metrics('1h');
  raise exception 'Suspended staff retained operational metrics access';
exception when insufficient_privilege then null;
end
$$;
reset role;
select 'passed: bounded allowlisted ingestion, latency histogram, counters, pressure, time windows and staff MFA' as result;
rollback;
