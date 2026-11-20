begin;

insert into auth.users(id,email,email_confirmed_at) values
  ('7f300000-0000-4000-8000-000000000001','report-owner@example.invalid',now()),
  ('7f300000-0000-4000-8000-000000000002','report-other@example.invalid',now());
insert into public.st_profiles(id,handle,name) values
  ('7f300000-0000-4000-8000-000000000001','report_owner','Owner'),
  ('7f300000-0000-4000-8000-000000000002','report_other','Other');
insert into sectalk_private.staff(user_id) values
  ('7f300000-0000-4000-8000-000000000001'),('7f300000-0000-4000-8000-000000000002');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
  ('7f310000-0000-4000-8000-000000000001','7f300000-0000-4000-8000-000000000001','totp','verified',now(),now()),
  ('7f310000-0000-4000-8000-000000000002','7f300000-0000-4000-8000-000000000002','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
  ('7f320000-0000-4000-8000-000000000001','7f300000-0000-4000-8000-000000000001','aal2','7f310000-0000-4000-8000-000000000001'),
  ('7f320000-0000-4000-8000-000000000002','7f300000-0000-4000-8000-000000000002','aal2','7f310000-0000-4000-8000-000000000002');
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
  (gen_random_uuid(),'7f320000-0000-4000-8000-000000000001','totp',now(),now()),
  (gen_random_uuid(),'7f320000-0000-4000-8000-000000000002','totp',now(),now());
insert into sectalk_private.st_v6_operation_rollups values
  ('2020-02-01 15:50+00','file_upload',10,2,1,0,1,3,array[4,0,0,5,0,1,0,0,0]),
  ('2020-02-01 15:50+00','billing_webhook',9,0,0,0,0,1,array[9,0,0,0,0,0,0,0,0]),
  ('2020-02-01 16:00+00','meeting_token',20,0,0,0,0,1,array[20,0,0,0,0,0,0,0,0]);

do $$
declare
  owner_id constant uuid:='7f300000-0000-4000-8000-000000000001';
  other_id constant uuid:='7f300000-0000-4000-8000-000000000002';
  owner_session constant uuid:='7f320000-0000-4000-8000-000000000001';
  other_session constant uuid:='7f320000-0000-4000-8000-000000000002';
  acquisition constant uuid:=gen_random_uuid();
  job record;
  snapshot jsonb;
begin
  if has_function_privilege('authenticated','public.st_v6_claim_operational_reports(uuid)','execute')
    or has_function_privilege('anon','public.st_v6_operational_report_export(uuid)','execute')
    or has_table_privilege('service_role','sectalk_private.st_v6_operational_report_runs','select') then
    raise exception 'Report payloads or worker functions are too broadly accessible';
  end if;
  snapshot:=sectalk_private.st_v6_operational_report_snapshot('2020-02-01 16:00+00',interval '24 hours');
  if snapshot is distinct from '[{"operation":"file_upload","requests":10,"client_errors":2,"server_errors":1,"throttled":0,
    "unavailable":1,"peak_in_flight":3,"p50_band":4,"p95_band":6}]'::jsonb then
    raise exception 'Incorrect aggregation, minimum row size, or completed bucket boundary';
  end if;

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'aal','aal1','session_id',owner_session)::text,true);
  begin
    perform public.st_v6_set_operational_report('daily',true);
    raise exception 'AAL1 could create a staff report schedule' using errcode='P0100';
  exception when sqlstate '42501' then null; end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'aal','aal2','session_id',owner_session)::text,true);
  begin
    perform public.st_v6_set_operational_report('hourly',true);
    raise exception 'An unbounded cadence was accepted' using errcode='P0100';
  exception when sqlstate 'P0001' then null; end;
  perform public.st_v6_set_operational_report('daily',true);
  reset role;
  if exists(select 1 from public.st_v6_claim_operational_reports(gen_random_uuid()) delivery
    where delivery.email='report-owner@example.invalid') then raise exception 'A report was queued before it was due'; end if;
  update sectalk_private.st_v6_operational_report_schedules set next_at=now() where owner=owner_id;
  select * into job from public.st_v6_claim_operational_reports(acquisition) delivery
    where delivery.email='report-owner@example.invalid';
  if job.id is null or not public.st_v6_confirm_operational_report(job.id,job.lease)
    or exists(select 1 from public.st_v6_claim_operational_reports(acquisition)) then
    raise exception 'The report schedule or idempotent worker claim failed';
  end if;

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',other_id::text,true);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',other_id,'aal','aal2','session_id',other_session)::text,true);
  if public.st_v6_operational_report_export(job.id) is not null then raise exception 'Another staff account exported the report'; end if;
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'aal','aal2','session_id',owner_session)::text,true);
  if public.st_v6_operational_report_export(job.id)->'rows' is distinct from job.rows then
    raise exception 'The owner export differs from the immutable email snapshot';
  end if;
  perform public.st_v6_set_operational_report('daily',false);
  reset role;
  if public.st_v6_confirm_operational_report(job.id,job.lease) then raise exception 'Pause retained a usable email lease'; end if;
  perform public.st_v6_set_operational_report('weekly',true);
  update auth.users set email='unconsented-new-address@example.invalid' where id=owner_id;
  update sectalk_private.st_v6_operational_report_schedules set next_at=now() where owner=owner_id;
  perform public.st_v6_claim_operational_reports(gen_random_uuid());
  if exists(select 1 from sectalk_private.st_v6_operational_report_schedules where owner=owner_id and active) then
    raise exception 'Report delivery consent was carried to a different email address';
  end if;
end $$;

select 'passed: suppressed aggregate snapshots, MFA ownership, bounded schedules and verified email consent' as result;
rollback;
