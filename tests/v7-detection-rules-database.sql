begin;

do $$
declare
  operator_id uuid:=gen_random_uuid();
  outsider_id uuid:=gen_random_uuid();
  actor_session uuid:=gen_random_uuid();
  other_session uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid();
  verified_claim text;
  test_rule uuid;
  anomaly_rule uuid;
  trial jsonb;
  single_error jsonb:='[{"operation":"file_upload","duration_ms":80,"status":400,"in_flight":1}]';
  reason text:='QA recorded and reviewed detection rollout';
begin
  insert into auth.users(id,email) values(operator_id,operator_id||'@example.invalid'),(outsider_id,outsider_id||'@example.invalid');
  insert into public.st_profiles(id,handle,name) values
    (operator_id,'rule_'||left(operator_id::text,8),'Detection operator QA'),
    (outsider_id,'rule_'||left(outsider_id::text,8),'Unprovisioned staff QA');
  insert into sectalk_private.staff(user_id) values(outsider_id);
  insert into sectalk_private.st_v7_detection_operators(user_id) values(operator_id);
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,operator_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values
    (actor_session,operator_id,'aal2',factor),(other_session,outsider_id,'aal1',null);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),actor_session,'totp',now(),now());
  if has_function_privilege('anon','public.st_v7_detection_rules()','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v7_detection_matches','select')
    or has_function_privilege('authenticated','sectalk_private.st_v7_observe_detection_window(text,text,timestamptz)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v7_detection_versions','insert') then
    raise exception 'Detection definitions or producer entry point are exposed'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',outsider_id,'role','authenticated',
    'session_id',other_session,'aal','aal1')::text,true);
  set local role authenticated;
  if public.st_v7_detection_rule_access()<>'none' then raise exception 'Staff inherited separate provisioning'; end if;
  begin
    perform public.st_v7_detection_rules();
    raise exception 'Unprovisioned staff accessed detection data';
  exception when insufficient_privilege then null; end;
  reset role;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',operator_id,'role','authenticated',
    'session_id',actor_session,'aal','aal1')::text,true);
  set local role authenticated;
  if public.st_v7_detection_rule_access()<>'mfa' then raise exception 'AAL1 obtained verified detection access'; end if;
  begin
    perform public.st_v7_save_detection_rule(null,null,'No TOTP','operations','file_upload','client_errors',2);
    raise exception 'AAL1 operator wrote a rule';
  exception when insufficient_privilege then null; end;
  reset role;

  perform public.st_v6_record_operational_metrics(single_error||single_error);
  verified_claim:=jsonb_build_object('sub',operator_id,'role','authenticated','session_id',actor_session,'aal','aal2')::text;
  perform set_config('request.jwt.claims',verified_claim,true);
  set local role authenticated;
  begin
    perform public.st_v7_save_detection_rule(null,null,'Unsafe scope','operations','private_chat','messages',2);
    raise exception 'Unsupported plaintext source accepted';
  exception when invalid_parameter_value then null; end;
  test_rule:=public.st_v7_save_detection_rule(null,null,'Upload errors QA','operations','file_upload','client_errors',2);
  begin
    perform public.st_v7_deploy_detection_rule(test_rule,1,'shadow',reason);
    raise exception 'Untested rule could be deployed';
  exception when sqlstate 'PT409' then null; end;
  trial:=public.st_v7_test_detection_rule(test_rule,1);
  if (trial->>'matched_windows')::integer<1 then raise exception 'Historical aggregate backtest missed real samples'; end if;
  begin
    perform public.st_v7_deploy_detection_rule(test_rule,1,'enabled',reason);
    raise exception 'Rule bypassed shadow';
  exception when sqlstate 'PT409' then null; end;
  perform public.st_v7_deploy_detection_rule(test_rule,1,'shadow',reason);
  reset role;
  perform public.st_v6_record_operational_metrics('[{"operation":"file_publish","duration_ms":80,"status":400,"in_flight":1}]');
  perform public.st_v6_record_operational_metrics(single_error);
  if exists(select 1 from sectalk_private.st_v7_detection_matches m where m.rule_id=test_rule) then
    raise exception 'Baseline or unrelated operation triggered a match';
  end if;
  perform public.st_v6_record_operational_metrics(single_error||single_error);
  if (select count(*) from sectalk_private.st_v7_detection_matches m where m.rule_id=test_rule and m.mode='shadow')<>1 then
    raise exception 'Shadow detections were missing or duplicated';
  end if;
  set local role authenticated;
  perform public.st_v7_deploy_detection_rule(test_rule,1,'enabled',reason);
  reset role;
  perform public.st_v6_record_operational_metrics(single_error);
  if exists(select 1 from sectalk_private.st_v7_detection_matches m where m.rule_id=test_rule and m.mode='enabled') then
    raise exception 'Enabled mode replayed the shadow activation';
  end if;
  perform public.st_v6_record_operational_metrics(single_error);
  if not exists(select 1 from sectalk_private.st_v7_detection_matches m where m.rule_id=test_rule and m.mode='enabled' and m.observed=2) then
    raise exception 'Enabled mode did not evaluate new aggregate events';
  end if;
  set local role authenticated;
  perform public.st_v7_save_detection_rule(test_rule,1,null,'operations','file_upload','client_errors',1000000);
  if (public.st_v7_detection_rule_detail(test_rule)->>'active_version')::integer<>1 then
    raise exception 'Draft changes replaced the live version';
  end if;
  perform public.st_v7_test_detection_rule(test_rule,2);
  perform public.st_v7_deploy_detection_rule(test_rule,2,'shadow',reason);
  perform public.st_v7_deploy_detection_rule(test_rule,1,'rollback',reason);
  if not exists(select 1 from public.st_v7_detection_rules() r where r.id=test_rule and r.active_version=1 and r.mode='enabled') then
    raise exception 'Rollback did not restore the recorded version and mode'; end if;
  perform public.st_v7_deploy_detection_rule(test_rule,1,'paused',reason);
  reset role;
  perform public.st_v6_record_operational_metrics(single_error||single_error||single_error);
  if (select count(*) from sectalk_private.st_v7_detection_matches m where m.rule_id=test_rule)<>2 then
    raise exception 'Paused rule emitted new matches';
  end if;
  begin
    update sectalk_private.st_v7_detection_versions v set threshold=10 where v.rule_id=test_rule and v.version=1;
    raise exception 'Activated rule version was editable';
  exception when insufficient_privilege then null; end;

  set local role authenticated;
  anomaly_rule:=public.st_v7_save_detection_rule(null,null,'Login anomaly aggregate QA','login_anomalies','platform','anomalies',3);
  perform public.st_v7_test_detection_rule(anomaly_rule,1);
  perform public.st_v7_deploy_detection_rule(anomaly_rule,1,'shadow',reason);
  reset role;
  insert into sectalk_private.st_v7_login_anomalies(user_id,observed_session,observed_at)
    select outsider_id,gen_random_uuid(),now() from generate_series(1,2);
  if exists(select 1 from sectalk_private.st_v7_detection_matches m where m.rule_id=anomaly_rule) then
    raise exception 'Small anomaly cohort produced a match'; end if;
  insert into sectalk_private.st_v7_login_anomalies(user_id,observed_session,observed_at) values(outsider_id,gen_random_uuid(),now());
  if not exists(select 1 from sectalk_private.st_v7_detection_matches m where m.rule_id=anomaly_rule and m.observed=3)
    or not exists(select 1 from auth.sessions where id=other_session) then
    raise exception 'Anomaly feed did not record the threshold or affected native access';
  end if;
end $$;

select 'passed: dedicated TOTP, immutable versioning, backtesting, scoped live shadow/enabled, rollback, pause, and nonpunitive aggregate anomaly matches' as result;
rollback;
