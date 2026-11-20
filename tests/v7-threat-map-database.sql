begin;

do $$
declare
  operator_id uuid:=gen_random_uuid(); operator_session uuid:=gen_random_uuid(); factor uuid:=gen_random_uuid();
  subject uuid; native_session uuid; duplicated_subject uuid;
  yesterday date:=(now() at time zone 'UTC')::date-1;
  pseudonym text:=encode(extensions.gen_random_bytes(32),'hex');
  claims text; result jsonb; index integer; cohort_asn bigint;
begin
  insert into auth.users(id,email,email_confirmed_at,encrypted_password)
    values(operator_id,operator_id||'@example.invalid',now(),'fixture');
  insert into public.st_profiles(id,handle,name) values(operator_id,'map_'||left(operator_id::text,8),'Map operator fixture');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,operator_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(operator_session,operator_id,'aal2',factor);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),operator_session,'totp',now(),now());
  insert into sectalk_private.st_v7_account_operators values(operator_id,'operator');
  insert into sectalk_private.st_v7_password_failures(identifier,minute,attempts) values(pseudonym,date_trunc('minute',now()),4);
  for index in 1..12 loop
    subject:=case when index=12 then duplicated_subject else gen_random_uuid() end;
    native_session:=gen_random_uuid();
    cohort_asn:=case when index<=7 then 4200001440 else 4200001880 end;
    if index<>12 then
      insert into auth.users(id,email,email_confirmed_at,encrypted_password)
        values(subject,subject||'@example.invalid',now(),'fixture');
    end if;
    if index=11 then duplicated_subject:=subject; end if;
    insert into auth.sessions(id,user_id,aal,ip,user_agent) values(native_session,subject,'aal1','192.0.2.10','Chrome/125');
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),native_session,'password',now(),now());
    perform public.st_v7_score_password_session(subject,native_session,pseudonym,jsonb_build_object(
      'asn',cohort_asn,'reputation','poor','tor',false,'vpn',false,'confidence',90,'radiusKm',120,
      'latitude',case when index<=7 then 48 else -33 end,'longitude',case when index<=7 then 16 else 152 end));
    if index<=7 then
      insert into sectalk_private.st_v7_account_admin_audit(actor,target,action,request_id,reason,occurred_at)
        values(operator_id,subject,'session_revoked',native_session,'QA map audited local threat response',now()-interval '1 day');
    end if;
  end loop;
  update sectalk_private.st_v7_threat_observations o set observed_day=yesterday
    where o.asn in (4200001440,4200001880) and o.event='high_risk_sign_in';
  if not exists(select 1 from sectalk_private.st_v7_threat_observations where asn=4200001440 and latitude_band=6 and longitude_band=9)
    or has_table_privilege('authenticated','sectalk_private.st_v7_threat_observations','select') then
    raise exception 'Source quantization or private storage failed';
  end if;
  claims:=jsonb_build_object('sub',operator_id,'role','authenticated','session_id',operator_session,'aal','aal2')::text;
  perform set_config('request.jwt.claims',claims,true);
  set local role authenticated;
  result:=public.st_v7_security_threat_map(yesterday);
  if result::text not like '%4200001440%' or result::text like '%4200001880%'
    or not exists(select 1 from jsonb_array_elements(result->'cells') c where c->>'event'='high_risk_sign_in'
      and c->>'latitude_band'='6' and c->>'longitude_band'='9' and c->>'accounts_floor'='5')
    or not exists(select 1 from jsonb_array_elements(result->'networks') n where n->>'event'='session_terminated'
      and n->>'asn'='4200001440' and n->>'accounts_floor'='5')
    or result::text ~ '(subject_tag|session_tag|192\.0\.2\.10|account_id|coordinates)' then
    raise exception 'Privacy bounds or threat action aggregation failed';
  end if;
  begin
    perform public.st_v7_security_threat_map(yesterday+1);
    raise exception 'The open day allowed repeated count sampling';
  exception when invalid_parameter_value then null; end;
  reset role;
  delete from sectalk_private.st_v7_account_operators where user_id=operator_id;
  set local role authenticated;
  begin
    perform public.st_v7_security_threat_map(yesterday);
    raise exception 'Removed operator still read the map';
  exception when insufficient_privilege then null; end;
  reset role;
end $$;

select 'passed: trusted risk intake, coarse cells, rounded cohorts, small-group suppression, current-day denial and operator scope' as result;
rollback;
