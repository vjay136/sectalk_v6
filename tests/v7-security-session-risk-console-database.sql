begin;

do $$
declare
  operator_id uuid:=gen_random_uuid(); target_id uuid:=gen_random_uuid();
  operator_session uuid:=gen_random_uuid(); target_session uuid:=gen_random_uuid(); sibling_session uuid:=gen_random_uuid();
  person uuid; factor uuid; target_factor uuid;
  old_proof timestamptz:=clock_timestamp()-interval '2 minutes';
  new_proof timestamptz:=clock_timestamp()+interval '2 seconds';
  operator_claims text; old_claims jsonb;
begin
  foreach person in array array[operator_id,target_id] loop
    insert into auth.users(id,email,email_confirmed_at,encrypted_password)
      values(person,person||'@example.invalid',now(),'fixture');
    insert into auth.identities(provider_id,user_id,identity_data,provider)
      values(person::text,person,jsonb_build_object('sub',person),'email');
    insert into public.st_profiles(id,handle,name) values(person,'risk_'||left(person::text,8),'Risk console fixture');
    factor:=gen_random_uuid();
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor,person,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(
      case when person=operator_id then operator_session else target_session end,person,'aal2',factor);
    if person=target_id then target_factor:=factor; end if;
  end loop;
  insert into auth.sessions(id,user_id,aal,factor_id) values(sibling_session,target_id,'aal2',target_factor);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
    (gen_random_uuid(),operator_session,'totp',now(),now()),
    (gen_random_uuid(),target_session,'totp',old_proof,old_proof),
    (gen_random_uuid(),sibling_session,'totp',old_proof,old_proof);
  insert into sectalk_private.st_v7_session_scores(session_id,user_id,score,signals,provider,latitude,longitude,radius_km) values
    (target_session,target_id,65,array['impossible_travel'],'matched',10,25,200),
    (sibling_session,target_id,60,array['tor'],'matched',null,null,null);
  insert into sectalk_private.st_v7_account_operators values(operator_id,'operator');
  operator_claims:=jsonb_build_object('sub',operator_id,'role','authenticated','session_id',operator_session,'aal','aal2')::text;
  old_claims:=jsonb_build_object('sub',target_id,'role','authenticated','session_id',target_session,'aal','aal2',
    'amr',jsonb_build_array(jsonb_build_object('method','totp','timestamp',extract(epoch from date_trunc('second',old_proof))::bigint)));

  perform set_config('request.jwt.claims',old_claims::text,true);
  set local role authenticated;
  if public.st_v7_login_risk_status()<>'clear' then raise exception 'Baseline native proof was denied'; end if;
  begin
    perform public.st_v7_security_risk_sessions(true);
    raise exception 'An ordinary account opened security risk data';
  exception when insufficient_privilege then null; end;
  reset role;

  perform set_config('request.jwt.claims',operator_claims,true);
  set local role authenticated;
  if (select count(*) from public.st_v7_security_risk_sessions(true))<>1 or
      (select count(*) from public.st_v7_security_risk_sessions(false))<>2 then
    raise exception 'Impossible-travel and high-risk filters diverged';
  end if;
  if not public.st_v7_require_risk_session_totp(target_id,target_session,'QA-T12 risk decision with case reference')
      or public.st_v7_require_risk_session_totp(target_id,target_session,'QA-T12 identical queued request retry') then
    raise exception 'Authenticated risk step-up was not idempotent';
  end if;
  reset role;

  perform set_config('request.jwt.claims',old_claims::text,true);
  set local role authenticated;
  if public.st_v7_login_risk_status()<>'authenticator' then raise exception 'Old AAL2 token bypassed requested proof'; end if;
  reset role;
  update auth.mfa_amr_claims set updated_at=new_proof where session_id=target_session and authentication_method='totp';
  set local role authenticated;
  if public.st_v7_login_risk_status()<>'authenticator' then raise exception 'Old token borrowed recent proof from a new token'; end if;
  perform set_config('request.jwt.claims',jsonb_set(old_claims,'{amr,0,timestamp}',
    to_jsonb(extract(epoch from date_trunc('second',new_proof))::bigint))::text,true);
  if public.st_v7_login_risk_status()<>'clear' then raise exception 'New native proof did not restore access'; end if;
  reset role;

  perform set_config('request.jwt.claims',operator_claims,true);
  set local role authenticated;
  if (select s.step_up_state from public.st_v7_security_risk_sessions(true) s where s.session_id=target_session)<>'verified'
    then raise exception 'Operator verification state did not refresh'; end if;
  if not public.st_v7_account_admin_revoke_session(target_id,target_session,'QA-T12 terminate after review') then
    raise exception 'Authorized termination failed';
  end if;
  reset role;
  if (select count(*) from sectalk_private.st_v7_account_admin_audit a where a.target=target_id and a.request_id=target_session)<>2
    or not exists(select 1 from auth.sessions where id=sibling_session) then
    raise exception 'Risk audit linkage or surviving session guarantee was lost';
  end if;
end $$;

select 'passed: risk console scope, impossible-travel filter, stale assurance denial, proof freshness and audited termination' as result;
rollback;
