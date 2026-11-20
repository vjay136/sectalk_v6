begin;

do $$
declare
  operator_id uuid:=gen_random_uuid();
  reviewer_id uuid:=gen_random_uuid();
  target_id uuid:=gen_random_uuid();
  operator_session uuid:=gen_random_uuid();
  reviewer_session uuid:=gen_random_uuid();
  target_session uuid:=gen_random_uuid();
  actor uuid;
  factor uuid;
  request_time timestamptz;
begin
  foreach actor in array array[operator_id,reviewer_id,target_id] loop
    insert into auth.users(id,email,email_confirmed_at,encrypted_password)
      values(actor,actor||'@example.invalid',now(),'fixture');
    insert into auth.identities(provider_id,user_id,identity_data,provider)
      values(actor::text,actor,jsonb_build_object('sub',actor),'email');
    insert into public.st_profiles(id,handle,name) values(actor,'qa_'||left(actor::text,8),'Admin management test');
    factor:=gen_random_uuid();
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id)
      values(case actor when operator_id then operator_session when reviewer_id then reviewer_session else target_session end,
        actor,'aal2',factor);
  end loop;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    select gen_random_uuid(),s,'totp',now(),now() from unnest(array[operator_session,reviewer_session,target_session]) s;
  insert into sectalk_private.st_v7_account_operators(user_id,capability)
    values(operator_id,'operator'),(reviewer_id,'reviewer');

  perform set_config('request.jwt.claims',jsonb_build_object('sub',operator_id,'role','authenticated',
    'session_id',operator_session,'aal','aal2')::text,true);
  if has_function_privilege('anon','public.st_v7_account_admin_action(uuid,text,text)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v7_account_admin_audit','select')
    or has_table_privilege('authenticated','sectalk_private.st_v7_account_operators','insert')
    then raise exception 'Admin privileges or audit were exposed'; end if;
  set local role authenticated;
  perform public.st_v7_account_admin_action(target_id,'reset_requested','QA-001 verified customer request');
  begin
    perform public.st_v7_account_admin_action(target_id,'reset_completed','QA-001 independent approval bypass');
    raise exception 'An operator approved their own request';
  exception when insufficient_privilege then null; end;
  reset role;
  select c.requested_at into request_time from sectalk_private.st_v7_account_security_changes c where c.user_id=target_id
    and c.ready_at=c.requested_at+interval '24 hours' and c.expires_at=c.requested_at+interval '7 days';
  if request_time is null then raise exception 'The reset did not start its cooling-off period'; end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',reviewer_id,'role','authenticated',
    'session_id',reviewer_session,'aal','aal2')::text,true);
  set local role authenticated;
  begin
    perform public.st_v7_account_admin_action(target_id,'reset_completed','QA-001 early approval');
    raise exception 'A reviewer approved before the cooling-off period';
  exception when invalid_parameter_value then null; end;
  reset role;
  update sectalk_private.st_v7_account_security_changes set ready_at=now()-interval '1 minute' where user_id=target_id;
  delete from sectalk_private.st_v7_account_operators where user_id=operator_id;
  set local role authenticated;
  begin
    perform public.st_v7_account_admin_action(target_id,'reset_completed','QA-001 grant revocation check');
    raise exception 'A revoked requestor authorized account recovery';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into sectalk_private.st_v7_account_operators values(operator_id,'operator');

  set local role authenticated;
  perform public.st_v7_account_admin_action(target_id,'reset_completed','QA-001 independent customer verification');
  reset role;
  if exists(select 1 from auth.mfa_factors where user_id=target_id)
    or exists(select 1 from auth.sessions where user_id=target_id)
    or (select count(*) from sectalk_private.st_v7_account_admin_audit where target=target_id)<>2
    or (select count(*) from sectalk_private.st_v7_account_security_events where user_id=target_id)<>2
    then raise exception 'Account reset did not revoke factors and sessions or retain complete audit'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',target_id,'role','authenticated',
    'session_id',target_session,'aal','aal2')::text,true);
  set local role authenticated;
  if not public.st_v7_account_data_unavailable() then raise exception 'Old bearer token still passes the data gate'; end if;
  reset role;
  target_session:=gen_random_uuid();
  insert into auth.sessions(id,user_id,aal) values(target_session,target_id,'aal1');
  perform set_config('request.jwt.claims',jsonb_build_object('sub',target_id,'role','authenticated',
    'session_id',target_session,'aal','aal1')::text,true);
  set local role authenticated;
  if public.st_v7_account_data_unavailable() then raise exception 'Account recovery blocked a new legitimate session'; end if;
end $$;

select 'passed: native account operator and reviewer authority, cooling-off, revoked request, factor/session revocation and audit' as result;
rollback;
