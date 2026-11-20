begin;

do $$
declare
  operator_id uuid := gen_random_uuid(); reviewer_id uuid := gen_random_uuid();
  target_id uuid := gen_random_uuid(); outsider_id uuid := gen_random_uuid();
  operator_session uuid := gen_random_uuid(); reviewer_session uuid := gen_random_uuid();
  flagged uuid := gen_random_uuid(); valid uuid := gen_random_uuid(); foreign_session uuid := gen_random_uuid();
  actor uuid; native_session uuid; factor uuid;
begin
  foreach actor in array array[operator_id,reviewer_id,target_id,outsider_id] loop
    insert into auth.users(id,email,email_confirmed_at,encrypted_password)
      values(actor,actor||'@example.invalid',now(),'fixture');
    insert into auth.identities(provider_id,user_id,identity_data,provider)
      values(actor::text,actor,jsonb_build_object('sub',actor),'email');
    insert into public.st_profiles(id,handle,name) values(actor,'ts_'||left(actor::text,8),'Operator session fixture');
    if actor in (operator_id,reviewer_id) then
      factor:=gen_random_uuid();
      native_session:=case when actor=operator_id then operator_session else reviewer_session end;
      insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
        values(factor,actor,'totp','verified',now(),now());
      insert into auth.sessions(id,user_id,aal,factor_id) values(native_session,actor,'aal2',factor);
      insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
        values(gen_random_uuid(),native_session,'totp',now(),now());
    end if;
  end loop;
  insert into auth.sessions(id,user_id,aal,user_agent,ip) values
    (flagged,target_id,'aal1','Edg/123.0 opaque operator fixture','192.0.2.12'),
    (valid,target_id,'aal1','Firefox/124','192.0.2.14'),(foreign_session,outsider_id,'aal1','Chrome/125','192.0.2.16');
  insert into sectalk_private.st_v7_session_scores(session_id,user_id,score,signals,provider,latitude,longitude,radius_km)
    values(flagged,target_id,65,array['impossible_travel'],'matched',20,30,150);
  insert into sectalk_private.st_v7_account_operators values(operator_id,'operator'),(reviewer_id,'reviewer');

  if has_function_privilege('anon','public.st_v7_account_admin_sessions(uuid)','execute')
    or has_function_privilege('anon','public.st_v7_account_admin_revoke_session(uuid,uuid,text)','execute') then
    raise exception 'Anonymous session operations exposure';
  end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',outsider_id,'role','authenticated',
    'session_id',foreign_session,'aal','aal1')::text,true);
  set local role authenticated;
  begin
    perform public.st_v7_account_admin_sessions(target_id);
    raise exception 'An ordinary user viewed another account''s sessions';
  exception when insufficient_privilege then null; end;
  reset role;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',reviewer_id,'role','authenticated',
    'session_id',reviewer_session,'aal','aal2')::text,true);
  set local role authenticated;
  if (select count(*) from public.st_v7_account_admin_sessions(target_id))<>2 then raise exception 'Reviewer inventory mismatch'; end if;
  begin
    perform public.st_v7_account_admin_revoke_session(target_id,flagged,'QA-100 reviewer may not revoke');
    raise exception 'A review-only account revoked a session';
  exception when insufficient_privilege then null; end;
  reset role;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',operator_id,'role','authenticated',
    'session_id',operator_session,'aal','aal2')::text,true);
  set local role authenticated;
  if not exists(select 1 from public.st_v7_account_admin_sessions(target_id) s
    where s.id=flagged and s.browser='Edge' and s.risk='High' and s.signals=array['impossible_travel']) then
    raise exception 'Safe risk projection mismatch';
  end if;
  if public.st_v7_account_admin_revoke_session(target_id,foreign_session,'QA-100 target-session pairing check') then
    raise exception 'A foreign session was revoked';
  end if;
  if not public.st_v7_account_admin_revoke_session(target_id,flagged,'QA-100 independently reviewed risk')
    or public.st_v7_account_admin_revoke_session(target_id,flagged,'QA-100 concurrent retry is harmless') then
    raise exception 'Scoped and idempotent revocation failed';
  end if;
  reset role;
  if exists(select 1 from auth.sessions where id=flagged)
    or (select count(*) from auth.sessions where id in (valid,foreign_session))<>2
    or (select count(*) from sectalk_private.st_v7_account_admin_audit a where a.target=target_id and a.request_id=flagged
      and a.action='session_revoked' and a.actor=operator_id)<>1 then
    raise exception 'Native session state or audit mismatch';
  end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',target_id,'role','authenticated',
    'session_id',flagged,'aal','aal1')::text,true);
  set local role authenticated;
  if not public.st_v7_account_data_unavailable() then raise exception 'Stale token still has access'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',target_id,'role','authenticated',
    'session_id',valid,'aal','aal1')::text,true);
  if public.st_v7_account_data_unavailable() then raise exception 'Healthy session was restricted'; end if;
end $$;

select 'passed: isolated operator session inventory, risk projection, scoped revocation, stale bearer denial and audit' as result;
rollback;
