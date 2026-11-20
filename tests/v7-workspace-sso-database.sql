begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid();
  sso_session uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid(); owner_factor uuid:=gen_random_uuid();
  workspace uuid; code_value uuid:=gen_random_uuid(); provider text:='custom:rollback-sso';
  cookie_digest text:=repeat('a',64); challenge text:=repeat('b',43); proof jsonb;
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'sso-owner@example.invalid',now()),(actor,'user@enterprise.example.invalid',now());
  insert into public.st_profiles values(owner_id,'sso_rollback_owner','SSO owner');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(owner_factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',owner_factor),
    (sso_session,actor,'aal1',null),(password_session,actor,'aal1',null);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
    (gen_random_uuid(),sso_session,'oauth',now(),now()),(gen_random_uuid(),password_session,'password',now(),now());
  insert into auth.identities(id,provider_id,user_id,identity_data,provider)
    values(gen_random_uuid(),'verified-subject',actor,'{"email":"user@enterprise.example.invalid","email_verified":true}',provider);
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Fixture OIDC','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values('enterprise.example.invalid',provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  workspace:=public.st_v2_create_workspace('SSO Enterprise fixture');
  if public.st_v7_workspace_sso_settings(workspace)->>'access'<>'mfa' then raise exception 'Owner read without fresh TOTP'; end if;
  if has_function_privilege('authenticated','public.st_v7_workspace_sso_claim(text,text,text)','execute') then
    raise exception 'Authenticated browser could mint scoped provenance directly';
  end if;
  reset role;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(workspace,'enterprise.example.invalid',now());
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(workspace,'save','enterprise.example.invalid','oidc',true);
  reset role;
  set local role service_role;
  proof:=public.st_v7_workspace_sso_begin('enterprise.example.invalid',cookie_digest,challenge);
  if proof->>'provider' is distinct from provider then raise exception 'Approved provider not discovered'; end if;
  if public.st_v7_workspace_sso_claim(cookie_digest,code_value::text,challenge) is not null then raise exception 'Missing native flow forged provenance'; end if;
  reset role;
  insert into auth.flow_state(id,user_id,auth_code,code_challenge_method,code_challenge,provider_type,authentication_method,auth_code_issued_at)
    values(gen_random_uuid(),actor,code_value::text,'s256',challenge,'custom:wrong','oauth',now());
  set local role service_role;
  if public.st_v7_workspace_sso_claim(cookie_digest,code_value::text,challenge) is not null then raise exception 'Wrong native provider accepted'; end if;
  reset role;
  update auth.flow_state set provider_type=provider where auth_code=code_value::text;
  set local role service_role;
  if public.st_v7_workspace_sso_claim(cookie_digest,code_value::text,repeat('c',43)) is not null then raise exception 'Wrong challenge accepted'; end if;
  proof:=public.st_v7_workspace_sso_claim(cookie_digest,code_value::text,challenge);
  if proof->>'principal' is distinct from actor::text
    or public.st_v7_workspace_sso_claim(cookie_digest,code_value::text,challenge) is not null then
    raise exception 'Native flow was not bound once to trusted subject';
  end if;
  reset role;
  update auth.sessions set created_at=clock_timestamp() where id=sso_session;
  set local role service_role;
  if public.st_v7_workspace_sso_finish(cookie_digest,actor,sso_session)->>'workspace' is distinct from workspace::text then
    raise exception 'Eligible native session was not admitted'; end if;
  reset role;
  if not exists(select 1 from public.st_v2_members where workspace_id=workspace and user_id=actor and role='member') then
    raise exception 'JIT did not safely create ordinary workspace membership';
  end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',actor,'session_id',password_session,'role','authenticated',
    'user_metadata',jsonb_build_object('provider',provider),'amr',jsonb_build_array(jsonb_build_object('method','oauth')))::text,true);
  if public.st_v7_workspace_uses_sso(workspace) then raise exception 'Password or metadata reused native receipt'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',actor,'session_id',sso_session,'role','authenticated')::text,true);
  if not public.st_v7_workspace_uses_sso(workspace) then raise exception 'Native receipt missing'; end if;
  reset role;
  delete from public.st_v2_members where workspace_id=workspace and user_id=actor;
  insert into sectalk_private.st_v7_workspace_sso_attempts(digest,challenge,workspace,protocol,provider,domain,claimed_by)
    values(repeat('d',64),challenge,workspace,'oidc',provider,'enterprise.example.invalid',actor);
  set local role service_role;
  if public.st_v7_workspace_sso_finish(repeat('d',64),actor,sso_session) is not null then raise exception 'JIT re-enrolled a removed member'; end if;
  reset role;
end
$$;
select 'passed: verified plan and domain, owner TOTP, trusted native flow, scoped receipt, JIT and durable offboarding' as result;
rollback;
