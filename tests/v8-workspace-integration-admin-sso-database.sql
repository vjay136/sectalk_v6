begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid(); signed_session uuid:=gen_random_uuid();
  space uuid; other_space uuid; endpoint uuid:=gen_random_uuid(); key_id uuid; replacement uuid;
  job uuid; lease uuid:=gen_random_uuid(); digest text:=encode(extensions.gen_random_bytes(32),'hex');
  provider text:='custom:integration-admin-rollback'; domain text:='integration-admin.example.invalid';
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  sso_claim jsonb:=jsonb_build_object('sub',owner_id,'session_id',signed_session,'role','authenticated','aal','aal1');
  settings jsonb;
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (owner_id,'owner@integration-admin.example.invalid',now()),(actor,'admin@integration-admin.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values
    (owner_id,'integration_scope_owner','Integration owner'),(actor,'integration_scope_admin','Integration administrator');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),(signed_session,owner_id,'aal1',null);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Integration fixture','fixture-client','synthetic-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  space:=public.st_v2_create_workspace('Integration SSO fixture');
  other_space:=public.st_v2_create_workspace('Unprotected integrations control');
  key_id:=public.st_v6_create_integration_key(space,'Initial key','initial000',digest,array['workspace:read'],7);
  perform public.st_v6_register_webhook(space,endpoint,'Initial webhook','https://target.example.invalid/hook',repeat('a',80),array['room.created']);
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(space,actor,'admin');
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(space,domain,now());
  insert into sectalk_private.st_v6_webhook_jobs(endpoint_id,event_id,payload,lease,lease_expires)
    values(endpoint,gen_random_uuid(),'{}',lease,now()+interval '1 minute') returning id into job;
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(space,'save',domain,'oidc',false);
  if public.st_v8_workspace_integration_admin_policy(space,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Integration SSO was configured without a live workspace receipt'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(signed_session,space,owner_id,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_integration_admin_policy(space,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not configure integration SSO'; end if;
  if public.st_v6_integration_access(space) is distinct from 'sso'
    or public.st_v6_integration_access(other_space) is distinct from 'verified' then raise exception 'Integration scope was not isolated'; end if;
  begin
    perform public.st_v6_integration_key_list(space);
    raise exception 'Standard session could list keys';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_webhook_status(space);
    raise exception 'Standard session could list webhook jobs';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_create_integration_key(space,'Denied key','denied0000',repeat('c',64),array['workspace:read'],7);
    raise exception 'Standard session could create keys';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_register_webhook(space,gen_random_uuid(),'Denied endpoint','https://target.example.invalid/denied',
      repeat('a',80),array['room.created']);
    raise exception 'Standard session could register webhooks';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_revoke_integration_key(space,key_id);
    raise exception 'Standard session could revoke keys';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_revoke_webhook(space,endpoint);
    raise exception 'Standard session could revoke webhooks';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',actor,'role','authenticated')::text,true);
  if public.st_v6_integration_access(space) is distinct from 'none' then raise exception 'Non-owner integration visibility changed'; end if;
  perform set_config('request.jwt.claims',sso_claim::text,true);
  if public.st_v6_integration_access(space) is distinct from 'mfa'
    or public.st_v8_workspace_integration_admin_policy(space,false)->>'access' is distinct from 'mfa' then
    raise exception 'SSO was accepted in place of the fresh owner authenticator'; end if;
  reset role;
  update auth.sessions set aal='aal2',factor_id=factor where id=signed_session;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),signed_session,'totp',now(),now());
  set local role authenticated;
  perform set_config('request.jwt.claims',(sso_claim||'{"aal":"aal2"}'::jsonb)::text,true);
  if public.st_v6_integration_access(space) is distinct from 'verified'
    or not exists(select from public.st_v6_integration_key_list(space) where id=key_id)
    or not (public.st_v6_webhook_status(space) @> jsonb_build_array(jsonb_build_object('id',endpoint))) then
    raise exception 'Signed and independently verified owner lost integration controls'; end if;
  replacement:=public.st_v6_create_integration_key(space,'Authorized replacement','replace000',repeat('b',64),array['workspace:read'],7);
  perform public.st_v6_revoke_integration_key(space,replacement);
  if not exists(select from public.st_v6_integration_key_list(space) where id=replacement and revoked_at is not null) then
    raise exception 'Verified signed owner could not revoke a key'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  if public.st_v6_integration_access(space) is distinct from 'sso' then raise exception 'Disabled provider retained integration access'; end if;
  reset role;
  set local role service_role;
  perform set_config('request.jwt.claims','{"role":"service_role"}',true);
  if public.st_v6_integration_read(digest,'workspace',null,5)#>>'{data,id}' is distinct from space::text
    or not public.st_v6_webhook_lease_active(job,lease) then raise exception 'Integration SSO blocked a separate live credential'; end if;
  perform public.st_v6_finish_webhook(job,lease,204,false);
  reset role;
  if not exists(select from sectalk_private.st_v6_webhook_jobs where id=job and state='sent') then
    raise exception 'Worker could not finish queued work after provider disable'; end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  settings:=public.st_v8_workspace_integration_admin_policy(space,false);
  if settings->>'required' is distinct from 'false' or public.st_v6_integration_access(space) is distinct from 'verified' then
    raise exception 'Fresh owner recovery did not restore credential administration'; end if;
end $$;
rollback;
