begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid(); other uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid();
  sso_session uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid();
  workspace uuid; second_workspace uuid;
  provider text:='custom:directory-sso-rollback'; domain text:='directory-sso.example.invalid';
  other_handle text:='dir_'||left(replace(other::text,'-',''),12);
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  plain_claim text:=jsonb_build_object('sub',actor,'session_id',password_session,'role','authenticated')::text;
  provider_claim text:=jsonb_build_object('sub',actor,'session_id',sso_session,'role','authenticated')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'owner@directory-sso.example.invalid',now()),
    (actor,'member@directory-sso.example.invalid',now()),(other,'other@directory-sso.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values(owner_id,'dir_'||left(replace(owner_id::text,'-',''),12),'Directory owner'),
    (actor,'dir_'||left(replace(actor::text,'-',''),12),'Directory member'),
    (other,other_handle,'Directory hidden sentinel');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),
    (sso_session,actor,'aal1',null),(password_session,actor,'aal1',null);
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Fixture OIDC','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  workspace:=public.st_v2_create_workspace('Workspace directory SSO fixture');
  second_workspace:=public.st_v2_create_workspace('Separate unprotected directory');
  if public.st_v8_workspace_directory_policy(workspace,true)->>'access' is distinct from 'mfa' then
    raise exception 'Owner enabled directory SSO without fresh TOTP'; end if;
  reset role;

  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(workspace,domain,now());
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,actor,'member'),(workspace,other,'member'),(second_workspace,actor,'member');
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(workspace,'save',domain,'oidc',true);
  if public.st_v8_workspace_directory_policy(workspace,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Directory SSO enabled without observed provider session'; end if;
  if not exists(select 1 from public.st_v7_workspace_people(workspace) where id=other) then
    raise exception 'Default directory omitted staff results'; end if;
  reset role;

  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(sso_session,workspace,actor,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_directory_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not require directory SSO'; end if;
  begin
    perform public.st_v7_workspace_people(workspace);
    raise exception 'Password owner could read protected staff directory';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v2_set_member(workspace,other,'suspend');
    raise exception 'Password owner could manage protected directory members';
  exception when insufficient_privilege then null;
  end;

  perform set_config('request.jwt.claims',plain_claim,true);
  if not public.st_v8_workspace_directory_requires_sso(workspace)
    or public.st_v8_workspace_directory_requires_sso(second_workspace)
    or not exists(select 1 from public.st_v2_members where workspace_id=workspace and user_id=actor)
    or exists(select 1 from public.st_v2_members where workspace_id=workspace and user_id=other)
    or exists(select 1 from public.st_profiles where id=other)
    or exists(select 1 from public.st_v6_search_people where id=other)
    or exists(select 1 from public.st_v6_search(other_handle,'person','{}') where id=other) then
    raise exception 'Password session saw protected membership or profiles, or lost its own membership'; end if;
  perform set_config('request.jwt.claims',provider_claim,true);
  if public.st_v8_workspace_directory_requires_sso(workspace)
    or not exists(select 1 from public.st_v2_members where workspace_id=workspace and user_id=other)
    or not exists(select 1 from public.st_profiles where id=other)
    or not exists(select 1 from public.st_v6_search(other_handle,'person','{}') where id=other) then
    raise exception 'Provider receipt did not restore member, profile and Search access'; end if;
  if public.st_v8_workspace_directory_policy(workspace,false)->>'required' is not null then
    raise exception 'Ordinary SSO member could recover directory settings'; end if;
  reset role;

  insert into public.st_v2_members(workspace_id,user_id,role) values(second_workspace,other,'member');
  set local role authenticated;
  perform set_config('request.jwt.claims',plain_claim,true);
  if not exists(select 1 from public.st_profiles where id=other)
    or not exists(select 1 from public.st_v6_search_people where id=other)
    or exists(select 1 from public.st_v2_members where workspace_id=workspace and user_id=other) then
    raise exception 'Another shared workspace failed to preserve ordinary profile access'; end if;
  reset role;

  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  perform set_config('request.jwt.claims',provider_claim,true);
  if not public.st_v8_workspace_directory_requires_sso(workspace)
    or exists(select 1 from public.st_v2_members where workspace_id=workspace and user_id=other) then
    raise exception 'Disabled provider retained scoped directory access'; end if;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_directory_policy(workspace,false)->>'required' is distinct from 'false' then
    raise exception 'Fresh owner could not recover the directory'; end if;
  if not exists(select 1 from public.st_v7_workspace_people(workspace) where id=other) then
    raise exception 'Staff directory stayed blocked after recovery'; end if;
  perform public.st_v2_set_member(workspace,other,'suspend');
  if not exists(select 1 from public.st_v7_workspace_people(workspace,p_status=>'suspended') where id=other) then
    raise exception 'Member management did not restore after recovery'; end if;
end $$;
rollback;
