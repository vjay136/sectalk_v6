begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid(); other uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid();
  sso_session uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid();
  workspace uuid; second_workspace uuid;
  team uuid:=gen_random_uuid(); other_team uuid:=gen_random_uuid(); classroom uuid:=gen_random_uuid(); delegated uuid:=gen_random_uuid();
  provider text:='custom:groups-sso-rollback'; domain text:='groups-sso.example.invalid';
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  plain_claim text:=jsonb_build_object('sub',actor,'session_id',password_session,'role','authenticated')::text;
  provider_claim text:=jsonb_build_object('sub',actor,'session_id',sso_session,'role','authenticated')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'owner@groups-sso.example.invalid',now()),
    (actor,'member@groups-sso.example.invalid',now()),(other,'other@groups-sso.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values(owner_id,'dir_'||left(replace(owner_id::text,'-',''),12),'Groups owner'),
    (actor,'dir_'||left(replace(actor::text,'-',''),12),'Groups member'),
    (other,'grp_'||left(replace(other::text,'-',''),12),'Other roster member');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),
    (sso_session,actor,'aal1',null),(password_session,actor,'aal1',null);
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Fixture OIDC','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  workspace:=public.st_v6_create_typed_workspace(gen_random_uuid(),'Workspace groups SSO fixture','school');
  second_workspace:=public.st_v2_create_workspace('Separate unprotected groups');
  if public.st_v8_workspace_groups_policy(workspace,true)->>'access' is distinct from 'mfa' then
    raise exception 'Owner enabled groups SSO without fresh TOTP'; end if;
  reset role;

  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(workspace,domain,now());
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,actor,'member'),(workspace,other,'member'),(second_workspace,actor,'member');
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(workspace,'save',domain,'oidc',true);
  if public.st_v8_workspace_groups_policy(workspace,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Groups SSO enabled without observed provider session'; end if;
  perform public.st_v6_workspace_group_create(workspace,team,'team','Receipt team','Protected roster');
  perform public.st_v6_workspace_group_create(second_workspace,other_team,'team','Outside team','Normal roster');
  perform public.st_v6_workspace_group_change(workspace,team,'member_added',p_user=>other);
  perform public.st_v7_school_classes(workspace,'create',classroom,'Independent classroom');
  perform public.st_v7_workspace_custom_roles(workspace,'save',delegated,0,jsonb_build_object(
    'name','One team editor','target',team,'permissions',array['rename'],'enabled',true,'device','any'));
  perform public.st_v7_workspace_custom_roles(workspace,'assign',delegated,1,p_account=>actor);
  if not exists(select 1 from public.st_v6_workspace_group_members where group_id=team and user_id=other) then
    raise exception 'Default group membership unexpectedly hidden'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(sso_session,workspace,actor,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_groups_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not require groups SSO'; end if;
  if not public.st_v8_workspace_groups_requires_sso(workspace)
    or exists(select 1 from public.st_v6_workspace_groups where id=team)
    or exists(select 1 from public.st_v6_workspace_group_members where group_id=team)
    or not exists(select 1 from public.st_v6_workspace_groups where id=classroom)
    or not exists(select 1 from public.st_v6_workspace_groups where id=other_team)
    or jsonb_array_length(public.st_v7_school_classes(workspace))<>1 then
    raise exception 'Groups SSO leaked protected rows, hid School or hid another workspace'; end if;
  begin
    perform public.st_v6_workspace_group_create(workspace,gen_random_uuid(),'team','Blocked team','');
    raise exception 'Password owner created a protected team';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_workspace_group_change(workspace,team,'member_added',p_user=>actor);
    raise exception 'Password owner changed a protected roster';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',plain_claim,true);
  if not public.st_v8_workspace_groups_requires_sso(workspace)
    or cardinality(public.st_v7_custom_group_access(workspace,team))<>0 then
    raise exception 'Password member retained protected delegation'; end if;
  begin
    perform public.st_v6_workspace_group_change(workspace,team,'rename','Blocked name','');
    raise exception 'Password member updated protected team through delegated role';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',provider_claim,true);
  if public.st_v8_workspace_groups_requires_sso(workspace)
    or not exists(select 1 from public.st_v6_workspace_groups where id=team)
    or not exists(select 1 from public.st_v6_workspace_group_members where group_id=team and user_id=other)
    or public.st_v7_custom_group_access(workspace,team)<>array['rename'] then
    raise exception 'Live provider session lost group, roster or existing delegation'; end if;
  perform public.st_v6_workspace_group_change(workspace,team,'rename','Named via signed workspace session','');
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  if not public.st_v8_workspace_groups_requires_sso(workspace)
    or exists(select 1 from public.st_v6_workspace_groups where id=team) then
    raise exception 'Disabled provider retained groups access'; end if;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_groups_policy(workspace,false)->>'required' is distinct from 'false' then
    raise exception 'Fresh owner could not recover group access'; end if;
  if not exists(select 1 from public.st_v6_workspace_groups where id=team and name='Named via signed workspace session') then
    raise exception 'Groups stayed blocked after recovery or delegated change failed'; end if;
end $$;
rollback;
