begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); member_id uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid(); signed_session uuid:=gen_random_uuid();
  space uuid:=gen_random_uuid(); other_space uuid; task uuid;
  provider text:='custom:workspace-entry-rollback'; domain text:='entry-sso.example.invalid';
  owner_claim jsonb:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2');
  signed_claim jsonb:=jsonb_build_object('sub',member_id,'session_id',signed_session,'role','authenticated','aal','aal1');
  settings jsonb;
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (owner_id,'owner@entry-sso.example.invalid',now()),(member_id,'member@entry-sso.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values
    (owner_id,'entry_policy_owner','Entry owner'),(member_id,'entry_policy_member','Entry member');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),(signed_session,member_id,'aal1',null);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Entry fixture','fixture-client','synthetic-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim::text,true);
  space:=public.st_v6_create_typed_workspace(space,'Locked entry fixture','enterprise');
  other_space:=public.st_v2_create_workspace('Unprotected entry control');
  task:=public.st_v2_add_item(space,'task','Protected task','Synthetic workspace task',null);
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(space,member_id,'member');
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(space,domain,now());
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(space,'save',domain,'oidc',false);
  if public.st_v8_workspace_entry_policy(space,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Entry policy accepted an unproven provider'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(signed_session,space,member_id,'oidc',provider);
  set local role authenticated;
  settings:=public.st_v8_workspace_entry_policy(space,true);
  if settings->>'required' is distinct from 'true'
    or exists(select 1 from public.st_v2_workspaces where id=space)
    or exists(select 1 from public.st_v6_workspace_policy where workspace_id=space)
    or exists(select 1 from public.st_v2_items where id=task)
    or not exists(select 1 from public.st_v2_workspaces where id=other_space)
    or (select count(*) from public.st_v2_members m where m.workspace_id=space)<>1
    or not exists(select 1 from public.st_v8_workspace_entry_shells(array[space,other_space]) s
      where s.id=space and s.name='Locked entry fixture') then
    raise exception 'Protected landing leaked private metadata or lost its own switcher/recovery'; end if;
  begin
    perform public.st_v2_add_item(space,'task','Unauthorized board item','Synthetic denied task',null);
    raise exception 'Password owner wrote to protected planning';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v2_set_member(space,member_id,'admin');
    raise exception 'Password owner changed protected roster';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',signed_claim::text,true);
  if not exists(select 1 from public.st_v2_workspaces where id=space)
    or not exists(select 1 from public.st_v6_workspace_policy where workspace_id=space)
    or not exists(select 1 from public.st_v2_items where id=task)
    or (select count(*) from public.st_v2_members m where m.workspace_id=space)<>2
    or exists(select 1 from public.st_v8_workspace_entry_shells(array[space,other_space]))
    or public.st_v8_workspace_entry_policy(space,false)->>'access' is distinct from 'none' then
    raise exception 'Signed member lost full workspace or accessed owner recovery'; end if;
  perform public.st_v2_complete_task(task,true);
  -- Prove the independently enabled planner restriction survives entry recovery.
  perform set_config('request.jwt.claims',owner_claim::text,true);
  perform public.st_v8_workspace_planner_policy(space,true);
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  perform set_config('request.jwt.claims',signed_claim::text,true);
  if exists(select 1 from public.st_v2_workspaces where id=space)
    or not exists(select 1 from public.st_v8_workspace_entry_shells(array[space]) s where s.id=space) then
    raise exception 'Disabled provider retained workspace entry'; end if;
  perform set_config('request.jwt.claims',owner_claim::text,true);
  settings:=public.st_v8_workspace_entry_policy(space,false);
  if settings->>'required' is distinct from 'false'
    or not exists(select 1 from public.st_v2_workspaces where id=space)
    or not exists(select 1 from public.st_v6_workspace_policy where workspace_id=space)
    or exists(select 1 from public.st_v2_items where id=task) then
    raise exception 'Fresh owner could not recover workspace entry or recovery reset planner policy'; end if;
end $$;
select 'passed: private workspace entry, own switcher, roster and planner protection, independent scopes and recovery' as result;
rollback;
