begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); delegate_id uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid(); signed_session uuid:=gen_random_uuid();
  delegate_session uuid:=gen_random_uuid();
  space uuid; other_space uuid; room uuid:=gen_random_uuid(); post uuid:=gen_random_uuid(); custom_role uuid:=gen_random_uuid();
  provider text:='custom:role-admin-rollback'; domain text:='role-admin.example.invalid';
  owner_claim jsonb:=jsonb_build_object('sub',owner_id,'session_id',password_session,'role','authenticated','aal','aal2');
  signed_claim jsonb:=owner_claim||jsonb_build_object('session_id',signed_session,'aal','aal1');
  definition jsonb:=jsonb_build_object('name','Delegate room pin','target',room,'scope_type','room',
    'permissions',array['room.pin'],'device','any','enabled',true);
  action text;
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (owner_id,'owner@role-admin.example.invalid',now()),(delegate_id,'member@role-admin.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values
    (owner_id,'role_scope_owner','Role scope owner'),(delegate_id,'role_scope_member','Role scope member');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values
    (password_session,owner_id,'aal2',factor),(signed_session,owner_id,'aal1',null),(delegate_session,delegate_id,'aal1',null);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),password_session,'totp',now(),now());
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Role management fixture','fixture-client','synthetic-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim::text,true);
  space:=public.st_v2_create_workspace('Role admin SSO fixture');
  other_space:=public.st_v2_create_workspace('Unprotected role admin control');
  perform public.st_v6_room_create(room,space,'Protected role target','private','blank');
  perform public.st_v6_room_post(room,post,'Verify existing delegated access');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(space,delegate_id,'member');
  insert into public.st_v6_room_members(room_id,user_id,role) values(room,delegate_id,'member');
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(space,domain,now());
  set local role authenticated;
  perform public.st_v7_workspace_custom_roles(space,'save',custom_role,0,definition);
  perform public.st_v7_workspace_custom_roles(space,'assign',custom_role,1,p_account=>delegate_id);
  if not (public.st_v7_custom_role_targets(space) @> jsonb_build_array(jsonb_build_object('id',room))) then
    raise exception 'Eligible resource fixture was missing before opt-in'; end if;
  perform public.st_v7_workspace_sso_settings(space,'save',domain,'oidc',false);
  if public.st_v8_workspace_custom_role_admin_policy(space,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Role policy accepted an unproven provider'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(signed_session,space,owner_id,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_custom_role_admin_policy(space,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not require role administration SSO'; end if;
  if public.st_v7_workspace_custom_roles(space) is distinct from '{"access":"sso"}'::jsonb
    or public.st_v7_custom_role_targets(space) is distinct from '[]'::jsonb
    or public.st_v7_workspace_custom_roles(other_space)->>'access' is distinct from 'verified' then
    raise exception 'Role definitions or target metadata were exposed, or another workspace was blocked'; end if;
  foreach action in array array['save','assign','revoke','gate','simulate'] loop
    if public.st_v7_workspace_custom_roles(space,action,custom_role,1,definition,delegate_id) is distinct from '{"access":"sso"}'::jsonb then
      raise exception 'Standard owner could perform role administration action %',action; end if;
  end loop;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',delegate_id,'session_id',delegate_session,
    'role','authenticated','aal','aal1')::text,true);
  if public.st_v7_workspace_custom_roles(space)->>'access' is distinct from 'none'
    or public.st_v7_custom_room_access(room) is distinct from array['room.pin'] then
    raise exception 'Ordinary member gained editor access or lost its existing assignment'; end if;
  perform public.st_v6_room_settings(room,'pin',post);
  perform set_config('request.jwt.claims',signed_claim::text,true);
  if public.st_v7_workspace_custom_roles(space)->>'access' is distinct from 'mfa'
    or public.st_v8_workspace_custom_role_admin_policy(space,false)->>'access' is distinct from 'mfa' then
    raise exception 'Provider session replaced the independent authenticator'; end if;
  reset role;
  update auth.sessions set aal='aal2',factor_id=factor where id=signed_session;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),signed_session,'totp',now(),now());
  set local role authenticated;
  perform set_config('request.jwt.claims',(signed_claim||'{"aal":"aal2"}')::text,true);
  if public.st_v7_workspace_custom_roles(space)#>>'{roles,0,id}' is distinct from custom_role::text
    or not (public.st_v7_custom_role_targets(space) @> jsonb_build_array(jsonb_build_object('id',room))) then
    raise exception 'Pinned session with fresh TOTP could not read the role and targets'; end if;
  if public.st_v7_workspace_custom_roles(space,'revoke',custom_role,1,p_account=>delegate_id)#>'{roles,0,assignments}' is distinct from '[]'::jsonb then
    raise exception 'Pinned session with fresh TOTP could not revoke an assignment'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  if public.st_v7_workspace_custom_roles(space)->>'access' is distinct from 'sso' then
    raise exception 'Disabled provider retained role editor access'; end if;
  perform set_config('request.jwt.claims',owner_claim::text,true);
  if public.st_v8_workspace_custom_role_admin_policy(space,false)->>'required' is distinct from 'false'
    or public.st_v7_workspace_custom_roles(space)->>'access' is distinct from 'verified' then
    raise exception 'Fresh owner could not recover the role editor after disconnect'; end if;
end $$;
select 'passed: custom role management SSO, delegated access and fresh owner recovery' as result;
rollback;
