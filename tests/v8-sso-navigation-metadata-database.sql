begin;
do $$
declare
  actor uuid:=gen_random_uuid(); foreign_actor uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); plain_session uuid:=gen_random_uuid(); signed_session uuid:=gen_random_uuid();
  foreign_session uuid:=gen_random_uuid(); space uuid; foreign_space uuid;
  room uuid:=gen_random_uuid(); managed uuid:=gen_random_uuid(); foreign_room uuid:=gen_random_uuid();
  group_id uuid:=gen_random_uuid(); file_id uuid:=gen_random_uuid();
  provider text:='custom:navigation-sso-rollback'; domain text:='navigation-sso.example.invalid';
  plain_claim text:=jsonb_build_object('sub',actor,'session_id',plain_session,'role','authenticated','aal','aal2')::text;
  signed_claim text:=jsonb_build_object('sub',actor,'session_id',signed_session,'role','authenticated','aal','aal2')::text;
  foreign_claim text:=jsonb_build_object('sub',foreign_actor,'session_id',foreign_session,'role','authenticated','aal','aal1')::text;
  view jsonb; targets jsonb;
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (actor,'owner@navigation-sso.example.invalid',now()),(foreign_actor,'other@navigation-sso.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values
    (actor,'navigation_sso_owner','Navigation scope owner'),(foreign_actor,'navigation_sso_other','Unrelated owner');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(actor,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,actor,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values
    (plain_session,actor,'aal2',factor),(signed_session,actor,'aal2',factor),(foreign_session,foreign_actor,'aal1',null);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),plain_session,'totp',now(),now()),(gen_random_uuid(),signed_session,'totp',now(),now());
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Navigation fixture','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',foreign_claim,true);
  foreign_space:=public.st_v2_create_workspace('Unrelated navigation workspace');
  perform public.st_v6_room_create(foreign_room,foreign_space,'Unrelated room name','public','blank');
  perform set_config('request.jwt.claims',plain_claim,true);
  space:=public.st_v2_create_workspace('Pinned navigation workspace');
  perform public.st_v6_room_create(room,space,'Protected standard selector name','private','blank');
  perform public.st_v8_managed_room_policy(space,true);
  perform public.st_v6_room_create(managed,space,'Protected managed selector name','private','blank');
  perform public.st_v6_workspace_group_create(space,group_id,'team','Protected group selector name','');
  reset role;
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(space,domain,now());
  insert into sectalk_private.st_v6_workspace_files(workspace,id,uploader,filename,size_bytes,published_at)
    values(space,file_id,actor,'Protected file selector name.txt',1,now());
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(space,'save',domain,'oidc',false);
  view:=public.st_v7_permission_catalog(space,room);
  targets:=public.st_v7_custom_role_targets(space);
  if view->>'room_requires_sso' is distinct from 'false' or view->>'room_role' is distinct from 'owner'
    or view#>>'{room,messaging.message.send}' is distinct from 'allowed'
    or not (targets @> jsonb_build_array(jsonb_build_object('id',room),jsonb_build_object('id',group_id),jsonb_build_object('id',file_id)))
    or (view->'workspaces' @> jsonb_build_array(jsonb_build_object('id',foreign_space))) then
    raise exception 'Default navigation or current-tenant filters changed'; end if;

  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(signed_session,space,actor,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_managed_content_policy(space,true)->>'required' is distinct from 'true' then
    raise exception 'Could not configure managed message scope'; end if;
  view:=public.st_v7_permission_catalog(space,managed);
  if view#>>'{room,messaging.message.send}' is distinct from 'sso_required'
    or not (view->'rooms' @> jsonb_build_array(jsonb_build_object('id',managed))) then
    raise exception 'Managed message SSO did not affect the action separately from metadata'; end if;

  perform public.st_v8_workspace_directory_policy(space,true);
  perform public.st_v8_workspace_audit_policy(space,true);
  perform public.st_v8_workspace_integration_admin_policy(space,true);
  perform public.st_v8_workspace_groups_policy(space,true);
  perform public.st_v8_workspace_file_policy(space,true);
  perform public.st_v8_workspace_room_structure_policy(space,true);
  view:=public.st_v7_permission_catalog(space,room);
  if view->>'room_requires_sso' is distinct from 'true' or view->'rooms' is distinct from '[]'::jsonb
    or view->>'room_role' is not null or view->'room' is distinct from '{}'::jsonb
    or view#>>'{workspace,workspace.member.read}' is distinct from 'sso_required'
    or view#>>'{workspace,admin.user.suspend}' is distinct from 'sso_required'
    or view#>>'{workspace,admin.user.role.write}' is distinct from 'sso_required'
    or view#>>'{workspace,audit.log.read}' is distinct from 'sso_required'
    or view#>>'{workspace,integration.key.manage}' is distinct from 'sso_required'
    or public.st_v6_room_permission_state(room) is not null
    or public.st_v7_custom_role_targets(space) is distinct from '[]'::jsonb then
    raise exception 'Restricted room context or adjacent selector remained visible'; end if;
  view:=public.st_v7_permission_catalog(foreign_space,foreign_room);
  if view->>'room_requires_sso' is distinct from 'false' or view->'rooms' is distinct from '[]'::jsonb
    or view->'room' is distinct from '{}'::jsonb then raise exception 'Foreign scope was disclosed'; end if;

  perform set_config('request.jwt.claims',signed_claim,true);
  view:=public.st_v7_permission_catalog(space,managed);
  targets:=public.st_v7_custom_role_targets(space);
  if view->>'room_requires_sso' is distinct from 'false' or view->>'room_role' is distinct from 'owner'
    or view#>>'{room,messaging.message.send}' is distinct from 'allowed'
    or view#>>'{workspace,audit.log.read}' is distinct from 'allowed'
    or not (targets @> jsonb_build_array(jsonb_build_object('id',room),jsonb_build_object('id',group_id),jsonb_build_object('id',file_id)))
    or public.st_v6_room_permission_state(room) is null then raise exception 'Signed session lost normal selector behavior'; end if;

  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  if public.st_v7_permission_catalog(space,room)->>'room_requires_sso' is distinct from 'true' then
    raise exception 'Disabled provider retained permission metadata'; end if;
  perform set_config('request.jwt.claims',plain_claim,true);
  perform public.st_v8_workspace_room_structure_policy(space,false);
  view:=public.st_v7_permission_catalog(space,room);
  if view->>'room_requires_sso' is distinct from 'false' or view->>'room_role' is distinct from 'owner'
    or view#>>'{workspace,audit.log.read}' is distinct from 'sso_required' then
    raise exception 'Owner recovery failed or cleared unrelated scopes'; end if;
end $$;
rollback;
