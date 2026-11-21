begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); manager_id uuid:=gen_random_uuid(); viewer_id uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid(); provider_session uuid:=gen_random_uuid();
  viewer_session uuid:=gen_random_uuid(); plain_session uuid:=gen_random_uuid();
  space uuid; other_space uuid; channel_id uuid; other_channel uuid; fresh_channel uuid;
  provider text:='custom:channel-structure-rollback'; domain text:='channel-structure.example.invalid';
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  provider_claim text:=jsonb_build_object('sub',manager_id,'session_id',provider_session,'role','authenticated','aal','aal1')::text;
  viewer_claim text:=jsonb_build_object('sub',viewer_id,'session_id',viewer_session,'role','authenticated','aal','aal1')::text;
  plain_claim text:=jsonb_build_object('sub',manager_id,'session_id',plain_session,'role','authenticated','aal','aal1')::text;
  settings jsonb; operation text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'owner@channel-structure.example.invalid',now()),
    (manager_id,'manager@channel-structure.example.invalid',now()),(viewer_id,'viewer@channel-structure.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values(owner_id,'dir_'||left(replace(owner_id::text,'-',''),12),'Channel owner'),
    (manager_id,'dir_'||left(replace(manager_id::text,'-',''),12),'Channel manager'),
    (viewer_id,'dir_'||left(replace(viewer_id::text,'-',''),12),'Channel viewer');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),
    (provider_session,manager_id,'aal1',null),(plain_session,manager_id,'aal1',null),(viewer_session,viewer_id,'aal1',null);
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Channel fixture','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  space:=public.st_v2_create_workspace('Channel directory SSO fixture');
  other_space:=public.st_v2_create_workspace('Independent channels fixture');
  channel_id:=public.st_v2_create_channel(space,'protected-directory');
  other_channel:=public.st_v2_create_channel(other_space,'other-directory');
  perform public.st_v6_manage_channel(channel_id,'visibility',null,'private');
  if public.st_v8_workspace_channel_structure_policy(space,true)->>'access' is distinct from 'mfa' then
    raise exception 'Configured without fresh TOTP'; end if;
  reset role;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(space,domain,now());
  insert into public.st_v2_members(workspace_id,user_id,role)
    values(space,manager_id,'admin'),(space,viewer_id,'member'),(other_space,manager_id,'member');

  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(space,'save',domain,'oidc',true);
  if public.st_v8_workspace_channel_structure_policy(space,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Configured without observed provider session'; end if;
  if not exists(select from public.st_v2_channels where id=channel_id) then
    raise exception 'Default policy hides existing channels'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(provider_session,space,manager_id,'oidc',provider),(viewer_session,space,viewer_id,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_channel_structure_policy(space,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not require channel SSO'; end if;
  if not public.st_v8_workspace_channel_structure_requires_sso(space)
    or exists(select from public.st_v2_channels where id=channel_id) then raise exception 'Password owner retained directory access'; end if;
  settings:=public.st_v6_channel_details(channel_id);
  if settings is distinct from '{"can_read":false,"can_manage":false,"structure_sso_required":true}'::jsonb then
    raise exception 'Password owner retained private roster or audit'; end if;
  begin
    perform public.st_v2_create_channel(space,'blocked-create');
    raise exception 'Password owner created channel';
  exception when insufficient_privilege then null;
  end;
  foreach operation in array array['visibility','add_member','remove_member','transfer_owner','archive','restore'] loop
    begin
      perform public.st_v6_manage_channel(channel_id,operation,viewer_id,'workspace');
      raise exception 'Password owner changed channel structure through %',operation;
    exception when insufficient_privilege then null;
    end;
  end loop;

  perform set_config('request.jwt.claims',plain_claim,true);
  if not public.st_v8_workspace_channel_structure_requires_sso(space)
    or exists(select from public.st_v2_channels where id=channel_id)
    or not exists(select from public.st_v2_channels where id=other_channel) then raise exception 'Wrong workspace or session gate'; end if;

  perform set_config('request.jwt.claims',viewer_claim,true);
  if public.st_v8_workspace_channel_structure_requires_sso(space)
    or exists(select from public.st_v2_channels where id=channel_id)
    or public.st_v6_channel_details(channel_id) is distinct from '{"can_read":false,"can_manage":false}'::jsonb then
    raise exception 'Signed member inherited unrelated private access'; end if;

  perform set_config('request.jwt.claims',provider_claim,true);
  if public.st_v8_workspace_channel_structure_requires_sso(space)
    or not exists(select from public.st_v2_channels where id=channel_id)
    or public.st_v6_channel_details(channel_id)->>'can_manage' is distinct from 'true' then
    raise exception 'Signed manager lost channel management'; end if;
  fresh_channel:=public.st_v2_create_channel(space,'signed-create');
  perform public.st_v6_manage_channel(channel_id,'add_member',viewer_id,null);
  if not (public.st_v6_channel_details(channel_id)->'members' @> jsonb_build_array(viewer_id)) then
    raise exception 'Signed manager could not add a private member'; end if;
  perform public.st_v6_manage_channel(fresh_channel,'archive');
  perform public.st_v6_manage_channel(fresh_channel,'restore');
  perform set_config('request.jwt.claims',viewer_claim,true);
  if not exists(select from public.st_v2_channels where id=channel_id and visibility='private') then
    raise exception 'Signed, explicitly added member lost private access'; end if;

  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  if not public.st_v8_workspace_channel_structure_requires_sso(space)
    or exists(select from public.st_v2_channels where id=channel_id) then
    raise exception 'Disabled provider retained channel access'; end if;
  perform set_config('request.jwt.claims',owner_claim,true);
  settings:=public.st_v8_workspace_channel_structure_policy(space,false);
  if settings->>'required' is distinct from 'false' or not exists(select from public.st_v2_channels where id=channel_id) then
    raise exception 'Fresh owner could not recover directory access'; end if;
end $$;
rollback;
