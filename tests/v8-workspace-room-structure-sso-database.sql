begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); manager_id uuid:=gen_random_uuid(); viewer_id uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid(); manager_session uuid:=gen_random_uuid();
  viewer_session uuid:=gen_random_uuid(); plain_session uuid:=gen_random_uuid();
  space uuid; other_space uuid; main_room uuid:=gen_random_uuid(); private_room uuid:=gen_random_uuid();
  other_room uuid:=gen_random_uuid(); candidate_room uuid:=gen_random_uuid();
  provider text:='custom:room-structure-rollback'; domain text:='room-structure.example.invalid';
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  manager_claim text:=jsonb_build_object('sub',manager_id,'session_id',manager_session,'role','authenticated','aal','aal1')::text;
  viewer_claim text:=jsonb_build_object('sub',viewer_id,'session_id',viewer_session,'role','authenticated','aal','aal1')::text;
  plain_claim text:=jsonb_build_object('sub',viewer_id,'session_id',plain_session,'role','authenticated','aal','aal1')::text;
  settings jsonb;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'owner@room-structure.example.invalid',now()),
    (manager_id,'manager@room-structure.example.invalid',now()),(viewer_id,'viewer@room-structure.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values(owner_id,'dir_'||left(replace(owner_id::text,'-',''),12),'Room owner'),
    (manager_id,'dir_'||left(replace(manager_id::text,'-',''),12),'Room manager'),
    (viewer_id,'dir_'||left(replace(viewer_id::text,'-',''),12),'Room viewer');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),
    (manager_session,manager_id,'aal1',null),(viewer_session,viewer_id,'aal1',null),(plain_session,viewer_id,'aal1',null);
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Room fixture','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  space:=public.st_v2_create_workspace('Room directory SSO fixture');
  other_space:=public.st_v2_create_workspace('Independent rooms fixture');
  perform public.st_v6_room_create(main_room,space,'Protected room','public','blank');
  perform public.st_v6_room_create(private_room,space,'Private room','private','blank');
  perform public.st_v6_room_create(other_room,other_space,'Independent room','public','blank');
  if public.st_v8_workspace_room_structure_policy(space,true)->>'access' is distinct from 'mfa' then
    raise exception 'Configured room SSO without fresh TOTP'; end if;
  reset role;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(space,domain,now());
  insert into public.st_v2_members(workspace_id,user_id,role)
    values(space,manager_id,'admin'),(space,viewer_id,'member'),(other_space,viewer_id,'member');
  insert into public.st_v6_room_entries(room_id,user_id,kind,invited_role,expires_at)
    values(main_room,viewer_id,'request','member',now()+interval '1 day');
  insert into public.st_v6_room_bans(room_id,user_id) values(private_room,manager_id);
  insert into public.st_v6_room_timeouts(room_id,user_id,until_at) values(main_room,viewer_id,now()+interval '5 minutes');
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(space,'save',domain,'oidc',true);
  if public.st_v8_workspace_room_structure_policy(space,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Configured without observed provider session'; end if;
  if not exists(select from public.st_v6_rooms where id=main_room)
    or not exists(select from public.st_v6_room_entries where room_id=main_room)
    or not exists(select from public.st_v6_room_bans where room_id=private_room)
    or not exists(select from public.st_v6_room_timeouts where room_id=main_room) then
    raise exception 'Default policy hid original room metadata'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(manager_session,space,manager_id,'oidc',provider),(viewer_session,space,viewer_id,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_room_structure_policy(space,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not require room SSO'; end if;
  if not public.st_v8_workspace_room_structure_requires_sso(space)
    or exists(select from public.st_v6_rooms where id in (main_room,private_room))
    or exists(select from public.st_v6_room_members where room_id=main_room)
    or exists(select from public.st_v6_room_entries where room_id=main_room)
    or exists(select from public.st_v6_room_bans where room_id=private_room)
    or exists(select from public.st_v6_room_timeouts where room_id=main_room)
    or exists(select from public.st_v6_room_audit where room_id=main_room)
    or exists(select from public.st_v6_room_management_audit(main_room))
    or public.st_v6_room_my_role(main_room) is not null then raise exception 'Password owner retained room metadata'; end if;
  begin
    perform public.st_v6_room_create(candidate_room,space,'Blocked room','public','blank');
    raise exception 'Password owner created a room';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_manage_room(main_room,'archive');
    raise exception 'Password owner archived a room';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_room_settings(main_room,'slow',null,10);
    raise exception 'Password owner changed a room setting';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_set_room_role_overrides(main_room,'member','{"post":"deny"}');
    raise exception 'Password owner changed room role settings';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_set_room_forwarding(main_room,false);
    raise exception 'Password owner changed room forwarding';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_set_room_classification(main_room,'internal');
    raise exception 'Password owner changed room classification';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_set_room_typing_policy(main_room,false);
    raise exception 'Password owner changed room typing policy';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',plain_claim,true);
  if not public.st_v8_workspace_room_structure_requires_sso(space)
    or exists(select from public.st_v6_rooms where id=main_room)
    or not exists(select from public.st_v6_rooms where id=other_room) then raise exception 'Wrong workspace or session gate'; end if;
  begin
    perform public.st_v6_room_membership(main_room,'join');
    raise exception 'Password viewer joined a protected room';
  exception when insufficient_privilege then null;
  end;
  perform public.st_v6_room_membership(other_room,'join');

  perform set_config('request.jwt.claims',viewer_claim,true);
  if public.st_v8_workspace_room_structure_requires_sso(space)
    or not exists(select from public.st_v6_rooms where id=main_room)
    or exists(select from public.st_v6_rooms where id=private_room) then raise exception 'Signed viewer lost normal room visibility'; end if;
  perform public.st_v6_room_membership(main_room,'join');
  if public.st_v6_room_my_role(main_room) is distinct from 'member' then raise exception 'Signed viewer could not join'; end if;

  perform set_config('request.jwt.claims',manager_claim,true);
  perform public.st_v6_room_create(candidate_room,space,'Signed manager room','public','blank');
  perform public.st_v6_room_settings(candidate_room,'slow',null,10);
  perform public.st_v6_manage_room(candidate_room,'visibility','private');
  perform public.st_v6_manage_room(candidate_room,'archive');
  perform public.st_v6_manage_room(candidate_room,'restore');
  if not exists(select from public.st_v6_rooms where id=candidate_room and kind='private' and slow_seconds=10 and not archived)
    or not exists(select from public.st_v6_room_management_audit(candidate_room)) then raise exception 'Signed manager lost lifecycle controls'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  if not public.st_v8_workspace_room_structure_requires_sso(space)
    or exists(select from public.st_v6_rooms where id=main_room) then raise exception 'Disabled provider retained room access'; end if;
  perform set_config('request.jwt.claims',owner_claim,true);
  settings:=public.st_v8_workspace_room_structure_policy(space,false);
  if settings->>'required' is distinct from 'false'
    or not exists(select from public.st_v6_rooms where id=main_room) then raise exception 'Fresh owner could not recover room access'; end if;
end $$;
rollback;
