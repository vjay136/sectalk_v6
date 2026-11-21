begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); manager_id uuid:=gen_random_uuid(); recipient uuid:=gen_random_uuid();
  link_recipient uuid:=gen_random_uuid(); declining uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid(); provider_session uuid:=gen_random_uuid();
  space uuid; other_space uuid; direct_invite uuid; declined_invite uuid; invitation_token text; settings jsonb;
  provider text:='custom:invitation-admin-rollback'; domain text:='invitation-admin.example.invalid';
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  signed_claim text:=jsonb_build_object('sub',manager_id,'session_id',provider_session,'role','authenticated','aal','aal1')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (owner_id,'owner@invitation-admin.example.invalid',now()),(manager_id,'manager@invitation-admin.example.invalid',now()),
    (recipient,'handle@invitation-admin.example.invalid',now()),(link_recipient,'link@invitation-admin.example.invalid',now()),
    (declining,'decline@invitation-admin.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values
    (owner_id,'invite_sso_owner','Invitation owner'),(manager_id,'invite_sso_manager','Invitation manager'),
    (recipient,'invite_sso_recipient','Handle recipient'),(link_recipient,'invite_sso_link','Link recipient'),
    (declining,'invite_sso_decliner','Declining recipient');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),(provider_session,manager_id,'aal1',null);
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Invitation fixture','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  space:=public.st_v2_create_workspace('Invitation SSO fixture');
  other_space:=public.st_v2_create_workspace('Independent invitations');
  if public.st_v8_workspace_invitation_admin_policy(space,true)->>'access' is distinct from 'mfa' then
    raise exception 'Invitation SSO was configured without fresh TOTP'; end if;
  reset role;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(space,domain,now());
  insert into public.st_v2_members(workspace_id,user_id,role) values(space,manager_id,'admin');
  set local role authenticated;
  if not public.st_v2_invite(space,'invite_sso_recipient') or not public.st_v2_invite(space,'invite_sso_decliner') then
    raise exception 'Default policy prevented invitation issuance'; end if;
  select id into strict direct_invite from public.st_v2_invites where workspace_id=space and invitee=recipient;
  select id into strict declined_invite from public.st_v2_invites where workspace_id=space and invitee=declining;
  invitation_token:=public.st_v6_workspace_link_create(space,'link@invitation-admin.example.invalid',24)->>'token';
  perform public.st_v7_workspace_sso_settings(space,'save',domain,'oidc',false);
  if public.st_v8_workspace_invitation_admin_policy(space,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Invitation SSO was configured without live provider proof'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(provider_session,space,manager_id,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_invitation_admin_policy(space,true)->>'required' is distinct from 'true' then
    raise exception 'Invitation SSO could not be configured'; end if;
  if not public.st_v8_workspace_invitation_admin_requires_sso(space)
    or public.st_v8_workspace_invitation_admin_requires_sso(other_space)
    or exists(select from public.st_v2_invites where id=direct_invite) then raise exception 'Staff invite rows or scope leaked'; end if;
  begin
    perform public.st_v2_invite(space,'invite_sso_link');
    raise exception 'Standard session issued a handle invite';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_bulk_workspace_invite(space,array['invite_sso_link']);
    raise exception 'Standard session issued CSV invites';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_workspace_link_create(space,'link@invitation-admin.example.invalid',24);
    raise exception 'Standard session minted a link invite';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_workspace_link_policy_get(space);
    raise exception 'Standard session read the link policy';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_workspace_link_policy_set(space,array[domain]);
    raise exception 'Standard session changed the link policy';
  exception when insufficient_privilege then null;
  end;
  perform public.st_v6_workspace_link_policy_set(other_space,array[domain]);

  perform set_config('request.jwt.claims',jsonb_build_object('sub',recipient,'role','authenticated')::text,true);
  if not exists(select from public.st_v2_invites where id=direct_invite)
    or exists(select from public.st_v2_invites where id=declined_invite) then raise exception 'Recipient inbox lost its own scope'; end if;
  if public.st_v2_reply_invite(direct_invite,true) is distinct from space then raise exception 'Recipient could not accept without SSO'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',link_recipient,'role','authenticated')::text,true);
  if public.st_v6_workspace_link_accept(invitation_token) is distinct from space then raise exception 'Existing verified link join failed'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',declining,'role','authenticated')::text,true);
  perform public.st_v2_reply_invite(declined_invite,false);

  perform set_config('request.jwt.claims',signed_claim,true);
  if public.st_v8_workspace_invitation_admin_requires_sso(space)
    or not exists(select from public.st_v2_invites where id=direct_invite and status='accepted')
    or not exists(select from public.st_v2_invites where id=declined_invite and status='declined') then
    raise exception 'Signed manager lost expected invitation history'; end if;
  perform public.st_v6_workspace_link_policy_set(space,array[domain]);
  if public.st_v6_workspace_link_policy_get(space)<>array[domain]
    or public.st_v6_workspace_link_create(space,'another@invitation-admin.example.invalid',24)->>'token' is null then
    raise exception 'Signed manager lost link administration'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  if not public.st_v8_workspace_invitation_admin_requires_sso(space)
    or exists(select from public.st_v2_invites where id=direct_invite) then raise exception 'Disabled provider retained invitation privilege'; end if;
  perform set_config('request.jwt.claims',owner_claim,true);
  settings:=public.st_v8_workspace_invitation_admin_policy(space,false);
  if settings->>'required' is distinct from 'false' or not exists(select from public.st_v2_invites where id=direct_invite) then
    raise exception 'Fresh owner could not recover invitation management'; end if;
end $$;
rollback;
