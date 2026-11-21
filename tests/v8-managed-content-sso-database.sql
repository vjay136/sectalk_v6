begin;
do $$
<<fixture>>
declare
  owner_id uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid(); factor uuid:=gen_random_uuid();
  owner_session uuid:=gen_random_uuid(); sso_session uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid();
  workspace uuid; room_id uuid:=gen_random_uuid(); channel_id uuid;
  provider text:='custom:managed-sso-rollback'; domain text:='managed-sso.example.invalid';
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  plain_claim text:=jsonb_build_object('sub',actor,'session_id',password_session,'role','authenticated',
    'user_metadata',jsonb_build_object('provider',provider),'amr',jsonb_build_array(jsonb_build_object('method','oauth')))::text;
  provider_claim text:=jsonb_build_object('sub',actor,'session_id',sso_session,'role','authenticated')::text;
  stale_room uuid; stale_channel uuid; permitted_room uuid; permitted_channel uuid; pending_room uuid;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'owner@managed-sso.example.invalid',now()),
    (actor,'user@managed-sso.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values(owner_id,'mco_'||left(replace(owner_id::text,'-',''),12),'Owner'),
    (actor,'mca_'||left(replace(actor::text,'-',''),12),'Member');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),
    (sso_session,actor,'aal1',null),(password_session,actor,'aal1',null);
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Fixture OIDC','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  workspace:=public.st_v2_create_workspace('Managed content SSO fixture');
  if public.st_v8_workspace_managed_content_policy(workspace,true)->>'access' is distinct from 'mfa' then
    raise exception 'Owner enabled managed content SSO without fresh native TOTP'; end if;
  reset role;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(workspace,domain,now());
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,actor,'member');
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(workspace,'save',domain,'oidc',true);
  if public.st_v8_workspace_managed_content_policy(workspace,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Managed content SSO enabled without an observed provider receipt'; end if;
  perform public.st_v8_set_channel_mode_policy(workspace,true);
  channel_id:=public.st_v2_create_channel(workspace,'managed-receipt-channel');
  perform public.st_v8_managed_room_policy(workspace,true);
  perform public.st_v6_room_create(room_id,workspace,'Managed receipt room','private','blank');
  reset role;
  insert into public.st_v6_room_members(room_id,user_id,role) values(room_id,actor,'member');
  set local role authenticated;
  perform set_config('request.jwt.claims',plain_claim,true);
  stale_channel:=(public.st_v8_managed_channel_ticket(channel_id,'read')->>'ticket')::uuid;
  stale_room:=(public.st_v8_managed_room_ticket(room_id)->>'ticket')::uuid;
  if stale_channel is null or stale_room is null then raise exception 'Default mode unexpectedly enforced SSO'; end if;
  reset role;

  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(sso_session,workspace,actor,'oidc',provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_managed_content_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not enable managed content SSO'; end if;
  perform set_config('request.jwt.claims',plain_claim,true);
  if public.st_v8_managed_channel_still_readable(channel_id) or public.st_v8_managed_room_readable(room_id)
    or public.st_v8_workspace_managed_content_policy(workspace,false)->>'required' is not null then
    raise exception 'Password session could read managed content or change its SSO policy'; end if;
  begin
    perform public.st_v8_managed_channel_ticket(channel_id,'send',gen_random_uuid(),'Blocked through password');
    raise exception 'Password session could start managed channel publishing';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v8_managed_room_ticket(room_id,gen_random_uuid(),'Blocked through password');
    raise exception 'Password session could start managed room publishing';
  exception when insufficient_privilege then null;
  end;
  reset role;
  set local role service_role;
  if public.st_v8_read_managed_channel(stale_channel,actor,null,null,10) is not null
    or public.st_v8_managed_room_work(stale_room,actor,'read') is not null then
    raise exception 'A pre-policy password ticket could be redeemed after activation'; end if;
  reset role;

  set local role authenticated;
  perform set_config('request.jwt.claims',provider_claim,true);
  if public.st_v8_managed_channel_still_readable(channel_id) is not true or public.st_v8_managed_room_readable(room_id) is not true then
    raise exception 'Native provider receipt was denied on a managed content feed'; end if;
  permitted_channel:=(public.st_v8_managed_channel_ticket(channel_id,'read')->>'ticket')::uuid;
  permitted_room:=(public.st_v8_managed_room_ticket(room_id)->>'ticket')::uuid;
  pending_room:=(public.st_v8_managed_room_ticket(room_id)->>'ticket')::uuid;
  reset role;
  set local role service_role;
  if public.st_v8_read_managed_channel(permitted_channel,actor,null,null,10) is distinct from '[]'::jsonb
    or public.st_v8_managed_room_work(permitted_room,actor,'read') is distinct from '[]'::jsonb then
    raise exception 'Provider receipt was not accepted through the service ticket boundary'; end if;
  reset role;

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_entry_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not enable workspace entry for the typing fixture'; end if;
  perform set_config('request.jwt.claims',plain_claim,true);
  perform public.st_v6_room_typing(room_id,null,true);
  if public.st_v6_room_typing_status(room_id,null) is distinct from '{}'::jsonb then
    raise exception 'Password session could read managed room typing under entry SSO'; end if;
  reset role;
  if exists(select 1 from sectalk_private.room_typing t where t.room_id=fixture.room_id and t.user_id=actor
      and t.expires_at is not null) then
    raise exception 'Password session published managed room typing under entry SSO'; end if;

  set local role authenticated;
  perform set_config('request.jwt.claims',provider_claim,true);
  if public.st_v6_room_typing_status(room_id,null)->>'share_own_typing' is distinct from 'true' then
    raise exception 'Active provider session could not read managed room typing'; end if;
  perform public.st_v6_room_typing(room_id,null,true);
  reset role;
  if not exists(select 1 from sectalk_private.room_typing t where t.room_id=fixture.room_id and t.user_id=actor
      and t.expires_at is not null) then
    raise exception 'Active provider session could not publish managed room typing'; end if;

  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role service_role;
  if public.st_v8_managed_room_work(pending_room,actor,'read') is not null then
    raise exception 'Disabled provider could redeem previously authorized ticket'; end if;
  reset role;
  set local role authenticated;
  perform set_config('request.jwt.claims',provider_claim,true);
  if public.st_v6_room_typing_status(room_id,null) is distinct from '{}'::jsonb then
    raise exception 'Disabled provider could still read managed room typing'; end if;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_entry_policy(workspace,false)->>'required' is distinct from 'false' then
    raise exception 'Fresh owner could not restore entry access'; end if;
  if public.st_v8_workspace_managed_content_policy(workspace,false)->>'required' is distinct from 'false' then
    raise exception 'Fresh owner could not restore managed message access'; end if;
  perform set_config('request.jwt.claims',plain_claim,true);
  if public.st_v8_managed_room_readable(room_id) is not true
     or public.st_v6_room_typing_status(room_id,null)->>'share_own_typing' is distinct from 'true' then
    raise exception 'Restore left the room inaccessible'; end if;
  reset role;
  if has_function_privilege('authenticated','sectalk_private.st_v8_managed_room_ticket(uuid,uuid,text)','execute')
    or has_function_privilege('service_role','sectalk_private.st_v8_managed_room_work(uuid,uuid,text,jsonb)','execute')
    or has_function_privilege('anon','public.st_v8_workspace_managed_content_policy(uuid,boolean)','execute') then
    raise exception 'An unchecked managed content entry point remains available'; end if;
end $$;
select 'passed: managed content requires current workspace provider receipts, including ticket replay and owner recovery';
rollback;
