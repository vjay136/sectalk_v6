begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); member_id uuid:=gen_random_uuid(); guest_id uuid:=gen_random_uuid();
  tenant uuid:=gen_random_uuid(); meeting uuid:=gen_random_uuid(); other_meeting uuid:=gen_random_uuid();
  plain_session uuid:=gen_random_uuid(); sso_session uuid:=gen_random_uuid(); guest_link uuid:=gen_random_uuid();
  plain_binding uuid; sso_binding uuid;
  provider text:='custom:livekit-native-test'; domain text:='livekit-native.example.invalid';
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'owner@livekit-native.example.invalid',now()),
    (member_id,'member@livekit-native.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values(owner_id,'native_media_owner','Native media owner'),
    (member_id,'native_media_member','Native media member');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into public.st_v2_workspaces(id,name,owner) values(tenant,'Native media fixture',owner_id);
  insert into public.st_v2_members(workspace_id,user_id,role) values(tenant,owner_id,'owner'),(tenant,member_id,'member');
  insert into auth.sessions(id,user_id,aal) values(plain_session,member_id,'aal1'),(sso_session,member_id,'aal1');
  insert into public.st_v3_meetings(id,workspace_id,host_id,title,status,starts_at,ends_at)
    values(meeting,tenant,owner_id,'Managed fixture','live',now(),now()+interval '30 minutes'),
      (other_meeting,tenant,owner_id,'Other fixture','live',now(),now()+interval '30 minutes');
  insert into public.st_v3_attendance(meeting_id,user_id,status,admitted_at)
    values(meeting,member_id,'admitted',now()),(other_meeting,member_id,'admitted',now());
  insert into sectalk_private.st_v6_guest_policy(meeting,enabled) values(meeting,true);
  insert into sectalk_private.st_v6_guest_link(id,meeting,owner,digest,expires_at)
    values(guest_link,meeting,owner_id,repeat('a',64),now()+interval '10 minutes');
  insert into sectalk_private.st_v6_guest_visit(id,link,digest,captcha_digest,display_name,state)
    values(guest_id,guest_link,repeat('b',64),repeat('c',64),'Invited guest','approved');

  if has_function_privilege('authenticated','public.st_v8_livekit_bound_admission(text,uuid,uuid,integer,uuid)','execute')
    or has_function_privilege('anon','public.st_v8_livekit_bind_member(uuid,text)','execute') then
    raise exception 'Callable roles exceed the admission contract'; end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',member_id,'session_id',plain_session,'role','authenticated')::text,true);
  plain_binding:=public.st_v8_livekit_bind_member(meeting,'managed');
  if plain_binding is null or plain_binding is distinct from public.st_v8_livekit_bind_member(meeting,'managed') then
    raise exception 'Standard session could not reuse its exact binding'; end if;
  reset role;
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Fixture OIDC','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(tenant,domain,now());
  insert into sectalk_private.st_v7_workspace_sso(workspace,domain,protocol,provider) values(tenant,domain,'oidc',provider);
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(sso_session,tenant,member_id,'oidc',provider);
  insert into sectalk_private.st_v8_workspace_member_media_sso(workspace,protocol,provider) values(tenant,'oidc',provider);
  set local role authenticated;
  if public.st_v8_livekit_bind_member(meeting,'managed') is not null then
    raise exception 'Password session issued a binding after policy activation'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',member_id,'session_id',sso_session,'role','authenticated')::text,true);
  sso_binding:=public.st_v8_livekit_bind_member(meeting,'managed');
  if sso_binding is null or sso_binding=plain_binding then raise exception 'Provider session did not receive its own binding'; end if;
  reset role;
  set local role service_role;
  if not public.st_v8_livekit_bound_admission('managed',meeting,member_id,null,sso_binding)
    or not public.st_v8_livekit_bound_admission('managed',meeting,guest_id,null,null)
    or public.st_v8_livekit_bound_admission('managed',meeting,member_id,null,plain_binding)
    or public.st_v8_livekit_bound_admission('managed',meeting,member_id,null,null)
    or public.st_v8_livekit_bound_admission('managed',other_meeting,member_id,null,sso_binding)
    or public.st_v8_livekit_bound_admission('managed',meeting,guest_id,null,sso_binding) then
    raise exception 'Incorrect binding, password session, or guest behavior'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role service_role;
  if public.st_v8_livekit_bound_admission('managed',meeting,member_id,null,sso_binding) then
    raise exception 'Bound access survived provider disconnect'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=true where identifier=provider;
  delete from auth.sessions where id=sso_session;
  set local role service_role;
  if public.st_v8_livekit_bound_admission('managed',meeting,member_id,null,sso_binding) then
    raise exception 'Bound access survived native session revocation'; end if;
  reset role;
end $$;
rollback;
