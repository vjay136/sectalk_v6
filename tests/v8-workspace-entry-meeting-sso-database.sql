begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid(); other uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid();
  sso_session uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid();
  workspace uuid; second_workspace uuid;
  meeting uuid:=gen_random_uuid(); room uuid:=gen_random_uuid(); room_call uuid:=gen_random_uuid();
  unprotected uuid:=gen_random_uuid();
  presenter_digest text:=repeat('b',64);
  provider text:='custom:entry-meeting-rollback'; domain text:='entry-meeting.example.invalid';
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  plain_claim text:=jsonb_build_object('sub',actor,'session_id',password_session,'role','authenticated')::text;
  provider_claim text:=jsonb_build_object('sub',actor,'session_id',sso_session,'role','authenticated')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'owner@entry-meeting.example.invalid',now()),
    (actor,'member@entry-meeting.example.invalid',now()),(other,'other@entry-meeting.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values(owner_id,'dir_'||left(replace(owner_id::text,'-',''),12),'Schedule owner'),
    (actor,'dir_'||left(replace(actor::text,'-',''),12),'Schedule member'),
    (other,'mtg_'||left(replace(other::text,'-',''),12),'Meeting viewer');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),
    (sso_session,actor,'aal1',null),(password_session,actor,'aal1',null);
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Fixture OIDC','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  workspace:=public.st_v2_create_workspace('Workspace schedule SSO fixture');
  second_workspace:=public.st_v2_create_workspace('Separate unprotected schedule');
  if public.st_v8_workspace_entry_policy(workspace,true)->>'access' is distinct from 'mfa' then
    raise exception 'Owner enabled schedule SSO without fresh TOTP'; end if;
  reset role;

  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(workspace,domain,now());
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,actor,'member'),(workspace,other,'member'),(second_workspace,actor,'member');
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(workspace,'save',domain,'oidc',true);
  if public.st_v8_workspace_entry_policy(workspace,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Schedule SSO enabled without observed provider session'; end if;
  perform public.st_v3_schedule(workspace,'Scheduled SSO sentinel','Protected agenda',now(),now()+interval '1 hour',meeting);
  perform public.st_v3_meeting_state(meeting,'live');
  perform public.st_v6_send_meeting_chat(meeting,gen_random_uuid(),'Protected collaboration sentinel');
  perform public.st_v6_set_meeting_hand(meeting,true);
  perform public.st_v3_schedule(second_workspace,'Other meeting','',now(),now()+interval '1 hour',unprotected);
  perform public.st_v3_meeting_state(unprotected,'live');
  perform public.st_v6_send_meeting_chat(unprotected,gen_random_uuid(),'Independent collaboration sentinel');
  perform public.st_v6_room_create(room,workspace,'Independent room calls','private','project');
  perform public.st_v6_start_room_call(room,room_call,'Independent room call');
  if not exists(select 1 from public.st_v3_attendance where meeting_id=meeting and user_id=owner_id) then
    raise exception 'Default meeting schedule unexpectedly blocked the host'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(sso_session,workspace,actor,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_entry_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not require schedule SSO'; end if;
  if not public.st_v8_workspace_schedule_requires_sso(workspace)
    or exists(select 1 from public.st_v3_meetings where id=meeting)
    or exists(select 1 from public.st_v3_attendance where meeting_id=meeting)
    or (select count(*) from public.st_v3_meetings where id in (room_call,unprotected))<>1
    or public.st_v6_room_calls(room) is not null
    or public.st_v8_workspace_member_media_allowed(meeting)
    or public.st_v3_media_access(meeting)
    or exists(select 1 from public.st_v6_meeting_chat where meeting_id=meeting)
    or exists(select 1 from public.st_v6_meeting_hands where meeting_id=meeting)
    or exists(select 1 from public.st_v6_meeting_controls where meeting_id=meeting)
    or not public.st_v3_media_access(unprotected)
    or not exists(select 1 from public.st_v6_meeting_chat where meeting_id=unprotected) then
    raise exception 'Password owner received protected meeting data or lost unprotected collaboration'; end if;
  begin
    perform public.st_v3_schedule(workspace,'Blocked meeting','',now(),now()+interval '1 hour',gen_random_uuid());
    raise exception 'Password owner scheduled a protected meeting';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_start_instant_meeting(gen_random_uuid(),workspace,'Blocked instant meeting',30);
    raise exception 'Password owner created protected instant meeting';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_schedule_series(workspace,gen_random_uuid(),'Blocked series','',now(),now()+interval '1 hour','daily',2,'UTC');
    raise exception 'Password owner created protected recurring meeting';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',plain_claim,true);
  if not public.st_v8_workspace_schedule_requires_sso(workspace)
    or exists(select 1 from public.st_v3_notifications where meeting_id=meeting)
    or exists(select 1 from public.st_v6_search('Scheduled SSO sentinel','meeting','{}') where id=meeting) then
    raise exception 'Workspace member password session saw protected meeting details or notifications'; end if;
  begin
    perform public.st_v3_request_admission(meeting);
    raise exception 'Password member requested protected meeting admission';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',provider_claim,true);
  if public.st_v8_workspace_schedule_requires_sso(workspace)
    or not exists(select 1 from public.st_v3_notifications where meeting_id=meeting)
    or not exists(select 1 from public.st_v6_search('Scheduled SSO sentinel','meeting','{}') where id=meeting)
    or public.st_v3_request_admission(meeting) is distinct from 'waiting' then
    raise exception 'Live provider session lost schedule, Search, notification or lobby access'; end if;
  perform set_config('request.jwt.claims',owner_claim,true);
  begin
    perform public.st_v3_admit(meeting,actor,true);
    raise exception 'Password owner managed protected lobby';
  exception when insufficient_privilege then null;
  end;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(owner_session,workspace,owner_id,'oidc',provider);
  set local role authenticated;
  perform public.st_v3_admit(meeting,actor,true);
  if not exists(select 1 from public.st_v3_attendance where meeting_id=meeting and user_id=actor and status='admitted') then
    raise exception 'Live owner provider session could not admit attendee'; end if;
  perform set_config('request.jwt.claims',provider_claim,true);
  if not public.st_v3_media_access(meeting)
    or (select count(*) from public.st_v6_meeting_roster(meeting))<>2
    or not exists(select 1 from public.st_v6_meeting_chat where meeting_id=meeting and user_id=owner_id)
    or not exists(select 1 from public.st_v6_meeting_hands where meeting_id=meeting and user_id=owner_id)
    or not exists(select 1 from public.st_v6_meeting_controls where meeting_id=meeting) then
    raise exception 'Admitted provider session lost meeting collaboration'; end if;
  perform public.st_v6_send_meeting_chat(meeting,gen_random_uuid(),'Verified member can collaborate');
  perform public.st_v6_set_meeting_hand(meeting,true);
  perform public.st_v6_send_meeting_reaction(meeting,'heart');
  if not public.st_v6_screen_presenter(meeting,presenter_digest,'claim')
    or not public.st_v6_screen_presenter(meeting,presenter_digest,'renew') then
    raise exception 'Admitted provider session could not present'; end if;
  perform set_config('request.jwt.claims',plain_claim,true);
  if public.st_v3_media_access(meeting)
    or exists(select 1 from public.st_v6_meeting_chat where meeting_id=meeting)
    or exists(select 1 from public.st_v6_meeting_hands where meeting_id=meeting)
    or exists(select 1 from public.st_v6_meeting_reactions where meeting_id=meeting)
    or public.st_v6_screen_presenter(meeting,presenter_digest,'renew') then
    raise exception 'Password session inherited meeting access from another session of the same attendee'; end if;
  if not public.st_v6_screen_presenter(meeting,presenter_digest,'release') then
    raise exception 'Existing presenter could not release their lease'; end if;
  begin
    perform public.st_v6_meeting_roster(meeting);
    raise exception 'Password session read the active meeting roster';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_send_meeting_chat(meeting,gen_random_uuid(),'Password session write');
    raise exception 'Password session sent meeting chat';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_set_meeting_hand(meeting,false);
    raise exception 'Password session changed hand status';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',owner_claim,true);
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  if not public.st_v8_workspace_schedule_requires_sso(workspace)
    or exists(select 1 from public.st_v3_meetings where id=meeting)
    or public.st_v3_media_access(meeting)
    or exists(select 1 from public.st_v6_meeting_chat where meeting_id=meeting) then
    raise exception 'Disabled provider retained schedule or meeting collaboration access'; end if;
  perform public.st_v3_meeting_state(meeting,'ended');
  perform public.st_v3_meeting_state(room_call,'ended');
  if public.st_v8_workspace_entry_policy(workspace,false)->>'required' is distinct from 'false' then
    raise exception 'Fresh owner could not recover schedule'; end if;
  if (select count(*) from public.st_v3_meetings where id in (meeting,room_call) and status='ended')<>2 then
    raise exception 'Meeting remained hidden after workspace recovery or could not end'; end if;
end $$;
rollback;

begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); member_id uuid:=gen_random_uuid(); guest_id uuid:=gen_random_uuid();
  tenant uuid:=gen_random_uuid(); meeting uuid:=gen_random_uuid(); other_meeting uuid:=gen_random_uuid();
  plain_session uuid:=gen_random_uuid(); sso_session uuid:=gen_random_uuid(); guest_link uuid:=gen_random_uuid();
  plain_binding uuid; sso_binding uuid;
  provider text:='custom:entry-livekit-test'; domain text:='entry-livekit.example.invalid';
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'owner@entry-livekit.example.invalid',now()),
    (member_id,'member@entry-livekit.example.invalid',now());
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
  insert into sectalk_private.st_v8_workspace_entry_sso(workspace,protocol,provider) values(tenant,'oidc',provider);
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

select 'passed: entry meeting schedules, lobby, in-app collaboration, member media, room-call shutdown and independent guest admission';
