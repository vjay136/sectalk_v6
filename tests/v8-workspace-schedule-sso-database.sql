begin;
do $$
<<fixture>>
declare
  owner_id uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid(); other uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid();
  sso_session uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid();
  workspace uuid; second_workspace uuid;
  meeting uuid:=gen_random_uuid(); room uuid:=gen_random_uuid(); room_call uuid:=gen_random_uuid();
  unprotected uuid:=gen_random_uuid();
  protected_notice bigint; ordinary_notice bigint;
  provider text:='custom:schedule-sso-rollback'; domain text:='schedule-sso.example.invalid';
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  plain_claim text:=jsonb_build_object('sub',actor,'session_id',password_session,'role','authenticated')::text;
  provider_claim text:=jsonb_build_object('sub',actor,'session_id',sso_session,'role','authenticated')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'owner@schedule-sso.example.invalid',now()),
    (actor,'member@schedule-sso.example.invalid',now()),(other,'other@schedule-sso.example.invalid',now());
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
  if public.st_v8_workspace_schedule_policy(workspace,true)->>'access' is distinct from 'mfa' then
    raise exception 'Owner enabled schedule SSO without fresh TOTP'; end if;
  reset role;

  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(workspace,domain,now());
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,actor,'member'),(workspace,other,'member'),(second_workspace,actor,'member');
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(workspace,'save',domain,'oidc',true);
  if public.st_v8_workspace_schedule_policy(workspace,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Schedule SSO enabled without observed provider session'; end if;
  perform public.st_v3_schedule(workspace,'Scheduled SSO sentinel','Protected agenda',now(),now()+interval '1 hour',meeting);
  perform public.st_v3_meeting_state(meeting,'live');
  perform public.st_v3_schedule(second_workspace,'Other meeting','',now(),now()+interval '1 hour',unprotected);
  perform public.st_v6_room_create(room,workspace,'Independent room calls','private','project');
  perform public.st_v6_start_room_call(room,room_call,'Independent room call');
  if not exists(select 1 from public.st_v3_attendance where meeting_id=meeting and user_id=owner_id) then
    raise exception 'Default meeting schedule unexpectedly blocked the host'; end if;
  reset role;
  select n.id into strict protected_notice from public.st_v3_notifications n
    where (n.meeting_id,n.recipient,n.kind)=(meeting,actor,'meeting.scheduled');
  select n.id into strict ordinary_notice from public.st_v3_notifications n
    where (n.meeting_id,n.recipient,n.kind)=(unprotected,actor,'meeting.scheduled');
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(sso_session,workspace,actor,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_schedule_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not require schedule SSO'; end if;
  if not public.st_v8_workspace_schedule_requires_sso(workspace)
    or exists(select 1 from public.st_v3_meetings where id=meeting)
    or exists(select 1 from public.st_v3_attendance where meeting_id=meeting)
    or (select count(*) from public.st_v3_meetings where id in (room_call,unprotected))<>2
    or not public.st_v3_media_access(meeting) then
    raise exception 'Schedule leaked rows, hid independent room calls, or affected existing media identity'; end if;
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
  begin
    perform public.st_v6_moderate_meeting(meeting,'lock',null,true);
    raise exception 'Password owner moderated a protected meeting';
  exception when insufficient_privilege then null;
  end;
  perform public.st_v6_moderate_meeting(room_call,'chat',null,false);
  if not exists(select 1 from public.st_v3_meetings where id=room_call and chat_disabled) then
    raise exception 'Schedule policy blocked independent room-call moderation'; end if;
  perform set_config('request.jwt.claims',plain_claim,true);
  if not public.st_v8_workspace_schedule_requires_sso(workspace)
    or exists(select 1 from public.st_v3_notifications where meeting_id=meeting)
    or exists(select 1 from public.st_v6_search('Scheduled SSO sentinel','meeting','{}') where id=meeting) then
    raise exception 'Workspace member password session saw protected meeting details or notifications'; end if;
  perform public.st_v3_mark_notification(protected_notice,'meeting');
  perform public.st_v3_mark_notification(null::bigint);
  reset role;
  if not exists(select 1 from public.st_v3_notifications n where n.id=protected_notice and n.read_at is null)
    or not exists(select 1 from public.st_v3_notifications n where n.id=ordinary_notice and n.read_at is not null) then
    raise exception 'Password-only notification acknowledgements did not respect the schedule scope'; end if;
  set local role authenticated;
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
  perform public.st_v3_mark_notification(protected_notice,'meeting');
  if not exists(select 1 from public.st_v3_notifications n where n.id=protected_notice and n.read_at is not null) then
    raise exception 'Live provider session could not acknowledge the protected notice'; end if;
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
  perform public.st_v6_moderate_meeting(meeting,'chat',null,false);
  if not exists(select 1 from public.st_v3_meetings where id=meeting and chat_disabled and not meeting_locked) then
    raise exception 'Verified owner lost moderation or a denied request changed the meeting'; end if;
  if not exists(select 1 from public.st_v3_attendance where meeting_id=meeting and user_id=actor and status='admitted') then
    raise exception 'Live owner provider session could not admit attendee'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  update public.st_v3_notifications n set read_at=null where n.id=protected_notice;
  insert into sectalk_private.st_v8_workspace_entry_sso values(workspace,'oidc',provider);
  if has_function_privilege('authenticated','sectalk_private.st_v6_moderate_meeting(uuid,text,uuid,boolean)','execute') then
    raise exception 'Ungated moderation helper exposed'; end if;
  set local role authenticated;
  if not public.st_v8_workspace_schedule_requires_sso(workspace)
    or exists(select 1 from public.st_v3_meetings where id=meeting) then
    raise exception 'Disabled provider retained schedule access'; end if;
  perform set_config('request.jwt.claims',provider_claim,true);
  perform public.st_v3_mark_notification(null::bigint,'meeting');
  reset role;
  if not exists(select 1 from public.st_v3_notifications n where n.id=protected_notice and n.read_at is null) then
    raise exception 'Revoked provider session could acknowledge the notice'; end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  begin
    perform public.st_v6_moderate_meeting(meeting,'chat',null,true);
    raise exception 'Revoked provider session could moderate a meeting';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_moderate_meeting(room_call,'chat',null,true);
    raise exception 'Workspace entry policy did not block room-call moderation';
  exception when insufficient_privilege then null;
  end;
  perform public.st_v6_moderate_meeting(meeting,'end',null,null);
  reset role;
  delete from sectalk_private.st_v8_workspace_entry_sso e where e.workspace=fixture.workspace;
  set local role authenticated;
  if public.st_v8_workspace_schedule_policy(workspace,false)->>'required' is distinct from 'false' then
    raise exception 'Fresh owner could not recover schedule'; end if;
  if not exists(select 1 from public.st_v3_meetings where id=meeting and status='ended') then
    raise exception 'Meeting remained hidden after workspace recovery or could not end'; end if;
  perform set_config('request.jwt.claims',plain_claim,true);
  perform public.st_v3_mark_notification(protected_notice);
  if not exists(select 1 from public.st_v3_notifications n where n.id=protected_notice and n.read_at is not null) then
    raise exception 'Workspace recovery did not restore notification acknowledgement'; end if;
end $$;
rollback;
