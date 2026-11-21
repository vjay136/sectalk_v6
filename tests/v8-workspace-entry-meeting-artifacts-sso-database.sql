begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); member_id uuid:=gen_random_uuid();
  owner_session uuid:=gen_random_uuid(); signed_session uuid:=gen_random_uuid(); factor uuid:=gen_random_uuid();
  space uuid; meeting uuid:=gen_random_uuid(); live uuid:=gen_random_uuid(); recording uuid:=gen_random_uuid();
  live_recording uuid:=gen_random_uuid(); roster jsonb;
  provider text:='custom:entry-artifacts-rollback'; domain text:='entry-artifacts.example.invalid';
  claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (owner_id,'owner@entry-artifacts.example.invalid',now()),(member_id,'member@entry-artifacts.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values
    (owner_id,'artifact_scope_owner','Artifact owner'),(member_id,'artifact_scope_member','Artifact member');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),(signed_session,member_id,'aal1',null);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Artifact fixture','fixture-client','synthetic-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',claim,true);
  space:=public.st_v2_create_workspace('Meeting entry artifact fixture');
  perform public.st_v6_set_recording_policy(space,true);
  if public.st_v8_meeting_artifact_viewer() is distinct from jsonb_build_object('actor',owner_id,'session',owner_session) then
    raise exception 'Native viewer handoff could not prove the subject and session'; end if;
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(space,member_id,'member');
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(space,domain,now());
  insert into public.st_v3_meetings(id,workspace_id,host_id,title,status,starts_at,ends_at) values
    (meeting,space,owner_id,'Synthetic completed meeting','ended',now()-interval '30 minutes',now()-interval '5 minutes'),
    (live,space,owner_id,'Synthetic live meeting','live',now(),now()+interval '30 minutes');
  roster:=jsonb_build_object(owner_id::text,'PA_test_owner',member_id::text,'PA_test_member');
  insert into sectalk_private.st_v6_recording(meeting_id,id,status,roster,approvals) values
    (meeting,recording,'ready',roster,jsonb_build_object(owner_id::text,true,member_id::text,true)),
    (live,live_recording,'collecting',roster,jsonb_build_object(owner_id::text,true));
  insert into sectalk_private.st_v6_caption_session(meeting,source_language,expires_at,line_count)
    values(meeting,'en',now()+interval '1 day',1);
  insert into sectalk_private.st_v6_caption_consent(meeting,actor,participant_sid) values
    (meeting,owner_id,'PA_test_owner'),(meeting,member_id,'PA_test_member');
  insert into sectalk_private.st_v6_caption_line(meeting,actor,sequence,speaker,line)
    values(meeting,member_id,1,'Synthetic member','The milestone is confirmed.');
  perform public.st_v6_meeting_summary_command(meeting,owner_id,'policy',true);
  perform public.st_v6_meeting_summary_command(meeting,owner_id,'opt-in');
  perform public.st_v6_meeting_summary_command(meeting,member_id,'opt-in');
  if public.st_v8_app_recording_command(meeting,owner_id,owner_session,'download')#>>'{recording,id}' is distinct from recording::text
    or public.st_v8_app_meeting_summary_command(meeting,owner_id,owner_session,'source')#>>'{source,0,line}'
      is distinct from 'The milestone is confirmed.' then raise exception 'Ordinary artifact access failed before opt-in'; end if;
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(space,'save',domain,'oidc',false);
  if public.st_v8_workspace_entry_policy(space,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Unproven provider was accepted'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(signed_session,space,member_id,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_entry_policy(space,true)->>'required' is distinct from 'true' then
    raise exception 'Could not activate entry'; end if;
  begin
    perform public.st_v6_set_recording_policy(space,true);
    raise exception 'Standard owner enabled recording without SSO';
  exception when insufficient_privilege then null; end;
  reset role;
  set local role service_role;
  if public.st_v8_app_recording_command(meeting,owner_id,owner_session,'download') is not null
    or public.st_v8_app_recording_command(meeting,owner_id,signed_session,'view') is not null
    or public.st_v8_app_meeting_summary_command(meeting,owner_id,owner_session,'source') is not null
    or public.st_v8_app_meeting_summary_command(meeting,member_id,signed_session,'source')#>>'{source,0,line}'
      is distinct from 'The milestone is confirmed.'
    or public.st_v8_app_recording_command(meeting,member_id,signed_session,'download')#>>'{recording,id}' is distinct from recording::text then
    raise exception 'Artifact gate accepted a mismatched or unsigned session or denied signed content'; end if;
  if public.st_v8_app_meeting_summary_command(meeting,owner_id,owner_session,'withdraw') is distinct from '{"withdrawn":true}'::jsonb
    or public.st_v8_app_recording_command(live,owner_id,owner_session,'withdraw',live_recording)#>>'{recording,status}'
      is distinct from 'discard'
    or public.st_v6_recording_command(live,null,'cleaned',live_recording)#>>'{recording,status}' is distinct from 'failed' then
    raise exception 'Entry blocked a safety withdrawal or independent cleanup'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role service_role;
  if public.st_v8_app_recording_command(meeting,member_id,signed_session,'download') is not null
    or public.st_v8_app_meeting_summary_command(meeting,member_id,signed_session,'source') is not null then
    raise exception 'Provider disconnection left artifact access active'; end if;
  reset role;
  set local role authenticated;
  if public.st_v8_workspace_entry_policy(space,false)->>'required' is distinct from 'false' then
    raise exception 'Fresh owner could not recover entry'; end if;
  reset role;
  if public.st_v8_app_recording_command(meeting,owner_id,owner_session,'download')#>>'{recording,id}' is distinct from recording::text
    or public.st_v8_app_meeting_summary_command(meeting,owner_id,owner_session,'source') is not null then
    raise exception 'Recovery removed the recording or restored withdrawn consent'; end if;
end $$;
select 'passed: entry recording and summary scope, exact native session, safety withdrawal, service cleanup and recovery';
rollback;
