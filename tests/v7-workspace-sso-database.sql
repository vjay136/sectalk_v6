begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid();
  sso_session uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid(); owner_factor uuid:=gen_random_uuid();
  workspace uuid; meeting_id uuid:=gen_random_uuid(); code_value uuid:=gen_random_uuid(); provider text:='custom:rollback-sso';
  cookie_digest text:=repeat('a',64); challenge text:=repeat('b',43); proof jsonb;
  channel_id uuid; post_id uuid:=gen_random_uuid();
  room_id uuid:=gen_random_uuid(); room_post uuid:=gen_random_uuid(); linked_task uuid:=gen_random_uuid();
  guest_room uuid:=gen_random_uuid(); guest_post uuid:=gen_random_uuid(); guest_digest text:=repeat('e',64);
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'sso-owner@example.invalid',now()),(actor,'user@enterprise.example.invalid',now());
  insert into public.st_profiles values(owner_id,'sso_rollback_owner','SSO owner');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(owner_factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',owner_factor),
    (sso_session,actor,'aal1',null),(password_session,actor,'aal1',null);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
    (gen_random_uuid(),sso_session,'oauth',now(),now()),(gen_random_uuid(),password_session,'password',now(),now());
  insert into auth.identities(id,provider_id,user_id,identity_data,provider)
    values(gen_random_uuid(),'verified-subject',actor,'{"email":"user@enterprise.example.invalid","email_verified":true}',provider);
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Fixture OIDC','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values('enterprise.example.invalid',provider);
  if has_function_privilege('authenticated','sectalk_private.st_v8_room_membership_role(uuid,uuid)','execute')
    or has_function_privilege('anon','public.st_v8_standard_room_requires_sso(uuid)','execute') then
    raise exception 'Standard room policy exposes an unauthorized native function'; end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  workspace:=public.st_v2_create_workspace('SSO Enterprise fixture');
  if public.st_v7_workspace_sso_settings(workspace)->>'access'<>'mfa' then raise exception 'Owner read without fresh TOTP'; end if;
  if public.st_v8_workspace_standard_room_policy(workspace,true)->>'access' is distinct from 'mfa' then
    raise exception 'Room policy accepted a claim without a fresh native factor'; end if;
  if has_function_privilege('authenticated','public.st_v7_workspace_sso_claim(text,text,text)','execute') then
    raise exception 'Authenticated browser could mint scoped provenance directly';
  end if;
  reset role;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(workspace,'enterprise.example.invalid',now());
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(workspace,'save','enterprise.example.invalid','oidc',true);
  if public.st_v8_workspace_standard_room_policy(workspace,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Room policy allowed activation without a live native provider session'; end if;
  reset role;
  set local role service_role;
  proof:=public.st_v7_workspace_sso_begin('enterprise.example.invalid',cookie_digest,challenge);
  if proof->>'provider' is distinct from provider then raise exception 'Approved provider not discovered'; end if;
  if public.st_v7_workspace_sso_claim(cookie_digest,code_value::text,challenge) is not null then raise exception 'Missing native flow forged provenance'; end if;
  reset role;
  insert into auth.flow_state(id,user_id,auth_code,code_challenge_method,code_challenge,provider_type,authentication_method,auth_code_issued_at)
    values(gen_random_uuid(),actor,code_value::text,'s256',challenge,'custom:wrong','oauth',now());
  set local role service_role;
  if public.st_v7_workspace_sso_claim(cookie_digest,code_value::text,challenge) is not null then raise exception 'Wrong native provider accepted'; end if;
  reset role;
  update auth.flow_state set provider_type=provider where auth_code=code_value::text;
  set local role service_role;
  if public.st_v7_workspace_sso_claim(cookie_digest,code_value::text,repeat('c',43)) is not null then raise exception 'Wrong challenge accepted'; end if;
  proof:=public.st_v7_workspace_sso_claim(cookie_digest,code_value::text,challenge);
  if proof->>'principal' is distinct from actor::text
    or public.st_v7_workspace_sso_claim(cookie_digest,code_value::text,challenge) is not null then
    raise exception 'Native flow was not bound once to trusted subject';
  end if;
  reset role;
  update auth.sessions set created_at=clock_timestamp() where id=sso_session;
  set local role service_role;
  if public.st_v7_workspace_sso_finish(cookie_digest,actor,sso_session)->>'workspace' is distinct from workspace::text then
    raise exception 'Eligible native session was not admitted'; end if;
  reset role;
  if not exists(select 1 from public.st_v2_members where workspace_id=workspace and user_id=actor and role='member') then
    raise exception 'JIT did not safely create ordinary workspace membership';
  end if;
  insert into public.st_v3_meetings(id,workspace_id,host_id,title,starts_at,ends_at,status)
    values(meeting_id,workspace,owner_id,'SSO gate fixture',now(),now()+interval '1 hour','live');
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_member_media_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Owner could not pin the approved native provider receipt';
  end if;
  channel_id:=public.st_v2_create_channel(workspace,'sso-fixture-channel');
  perform public.st_v2_post(channel_id,post_id,'Synthetic receipt rollback message');
  proof:=public.st_v8_workspace_standard_channel_policy(workspace,true);
  if proof->>'required' is distinct from 'true' then raise exception 'Owner could not enable standard channel receipts'; end if;
  perform public.st_v6_room_create(room_id,workspace,'Private receipt room','private','blank');
  perform public.st_v6_room_create(guest_room,workspace,'Public receipt room','public','blank');
  perform public.st_v6_room_post(room_id,room_post,'Standard room receipt rollback search content');
  perform public.st_v6_task_create(linked_task,room_id,null,'Synthetic linked room task',room_post);
  perform public.st_v6_room_post(guest_room,guest_post,'Public guest receipt preview');
  reset role;
  insert into public.st_v6_room_members(room_id,user_id,role) values(room_id,actor,'member');
  update public.st_v6_rooms r set classification='public',forwarding_allowed=true where r.id=guest_room;
  set local role service_role;
  proof:=public.st_v6_room_guest_command('create',guest_room,owner_id,null,guest_digest,null,array[guest_post]);
  if proof->>'created' is null then raise exception 'Guest pre-activation control could not create a valid link'; end if;
  reset role;
  set local role authenticated;
  proof:=public.st_v8_workspace_standard_room_policy(workspace,true);
  if proof->>'required' is distinct from 'true' then raise exception 'Owner could not enable standard room receipts'; end if;
  begin
    perform public.st_v6_room_create(gen_random_uuid(),workspace,'Protected starter','public','project');
    raise exception 'Password session could publish a protected starter post';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',actor,'session_id',password_session,'role','authenticated',
    'user_metadata',jsonb_build_object('provider',provider),'amr',jsonb_build_array(jsonb_build_object('method','oauth')))::text,true);
  if public.st_v7_workspace_uses_sso(workspace) then raise exception 'Password or metadata reused native receipt'; end if;
  if public.st_v8_workspace_member_media_allowed(meeting_id) then raise exception 'Password or metadata bypassed media gate'; end if;
  if exists(select 1 from public.st_v2_posts p where p.id=post_id) then raise exception 'Password or metadata bypassed channel read gate'; end if;
  begin
    perform public.st_v2_post(channel_id,gen_random_uuid(),'Password should be rejected');
    raise exception 'Password or metadata bypassed channel write gate';
  exception when insufficient_privilege then null;
  end;
  if not public.st_v8_standard_room_requires_sso(room_id) or not exists(select 1 from public.st_v6_rooms r where r.id=room_id)
    or exists(select 1 from public.st_v6_room_posts p where p.id=room_post)
    or exists(select 1 from public.st_v6_search('receipt rollback search','room','{}'))
    or exists(select 1 from public.st_v6_room_thread_state(room_id,array[room_post]))
    or public.st_v6_task_source(linked_task) is distinct from '{"available":false}'::jsonb then
    raise exception 'Password session bypassed room timeline, Search, thread or task source gate'; end if;
  if public.st_v8_workspace_standard_room_policy(workspace,false)->>'required' is not null then
    raise exception 'Member changed the room sign-in policy'; end if;
  begin
    perform public.st_v6_room_post(room_id,gen_random_uuid(),'Password room posting denied');
    raise exception 'Unexpected room publishing result';
  exception when raise_exception then
    if sqlerrm is distinct from 'Posting is unavailable' then raise; end if;
  end;
  reset role;
  set local role service_role;
  if public.st_v6_room_guest_command('redeem',guest_room,null,null,guest_digest,repeat('f',64)) is not null then
    raise exception 'Previously issued guest link bypassed protected room access'; end if;
  reset role;
  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',actor,'session_id',sso_session,'role','authenticated')::text,true);
  if not public.st_v7_workspace_uses_sso(workspace) then raise exception 'Native receipt missing'; end if;
  if not public.st_v8_workspace_member_media_allowed(meeting_id) then raise exception 'Pinned receipt did not pass media gate'; end if;
  if not exists(select 1 from public.st_v2_posts p where p.id=post_id) then raise exception 'Pinned receipt did not pass channel read gate'; end if;
  perform public.st_v2_post(channel_id,gen_random_uuid(),'Native scoped SQL send');
  if public.st_v8_standard_room_requires_sso(room_id)
    or not exists(select 1 from public.st_v6_room_posts p where p.id=room_post)
    or not exists(select 1 from public.st_v6_search('receipt rollback search','room','{}') p where p.id=room_post)
    or not exists(select 1 from public.st_v6_room_thread_state(room_id,array[room_post]))
    or public.st_v6_task_source(linked_task)->>'currentText' is distinct from 'Standard room receipt rollback search content' then
    raise exception 'Native receipt room timeline, Search, thread or task source access is missing'; end if;
  perform public.st_v6_room_post(room_id,gen_random_uuid(),'Native authorized room reply','message',room_post);
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  if public.st_v8_workspace_member_media_allowed(meeting_id) then raise exception 'Stale provider bypassed the gate'; end if;
  if exists(select 1 from public.st_v2_posts p where p.id=post_id) then raise exception 'Stale provider bypassed channel read gate'; end if;
  if not public.st_v8_standard_room_requires_sso(room_id) or exists(select 1 from public.st_v6_room_posts p where p.id=room_post) then
    raise exception 'Stale provider bypassed room read gate'; end if;
  perform set_config('request.jwt.claims',owner_claim,true);
  proof:=public.st_v8_workspace_member_media_policy(workspace,false);
  if proof->>'required' is distinct from 'false' or not public.st_v8_workspace_member_media_allowed(meeting_id) then
    raise exception 'Native TOTP owner could not recover media during provider failure'; end if;
  proof:=public.st_v8_workspace_standard_channel_policy(workspace,false);
  if proof->>'required' is distinct from 'false' or not exists(select 1 from public.st_v2_posts p where p.id=post_id) then
    raise exception 'Native TOTP owner could not recover standard channels during provider failure'; end if;
  proof:=public.st_v8_workspace_standard_room_policy(workspace,false);
  if proof->>'required' is distinct from 'false' or not exists(select 1 from public.st_v6_room_posts p where p.id=room_post) then
    raise exception 'Native TOTP owner could not recover standard rooms during provider failure'; end if;
  reset role;
  set local role service_role;
  if public.st_v6_room_guest_command('redeem',guest_room,null,null,guest_digest,repeat('f',64)) is not null then
    raise exception 'Room policy recovery reactivated a revoked guest link'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=true where identifier=provider;
  delete from public.st_v2_members where workspace_id=workspace and user_id=actor;
  insert into sectalk_private.st_v7_workspace_sso_attempts(digest,challenge,workspace,protocol,provider,domain,claimed_by)
    values(repeat('d',64),challenge,workspace,'oidc',provider,'enterprise.example.invalid',actor);
  set local role service_role;
  if public.st_v7_workspace_sso_finish(repeat('d',64),actor,sso_session) is not null then raise exception 'JIT re-enrolled a removed member'; end if;
  reset role;
end
$$;
select 'passed: trusted native flow, JIT and offboarding, pinned media and standard channel and room gates, stale-provider denial and native TOTP recovery' as result;
rollback;
