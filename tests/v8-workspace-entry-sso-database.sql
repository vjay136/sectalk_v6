begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); member_user uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid(); signed_session uuid:=gen_random_uuid();
  space uuid:=gen_random_uuid(); other_space uuid; task uuid;
  room uuid:=gen_random_uuid(); post uuid:=gen_random_uuid(); channel uuid;
  provider text:='custom:workspace-entry-rollback'; domain text:='entry-sso.example.invalid';
  owner_claim jsonb:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2');
  signed_claim jsonb:=jsonb_build_object('sub',member_user,'session_id',signed_session,'role','authenticated','aal','aal1');
  settings jsonb;
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (owner_id,'owner@entry-sso.example.invalid',now()),(member_user,'member@entry-sso.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values
    (owner_id,'entry_policy_owner','Entry owner'),(member_user,'entry_policy_member','Entry member');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),(signed_session,member_user,'aal1',null);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Entry fixture','fixture-client','synthetic-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim::text,true);
  space:=public.st_v6_create_typed_workspace(space,'Locked entry fixture','enterprise');
  other_space:=public.st_v2_create_workspace('Unprotected entry control');
  perform public.st_v6_room_create(room,space,'Protected settings room','public','blank');
  perform public.st_v6_room_post(room,post,'Synthetic thread for receipt checks','message');
  insert into public.st_v6_thread_follows(room_id,post_id) values(room,post);
  channel:=public.st_v2_create_channel(space,'protected-settings');
  task:=public.st_v2_add_item(space,'task','Protected task','Synthetic workspace task',null);
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(space,member_user,'member');
  insert into public.st_v6_room_members(room_id,user_id,role) values(room,member_user,'member');
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(space,domain,now());
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(space,'save',domain,'oidc',false);
  perform public.st_v6_set_impersonation_watch(space,member_user,'vip');
  if not exists(select 1 from public.st_v6_impersonation_watch_list(space) w where w.member_id=member_user and w.tier='vip')
    or public.st_v7_workspace_active_profile_rules(space) is distinct from 'profile-rules-v1'
    or public.st_v7_workspace_rule_registry(space)->>'active' is distinct from 'profile-rules-v1' then
    raise exception 'Ordinary access before enabling workspace entry SSO failed';
  end if;
  if public.st_v8_workspace_entry_policy(space,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Entry policy accepted an unproven provider'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(signed_session,space,member_user,'oidc',provider);
  set local role authenticated;
  settings:=public.st_v8_workspace_entry_policy(space,true);
  if settings->>'required' is distinct from 'true'
    or exists(select 1 from public.st_v2_workspaces where id=space)
    or exists(select 1 from public.st_v6_workspace_policy where workspace_id=space)
    or exists(select 1 from public.st_v2_items where id=task)
    or not exists(select 1 from public.st_v2_workspaces where id=other_space)
    or (select count(*) from public.st_v2_members m where m.workspace_id=space)<>1
    or not exists(select 1 from public.st_v8_workspace_entry_shells(array[space,other_space]) s
      where s.id=space and s.name='Locked entry fixture') then
    raise exception 'Protected landing leaked private metadata or lost its own switcher/recovery'; end if;
  if public.st_v6_read_receipt_settings(space) is distinct from '{}'::jsonb
    or public.st_v6_read_receipt_settings(space,room) is distinct from '{}'::jsonb
    or public.st_v6_read_receipt_settings(other_space)->>'workspace_enabled' is distinct from 'true'
    or public.st_v6_read_receipt_settings()->>'personal_enabled' is distinct from 'true'
    or exists(select 1 from public.st_v6_thread_follows f where f.room_id=room) then
    raise exception 'Password session bypassed interaction scope or lost personal controls'; end if;
  delete from public.st_v6_thread_follows f where f.room_id=room and f.post_id=post;
  if found then raise exception 'Password session removed a protected followed thread'; end if;
  begin
    perform public.st_v6_set_read_receipt_policy(false,space);
    raise exception 'Password owner changed workspace read receipt policy';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_set_read_receipt_policy(false,null,room);
    raise exception 'Password owner changed room read receipt policy';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v2_add_item(space,'task','Unauthorized board item','Synthetic denied task',null);
    raise exception 'Password owner wrote to protected planning';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_room_retirement(room);
    raise exception 'Password owner read the room retirement state';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_room_retirement(room,'cancel');
    raise exception 'Password owner attempted to cancel room retirement';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_room_quiet_settings(room);
    raise exception 'Password owner read room quiet hours';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_set_room_quiet(room,'mute',true);
    raise exception 'Password owner changed room quiet hours';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_channel_quiet_settings(channel);
    raise exception 'Password owner read channel quiet hours';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_set_channel_quiet(channel,'mute',true);
    raise exception 'Password owner changed channel quiet hours';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v2_set_member(space,member_user,'admin');
    raise exception 'Password owner changed protected roster';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_impersonation_watch_list(space);
    raise exception 'Password owner read protected watch entries';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_set_impersonation_watch(space,member_user,null);
    raise exception 'Password owner removed a protected watch entry';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_workspace_active_profile_rules(space);
    raise exception 'Password owner read the protected rule version';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_workspace_rule_registry(space);
    raise exception 'Password owner read the protected registry';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_workspace_rule_registry(space,'clear',null,'00000000-0000-0000-0000-000000000000');
    raise exception 'Password owner changed the protected registry';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',signed_claim::text,true);
  if not exists(select 1 from public.st_v2_workspaces where id=space)
    or not exists(select 1 from public.st_v6_workspace_policy where workspace_id=space)
    or not exists(select 1 from public.st_v2_items where id=task)
    or (select count(*) from public.st_v2_members m where m.workspace_id=space)<>2
    or exists(select 1 from public.st_v8_workspace_entry_shells(array[space,other_space]))
    or public.st_v8_workspace_entry_policy(space,false)->>'access' is distinct from 'none' then
    raise exception 'Signed member lost full workspace or accessed owner recovery'; end if;
  perform public.st_v2_complete_task(task,true);
  insert into public.st_v6_thread_follows(room_id,post_id) values(room,post);
  perform public.st_v6_share_room_reads(room,array[post]);
  if public.st_v6_read_receipt_settings(space,room)->>'room_enabled' is distinct from 'true'
    or not exists(select 1 from public.st_v6_room_thread_state(room,array[post]) f where f.following) then
    raise exception 'Signed reader could not follow a thread or read its receipt settings'; end if;
  perform public.st_v6_set_room_quiet(room,'mute',true);
  perform public.st_v6_set_channel_quiet(channel,'mute',true);
  if public.st_v6_room_quiet_settings(room)->>'muted' is distinct from 'true'
    or public.st_v6_channel_quiet_settings(channel)->>'muted' is distinct from 'true'
    or public.st_v6_room_retirement(room)->>'can_manage' is distinct from 'false' then
    raise exception 'Signed member lost personal preferences or gained retirement controls'; end if;
  begin
    perform public.st_v6_impersonation_watch_list(space);
    raise exception 'Signed member read manager-only watch entries';
  exception when insufficient_privilege then null; end;
  reset role;
  update public.st_v2_members set role='admin' where workspace_id=space and user_id=member_user;
  set local role authenticated;
  if not exists(select 1 from public.st_v6_impersonation_watch_list(space) w where w.member_id=member_user and w.tier='vip')
    or public.st_v7_workspace_active_profile_rules(space) is distinct from 'profile-rules-v1'
    or public.st_v7_workspace_rule_registry(space)->>'owner' is distinct from 'false' then
    raise exception 'Signed manager could not load the watch entries and advisory rules';
  end if;
  perform public.st_v6_set_impersonation_watch(space,member_user,'executive');
  begin
    perform public.st_v7_workspace_rule_registry(space,'stage','profile-rules-v2','00000000-0000-0000-0000-000000000000');
    raise exception 'Signed admin changed an owner-only registry';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(owner_session,space,owner_id,'oidc',provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim::text,true);
  settings:=public.st_v7_workspace_rule_registry(space,'stage','profile-rules-v2','00000000-0000-0000-0000-000000000000');
  if settings->>'shadow' is distinct from 'profile-rules-v2' then
    raise exception 'Signed owner could not stage the new registry version';
  end if;
  if (select amount from public.st_v6_room_read_counts(room,array[post])) is distinct from 1::bigint
    or not exists(select 1 from public.st_v6_room_thread_state(room,array[post]) f where f.following) then
    raise exception 'Signed owner could not read the shared receipt or the preserved follow'; end if;
  perform public.st_v6_set_read_receipt_policy(false,null,room);
  if public.st_v6_read_receipt_settings(space,room)->>'room_enabled' is distinct from 'false' then
    raise exception 'Signed owner could not change the room read receipt policy'; end if;
  perform public.st_v6_manage_room(room,'archive');
  if public.st_v6_room_retirement(room,'schedule')->>'requested_at' is null then
    raise exception 'Signed and freshly verified owner could not schedule retirement'; end if;
  -- Prove the independently enabled planner restriction survives entry recovery.
  perform set_config('request.jwt.claims',owner_claim::text,true);
  perform public.st_v8_workspace_planner_policy(space,true);
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  perform set_config('request.jwt.claims',signed_claim::text,true);
  if exists(select 1 from public.st_v2_workspaces where id=space)
    or not exists(select 1 from public.st_v8_workspace_entry_shells(array[space]) s where s.id=space) then
    raise exception 'Disabled provider retained workspace entry'; end if;
  if public.st_v6_read_receipt_settings(space,room) is distinct from '{}'::jsonb
    or exists(select 1 from public.st_v6_thread_follows f where f.room_id=room) then
    raise exception 'Revoked receipt retained room interactions'; end if;
  begin
    perform public.st_v6_impersonation_watch_list(space);
    raise exception 'Disabled provider retained watch access';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_channel_quiet_settings(channel);
    raise exception 'Disabled provider retained channel quiet settings';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',owner_claim::text,true);
  settings:=public.st_v8_workspace_entry_policy(space,false);
  if settings->>'required' is distinct from 'false'
    or not exists(select 1 from public.st_v2_workspaces where id=space)
    or not exists(select 1 from public.st_v6_workspace_policy where workspace_id=space)
    or not exists(select 1 from public.st_v6_impersonation_watch_list(space) w where w.member_id=member_user and w.tier='executive')
    or public.st_v7_workspace_rule_registry(space)->>'owner' is distinct from 'true'
    or public.st_v7_workspace_rule_registry(space)->>'shadow' is distinct from 'profile-rules-v2'
    or exists(select 1 from public.st_v2_items where id=task) then
    raise exception 'Fresh owner could not recover workspace entry or recovery reset planner policy'; end if;
  if public.st_v6_room_retirement(room,'cancel')->>'requested_at' is not null
    or public.st_v6_room_quiet_settings(room)->>'muted' is distinct from 'false'
    or public.st_v6_channel_quiet_settings(channel)->>'muted' is distinct from 'false' then
    raise exception 'Recovery did not restore the owner’s settings and retirement controls'; end if;
  if public.st_v6_read_receipt_settings(space,room)->>'room_enabled' is distinct from 'false' then
    raise exception 'Recovery changed or hid the existing receipt policy'; end if;
end $$;
select 'passed: private workspace entry, roster, planner, impersonation watch and rule registry, independent scopes and recovery' as result;
rollback;
