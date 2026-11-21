begin;
do $test$
declare
  owner_id uuid:=gen_random_uuid(); member_id uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid(); signed_session uuid:=gen_random_uuid();
  space uuid; other_space uuid; action text; domain_name text; statement text; state jsonb;
  provider text:='custom:policy-admin-rollback'; domain text:='policy-admin.example.invalid';
  owner_claim jsonb:=jsonb_build_object('sub',owner_id,'session_id',password_session,'role','authenticated','aal','aal2');
  signed_claim jsonb:=owner_claim||jsonb_build_object('session_id',signed_session,'aal','aal1');
  message constant text:='Sign in with workspace single sign-on to manage policies.';
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (owner_id,'owner@policy-admin.example.invalid',now()),(member_id,'member@policy-admin.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values
    (owner_id,'policy_scope_owner','Policy scope owner'),(member_id,'policy_scope_member','Policy scope member');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(password_session,owner_id,'aal2',factor),(signed_session,owner_id,'aal1',null);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),password_session,'totp',now(),now());
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Policy management fixture','fixture-client','synthetic-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim::text,true);
  space:=public.st_v2_create_workspace('Policy admin SSO fixture');
  other_space:=public.st_v2_create_workspace('Unprotected policy administration control');
  perform public.st_v6_set_workspace_notification_policy(space,array['mention'],20);
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(space,member_id,'member');
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(space,domain,now());
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(space,'save',domain,'oidc',false);
  if public.st_v8_workspace_policy_admin_policy(space,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Unproven provider was accepted'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(signed_session,space,owner_id,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_policy_admin_policy(space,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not configure policy administration SSO'; end if;
  if public.st_v7_workspace_policies(other_space,'messaging')->>'access' is distinct from 'verified' then
    raise exception 'Policy requirement leaked to another workspace'; end if;
  foreach domain_name in array array['messaging','files','calls','ai','retention','sharing','dlp','external'] loop
    foreach action in array array['read','preview','apply','rollback'] loop
      if public.st_v7_workspace_policies(space,domain_name,action,0,'{}',0) is distinct from '{"access":"sso"}'::jsonb then
        raise exception 'Policy editor exposed % via %',domain_name,action; end if;
    end loop;
  end loop;
  foreach statement in array array[
    $$st_v6_workspace_policy_versions($1,'retention')$$, $$st_v6_workspace_policy_versions($1,'notifications')$$,
    $$st_v6_change_workspace_policy($1,'retention','preview','{"days":60}',0)$$,
    $$st_v6_change_workspace_policy($1,'notifications','apply','{"categories":[]}',1)$$,
    $$st_v6_change_workspace_policy($1,'notifications','rollback',null,1,0)$$,
    $$st_v6_set_workspace_reactions($1,'native',3)$$,
    $$st_v6_set_workspace_file_history_policy($1,true)$$,
    $$st_v6_set_tenant_feature_pause($1,'recurring_meetings',true)$$,
    $$st_v7_workspace_ai_settings($1,true,true,2,30)$$,
    $$st_v6_room_retention_policy($1,60)$$,
    $$st_v7_org_settings($1,'save','Rejected organization edit','blue',60,'none')$$,
    $$st_v7_save_file_egress_policy($1,0,'{"mode":"block"}')$$,
    $$st_v7_set_workspace_dlp($1,0,'{"pii":"warn","phi":"allow","payment_card":"allow","credential":"allow"}')$$,
    $$st_v6_workspace_link_policy_set($1,array['allowed.example.invalid'])$$,
    $$st_v6_set_workspace_notification_policy($1,array['task'],40)$$
  ] loop
    begin
      execute 'select public.'||statement using space;
      raise exception 'A standard session accessed protected policy operation %',statement;
    exception when insufficient_privilege then
      if sqlerrm is distinct from message then raise; end if;
    end;
  end loop;
  perform public.st_v6_set_tenant_feature_pause(space,'task_creation',true);
  if public.st_v7_org_settings(space,'save','Allowed branding change','blue',30,'none')->>'name' is distinct from 'Allowed branding change' then
    raise exception 'Policy administration scope blocked an organization edit with the same retention'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',member_id,'role','authenticated','aal','aal1')::text,true);
  if public.st_v6_workspace_notification_settings(space)->'mandatory_categories' is distinct from '["mention"]'::jsonb
    or public.st_v7_workspace_policies(space,'messaging')->>'access' is distinct from 'none' then
    raise exception 'A member lost effective notifications or gained the policy editor'; end if;
  perform set_config('request.jwt.claims',signed_claim::text,true);
  if public.st_v7_workspace_policies(space,'messaging')->>'access' is distinct from 'mfa'
    or public.st_v8_workspace_policy_admin_policy(space,false)->>'access' is distinct from 'mfa' then
    raise exception 'SSO substituted for the independent authenticator'; end if;
  reset role;
  update auth.sessions set aal='aal2',factor_id=factor where id=signed_session;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),signed_session,'totp',now(),now());
  set local role authenticated;
  perform set_config('request.jwt.claims',(signed_claim||'{"aal":"aal2"}')::text,true);
  state:=public.st_v7_workspace_policies(space,'messaging','preview',0,'{"set":"native","limit":3}');
  if state#>>'{proposed,limit}' is distinct from '3'
    or public.st_v7_workspace_policies(space,'messaging')->>'revision' is distinct from '0' then
    raise exception 'Verified signed owner could not preview without persisting changes'; end if;
  state:=public.st_v7_workspace_policies(space,'messaging','apply',0,'{"set":"native","limit":3}');
  if state->>'revision' is distinct from '1' or state#>>'{current,limit}' is distinct from '3'
    or public.st_v6_change_workspace_policy(space,'notifications','apply','{"categories":["task"],"quiet_minutes":40}',1)
      #>>'{current,quiet_minutes}' is distinct from '40' then
    raise exception 'Verified signed owner could not save both policy editors'; end if;
  perform public.st_v7_org_settings(space,'save','Verified retention change','blue',60,'none');
  if public.st_v7_workspace_policies(space,'retention')#>>'{current,days}' is distinct from '60' then
    raise exception 'Verified signed organization editor could not change retention'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  if public.st_v7_workspace_policies(space,'messaging')->>'access' is distinct from 'sso' then
    raise exception 'Disabled provider retained policy editor access'; end if;
  perform set_config('request.jwt.claims',owner_claim::text,true);
  state:=public.st_v8_workspace_policy_admin_policy(space,false);
  if state->>'required' is distinct from 'false'
    or public.st_v7_workspace_policies(space,'messaging')#>>'{current,limit}' is distinct from '3'
    or public.st_v6_workspace_policy_versions(space,'notifications')->>'version' is distinct from '2' then
    raise exception 'Fresh owner could not recover policy editors and persisted settings'; end if;

  reset role;
  update auth.custom_oauth_providers set enabled=true where identifier=provider;
  set local role authenticated;
  if public.st_v8_workspace_entry_policy(space,true)->>'required' is distinct from 'true' then
    raise exception 'Verified owner could not enable the workspace entry policy'; end if;
  if public.st_v7_workspace_policies(space,'messaging') is distinct from '{"access":"sso"}'::jsonb
    or public.st_v6_tenant_feature_state(space) is not null
    or public.st_v7_workspace_policies(other_space,'messaging')->>'access' is distinct from 'verified' then
    raise exception 'Entry SSO leaked policy administration or affected another workspace'; end if;
  foreach statement in array array[
    $$st_v6_workspace_policy_versions($1,'notifications')$$,
    $$st_v6_set_workspace_reactions($1,'native',6)$$,
    $$st_v6_set_workspace_notification_policy($1,array['mention'],20)$$,
    $$st_v6_set_tenant_feature_pause($1,'task_creation',false)$$,
    $$st_v6_set_tenant_feature_pause($1,'recurring_meetings',true)$$,
    $$st_v6_set_tenant_feature_pause($1,'integration_api',true)$$,
    $$st_v7_workspace_ai_settings($1)$$,
    $$st_v7_workspace_ai_settings($1,true,true,2,30)$$
  ] loop
    begin
      execute 'select public.'||statement using space;
      raise exception 'A password session accessed entry-protected policy operation %',statement;
    exception when insufficient_privilege then
      if sqlerrm is distinct from message then raise; end if;
    end;
  end loop;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',member_id,'role','authenticated','aal','aal1')::text,true);
  begin
    perform public.st_v6_workspace_notification_settings(space);
    raise exception 'A password-only member read entry-protected notification settings';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',signed_claim::text,true);
  if public.st_v6_workspace_notification_settings(space)->'mandatory_categories' is distinct from '["task"]'::jsonb then
    raise exception 'Signed owner lost effective workspace notification settings'; end if;
  perform set_config('request.jwt.claims',(signed_claim||'{"aal":"aal2"}')::text,true);
  if public.st_v7_workspace_policies(space,'messaging')->>'access' is distinct from 'verified'
    or public.st_v6_tenant_feature_state(space)->>'verified' is distinct from 'true'
    or public.st_v7_workspace_ai_settings(space)->>'owner' is distinct from 'true' then
    raise exception 'Signed owner lost Policy Center, workspace features, or AI policy'; end if;
  perform public.st_v6_set_tenant_feature_pause(space,'task_creation',false);
  perform public.st_v6_set_tenant_feature_pause(space,'integration_api',true);
  if not (public.st_v6_tenant_feature_state(space)->'features' @> '[{"feature":"integration_api","paused":true}]') then
    raise exception 'Signed owner could not change access for authorized API credentials'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  if public.st_v7_workspace_policies(space,'messaging')->>'access' is distinct from 'sso'
    or public.st_v6_tenant_feature_state(space) is not null then
    raise exception 'Disabled provider retained protected settings'; end if;
  perform set_config('request.jwt.claims',owner_claim::text,true);
  if public.st_v8_workspace_entry_policy(space,false)->>'required' is distinct from 'false' then
    raise exception 'Verified owner could not restore standard entry'; end if;
  if public.st_v7_workspace_policies(space,'messaging')->>'access' is distinct from 'verified'
    or not (public.st_v6_tenant_feature_state(space)->'features' @> '[{"feature":"integration_api","paused":true}]') then
    raise exception 'Entry recovery did not restore the existing policies'; end if;
end $test$;
select 'passed: workspace entry and independent policy SSO, direct writers, feature controls, effective rules and recovery' as result;
rollback;
