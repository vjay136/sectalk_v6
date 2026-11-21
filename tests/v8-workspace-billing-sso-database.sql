begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid(); other uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); actor_factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid();
  sso_session uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid();
  workspace uuid; second_workspace uuid;
  provider text:='custom:billing-sso-rollback'; domain text:='billing-sso.example.invalid';
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  plain_claim text:=jsonb_build_object('sub',actor,'session_id',password_session,'role','authenticated','aal','aal2')::text;
  provider_claim text:=jsonb_build_object('sub',actor,'session_id',sso_session,'role','authenticated','aal','aal2')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'owner@billing-sso.example.invalid',now()),
    (actor,'member@billing-sso.example.invalid',now()),(other,'other@billing-sso.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values(owner_id,'dir_'||left(replace(owner_id::text,'-',''),12),'Billing owner'),
    (actor,'dir_'||left(replace(actor::text,'-',''),12),'Billing member'),
    (other,'bil_'||left(replace(other::text,'-',''),12),'Ordinary user');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end,customer_id,subscription_id)
    values(owner_id,'enterprise','active',now()+interval '1 day','cus_billing_sso_fixture','sub_billing_sso_fixture');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now()),
    (actor_factor,actor,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),
    (sso_session,actor,'aal2',actor_factor),(password_session,actor,'aal2',actor_factor);
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Fixture OIDC','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  workspace:=public.st_v2_create_workspace('Workspace billing SSO fixture');
  second_workspace:=public.st_v2_create_workspace('Separate unprotected billing');
  if public.st_v8_workspace_billing_policy(workspace,true)->>'access' is distinct from 'mfa' then
    raise exception 'Owner enabled billing SSO without fresh TOTP'; end if;
  reset role;

  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now()),
      (gen_random_uuid(),sso_session,'totp',now(),now()),(gen_random_uuid(),password_session,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(workspace,domain,now());
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,actor,'member'),(workspace,other,'member'),(second_workspace,actor,'member');
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(workspace,'save',domain,'oidc',true);
  if public.st_v8_workspace_billing_policy(workspace,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Billing SSO enabled without observed provider session'; end if;
  perform public.st_v7_billing_admin_manage(workspace,actor,true);
  if public.st_v7_workspace_usage(workspace)->>'plan' is distinct from 'enterprise'
    or public.st_v8_workspace_seat_scope(workspace) is distinct from true then
    raise exception 'Default owner billing access failed'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(sso_session,workspace,actor,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_billing_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not require billing SSO'; end if;
  if public.st_v8_workspace_billing_access(workspace) is distinct from 'required'
    or public.st_v8_workspace_billing_access(second_workspace) is distinct from 'allowed'
    or not exists(select 1 from public.st_v2_subscriptions where user_id=owner_id and plan='enterprise')
    or public.st_v7_workspace_usage(second_workspace)->>'plan' is distinct from 'enterprise'
    or public.st_v7_workspace_payment_state(p_workspace=>workspace)->>'mode' is distinct from 'active' then
    raise exception 'Billing scope leaked access or lost account billing, payment state or another workspace'; end if;
  begin
    perform public.st_v7_billing_admin_manage(workspace,actor,false);
    raise exception 'Password owner changed protected billing delegation';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v7_workspace_usage(workspace);
    raise exception 'Password owner read protected workspace usage';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v8_workspace_seat_scope(workspace);
    raise exception 'Password owner was authorized for a protected seat purchase';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',plain_claim,true);
  if public.st_v8_workspace_billing_access(workspace) is distinct from 'required'
    or not exists(select 1 from jsonb_array_elements(public.st_v7_billing_admin_view()) item
      where item->>'id'=workspace::text and item->>'delegated'='true') then
    raise exception 'Billing chooser lost existing delegation or failed to require SSO'; end if;
  begin
    perform public.st_v7_billing_admin_view(workspace);
    raise exception 'Password delegate read protected billing summary';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v8_invoice_adjustment_scope(workspace);
    raise exception 'Password delegate authorized a protected invoice adjustment';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',provider_claim,true);
  if public.st_v8_workspace_billing_access(workspace) is distinct from 'allowed'
    or public.st_v7_billing_admin_view(workspace)->>'plan' is distinct from 'enterprise'
    or public.st_v8_workspace_seat_scope(workspace) is distinct from true
    or public.st_v8_invoice_adjustment_scope(workspace) is distinct from true then
    raise exception 'Verified delegated native session lost billing data or action grants'; end if;
  reset role;
  set local role service_role;
  if public.st_v7_billing_admin_provider_scope(workspace,actor)->>'customer' is distinct from 'cus_billing_sso_fixture' then
    raise exception 'Trusted service provider binding lost independent account scope'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  if public.st_v8_workspace_billing_access(workspace) is distinct from 'required' then
    raise exception 'Disabled provider retained scoped billing access'; end if;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_billing_policy(workspace,false)->>'required' is distinct from 'false' then
    raise exception 'Fresh owner could not recover billing settings'; end if;
  if public.st_v7_workspace_usage(workspace)->>'plan' is distinct from 'enterprise'
    or public.st_v7_billing_admin_manage(workspace)->>'access' is distinct from 'verified' then
    raise exception 'Workspace billing stayed blocked after owner recovery'; end if;

  reset role;
  update auth.custom_oauth_providers set enabled=true where identifier=provider;
  set local role authenticated;
  if public.st_v8_workspace_entry_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not require workspace entry SSO'; end if;
  if public.st_v8_workspace_billing_access(workspace) is distinct from 'required'
    or public.st_v8_workspace_billing_access(second_workspace) is distinct from 'allowed'
    or not exists(select 1 from public.st_v2_subscriptions where user_id=owner_id and plan='enterprise') then
    raise exception 'Entry policy leaked billing or interfered with separate account billing'; end if;
  begin
    perform public.st_v7_billing_admin_manage(workspace,actor,false);
    raise exception 'Password owner changed delegates while entry SSO was required';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v7_workspace_usage(workspace);
    raise exception 'Password owner read usage while entry SSO was required';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v8_workspace_seat_scope(workspace);
    raise exception 'Password owner approved seat changes while entry SSO was required';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',plain_claim,true);
  begin
    perform public.st_v7_billing_admin_view(workspace);
    raise exception 'Password delegate read billing details while entry SSO was required';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v8_invoice_adjustment_scope(workspace);
    raise exception 'Password delegate approved adjustments while entry SSO was required';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',provider_claim,true);
  if public.st_v8_workspace_billing_access(workspace) is distinct from 'allowed'
    or public.st_v7_billing_admin_view(workspace)->>'plan' is distinct from 'enterprise'
    or public.st_v8_workspace_seat_scope(workspace) is distinct from true
    or public.st_v8_invoice_adjustment_scope(workspace) is distinct from true then
    raise exception 'Signed delegate lost existing billing permissions'; end if;
  reset role;
  set local role service_role;
  if public.st_v7_billing_admin_provider_scope(workspace,actor)->>'customer' is distinct from 'cus_billing_sso_fixture' then
    raise exception 'Entry SSO blocked the independent provider binding'; end if;
  reset role;
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_billing_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Could not enable the independent billing SSO policy'; end if;
  if public.st_v8_workspace_entry_policy(workspace,false)->>'required' is distinct from 'false' then
    raise exception 'Verified owner could not restore standard entry'; end if;
  if public.st_v8_workspace_billing_access(workspace) is distinct from 'required' then
    raise exception 'Entry recovery disabled the separate billing policy'; end if;
  if public.st_v8_workspace_trial_session(workspace) is not null
    or public.st_v8_workspace_trial_session(second_workspace) is distinct from owner_session then
    raise exception 'Trial authorization did not separately enforce workspace billing SSO'; end if;
  begin
    perform public.st_v7_workspace_trial_status(workspace);
    raise exception 'Password owner read protected trial status';
  exception when insufficient_privilege then null; end;
  reset role;
  set local role service_role;
  begin
    perform public.st_v8_start_workspace_trial_for_session(workspace,owner_id,owner_session,'business',false);
    raise exception 'Service trial mutation ignored the current owner session scope';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(owner_session,workspace,owner_id,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_trial_session(workspace) is distinct from owner_session
    or public.st_v7_workspace_trial_status(workspace)->>'state' is distinct from 'subscribed' then
    raise exception 'Signed owner lost the protected trial scope'; end if;
  reset role;
  set local role service_role;
  begin
    perform public.st_v8_start_workspace_trial_for_session(workspace,owner_id,owner_session,'business',false);
    raise exception 'Existing plan did not block a trial';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role service_role;
  begin
    perform public.st_v8_start_workspace_trial_for_session(workspace,owner_id,owner_session,'business',false);
    raise exception 'A disconnected provider retained trial mutation access';
  exception when insufficient_privilege then null; end;
  reset role;
  set local role authenticated;
  if public.st_v8_workspace_billing_policy(workspace,false)->>'required' is distinct from 'false' then
    raise exception 'Verified owner could not restore standard billing sign-in'; end if;
  if public.st_v8_workspace_billing_access(workspace) is distinct from 'allowed' then
    raise exception 'Verified owner could not recover workspace billing'; end if;
end $$;
rollback;
