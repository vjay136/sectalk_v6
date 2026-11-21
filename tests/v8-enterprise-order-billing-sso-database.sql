begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); delegate_id uuid:=gen_random_uuid(); commercial_id uuid:=gen_random_uuid();
  account_id uuid; password_session uuid; signed_session uuid; factor_id uuid;
  workspace_id uuid; control_id uuid; order_id uuid:=gen_random_uuid(); other_order uuid:=gen_random_uuid();
  standard_claims jsonb:='{}'; signed_claims jsonb:='{}'; ledger jsonb;
  provider text:='custom:enterprise-order-sso'; domain text:='enterprise-order-sso.example.invalid';
  today date:=(now() at time zone 'UTC')::date;
  quote jsonb:=jsonb_build_object('reference','Isolated Enterprise SSO order','total',22000,'seats',25,
    'currency','USD','starts',today+5,'expires',today+3,'terms','Synthetic negotiated workspace order.');
begin
  foreach account_id in array array[owner_id,delegate_id,commercial_id] loop
    password_session:=gen_random_uuid();
    signed_session:=gen_random_uuid();
    factor_id:=gen_random_uuid();
    insert into auth.users(id,email,email_confirmed_at) values(account_id,account_id||'@'||domain,now());
    insert into public.st_profiles(id,handle,name)
      values(account_id,'eo_'||left(replace(account_id::text,'-',''),12),'Enterprise order SSO fixture');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,account_id,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values
      (password_session,account_id,'aal2',factor_id),(signed_session,account_id,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
      (gen_random_uuid(),password_session,'totp',now(),now()),(gen_random_uuid(),signed_session,'totp',now(),now());
    standard_claims:=standard_claims||jsonb_build_object(account_id::text,jsonb_build_object('sub',account_id,
      'session_id',password_session,'role','authenticated','aal','aal2'));
    signed_claims:=signed_claims||jsonb_build_object(account_id::text,jsonb_build_object('sub',account_id,
      'session_id',signed_session,'role','authenticated','aal','aal2'));
  end loop;
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Enterprise order fixture','fixture-client','isolated-placeholder',
      'https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);

  set local role authenticated;
  perform set_config('request.jwt.claims',standard_claims->>owner_id::text,true);
  workspace_id:=public.st_v2_create_workspace('Enterprise order SSO workspace');
  control_id:=public.st_v2_create_workspace('Unrestricted Enterprise order workspace');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace_id,delegate_id,'member');
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(workspace_id,domain,now());
  insert into sectalk_private.st_v8_enterprise_billing_operators(workspace,actor) values(workspace_id,commercial_id);

  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(workspace_id,'save',domain,'oidc',true);
  perform public.st_v7_billing_admin_manage(workspace_id,delegate_id,true);
  if public.st_v8_enterprise_billing_view(workspace_id)->'roles' is distinct from '["owner"]'::jsonb then
    raise exception 'Standard owner access failed before enabling SSO';
  end if;
  perform set_config('request.jwt.claims',standard_claims->>commercial_id::text,true);
  perform public.st_v8_enterprise_billing_command(workspace_id,order_id,'quote',quote);
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    select (signed_claims->id::text->>'session_id')::uuid,workspace_id,id,'oidc',provider
    from (values(owner_id),(delegate_id)) authorized(id);

  set local role authenticated;
  perform set_config('request.jwt.claims',standard_claims->>owner_id::text,true);
  if public.st_v8_workspace_entry_policy(workspace_id,true)->>'required' is distinct from 'true' then
    raise exception 'Could not require workspace entry SSO';
  end if;
  if public.st_v8_enterprise_billing_view(control_id)->'roles' is distinct from '["owner"]'::jsonb then
    raise exception 'Workspace entry rule affected another workspace';
  end if;
  foreach account_id in array array[owner_id,delegate_id] loop
    perform set_config('request.jwt.claims',standard_claims->>account_id::text,true);
    begin
      perform public.st_v8_enterprise_billing_view(workspace_id);
      raise exception 'Password tenant billing session opened protected ledger';
    exception when insufficient_privilege then null; end;
    begin
      perform public.st_v8_enterprise_billing_command(workspace_id,order_id,'accept','{"po":"UNAUTHORIZED"}');
      raise exception 'Password tenant billing session changed protected ledger';
    exception when insufficient_privilege then null; end;
  end loop;
  perform set_config('request.jwt.claims',signed_claims->>delegate_id::text,true);
  ledger:=public.st_v8_enterprise_billing_view(workspace_id);
  if ledger->'roles' is distinct from '["billing"]'::jsonb or ledger#>>'{orders,0,id}' is distinct from order_id::text then
    raise exception 'Signed delegate did not keep read-only ledger access';
  end if;
  begin
    perform public.st_v8_enterprise_billing_command(workspace_id,order_id,'accept','{"po":"DELEGATE"}');
    raise exception 'Signed delegate gained owner authority';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',signed_claims->>owner_id::text,true);
  perform public.st_v8_enterprise_billing_command(workspace_id,order_id,'accept','{"po":"AUTHORIZED-SSO"}');
  perform set_config('request.jwt.claims',standard_claims->>commercial_id::text,true);
  if not exists(select 1 from public.st_v8_enterprise_billing_workspaces() listed where listed.id=workspace_id)
    or public.st_v8_enterprise_billing_view(workspace_id)->'roles' is distinct from '["commercial"]'::jsonb then
    raise exception 'Independent commercial operator lost its workspace or ledger role';
  end if;
  perform public.st_v8_enterprise_billing_command(workspace_id,order_id,'invoice',jsonb_build_object('due',today+30));
  perform public.st_v8_enterprise_billing_command(workspace_id,other_order,'quote',
    quote||jsonb_build_object('reference','Dual-role quote','starts',today+6,'expires',today+3));
  reset role;
  insert into sectalk_private.st_v8_enterprise_billing_operators(workspace,actor) values(workspace_id,owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',standard_claims->>owner_id::text,true);
  ledger:=public.st_v8_enterprise_billing_view(workspace_id);
  if ledger->'roles' is distinct from '["commercial"]'::jsonb
    or not ledger->'orders' @> jsonb_build_array(jsonb_build_object('id',order_id,'po','AUTHORIZED-SSO')) then
    raise exception 'A dual-grant password session gained owner authority or lost commercial scope';
  end if;
  begin
    perform public.st_v8_enterprise_billing_command(workspace_id,other_order,'accept','{"po":"MIXED-AUTHORITY"}');
    raise exception 'A commercial grant expanded the password session to owner authority';
  exception when insufficient_privilege then null; end;
  reset role;
  delete from sectalk_private.st_v8_enterprise_billing_operators g where (g.workspace,g.actor)=(workspace_id,owner_id);
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  perform set_config('request.jwt.claims',signed_claims->>owner_id::text,true);
  begin
    perform public.st_v8_enterprise_billing_view(workspace_id);
    raise exception 'Disconnected provider retained protected Enterprise order access';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',standard_claims->>owner_id::text,true);
  if public.st_v8_workspace_entry_policy(workspace_id,false)->>'required' is distinct from 'false' then
    raise exception 'Verified owner could not restore standard workspace entry';
  end if;
  if public.st_v8_enterprise_billing_view(workspace_id)->'roles' is distinct from '["owner"]'::jsonb then
    raise exception 'Native owner recovery did not restore standard ledger access';
  end if;
end $$;

select 'passed: Enterprise order workspace SSO, owner/delegate roles, independent commercial capability and recovery' as result;
rollback;
