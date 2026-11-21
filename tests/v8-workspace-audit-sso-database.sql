begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid(); other uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid();
  sso_session uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid();
  workspace uuid; second_workspace uuid; entry bigint; room uuid:=gen_random_uuid();
  provider text:='custom:audit-sso-rollback'; domain text:='audit-sso.example.invalid';
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  plain_claim text:=jsonb_build_object('sub',actor,'session_id',password_session,'role','authenticated')::text;
  provider_claim text:=jsonb_build_object('sub',actor,'session_id',sso_session,'role','authenticated')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'owner@audit-sso.example.invalid',now()),
    (actor,'member@audit-sso.example.invalid',now()),(other,'other@audit-sso.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values(owner_id,'dir_'||left(replace(owner_id::text,'-',''),12),'Audit owner'),
    (actor,'dir_'||left(replace(actor::text,'-',''),12),'Audit member'),
    (other,'aud_'||left(replace(other::text,'-',''),12),'Audit member');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),
    (sso_session,actor,'aal1',null),(password_session,actor,'aal1',null);
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Fixture OIDC','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  workspace:=public.st_v2_create_workspace('Workspace audit SSO fixture');
  second_workspace:=public.st_v2_create_workspace('Separate unprotected audit');
  if public.st_v8_workspace_audit_policy(workspace,true)->>'access' is distinct from 'mfa' then
    raise exception 'Owner enabled audit SSO without fresh TOTP'; end if;
  reset role;

  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(workspace,domain,now());
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,actor,'admin'),(workspace,other,'admin'),(second_workspace,actor,'admin');
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(workspace,'save',domain,'oidc',true);
  if public.st_v8_workspace_audit_policy(workspace,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Audit SSO enabled without observed provider session'; end if;
  perform public.st_v6_room_create(room,workspace,'Private audit SSO room','private','project');
  if not exists(select 1 from public.st_v6_audit_search(workspace,'workspace created','workspace')) then
    raise exception 'Default audit access unexpectedly blocked'; end if;
  select id into entry from public.st_v6_audit_search(workspace,'workspace created','workspace');
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(sso_session,workspace,actor,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_audit_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not require audit SSO'; end if;
  if not public.st_v8_workspace_audit_requires_sso(workspace)
    or exists(select 1 from public.st_v2_workspace_audit where workspace_id=workspace)
    or not exists(select 1 from public.st_v2_workspace_audit where workspace_id=second_workspace)
    or not exists(select 1 from public.st_v6_audit_workspaces() w where w.id=workspace) then
    raise exception 'Audit scope leaked rows or changed recovery and unrelated workspaces'; end if;
  begin
    perform public.st_v6_audit_search(workspace,'',p_source=>'room');
    raise exception 'Password owner could search protected aggregate audit';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_audit_integrity_status(workspace,jsonb_build_array(jsonb_build_object('source','workspace','id',entry)));
    raise exception 'Password owner could query protected integrity proof';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_record_audit_export(workspace);
    raise exception 'Password owner could authorize a protected audit export';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',provider_claim,true);
  if public.st_v8_workspace_audit_requires_sso(workspace)
    or not exists(select 1 from public.st_v2_workspace_audit where id=entry)
    or not exists(select 1 from public.st_v6_audit_search(workspace,'workspace created','workspace'))
    or exists(select 1 from public.st_v6_audit_search(workspace,'private audit SSO room','room'))
    or public.st_v6_audit_integrity_status(workspace,jsonb_build_array(jsonb_build_object('source','workspace','id',entry)))->>'state' is distinct from 'matched' then
    raise exception 'Live audit receipt or existing room-role checks failed'; end if;
  begin
    perform public.st_v6_record_audit_export(workspace);
    raise exception 'Provider session skipped the export TOTP requirement';
  exception when insufficient_privilege then null;
  end;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(owner_session,workspace,owner_id,'oidc',provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  perform public.st_v6_record_audit_export(workspace);
  if not exists(select 1 from public.st_v2_workspace_audit where workspace_id=workspace and event='workspace.audit_export_requested') then
    raise exception 'Fresh owner with receipt could not authorize signed audit export'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  if not public.st_v8_workspace_audit_requires_sso(workspace)
    or exists(select 1 from public.st_v2_workspace_audit where id=entry) then
    raise exception 'Disabled provider retained scoped audit access'; end if;
  if public.st_v8_workspace_audit_policy(workspace,false)->>'required' is distinct from 'false' then
    raise exception 'Fresh owner could not recover audit access'; end if;
  if not exists(select 1 from public.st_v6_audit_search(workspace,'workspace created','workspace')) then
    raise exception 'Audit search stayed blocked after recovery'; end if;
end $$;
rollback;
