begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid(); other uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid();
  sso_session uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid();
  workspace uuid; second_workspace uuid;
  provider text:='custom:organization-sso-rollback'; domain text:='organization-sso.example.invalid';
  owner_sso uuid:=gen_random_uuid(); pending uuid; signed_pending uuid;
  pending_domain text:='managed-organization-settings.example.invalid';
  entry_domain text:='entry-governance.example.invalid'; stale_domain text:='stale-entry-governance.example.invalid';
  owner_sso_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_sso,'role','authenticated','aal','aal2')::text;
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  plain_claim text:=jsonb_build_object('sub',actor,'session_id',password_session,'role','authenticated')::text;
  provider_claim text:=jsonb_build_object('sub',actor,'session_id',sso_session,'role','authenticated')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'owner@organization-sso.example.invalid',now()),
    (actor,'member@organization-sso.example.invalid',now()),(other,'other@organization-sso.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values(owner_id,'dir_'||left(replace(owner_id::text,'-',''),12),'Organization owner'),
    (actor,'dir_'||left(replace(actor::text,'-',''),12),'Organization member'),
    (other,'org_'||left(replace(other::text,'-',''),12),'Independent operator');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),
    (sso_session,actor,'aal1',null),(password_session,actor,'aal1',null),(owner_sso,owner_id,'aal2',factor);
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Fixture OIDC','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  workspace:=public.st_v2_create_workspace('Workspace organization SSO fixture');
  second_workspace:=public.st_v2_create_workspace('Separate unprotected organization');
  if public.st_v8_workspace_organization_policy(workspace,true)->>'access' is distinct from 'mfa' then
    raise exception 'Owner enabled organization SSO without fresh TOTP'; end if;
  reset role;

  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now()),(gen_random_uuid(),owner_sso,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(workspace,domain,now());
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,actor,'member'),(workspace,other,'member'),(second_workspace,actor,'member');
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(workspace,'save',domain,'oidc',true);
  if public.st_v8_workspace_organization_policy(workspace,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Organization SSO enabled without observed provider session'; end if;
  perform public.st_v7_org_settings(workspace,'domain.start',p_domain=>pending_domain);
  pending:=(public.st_v7_org_settings(workspace,'domain.proof',p_domain=>pending_domain)->>'challenge')::uuid;
  if public.st_v8_workspace_residency(workspace)->>'eligible' is distinct from 'true' or pending is null then
    raise exception 'Default organization and residency settings unavailable'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(sso_session,workspace,actor,'oidc',provider),(owner_sso,workspace,owner_id,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_organization_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not require organization SSO'; end if;
  if not public.st_v8_workspace_organization_requires_sso(workspace)
    or public.st_v8_workspace_organization_requires_sso(second_workspace)
    or public.st_v7_workspace_sso_settings(workspace)->>'access' is distinct from 'verified'
    or public.st_v7_workspace_email_template(workspace,'delivery')->>'organization' is null
    or not exists(select 1 from public.st_v2_workspaces where id=workspace and brand_accent='blue') then
    raise exception 'Organization scope blocked provider recovery, existing invites or workspace identity'; end if;
  begin
    perform public.st_v7_org_settings(workspace,'domain.proof',p_domain=>pending_domain);
    raise exception 'Password owner could acquire protected DNS proof';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v7_org_settings(workspace,'save','Denied brand','teal',35,'eu');
    raise exception 'Password owner could update protected branding';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v7_workspace_email_template(workspace);
    raise exception 'Password owner could read protected invitation templates';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_room_retention_policy(workspace,21);
    raise exception 'Password owner could change protected retention';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v8_workspace_residency(workspace);
    raise exception 'Password owner could read protected residency';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v8_workspace_residency_change(workspace);
    raise exception 'Password owner could mutate protected residency';
  exception when insufficient_privilege then null;
  end;
  reset role;
  set local role service_role;
  if public.st_v7_finish_org_domain(workspace,pending,owner_id,owner_session) then
    raise exception 'DNS proof issued before policy was still accepted from a password session'; end if;
  reset role;

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_sso_claim,true);
  if public.st_v8_workspace_organization_requires_sso(workspace)
    or public.st_v7_org_settings(workspace)->>'name' is null
    or public.st_v8_workspace_residency(workspace)->>'eligible' is distinct from 'true' then
    raise exception 'Live owner SSO receipt lost protected settings'; end if;
  perform public.st_v7_org_settings(workspace,'save','Verified organization','teal',35,'eu');
  perform public.st_v7_workspace_email_template(workspace,'publish','Existing invitation','Join our workspace');
  perform public.st_v6_room_retention_policy(workspace,35);
  perform public.st_v8_workspace_residency_change(workspace);
  signed_pending:=(public.st_v7_org_settings(workspace,'domain.proof',p_domain=>pending_domain)->>'challenge')::uuid;
  reset role;
  set local role service_role;
  if not public.st_v7_finish_org_domain(workspace,signed_pending,owner_id,owner_sso) then
    raise exception 'Signed owner DNS handoff could not verify the domain'; end if;
  reset role;

  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  if not public.st_v8_workspace_organization_requires_sso(workspace) then
    raise exception 'Disabled provider retained organization access'; end if;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_organization_policy(workspace,false)->>'required' is distinct from 'false' then
    raise exception 'Fresh owner could not recover organization policies'; end if;
  if public.st_v7_org_settings(workspace)->>'accent' is distinct from 'teal'
    or public.st_v7_org_settings(workspace)->>'retentionDays' is distinct from '35' then
    raise exception 'Organization changes did not persist after owner recovery'; end if;

  reset role;
  update auth.custom_oauth_providers set enabled=true where identifier=provider;
  set local role authenticated;
  perform public.st_v7_org_settings(workspace,'domain.start',p_domain=>entry_domain);
  pending:=(public.st_v7_org_settings(workspace,'domain.proof',p_domain=>entry_domain)->>'challenge')::uuid;
  if public.st_v8_workspace_entry_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Verified owner could not enable entry SSO'; end if;
  if not public.st_v8_workspace_organization_requires_sso(workspace)
    or public.st_v8_workspace_organization_requires_sso(second_workspace)
    or public.st_v7_workspace_sso_settings(workspace)->>'access' is distinct from 'verified' then
    raise exception 'Organization access signal, other workspace, or graceful provider recovery changed'; end if;
  begin
    perform public.st_v7_org_settings(workspace);
    raise exception 'Password owner read organization data under entry SSO';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_org_settings(workspace,'save','Password update','amber',35,'us');
    raise exception 'Password owner changed branding under entry SSO';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_org_settings(workspace,'domain.proof',p_domain=>entry_domain);
    raise exception 'Password owner acquired a pending domain proof under entry SSO';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_workspace_residency(workspace);
    raise exception 'Password owner read residency under entry SSO';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_workspace_residency_change(workspace);
    raise exception 'Password owner changed residency under entry SSO';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_room_retention_policy(workspace);
    raise exception 'Password owner read direct room retention under entry SSO';
  exception when insufficient_privilege then null; end;
  reset role;
  set local role service_role;
  if public.st_v7_finish_org_domain(workspace,pending,owner_id,owner_session)
    or public.st_v7_finish_org_domain(workspace,pending,owner_id,sso_session) then
    raise exception 'DNS accepted a prepolicy password or wrong-principal proof'; end if;
  reset role;
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_sso_claim,true);
  if public.st_v8_workspace_organization_requires_sso(workspace)
    or public.st_v8_workspace_residency(workspace)->>'eligible' is distinct from 'true'
    or public.st_v6_room_retention_policy(workspace) is distinct from 35 then
    raise exception 'Signed owner lost regular organization paths'; end if;
  perform public.st_v7_org_settings(workspace,'save','Entry verified organization','violet',35,'apac');
  perform public.st_v8_workspace_residency_change(workspace);
  signed_pending:=(public.st_v7_org_settings(workspace,'domain.proof',p_domain=>entry_domain)->>'challenge')::uuid;
  perform public.st_v7_org_settings(workspace,'domain.start',p_domain=>stale_domain);
  pending:=(public.st_v7_org_settings(workspace,'domain.proof',p_domain=>stale_domain)->>'challenge')::uuid;
  reset role;
  set local role service_role;
  if not public.st_v7_finish_org_domain(workspace,signed_pending,owner_id,owner_sso) then
    raise exception 'Service could not finalize the signed owner DNS handoff'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role service_role;
  if pending is null or public.st_v7_finish_org_domain(workspace,pending,owner_id,owner_sso) then
    raise exception 'Service accepted the signed DNS handoff after provider revocation'; end if;
  reset role;
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_entry_policy(workspace,false)->>'required' is distinct from 'false' then
    raise exception 'Verified owner could not restore standard workspace entry'; end if;
  if public.st_v7_org_settings(workspace)->>'accent' is distinct from 'violet' then
    raise exception 'Saved branding did not persist after entry recovery'; end if;
end $$;
rollback;
