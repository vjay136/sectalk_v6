begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); admin_id uuid:=gen_random_uuid();
  actor_id uuid; factor uuid; session_id uuid; signed_session uuid:=gen_random_uuid(); admin_factor uuid;
  owner_claim text; admin_claim text; signed_claim jsonb;
  space uuid; other_space uuid; room uuid:=gen_random_uuid(); post uuid:=gen_random_uuid();
  original_hold uuid:=gen_random_uuid(); extra_hold uuid:=gen_random_uuid(); report uuid; export_case uuid; state jsonb;
  pending_case uuid; old_export uuid; old_evidence uuid; ticket_export uuid; ticket_evidence uuid;
  provider text:='custom:compliance-sso-rollback'; domain text:='compliance-sso.example.invalid';
  reason constant text:='Synthetic private hold rationale';
begin
  foreach actor_id in array array[owner_id,admin_id] loop
    factor:=gen_random_uuid(); session_id:=gen_random_uuid();
    insert into auth.users(id,email,email_confirmed_at) values(actor_id,actor_id||'@compliance-sso.example.invalid',now());
    insert into public.st_profiles(id,handle,name) values(actor_id,'comp_sso_'||left(actor_id::text,8),'Legal hold fixture');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,actor_id,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor_id,'aal2',factor);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    state:=jsonb_build_object('sub',actor_id,'session_id',session_id,'role','authenticated','aal','aal2');
    if actor_id=owner_id then owner_claim:=state::text;
    else admin_claim:=state::text; admin_factor:=factor; end if;
  end loop;
  signed_claim:=admin_claim::jsonb||jsonb_build_object('session_id',signed_session,'aal','aal1');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.sessions(id,user_id,aal) values(signed_session,admin_id,'aal1');
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Hold fixture','fixture-client','synthetic-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  space:=public.st_v2_create_workspace('Compliance SSO fixture');
  other_space:=public.st_v2_create_workspace('Unprotected compliance control');
  perform public.st_v6_room_create(room,space,'Preservation source','public','blank');
  perform public.st_v6_room_post(room,post,'Synthetic preserved material');
  perform public.st_v6_place_workspace_hold(space,original_hold,room,null,null,null,reason);
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(space,admin_id,'admin');
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(space,domain,now());
  set local role authenticated;
  perform set_config('request.jwt.claims',admin_claim,true);
  perform public.st_v6_room_membership(room,'join');
  report:=public.st_v6_submit_room_report(room,post,'threat','Fictional test report',true);
  export_case:=public.st_v7_request_compliance_export(space,'LEGAL-QA','Preserve the named records for a test case',
    jsonb_build_array(jsonb_build_object('kind','room_report','id',report::text)));
  perform set_config('request.jwt.claims',owner_claim,true);
  perform public.st_v7_review_compliance_export(export_case,'approved','Approved the specified synthetic report');
  perform public.st_v7_workspace_sso_settings(space,'save',domain,'oidc',false);
  perform set_config('request.jwt.claims',admin_claim,true);
  pending_case:=public.st_v7_request_compliance_export(space,'PENDING-QA','Preserve the named records for a test case',
    jsonb_build_array(jsonb_build_object('kind','room_report','id',report::text)));
  old_export:=public.st_v7_begin_compliance_operation(export_case,'build');
  old_evidence:=public.st_v7_begin_evidence_operation('capture',export_case,report,original_hold,null,reason);
  reset role;
  if public.st_v7_read_compliance_operation(old_export) is null or public.st_v7_read_evidence_operation(old_evidence) is null then
    raise exception 'Baseline tickets did not expose native material'; end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_compliance_policy(space,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Unproven provider was accepted'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(signed_session,space,admin_id,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_compliance_policy(space,true)->>'required' is distinct from 'true'
    or public.st_v7_compliance_access(other_space) is distinct from 'owner' then
    raise exception 'Fresh owner could not activate compliance SSO or scope crossed tenants'; end if;
  begin
    perform public.st_v7_review_compliance_export(pending_case,'approved',reason);
    raise exception 'Password owner approved a protected case';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_compliance_cases(space);
    raise exception 'Password owner read protected cases';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',admin_claim,true);
  if public.st_v7_compliance_access(space) is distinct from 'sso'
    or public.st_v7_evidence_vault(space) is distinct from '{"access":"sso"}'::jsonb
    or public.st_v7_permission_catalog(space,null)#>>'{workspace,compliance.export.request}' is distinct from 'sso_required' then
    raise exception 'Workspace policy failed to protect compliance and evidence metadata'; end if;
  begin
    perform public.st_v7_compliance_sources(space);
    raise exception 'Password admin read compliance sources';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_request_compliance_export(space,'DENIED-QA',reason,'[]');
    raise exception 'Password admin requested an export';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_begin_compliance_operation(export_case,'build');
    raise exception 'Password admin began an export operation';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_begin_evidence_operation('capture',export_case,report,original_hold,null,reason);
    raise exception 'Password admin began an evidence operation';
  exception when insufficient_privilege then null; end;
  reset role;
  set local role service_role;
  perform set_config('request.jwt.claims','{"role":"service_role"}',true);
  if public.st_v7_read_compliance_operation(old_export) is not null or public.st_v7_read_evidence_operation(old_evidence) is not null then
    raise exception 'An already minted password-session ticket survived opt-in'; end if;
  perform public.st_v7_finish_compliance_operation(old_export,null);
  perform public.st_v7_finish_evidence_operation(old_evidence,null);
  reset role;
  set local role authenticated;
  perform set_config('request.jwt.claims',signed_claim::text,true);
  if public.st_v7_compliance_access(space) is distinct from 'mfa' then
    raise exception 'SSO substituted for the required authenticator'; end if;
  reset role;
  update auth.sessions set aal='aal2',factor_id=admin_factor where id=signed_session;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),signed_session,'totp',now(),now());
  set local role authenticated;
  perform set_config('request.jwt.claims',(signed_claim||'{"aal":"aal2"}')::text,true);
  if public.st_v7_compliance_access(space) is distinct from 'admin'
    or public.st_v7_evidence_vault(space)#>>'{options,0,hold_id}' is distinct from original_hold::text then
    raise exception 'Signed verified admin could not open approved evidence'; end if;
  ticket_export:=public.st_v7_begin_compliance_operation(export_case,'build');
  ticket_evidence:=public.st_v7_begin_evidence_operation('capture',export_case,report,original_hold,null,reason);
  reset role;
  set local role service_role;
  perform set_config('request.jwt.claims','{"role":"service_role"}',true);
  if public.st_v7_read_compliance_operation(ticket_export) is null or public.st_v7_read_evidence_operation(ticket_evidence) is null then
    raise exception 'Service could not honor signed actor and session tickets'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role service_role;
  if public.st_v7_read_compliance_operation(ticket_export) is not null or public.st_v7_read_evidence_operation(ticket_evidence) is not null then
    raise exception 'Previously signed tickets survived provider disable'; end if;
  perform public.st_v7_finish_compliance_operation(ticket_export,null);
  perform public.st_v7_finish_evidence_operation(ticket_evidence,null);
  reset role;
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  state:=public.st_v8_workspace_compliance_policy(space,false);
  if state->>'required' is distinct from 'false'
    or not (public.st_v7_compliance_cases(space) @> jsonb_build_array(jsonb_build_object('id',pending_case,'state','pending'))) then
    raise exception 'Fresh owner could not recover original pending decisions'; end if;

  reset role;
  update auth.custom_oauth_providers set enabled=true where identifier=provider;
  set local role authenticated;
  perform set_config('request.jwt.claims',admin_claim,true);
  old_export:=public.st_v7_begin_compliance_operation(export_case,'build');
  old_evidence:=public.st_v7_begin_evidence_operation('capture',export_case,report,original_hold,null,reason);
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_entry_policy(space,true)->>'required' is distinct from 'true' then
    raise exception 'Verified owner could not enable workspace entry'; end if;
  if public.st_v7_compliance_access(space) is distinct from 'sso'
    or public.st_v7_compliance_access(other_space) is distinct from 'owner' then
    raise exception 'Workspace entry did not scope compliance permissions'; end if;
  begin
    perform public.st_v7_review_compliance_export(pending_case,'approved',reason);
    raise exception 'Password owner approved a case under entry SSO';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',admin_claim,true);
  if public.st_v7_evidence_vault(space) is distinct from '{"access":"sso"}'::jsonb then
    raise exception 'Password admin could open Evidence Vault'; end if;
  begin
    perform public.st_v7_compliance_cases(space);
    raise exception 'Password admin read the protected case list';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_begin_compliance_operation(export_case,'build');
    raise exception 'Password admin minted an entry-protected export ticket';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_begin_evidence_operation('capture',export_case,report,original_hold,null,reason);
    raise exception 'Password admin minted an entry-protected evidence ticket';
  exception when insufficient_privilege then null; end;
  reset role;
  set local role service_role;
  perform set_config('request.jwt.claims','{"role":"service_role"}',true);
  if public.st_v7_read_compliance_operation(old_export) is not null or public.st_v7_read_evidence_operation(old_evidence) is not null then
    raise exception 'Previously issued password tickets survived entry SSO'; end if;
  perform public.st_v7_finish_compliance_operation(old_export,null);
  perform public.st_v7_finish_evidence_operation(old_evidence,null);
  reset role;
  set local role authenticated;
  perform set_config('request.jwt.claims',(signed_claim||'{"aal":"aal2"}')::text,true);
  ticket_export:=public.st_v7_begin_compliance_operation(export_case,'build');
  ticket_evidence:=public.st_v7_begin_evidence_operation('capture',export_case,report,original_hold,null,reason);
  reset role;
  set local role service_role;
  perform set_config('request.jwt.claims','{"role":"service_role"}',true);
  if public.st_v7_read_compliance_operation(ticket_export) is null or public.st_v7_read_evidence_operation(ticket_evidence) is null then
    raise exception 'Signed export and evidence capabilities were unavailable'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role service_role;
  if public.st_v7_read_compliance_operation(ticket_export) is not null or public.st_v7_read_evidence_operation(ticket_evidence) is not null then
    raise exception 'Entry-protected tickets survived provider revocation'; end if;
  reset role;
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_entry_policy(space,false)->>'required' is distinct from 'false' then
    raise exception 'Verified owner could not restore standard entry'; end if;
  if not (public.st_v7_compliance_cases(space) @> jsonb_build_array(jsonb_build_object('id',pending_case,'state','pending'))) then
    raise exception 'Entry recovery failed to reopen the private ledger'; end if;
end $$;
select 'passed: independent and entry compliance SSO, exact service tickets, provider disconnect and pending-case recovery' as result;
rollback;
