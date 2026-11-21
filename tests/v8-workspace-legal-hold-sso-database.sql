begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); admin_id uuid:=gen_random_uuid();
  actor_id uuid; factor uuid; session_id uuid; signed_session uuid:=gen_random_uuid(); admin_factor uuid;
  owner_claim text; admin_claim text; signed_claim jsonb;
  space uuid; other_space uuid; room uuid:=gen_random_uuid(); post uuid:=gen_random_uuid();
  original_hold uuid:=gen_random_uuid(); extra_hold uuid:=gen_random_uuid(); report uuid; export_case uuid; state jsonb;
  provider text:='custom:legal-hold-rollback'; domain text:='holds.example.invalid';
  reason constant text:='Synthetic private hold rationale';
begin
  foreach actor_id in array array[owner_id,admin_id] loop
    factor:=gen_random_uuid(); session_id:=gen_random_uuid();
    insert into auth.users(id,email,email_confirmed_at) values(actor_id,actor_id||'@holds.example.invalid',now());
    insert into public.st_profiles(id,handle,name) values(actor_id,'legal_admin_'||left(actor_id::text,8),'Legal hold fixture');
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
  space:=public.st_v2_create_workspace('Legal holds SSO fixture');
  other_space:=public.st_v2_create_workspace('Unprotected legal holds control');
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
  if public.st_v8_workspace_legal_hold_policy(space,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Unproven provider was accepted'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(signed_session,space,admin_id,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_legal_hold_policy(space,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not activate hold SSO'; end if;
  if public.st_v6_workspace_hold_state(space) is distinct from '{"access":"verified","hold_sso_required":true}'::jsonb
    or public.st_v6_workspace_hold_state(other_space)->'holds' is distinct from '[]'::jsonb
    or public.st_v6_workspace_policy_versions(space,'retention')->>'version' is distinct from '0' then
    raise exception 'Hold purposes leaked or the opt-in affected an independent policy or tenant'; end if;
  begin
    perform public.st_v6_place_workspace_hold(space,extra_hold,room,null,null,null,reason);
    raise exception 'Password owner placed a protected hold';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_release_workspace_hold(space,original_hold,'Synthetic release reason');
    raise exception 'Password owner released a protected hold';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',admin_claim,true);
  state:=public.st_v7_evidence_vault(space);
  if state#>>'{options,0,hold_reason}' is distinct from 'Active preservation hold'
    or state#>>'{options,0,hold_id}' is distinct from original_hold::text then
    raise exception 'Evidence options exposed the rationale or lost custody linkage'; end if;
  perform set_config('request.jwt.claims',signed_claim::text,true);
  if public.st_v6_workspace_hold_state(space)->>'access' is distinct from 'mfa' then
    raise exception 'SSO substituted for native authenticator verification'; end if;
  reset role;
  update auth.sessions set aal='aal2',factor_id=admin_factor where id=signed_session;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),signed_session,'totp',now(),now());
  set local role authenticated;
  perform set_config('request.jwt.claims',(signed_claim||'{"aal":"aal2"}')::text,true);
  if public.st_v6_workspace_hold_state(space)#>>'{holds,0,reason}' is distinct from reason
    or public.st_v7_evidence_vault(space)#>>'{options,0,hold_reason}' is distinct from reason then
    raise exception 'Signed administrator lost the legitimate hold details'; end if;
  perform public.st_v6_place_workspace_hold(space,extra_hold,room,null,null,null,reason);
  perform public.st_v6_release_workspace_hold(space,extra_hold,'Synthetic release reason');
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  if not sectalk_private.st_v6_room_is_held(space,room) then raise exception 'Provider disable released active protections'; end if;
  set local role authenticated;
  if public.st_v6_workspace_hold_state(space)->>'hold_sso_required' is distinct from 'true' then
    raise exception 'Disabled provider retained hold administration'; end if;
  perform set_config('request.jwt.claims',owner_claim,true);
  state:=public.st_v8_workspace_legal_hold_policy(space,false);
  if state->>'required' is distinct from 'false'
    or jsonb_array_length(public.st_v6_workspace_hold_state(space)->'holds')<>2 then
    raise exception 'Fresh owner could not recover the hold ledger'; end if;
end $$;
select 'passed: legal hold SSO, evidence rationale isolation, retained preservation and owner recovery' as result;
rollback;
