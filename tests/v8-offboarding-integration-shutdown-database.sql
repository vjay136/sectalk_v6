begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); other_id uuid:=gen_random_uuid();
  actor uuid; session_id uuid; factor_id uuid; claims jsonb:='{}';
  workspace_id uuid; other_workspace uuid; request_id uuid:=gen_random_uuid(); case_id uuid;
  endpoint uuid:=gen_random_uuid(); other_endpoint uuid:=gen_random_uuid();
  job uuid; other_job uuid; lease uuid:=gen_random_uuid(); hold_id uuid:=gen_random_uuid();
  api_digest text:=encode(extensions.gen_random_bytes(32),'hex');
  other_api_digest text:=encode(extensions.gen_random_bytes(32),'hex');
  scim_digest text; other_scim_digest text;
  domain text:='offboarding-integration.example.invalid';
  other_domain text:='other-offboarding-integration.example.invalid';
  receipt jsonb;
begin
  foreach actor in array array[owner_id,reviewer_id,other_id] loop
    session_id:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'st_int_'||left(actor::text,8),'Offboarding integration QA');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',session_id,'aal','aal2'));
  end loop;
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values(owner_id,'enterprise','active',now()+interval '1 day'),(other_id,'enterprise','active',now()+interval '1 day');

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  workspace_id:=public.st_v2_create_workspace('Offboarding integration rollback');
  perform set_config('request.jwt.claims',claims->>other_id::text,true);
  other_workspace:=public.st_v2_create_workspace('Independent integration rollback');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace_id,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(workspace_id,reviewer_id);
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at)
    values(workspace_id,domain,now()),(other_workspace,other_domain,now());

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v6_create_integration_key(workspace_id,'Target key','target0000',api_digest,array['workspace:read'],7);
  perform public.st_v6_register_webhook(workspace_id,endpoint,'Target endpoint','https://target.example.invalid/hook',repeat('a',80),array['room.created']);
  scim_digest:=encode(extensions.digest(public.st_v8_scim_settings(workspace_id,'rotate',domain)->>'token','sha256'),'hex');
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'requested',workspace_id::text,
    'Approved exercise of offboarding integration revocation.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'approved',workspace_id::text);
  case_id:=(public.st_v8_workspace_offboarding(workspace_id)#>>'{request,case}')::uuid;
  perform set_config('request.jwt.claims',claims->>other_id::text,true);
  perform public.st_v6_create_integration_key(other_workspace,'Control key','other00000',other_api_digest,array['workspace:read'],7);
  perform public.st_v6_register_webhook(other_workspace,other_endpoint,'Control endpoint','https://other.example.invalid/hook',repeat('a',80),array['room.created']);
  other_scim_digest:=encode(extensions.digest(public.st_v8_scim_settings(other_workspace,'rotate',other_domain)->>'token','sha256'),'hex');
  reset role;
  insert into sectalk_private.st_v6_webhook_jobs(endpoint_id,event_id,payload,lease,lease_expires)
    values(endpoint,gen_random_uuid(),'{}',lease,now()+interval '1 minute') returning id into job;
  insert into sectalk_private.st_v6_webhook_jobs(endpoint_id,event_id,payload,lease,lease_expires)
    values(other_endpoint,gen_random_uuid(),'{}',lease,now()+interval '1 minute') returning id into other_job;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,workspace_id,owner_id,'Test preservation hold has priority over staging.',owner_id);
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action)
    values(case_id,workspace_id,owner_id,'downloaded');

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'read_only',workspace_id::text);
    raise exception 'Active preservation hold did not block integration shutdown';
  exception when insufficient_privilege then null; end;
  reset role;

  set local role service_role;
  if public.st_v6_integration_read(api_digest,'workspace',null,20)#>>'{data,id}' is distinct from workspace_id::text
    or public.st_v8_scim_request(scim_digest,'ServiceProviderConfig','GET',null)->>'status' is distinct from '200'
    or not public.st_v6_webhook_lease_active(job,lease) then
    raise exception 'Blocked staging changed live integrations';
  end if;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,release_reason='Release disposable fixture hold.'
    where h.id=hold_id;

  set local role authenticated;
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'read_only',workspace_id::text);
  receipt:=public.st_v8_workspace_offboarding(workspace_id)#>'{request,integrationShutdown}';
  if receipt->>'at' is null or receipt-'at' is distinct from '{"apiKeys":1,"webhooks":1,"webhookJobs":1,"scimTokens":1}'::jsonb then
    raise exception 'Unexpected integration receipt: %',receipt;
  end if;
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'read_only',workspace_id::text);
  if (public.st_v8_workspace_offboarding(workspace_id)#>'{request,integrationShutdown}') is distinct from receipt then
    raise exception 'Retry rewrote the receipt';
  end if;
  begin
    perform public.st_v6_create_integration_key(workspace_id,'Replacement','replace000',repeat('b',64),array['workspace:read'],7);
    raise exception 'API key was reissued for a staged workspace';
  exception when sqlstate 'PT423' then null; end;
  begin
    perform public.st_v6_register_webhook(workspace_id,gen_random_uuid(),'Replacement','https://target.example.invalid/hook',repeat('a',80),array['room.created']);
    raise exception 'Webhook was reissued for a staged workspace';
  exception when sqlstate 'PT423' then null; end;
  begin
    perform public.st_v8_scim_settings(workspace_id,'rotate',domain);
    raise exception 'SCIM credential was reissued for a staged workspace';
  exception when sqlstate 'PT423' then null; end;
  reset role;

  set local role service_role;
  begin
    perform public.st_v6_integration_read(api_digest,'workspace',null,20);
    raise exception 'Revoked API key still had access';
  exception when sqlstate 'PT401' then null; end;
  if public.st_v8_scim_request(scim_digest,'ServiceProviderConfig','GET',null)->>'status' is distinct from '401'
    or public.st_v6_webhook_lease_active(job,lease)
    or public.st_v6_integration_read(other_api_digest,'workspace',null,20)#>>'{data,id}' is distinct from other_workspace::text
    or public.st_v8_scim_request(other_scim_digest,'ServiceProviderConfig','GET',null)->>'status' is distinct from '200'
    or not public.st_v6_webhook_lease_active(other_job,lease) then
    raise exception 'Shut-down scope or live delivery lease was incorrect';
  end if;
  perform public.st_v6_finish_webhook(job,lease,200,false);
  reset role;

  insert into sectalk_private.st_v6_webhook_jobs(endpoint_id,event_id,payload)
    values(endpoint,gen_random_uuid(),'{}');
  if found or not exists(select 1 from sectalk_private.st_v6_webhook_jobs j where j.id=job and j.state='cancelled' and j.lease is null)
    or (select count(*) from sectalk_private.st_v8_offboarding_audit a where a.request=request_id and a.action='read_only')<>1 then
    raise exception 'Revoked endpoint admitted late work or retry changed audit history';
  end if;
  begin
    update sectalk_private.st_v8_offboarding_requests set integration_shutdown='{}' where id=request_id;
    raise exception 'Offboarding integration receipt was mutable';
  exception when insufficient_privilege then null; end;
end $$;

select 'passed: exact workspace API keys, leased deliveries and SCIM shut down after approved staging';
rollback;
