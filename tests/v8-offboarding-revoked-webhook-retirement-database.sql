begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; w uuid; other_workspace uuid; request_id uuid:=gen_random_uuid(); case_id uuid; hold_id uuid:=gen_random_uuid();
  approved_hook uuid:=gen_random_uuid(); protected_hook uuid:=gen_random_uuid(); late_hook uuid:=gen_random_uuid();
  manual_hook uuid:=gen_random_uuid(); item uuid; staged_job uuid; late_job uuid;
  fixture_destination text:='https://retirement-fixture.example.invalid/secret-destination';
  fixture_wrapped text:=repeat('q',80);
  copy jsonb; selected_plan jsonb; late_plan jsonb; receipt jsonb; status jsonb; baseline integer; manual_copy jsonb;
begin
  foreach actor in array array[owner_id,reviewer_id] loop
    session_id:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'batch_'||left(actor::text,8),'Disposable batch actor');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',session_id,'aal','aal2'));
  end loop;
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values(owner_id,'enterprise','active',now()+interval '1 day'),(reviewer_id,'enterprise','active',now()+interval '1 day');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  other_workspace:=public.st_v2_create_workspace('Disposable webhook identity control');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  w:=public.st_v2_create_workspace('Disposable webhook retirement source');
  foreach item in array array[approved_hook,protected_hook,late_hook,manual_hook] loop
    perform public.st_v6_register_webhook(w,item,'Disposable webhook '||left(item::text,6),fixture_destination,fixture_wrapped,array['room.created']);
  end loop;
  perform public.st_v6_revoke_webhook(w,manual_hook);
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(w,reviewer_id);
  insert into sectalk_private.st_v6_webhook_jobs(endpoint_id,event_id,payload)
    values(protected_hook,gen_random_uuid(),'{"type":"synthetic-disposable-event"}') returning id into staged_job;
  set local role authenticated;
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Review and retire one exact revoked webhook.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  case_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(case_id,w,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  baseline:=(public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,categories,integrations}')::integer;
  begin
    perform public.st_v8_offboarding_webhook(w,approved_hook,'capture',w::text);
    raise exception 'Captured before exact sanitized copy';
  exception when sqlstate 'PT409' then null; end;
  status:=public.st_v8_offboarding_webhook_status(w);
  if exists(select 1 from jsonb_array_elements(status->'endpoints') x where x->>'id'=protected_hook::text)
    or not exists(select 1 from jsonb_array_elements(status->'endpoints') x where x->>'id'=approved_hook::text)
    then raise exception 'Webhook with retained deliveries was listed or empty endpoint omitted'; end if;
  copy:=public.st_v8_offboarding_webhook(w,approved_hook,'copy',w::text);
  if copy->>'sha256' is distinct from encode(sha256(convert_to(copy->>'json','UTF8')),'hex')
    or (copy->>'json')::jsonb#>>'{endpoint,id}' is distinct from approved_hook::text
    or (copy->>'json')::jsonb->>'revocation' is distinct from 'offboarding'
    or (copy->>'json')::jsonb#>>'{workspaceAudit,0,event}' is distinct from 'integration.webhook_created'
    or copy::text like '%'||fixture_destination||'%' or copy::text like '%'||fixture_wrapped||'%'
    or (copy->>'json')::jsonb->'endpoint' ?| array['wrapped_key','destination']
    then raise exception 'Sanitized endpoint copy leaked private destination or signing material, or omitted custody evidence'; end if;
  manual_copy:=public.st_v8_offboarding_webhook(w,manual_hook,'copy',w::text);
  if (manual_copy->>'json')::jsonb->>'revocation' is distinct from 'owner'
    or jsonb_array_length((manual_copy->>'json')::jsonb->'workspaceAudit')<>2
    then raise exception 'Manually revoked webhook omitted original audit evidence'; end if;
  selected_plan:=public.st_v8_offboarding_webhook(w,approved_hook,'capture',w::text);
  perform public.st_v8_offboarding_webhook(w,late_hook,'copy',w::text);
  late_plan:=public.st_v8_offboarding_webhook(w,late_hook,'capture',w::text);
  begin
    perform public.st_v8_offboarding_webhook(w,approved_hook,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner self-approved';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_offboarding_webhook(w,approved_hook,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner removed a webhook before approval';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  status:=public.st_v8_offboarding_webhook_status(w);
  if jsonb_array_length(status->'endpoints')<>0 or not exists(select 1 from jsonb_array_elements(status->'plans') x
    where x->>'plan'=selected_plan->>'plan' and x->>'copySha256'=copy->>'sha256')
    then raise exception 'Incorrect independent reviewer scope or missing copy fingerprint'; end if;
  perform public.st_v8_offboarding_webhook(w,approved_hook,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  perform public.st_v8_offboarding_webhook(w,late_hook,'approve',w::text,(late_plan->>'plan')::uuid,late_plan->>'sha256');
  reset role;
  insert into sectalk_private.st_v6_webhook_jobs(endpoint_id,event_id,payload,state,attempts,last_status)
    values(late_hook,gen_random_uuid(),'{"type":"synthetic-late-sent-delivery"}','sent',1,204) returning id into late_job;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,w,owner_id,'Preserve disposable webhook evidence during verification.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_webhook(w,approved_hook,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Removed an endpoint under an active hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release the synthetic webhook hold.' where h.id=hold_id;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_webhook(w,late_hook,'delete',w::text,(late_plan->>'plan')::uuid,late_plan->>'sha256');
    raise exception 'Removed an endpoint with retained late delivery evidence';
  exception when sqlstate 'PT409' then null; end;
  receipt:=public.st_v8_offboarding_webhook(w,approved_hook,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  if receipt->>'deletedAt' is null or receipt is distinct from
    public.st_v8_offboarding_webhook(w,approved_hook,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256')
    or (public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,categories,integrations}')::integer<>baseline-1
    then raise exception 'No exact webhook retirement receipt or root dependency was reduced'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform public.st_v6_register_webhook(other_workspace,approved_hook,'Rejected endpoint ID reuse',fixture_destination,fixture_wrapped,
      array['room.created']);
    raise exception 'Reused the retired webhook identifier';
  exception when sqlstate 'PT409' then
    if sqlerrm<>'This webhook identifier is permanently retired' then raise; end if;
  end;
  reset role;
  if exists(select 1 from sectalk_private.st_v6_webhooks x where x.id=approved_hook)
    or not exists(select 1 from sectalk_private.st_v8_offboarding_retired_webhook t where
      (t.plan,t.endpoint,t.custody,t.sha256)=((selected_plan->>'plan')::uuid,approved_hook,(copy->>'json')::jsonb,copy->>'sha256'))
    or not exists(select 1 from sectalk_private.st_v6_webhook_jobs j where (j.id,j.endpoint_id,j.state)=(staged_job,protected_hook,'cancelled'))
    or not exists(select 1 from sectalk_private.st_v6_webhook_jobs j where (j.id,j.endpoint_id,j.state)=(late_job,late_hook,'sent'))
    or not exists(select 1 from public.st_v2_workspace_audit a
      where (a.workspace_id,a.target,a.event)=(w,approved_hook,'integration.webhook_created'))
    then raise exception 'Retirement changed protected audit or delivery rows'; end if;
end $$;

select 'passed: exact revoked webhook retirement, no destination/signing data in custody, approves separately, protects holds/jobs and reserves ID';
rollback;