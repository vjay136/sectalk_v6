begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; w uuid; other_workspace uuid; request_id uuid:=gen_random_uuid(); case_id uuid;
  retired_key uuid; protected_key uuid; late_key uuid; manual_key uuid; hold_id uuid:=gen_random_uuid();
  verifier text:=encode(extensions.gen_random_bytes(32),'hex');
  copy jsonb; selected_plan jsonb; late_plan jsonb; receipt jsonb; status jsonb; protected_category integer; manual_copy jsonb;
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
  other_workspace:=public.st_v2_create_workspace('Disposable API key reuse control');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  w:=public.st_v2_create_workspace('Disposable API key retirement source');
  retired_key:=public.st_v6_create_integration_key(w,'Offboarding candidate','retire0000',verifier,array['workspace:read'],7);
  protected_key:=public.st_v6_create_integration_key(w,'Retained usage data','presrv0000',encode(extensions.gen_random_bytes(32),'hex'),
    array['workspace:read'],7);
  late_key:=public.st_v6_create_integration_key(w,'Later usage data','lateky0000',encode(extensions.gen_random_bytes(32),'hex'),
    array['workspace:read'],7);
  manual_key:=public.st_v6_create_integration_key(w,'Previously revoked','oldkey0000',encode(extensions.gen_random_bytes(32),'hex'),
    array['workspace:read'],7);
  perform public.st_v6_revoke_integration_key(w,manual_key);
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(w,reviewer_id);
  insert into sectalk_private.st_v6_api_rate(key_id,minute,requests) values(protected_key,date_trunc('minute',now()),1);
  set local role authenticated;
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Review and retire scoped revoked credentials.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  case_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(case_id,w,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  protected_category:=(public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,categories,integrations}')::integer;
  begin
    perform public.st_v8_offboarding_api_key(w,retired_key,'capture',w::text);
    raise exception 'Captured before issuing the sanitized copy';
  exception when sqlstate 'PT409' then null; end;
  status:=public.st_v8_offboarding_api_key_status(w);
  if exists(select 1 from jsonb_array_elements(status->'keys') x where x->>'id'=protected_key::text)
    or not exists(select 1 from jsonb_array_elements(status->'keys') x where x->>'id'=retired_key::text)
    then raise exception 'Eligible and retained integration records were mixed'; end if;
  copy:=public.st_v8_offboarding_api_key(w,retired_key,'copy',w::text);
  if copy->>'sha256' is distinct from encode(sha256(convert_to(copy->>'json','UTF8')),'hex')
    or (copy->>'json')::jsonb#>>'{key,id}' is distinct from retired_key::text
    or (copy->>'json')::jsonb->>'revocation' is distinct from 'offboarding'
    or (copy->>'json')::jsonb#>>'{workspaceAudit,0,event}' is distinct from 'integration.key_created'
    or copy::text like '%'||verifier||'%' or copy::text like '%retire0000%'
    or (copy->>'json')::jsonb->'key' ? 'digest'
    then raise exception 'The sanitized key copy leaked private verification data or omitted custody evidence'; end if;
  manual_copy:=public.st_v8_offboarding_api_key(w,manual_key,'copy',w::text);
  if (manual_copy->>'json')::jsonb->>'revocation' is distinct from 'owner'
    or jsonb_array_length((manual_copy->>'json')::jsonb->'workspaceAudit')<>2
    then raise exception 'Manual revocation custody is incomplete'; end if;
  selected_plan:=public.st_v8_offboarding_api_key(w,retired_key,'capture',w::text);
  perform public.st_v8_offboarding_api_key(w,late_key,'copy',w::text);
  late_plan:=public.st_v8_offboarding_api_key(w,late_key,'capture',w::text);
  begin
    perform public.st_v8_offboarding_api_key(w,retired_key,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner self-approved';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_offboarding_api_key(w,retired_key,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner removed a key before approval';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  status:=public.st_v8_offboarding_api_key_status(w);
  if jsonb_array_length(status->'keys')<>0 or not exists(select 1 from jsonb_array_elements(status->'plans') x
    where x->>'plan'=selected_plan->>'plan' and x->>'copySha256'=copy->>'sha256')
    then raise exception 'Independent reviewer saw owner-only controls or could not match the exact copy'; end if;
  begin
    perform public.st_v8_offboarding_api_key(w,retired_key,'copy',w::text);
    raise exception 'Independent reviewer downloaded owner custody';
  exception when insufficient_privilege then null; end;
  perform public.st_v8_offboarding_api_key(w,retired_key,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  perform public.st_v8_offboarding_api_key(w,late_key,'approve',w::text,(late_plan->>'plan')::uuid,late_plan->>'sha256');
  reset role;
  insert into sectalk_private.st_v6_api_rate(key_id,minute,requests) values(late_key,date_trunc('minute',now()),1);
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,w,owner_id,'Preserve qualified synthetic integration keys during verification.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_api_key(w,retired_key,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Removed an integration key under an active hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release the synthetic integration hold.' where h.id=hold_id;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_api_key(w,late_key,'delete',w::text,(late_plan->>'plan')::uuid,late_plan->>'sha256');
    raise exception 'Removed a key with preserved live usage evidence';
  exception when sqlstate 'PT409' then null; end;
  receipt:=public.st_v8_offboarding_api_key(w,retired_key,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  if receipt->>'deletedAt' is null or receipt is distinct from
    public.st_v8_offboarding_api_key(w,retired_key,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256')
    or (public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,categories,integrations}')::integer<>protected_category-1
    then raise exception 'No exact retirement receipt or root dependency was reduced'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform public.st_v6_create_integration_key(other_workspace,'Historical reuse rejected','reused0000',verifier,array['workspace:read'],1);
    raise exception 'Reissued retired key verification data';
  exception when sqlstate 'PT409' then
    if sqlerrm<>'This API key is permanently retired' then raise; end if;
  end;
  reset role;
  if exists(select 1 from sectalk_private.st_v6_integration_keys k where k.id=retired_key)
    or not exists(select 1 from sectalk_private.st_v8_offboarding_retired_api_key t where
      (t.plan,t.key,t.custody,t.sha256)=((selected_plan->>'plan')::uuid,retired_key,(copy->>'json')::jsonb,copy->>'sha256'))
    or (select count(*) from sectalk_private.st_v6_api_rate k where k.key_id in (protected_key,late_key))<>2
    or not exists(select 1 from public.st_v2_workspace_audit a
      where (a.workspace_id,a.target,a.event)=(w,retired_key,'integration.key_created'))
    then raise exception 'Native key cleanup failed or altered protected audit and usage evidence'; end if;
end $$;

select 'passed: exact revoked API key retirement, redacted proof, independent approval, holds and live usage, original audit, key reuse blocked';
rollback;