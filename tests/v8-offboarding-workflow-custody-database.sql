begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); outsider_id uuid:=gen_random_uuid();
  actor uuid; sid uuid; factor uuid; claims jsonb:='{}'; w uuid; request_id uuid:=gen_random_uuid(); inventory_id uuid;
  ordinary uuid:=gen_random_uuid(); ordinary_request uuid; unrelated_case uuid; hold_id uuid:=gen_random_uuid();
  audit_plan jsonb; source_plan jsonb; storage_plan jsonb; plan jsonb; receipt jsonb; status jsonb;
  request_before jsonb; inventory_before jsonb; cascade_before integer; preserved_before integer;
begin
  foreach actor in array array[owner_id,reviewer_id,outsider_id] loop
    sid:=gen_random_uuid(); factor:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'custody_'||left(actor::text,8),'Disposable workflow actor');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(sid,actor,'aal2',factor);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),sid,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',sid,'aal','aal2'));
  end loop;
  insert into public.st_v2_workspaces(id,name,owner) values(ordinary,'Disposable ordinary control root',owner_id);
  insert into sectalk_private.st_v7_compliance_cases(workspace_id,requester,case_reference,reason,sources)
    values(ordinary,owner_id,'Disposable ordinary control','Ordinary workflow fixture.', '[{}]') returning id into unrelated_case;
  insert into sectalk_private.st_v8_offboarding_requests(id,workspace,requester,reason,snapshot,snapshot_sha256,case_id)
    values(gen_random_uuid(),ordinary,owner_id,'Ordinary workflow control request.','{}',repeat('a',64),unrelated_case) returning id into ordinary_request;
  delete from public.st_v2_workspaces where id=ordinary;
  if exists(select 1 from sectalk_private.st_v8_offboarding_requests r where r.id=ordinary_request)
    or exists(select 1 from sectalk_private.st_v7_compliance_cases c where c.id=unrelated_case)
    then raise exception 'Ordinary root cascades changed'; end if;

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  w:=public.st_v2_create_workspace('Disposable staged workflow custody');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(w,reviewer_id);
  insert into sectalk_private.st_v7_compliance_cases(workspace_id,requester,case_reference,reason,sources,state)
    values(w,owner_id,'Disposable unrelated case','Keep this unrelated evidence linked.', '[{}]','denied') returning id into unrelated_case;
  set local role authenticated;
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Preserve the original reviewed offboarding workflow.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  inventory_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(inventory_id,w,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  storage_plan:=public.st_v8_offboarding_storage_plan(w,'capture',p_confirmation=>w::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_storage_plan(w,'confirm',(storage_plan->>'plan')::uuid,w::text,storage_plan->>'sha256');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_workflow_custody(w,'capture',w::text);
    raise exception 'Workflow custody bypassed audit/source approvals';
  exception when sqlstate 'PT409' then null; end;
  audit_plan:=public.st_v8_offboarding_workspace_audit_custody(w,'capture',w::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_workspace_audit_custody(w,'approve',w::text,(audit_plan->>'plan')::uuid,audit_plan->>'sha256');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_offboarding_workspace_audit_custody(w,'detach',w::text,(audit_plan->>'plan')::uuid,audit_plan->>'sha256');
  source_plan:=public.st_v8_offboarding_reconciliation(w,'capture',w::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_reconciliation(w,'confirm',w::text,(source_plan->>'plan')::uuid,source_plan->>'sha256');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  plan:=public.st_v8_offboarding_workflow_custody(w,'capture',w::text);
  if plan->>'linked' is distinct from 'true' or plan->>'current' is distinct from 'true' or plan->>'plan' is null
    then raise exception 'Exact workflow plan was not captured'; end if;
  begin
    perform public.st_v8_offboarding_workflow_custody(w,'detach',w::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Owner executed workflow custody without independent approval';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_offboarding_workflow_custody(w,'approve',w::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Owner self-approved workflow custody';
  exception when insufficient_privilege then null; end;
  reset role;
  begin
    update sectalk_private.st_v8_offboarding_requests r set live_workspace=null where r.id=request_id;
    raise exception 'Raw FK release bypassed the custody transaction';
  exception when sqlstate 'PT423' then null; end;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>outsider_id::text,true);
  begin
    perform public.st_v8_offboarding_workflow_custody(w);
    raise exception 'Unrelated user accessed workflow custody';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_workflow_custody(w,'approve',w::text,(plan->>'plan')::uuid,plan->>'sha256');
  reset role;
  update sectalk_private.st_v7_compliance_cases c set case_reference='Later revised inventory reference' where c.id=inventory_id;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_workflow_custody(w,'detach',w::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Owner detached changed inventory using a stale digest';
  exception when sqlstate 'PT409' then null; end;
  source_plan:=public.st_v8_offboarding_reconciliation(w,'capture',w::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_reconciliation(w,'confirm',w::text,(source_plan->>'plan')::uuid,source_plan->>'sha256');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  plan:=public.st_v8_offboarding_workflow_custody(w,'capture',w::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_workflow_custody(w,'approve',w::text,(plan->>'plan')::uuid,plan->>'sha256');
  reset role;
  begin
    insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
      values(hold_id,w,owner_id,'Hold this disposable original workflow evidence.',owner_id);
    set local role authenticated;
    perform set_config('request.jwt.claims',claims->>owner_id::text,true);
    perform public.st_v8_offboarding_workflow_custody(w,'detach',w::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'Workflow custody ignored an active legal hold';
  exception when insufficient_privilege then null; end;
  reset role;
  select to_jsonb(r)-'live_workspace' into strict request_before from sectalk_private.st_v8_offboarding_requests r where r.id=request_id;
  select to_jsonb(c)-'live_workspace' into strict inventory_before from sectalk_private.st_v7_compliance_cases c where c.id=inventory_id;
  status:=sectalk_private.st_v8_offboarding_workspace_root_snapshot(w);
  cascade_before:=(status#>>'{summary,deleteActions,cascade}')::integer;
  preserved_before:=(status#>>'{summary,categories,preservation}')::integer;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  receipt:=public.st_v8_offboarding_workflow_custody(w,'detach',w::text,(plan->>'plan')::uuid,plan->>'sha256');
  if receipt->>'detachedAt' is null or receipt->>'linked' is distinct from 'false' or receipt is distinct from
    public.st_v8_offboarding_workflow_custody(w,'detach',w::text,(plan->>'plan')::uuid,plan->>'sha256')
    then raise exception 'Exact workflow custody was not discharged atomically or safe to retry'; end if;
  reset role;
  status:=sectalk_private.st_v8_offboarding_workspace_root_snapshot(w);
  if (status#>>'{summary,deleteActions,cascade}')::integer<>cascade_before-2
    or (status#>>'{summary,categories,preservation}')::integer<>preserved_before-2
    or not exists(select 1 from sectalk_private.st_v8_offboarding_requests r
      where r.id=request_id and r.live_workspace is null and to_jsonb(r)-'live_workspace'=request_before)
    or not exists(select 1 from sectalk_private.st_v7_compliance_cases c
      where c.id=inventory_id and c.live_workspace is null and to_jsonb(c)-'live_workspace'=inventory_before)
    or not exists(select 1 from sectalk_private.st_v7_compliance_cases c where (c.id,c.live_workspace)=(unrelated_case,w))
    or not exists(select 1 from sectalk_private.st_v8_offboarding_storage_plans p
      where (p.id,p.request)=((storage_plan->>'plan')::uuid,request_id) and p.reviewed_at is not null)
    or not exists(select 1 from public.st_v2_workspaces a where a.id=w)
    then raise exception 'Workflow custody changed native rows/Storage lineage or missed two live dependencies'; end if;
  update sectalk_private.st_v7_compliance_cases c set case_reference='Another late native inventory change' where c.id=inventory_id;
  if not exists(select 1 from sectalk_private.st_v7_compliance_cases c where (c.id,c.live_workspace)=(inventory_id,w))
    then raise exception 'Late inventory change did not restore the native root dependency'; end if;
  if has_function_privilege('anon','public.st_v8_offboarding_workflow_custody(uuid,text,text,uuid,text)','EXECUTE')
    or has_function_privilege('service_role','public.st_v8_offboarding_workflow_custody(uuid,text,text,uuid,text)','EXECUTE')
    then raise exception 'Workflow custody is callable without the reviewed native roles'; end if;
end $$;

select 'passed: atomic reviewed staged request and inventory retention, exact native records and reviewed Storage preserved, stale approvals rejected and ordinary cascades unchanged';
rollback;
