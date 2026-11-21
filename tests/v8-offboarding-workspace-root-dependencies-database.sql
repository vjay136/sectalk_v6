begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; workspace_id uuid; w uuid; request_id uuid:=gen_random_uuid(); case_id uuid;
  order_id uuid:=gen_random_uuid(); empty_root uuid:=gen_random_uuid(); snapshot jsonb; status jsonb; replacement jsonb;
  legacy_version text:='Synthetic confidential enterprise quote terms.';
  audit_custody_present boolean:=to_regclass('sectalk_private.st_v8_workspace_audit_custody') is not null;
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
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  workspace_id:=public.st_v2_create_workspace('Disposable workspace root preflight');
  reset role;
  w:=workspace_id;
  if sectalk_private.st_v8_offboarding_workspace_root_snapshot(w)#>>'{summary,unclassifiedConstraints}'
    is distinct from '0' then raise exception 'The installed workspace schema has unclassified root dependencies'; end if;
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(w,reviewer_id);
  insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values(w,1);
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,wrapped) values(w,1,'managed',repeat('a',80));
  set local role authenticated;
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Inspect exact workspace root dependencies.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  case_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(case_id,w,owner_id,'downloaded');
  insert into sectalk_private.st_v8_enterprise_orders(id,workspace,reference,currency,committed_seats,annual_total,starts_on,ends_on,
    expires_on,terms,quoted_by) values(order_id,w,'disposable quote','USD',1,100,current_date+1,current_date+365,current_date,legacy_version,owner_id);
  create table sectalk_private.offboarding_fixture_nullable_root(
    workspace uuid references public.st_v2_workspaces on delete set null,
    body text not null
  );
  insert into sectalk_private.offboarding_fixture_nullable_root values(w,'Synthetic unsupported business vocabulary stays private.');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  snapshot:=public.st_v8_offboarding_reconciliation(w,'capture',w::text);
  if (snapshot#>>'{summary,workspaceRootDependencies,deleteActions,restrict}')::integer is distinct from
      (case when audit_custody_present then 2 else 1 end)
    or snapshot#>>'{summary,workspaceRootDependencies,deleteActions,setNull}' is distinct from '1'
    or (snapshot#>>'{summary,workspaceRootDependencies,deleteActions,cascade}')::integer<=0
    or (snapshot#>>'{summary,workspaceRootDependencies,categories,preservation}')::integer<=0
    or snapshot#>>'{summary,workspaceRootDependencies,categories,billing}' is distinct from '1'
    or snapshot#>>'{summary,workspaceRootDependencies,categories,unclassified}' is distinct from '1'
    or (snapshot#>>'{summary,workspaceRootDependencies,unclassifiedConstraints}')::integer<1
    or snapshot#>>'{summary,workspaceRootDependencies,directReferencesClear}' is distinct from 'false'
    or snapshot::text like '%'||legacy_version||'%'
    or snapshot::text like '%offboarding_fixture_nullable_root%'
    or snapshot->>'providerBytes' is distinct from 'unverified'
    or snapshot->>'fullTenantErasure' is distinct from 'unverified'
    then raise exception 'Root dependency effects, preservation or confidentiality missing'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  status:=public.st_v8_offboarding_reconciliation(w,'confirm',w::text,(snapshot->>'plan')::uuid,snapshot->>'sha256');
  if status->>'reviewedAt' is null or status->>'current' is distinct from 'true' then raise exception 'Exact review failed'; end if;
  reset role;
  update sectalk_private.st_v8_enterprise_orders x set terms='Same billing row with revised synthetic quote terms.' where x.id=order_id;
  set local role authenticated;
  status:=public.st_v8_offboarding_reconciliation(w);
  if status->>'current' is distinct from 'false'
    or status#>'{summary,workspaceRootDependencies}' is distinct from snapshot#>'{summary,workspaceRootDependencies}'
    then raise exception 'A same-count restrictive row change was missed'; end if;
  begin
    perform public.st_v8_offboarding_reconciliation(w,'confirm',w::text,(snapshot->>'plan')::uuid,snapshot->>'sha256');
    raise exception 'Confirmed the previous root dependency fingerprint';
  exception when sqlstate 'PT409' then null; end;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  replacement:=public.st_v8_offboarding_reconciliation(w,'capture',w::text);
  if replacement->>'sha256' is not distinct from snapshot->>'sha256' or replacement->>'current' is distinct from 'true'
    then raise exception 'Did not capture changed same-count billing rows'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  status:=public.st_v8_offboarding_reconciliation(w,'confirm',w::text,(replacement->>'plan')::uuid,replacement->>'sha256');
  if status->>'reviewedAt' is null then raise exception 'New exact review failed'; end if;

  reset role;
  alter table public.st_v2_workspaces add unique(id,owner);
  create table sectalk_private.offboarding_fixture_composite_root (
    workspace uuid, owner_id uuid,
    foreign key(workspace,owner_id) references public.st_v2_workspaces(id,owner) on delete cascade
  );
  insert into sectalk_private.offboarding_fixture_composite_root values(w,owner_id);
  set local role authenticated;
  status:=public.st_v8_offboarding_reconciliation(w);
  if status#>>'{summary,workspaceRootDependencies,unsupportedConstraints}' is distinct from '1'
    or status->>'current' is distinct from 'false'
    then raise exception 'An unsupported composite reference did not fail closed'; end if;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_reconciliation(w,'capture',w::text);
    raise exception 'Captured root evidence with an unsupported reference shape';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  drop table sectalk_private.offboarding_fixture_composite_root;
  insert into sectalk_private.offboarding_fixture_nullable_root
    select w,'overflow synthetic root '||i from generate_series(1,500) i;
  set local role authenticated;
  status:=public.st_v8_offboarding_reconciliation(w);
  if status#>>'{summary,workspaceRootDependencies,overflowFamilies}' is distinct from '1'
    or not (status#>'{summary,overflow}' ? 'workspaceRootReferences') or status->>'current' is distinct from 'false'
    then raise exception 'A root dependency beyond the row cap was omitted'; end if;
  begin
    perform public.st_v8_offboarding_reconciliation(w,'capture',w::text);
    raise exception 'Captured an incomplete bounded root count';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  if not exists(select 1 from public.st_v2_workspaces x where x.id=w)
    or not exists(select 1 from sectalk_private.st_v8_enterprise_orders x where (x.id,x.workspace)=(order_id,w))
    then raise exception 'Final eligibility check removed preserved native records'; end if;
  drop table sectalk_private.offboarding_fixture_nullable_root;
  insert into public.st_v2_workspaces(id,name,owner) values(empty_root,'Disposable unreferenced root',owner_id);
  if sectalk_private.st_v8_offboarding_workspace_root_snapshot(empty_root)#>>'{summary,directReferencesClear}' is distinct from 'true'
    or not exists(select 1 from public.st_v2_workspaces x where x.id=empty_root)
    then raise exception 'An existing unreferenced native root did not pass the direct-reference gate'; end if;
  if has_function_privilege('anon','sectalk_private.st_v8_offboarding_workspace_root_snapshot(uuid)','EXECUTE')
    or has_function_privilege('authenticated','sectalk_private.st_v8_offboarding_workspace_root_snapshot(uuid)','EXECUTE')
    or has_function_privilege('service_role','sectalk_private.st_v8_offboarding_workspace_root_snapshot(uuid)','EXECUTE')
    then raise exception 'Root dependency fingerprint helper is callable outside the reviewed workflow'; end if;
end $$;

select 'passed: exact workspace-root dependency, protected restrictive billing rows, same-count stale review, unsupported and overflow gates';
rollback;
