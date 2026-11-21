begin;

create function sectalk_private.offboarding_root_rehearsal_fixture_trigger()
returns trigger language plpgsql set search_path='' as $$
begin
  raise exception 'An unreviewed hook must never run during root rehearsal';
end $$;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid();
  actor uuid; sid uuid; factor uuid; claims jsonb:='{}'; w uuid; request_id uuid:=gen_random_uuid(); inventory_id uuid;
  audit_plan jsonb; source_plan jsonb; workflow_plan jsonb; terminal_plan jsonb; receipt jsonb;
  removal jsonb; approved_at timestamptz;
  channel_id uuid; before_audit text; after_audit text; verified boolean;
begin
  foreach actor in array array[owner_id,reviewer_id] loop
    sid:=gen_random_uuid(); factor:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'reread_'||left(actor::text,8),'Disposable rehearsal actor');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(sid,actor,'aal2',factor);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),sid,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',sid,'aal','aal2'));
  end loop;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  w:=public.st_v2_create_workspace('Disposable bounded native root rehearsal');
  reset role;
  select x.id into strict channel_id from public.st_v2_channels x where (x.workspace_id,x.name)=(w,'general');
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(w,reviewer_id);
  set local role authenticated;
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Verify disposal plumbing for this synthetic native workspace.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  inventory_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(inventory_id,w,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  audit_plan:=public.st_v8_offboarding_workspace_audit_custody(w,'capture',w::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_workspace_audit_custody(w,'approve',w::text,(audit_plan->>'plan')::uuid,audit_plan->>'sha256');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_offboarding_workspace_audit_custody(w,'detach',w::text,(audit_plan->>'plan')::uuid,audit_plan->>'sha256');
  source_plan:=public.st_v8_offboarding_reconciliation(w,'capture',w::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_reconciliation(w,'confirm',w::text,(source_plan->>'plan')::uuid,source_plan->>'sha256');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  workflow_plan:=public.st_v8_offboarding_workflow_custody(w,'capture',w::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_workflow_custody(w,'approve',w::text,(workflow_plan->>'plan')::uuid,workflow_plan->>'sha256');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_offboarding_workflow_custody(w,'detach',w::text,(workflow_plan->>'plan')::uuid,workflow_plan->>'sha256');
  terminal_plan:=public.st_v8_offboarding_reconciliation(w,'capture',w::text);
  reset role;
  begin
    perform sectalk_private.st_v8_offboarding_root_rehearse(w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256');
    raise exception 'The rehearsal accepted an unreviewed root plan';
  exception when sqlstate 'PT409' then null; end;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_reconciliation(w,'confirm',w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256');
  if public.st_v8_offboarding_root_rehearsal(w,null,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256') is not null then
    raise exception 'The unsatisfied check exposed a rehearsal receipt'; end if;
  begin
    perform public.st_v8_offboarding_root_rehearsal(w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256');
    raise exception 'The independent reviewer was allowed to run the owner rehearsal';
  exception when insufficient_privilege then null; end;
  reset role;
  begin
    perform sectalk_private.st_v8_offboarding_root_rehearse(w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256');
    raise exception 'The rehearsal let the reviewer execute in the owner position';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  create table sectalk_private.offboarding_root_rehearsal_fixture_child (
    channel uuid not null references public.st_v2_channels(id) on delete cascade
  );
  insert into sectalk_private.offboarding_root_rehearsal_fixture_child values(channel_id);
  begin
    perform sectalk_private.st_v8_offboarding_root_rehearse(w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256');
    raise exception 'The rehearsal allowed an unreviewed transitive cascade';
  exception when sqlstate 'PT409' then
    if sqlerrm is distinct from 'Workspace root rehearsal only supports the two approvers and the empty default channel' then raise; end if;
  end;
  if not exists(select 1 from sectalk_private.offboarding_root_rehearsal_fixture_child x where x.channel=channel_id)
    then raise exception 'The denied transitive row was altered'; end if;
  drop table sectalk_private.offboarding_root_rehearsal_fixture_child;
  create trigger offboarding_root_rehearsal_fixture after delete on public.st_v2_channels
    for each row execute function sectalk_private.offboarding_root_rehearsal_fixture_trigger();
  begin
    perform sectalk_private.st_v8_offboarding_root_rehearse(w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256');
    raise exception 'The rehearsal permitted an unreviewed hook';
  exception when sqlstate 'PT409' then
    if sqlerrm is distinct from 'Workspace root rehearsal encountered an unreviewed delete hook' then raise; end if;
  end;
  drop trigger offboarding_root_rehearsal_fixture on public.st_v2_channels;
  select m.sha256 into strict before_audit from sectalk_private.st_v8_offboarding_audit_custody_manifest(w) m where m.valid;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_root_rehearsal(w,gen_random_uuid()::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256');
    raise exception 'The API accepted a different workspace confirmation';
  exception when insufficient_privilege then null; end;
  receipt:=public.st_v8_offboarding_root_rehearsal(w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256');
  if receipt->>'recordedAt' is null
    or (public.st_v8_offboarding_root_rehearsal(w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256')->>'recordedAt')
      is distinct from (receipt->>'recordedAt') then raise exception 'Exact retry did not preserve the original timestamp'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  if (public.st_v8_offboarding_root_rehearsal(w,null,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256')->>'recordedAt')
      is distinct from (receipt->>'recordedAt')
    or public.st_v8_offboarding_root_rehearsal(w,null,(terminal_plan->>'plan')::uuid,repeat('0',64)) is not null then
    raise exception 'Saved timestamp was not scoped to the exact reviewed digest'; end if;
  reset role;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  select m.valid,m.sha256 into strict verified,after_audit from sectalk_private.st_v8_offboarding_audit_custody_manifest(w) m;
  if receipt->>'deletedInsideRollback' is distinct from 'true' or receipt->>'rolledBack' is distinct from 'true'
    or receipt->>'providerBytes' is distinct from 'unverified' or receipt->>'backupErasure' is distinct from 'unverified'
    or not verified or before_audit is distinct from after_audit
    or not exists(select 1 from public.st_v2_workspaces x where x.id=w)
    or not exists(select 1 from public.st_v2_channels x where x.id=channel_id)
    or (select count(*) from public.st_v2_members x where x.workspace_id=w)<>2
    or exists(select 1 from sectalk_private.st_v8_offboarding_root_rehearsal_roster x where x.workspace=w)
    then raise exception 'The bounded physical DELETE did not roll back the full native scope'; end if;
  begin
    delete from public.st_v2_workspaces x where x.id=w;
    raise exception 'The root rehearsal authorized a subsequent permanent deletion';
  exception when sqlstate 'PT423' then null; end;
  if exists(select 1 from unnest(array['anon','authenticated','service_role']) r
    where has_function_privilege(r,'sectalk_private.st_v8_offboarding_root_rehearse(uuid,text,uuid,text)','EXECUTE')
      or has_table_privilege(r,'sectalk_private.st_v8_offboarding_root_rehearsal_roster','SELECT,INSERT,UPDATE,DELETE'))
    then raise exception 'An API role can issue or consume native rehearsal authorizations'; end if;
  if exists(select 1 from unnest(array['anon','authenticated','service_role']) r
    where has_table_privilege(r,'sectalk_private.st_v8_offboarding_root_rehearsal_receipts','SELECT,INSERT,UPDATE,DELETE'))
    or exists(select 1 from unnest(array['anon','service_role']) r
    where has_function_privilege(r,'public.st_v8_offboarding_root_rehearsal(uuid,text,uuid,text)','EXECUTE'))
    or has_schema_privilege('authenticated','sectalk_private','USAGE') then
    raise exception 'The rehearsal exposed private access or a non-user RPC grant';
  end if;

  begin
    perform sectalk_private.st_v8_offboarding_root_mutation(w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256',true);
    raise exception 'A rehearsal receipt authorized native removal by itself';
  exception when sqlstate 'PT409' then
    if sqlerrm is distinct from 'Independent approval for native root removal is required' then raise; end if;
  end;
  begin
    perform sectalk_private.st_v8_approve_offboarding_native_root(w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256');
    raise exception 'The owner approved their own native root removal';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform sectalk_private.st_v8_approve_offboarding_native_root(w,w::text,(terminal_plan->>'plan')::uuid,repeat('0',64));
    raise exception 'Native root approval accepted a different digest';
  exception when sqlstate 'PT409' then null; end;
  approved_at:=sectalk_private.st_v8_approve_offboarding_native_root(w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256');
  if approved_at is null or approved_at is distinct from sectalk_private.st_v8_approve_offboarding_native_root(
    w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256') then raise exception 'Native root approval was not idempotent'; end if;
  begin
    perform sectalk_private.st_v8_offboarding_root_mutation(w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256',true);
    raise exception 'The reviewer executed native root removal';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  create trigger offboarding_root_rehearsal_fixture after delete on public.st_v2_channels
    for each row execute function sectalk_private.offboarding_root_rehearsal_fixture_trigger();
  begin
    perform sectalk_private.st_v8_offboarding_root_mutation(w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256',true);
    raise exception 'Native root removal accepted a later unreviewed hook';
  exception when sqlstate 'PT409' then
    if sqlerrm is distinct from 'Workspace root rehearsal encountered an unreviewed delete hook' then raise; end if;
  end;
  drop trigger offboarding_root_rehearsal_fixture on public.st_v2_channels;
  if not exists(select 1 from public.st_v2_workspaces x where x.id=w)
    or exists(select 1 from sectalk_private.st_v8_offboarding_native_root_receipts x where x.workspace=w) then
    raise exception 'A failed removal changed the workspace or wrote a closure receipt'; end if;
  removal:=sectalk_private.st_v8_offboarding_root_mutation(w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256',true);
  if removal->>'nativeRecordRemoved' is distinct from 'true' or removal->>'removedAt' is null
    or removal->>'providerBytes' is distinct from 'unverified' or removal->>'backupErasure' is distinct from 'unverified'
    or removal is distinct from sectalk_private.st_v8_offboarding_root_mutation(w,w::text,(terminal_plan->>'plan')::uuid,terminal_plan->>'sha256',true)
    or exists(select 1 from public.st_v2_workspaces x where x.id=w)
    or exists(select 1 from public.st_v2_channels x where x.id=channel_id)
    or exists(select 1 from public.st_v2_members x where x.workspace_id=w)
    or exists(select 1 from sectalk_private.st_v8_offboarding_root_rehearsal_roster x where x.workspace=w)
    or not exists(select 1 from sectalk_private.st_v8_offboarding_requests x where x.id=request_id)
    or not exists(select 1 from sectalk_private.st_v7_compliance_cases x where x.id=inventory_id)
    or not exists(select 1 from sectalk_private.st_v8_offboarding_audit_custody_manifest(w) x
      where x.valid and x.sha256=before_audit) then raise exception 'Native removal did not preserve the exact retained evidence'; end if;
  begin
    insert into sectalk_private.st_v8_residency_history_links
      (workspace,approval,source_project,destination_project,side,vault_id,expires_at)
    values(w,gen_random_uuid(),'synthetic-origin','synthetic-destination','destination',gen_random_uuid(),now()+interval '1 hour');
    raise exception 'A transfer link was allowed to reattach to a removed workspace';
  exception when sqlstate 'PT409' then
    if sqlerrm is distinct from 'The workspace has an existing native removal receipt.' then raise; end if;
  end;
  if exists(select 1 from unnest(array['anon','authenticated','service_role']) r
    where has_function_privilege(r,'sectalk_private.st_v8_offboarding_root_mutation(uuid,text,uuid,text,boolean)','EXECUTE')
      or has_function_privilege(r,'sectalk_private.st_v8_approve_offboarding_native_root(uuid,text,uuid,text)','EXECUTE')
      or has_function_privilege(r,'sectalk_private.st_v8_guard_residency_history_link()','EXECUTE')
      or has_function_privilege(r,'sectalk_private.st_v8_guard_native_root_receipt_snapshot()','EXECUTE')
      or has_table_privilege(r,'sectalk_private.st_v8_offboarding_native_root_receipts','SELECT,INSERT,UPDATE,DELETE')) then
    raise exception 'A production API role can access the private executor or receipt'; end if;
end $$;

select 'passed: rollback-only rehearsal, independent approval, exact native removal, preserved custody, idempotency and regional-link reattachment denial';
rollback;
