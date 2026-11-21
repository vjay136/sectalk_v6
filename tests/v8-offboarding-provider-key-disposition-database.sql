begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; sid uuid; factor uuid;
  w uuid; control uuid:=gen_random_uuid(); req uuid:=gen_random_uuid(); inv uuid; claims jsonb:='{}';
  ticket jsonb; root jsonb; scope jsonb; plan jsonb; result jsonb; staged timestamptz; i integer; pin text; plan_id uuid;
  marker text; pins text[]:=array[replace(gen_random_uuid()::text,'-','')||repeat('A',11),
    replace(gen_random_uuid()::text,'-','')||repeat('B',11)];
begin
  foreach actor in array array[owner_id,reviewer_id] loop
    sid:=gen_random_uuid(); factor:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'byok_'||left(actor::text,8),'Disposable provider actor');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(sid,actor,'aal2',factor);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),sid,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',sid,'aal','aal2'));
  end loop;
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values(owner_id,'enterprise','active',now()+interval '1 day');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  w:=public.st_v2_create_workspace('Disposable exact provider key disposition');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(w,reviewer_id);
  insert into sectalk_private.st_v7_tenant_destroy_reviewers values(w,reviewer_id);
  for i in 1..2 loop
    set local role authenticated;
    ticket:=public.st_v7_begin_tenant_key_rotation(w,'byok','Disposable exact external key fixture.');
    if (ticket->>'version')::integer<>i then raise exception 'Unexpected native key history'; end if;
    marker:='external_v2_'||pins[i]||'_'||repeat('R',43);
    set local role service_role;
    if not public.st_v7_commit_tenant_key_rotation((ticket->>'ticket')::uuid,owner_id,marker,'disposable_external_'||i)
      then raise exception 'Native provider marker registration failed'; end if;
    reset role;
  end loop;
  set local role authenticated;
  perform public.st_v8_workspace_offboarding_change(w,req,'requested',w::text,'Review every synthetic external version exactly.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,req,'approved',w::text);
  inv:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(inv,w,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,req,'read_only',w::text);
  root:=public.st_v8_offboarding_reconciliation(w,'capture',w::text);
  if root#>>'{summary,providerKeyDisposition,state}' is distinct from 'unresolved-key-history'
    or root#>>'{summary,providerKeyDisposition,versions}' is distinct from '2'
    or root::text like '%'||pins[1]||'%' then raise exception 'Root review did not bind unresolved/redacted native key history'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_reconciliation(w,'confirm',w::text,(root->>'plan')::uuid,root->>'sha256');
  reset role;
  select r.staged_at into strict staged from sectalk_private.st_v8_offboarding_requests r where r.id=req;
  for i in 1..2 loop
    set local role authenticated;
    perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
    ticket:=public.st_v8_begin_tenant_provider_erasure(w,i,w::text);
    set local role service_role;
    if not public.st_v8_commit_tenant_provider_erasure((ticket->>'ticket')::uuid,reviewer_id,gen_random_uuid(),
      greatest(staged,clock_timestamp()),repeat(case when i=1 then 'a' else 'b' end,64))
      then raise exception 'Native evidence receipt fixture failed for version %',i; end if;
    set local role authenticated;
    perform set_config('request.jwt.claims',claims->>owner_id::text,true);
    scope:=public.st_v8_offboarding_reconciliation(w);
    if scope->>'current' is distinct from 'false' or scope#>>'{summary,providerKeyDisposition,matched}' is distinct from i::text
      then raise exception 'A same-count provider proof change left the prior root review current'; end if;
    begin
      perform public.st_v8_offboarding_provider_key_retirement(w,'capture',w::text);
      raise exception 'Provider retirement captured incomplete or stale evidence';
    exception when sqlstate 'PT409' then null; end;
  end loop;
  root:=public.st_v8_offboarding_reconciliation(w,'capture',w::text);
  if root#>>'{summary,providerKeyDisposition,state}' is distinct from 'exact-provider-key-evidence'
    then raise exception 'Complete pinned provider version history not recognized'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_reconciliation(w,'confirm',w::text,(root->>'plan')::uuid,root->>'sha256');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  plan:=public.st_v8_offboarding_provider_key_retirement(w,'capture',w::text);
  plan_id:=(plan->>'plan')::uuid;
  if plan->>'planSha256' is null then raise exception 'Native retirement plan did not bind the exact proof'; end if;
  begin
    perform public.st_v8_offboarding_provider_key_retirement(w,'retire',w::text,(plan->>'plan')::uuid,plan->>'planSha256');
    raise exception 'Retirement did not require independent approval';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_provider_key_retirement(w,'approve',w::text,(plan->>'plan')::uuid,plan->>'planSha256');
  reset role;
  create table sectalk_private.offboarding_provider_key_fixture_dependency (
    workspace uuid not null, version integer not null,
    foreign key(workspace,version) references sectalk_private.st_v7_tenant_key_versions on delete cascade
  );
  insert into sectalk_private.offboarding_provider_key_fixture_dependency values(w,2);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_provider_key_retirement(w,'retire',w::text,(plan->>'plan')::uuid,plan->>'planSha256');
    raise exception 'Retirement allowed a separate encrypted-record cascade';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  if not exists(select 1 from sectalk_private.offboarding_provider_key_fixture_dependency x where (x.workspace,x.version)=(w,2))
    then raise exception 'A denied dependency changed'; end if;
  drop table sectalk_private.offboarding_provider_key_fixture_dependency;
  set local role authenticated;
  result:=public.st_v8_offboarding_provider_key_retirement(w,'retire',w::text,(plan->>'plan')::uuid,plan->>'planSha256');
  if result is distinct from public.st_v8_offboarding_provider_key_retirement(w,'retire',w::text,
    (plan->>'plan')::uuid,plan->>'planSha256') or result->>'retiredAt' is null
    then raise exception 'Native retirement receipt was not safe to retry'; end if;
  scope:=public.st_v8_offboarding_reconciliation(w);
  if result->>'state' is distinct from 'native-markers-retired' or result->>'retiredVersions' is distinct from '2'
    or result->>'providerBytes' is distinct from 'unverified' or result->>'backupErasure' is distinct from 'unverified'
    or scope#>>'{summary,providerKeyDisposition,state}' is distinct from 'native-markers-retired'
    or scope#>>'{summary,providerKeyDisposition,receipt}' is distinct from result->>'receipt'
    or scope->>'current' is distinct from 'false' then raise exception 'Terminal root proof did not bind native retirement distinctly'; end if;
  reset role;
  if exists(select 1 from sectalk_private.st_v7_tenant_key_versions x where x.workspace=w)
    or not exists(select 1 from sectalk_private.st_v7_tenant_key_state x where x.workspace=w and x.destroyed_at is not null)
    or (select count(*) from sectalk_private.st_v8_provider_erasure_receipts e where (e.workspace,e.request)=(w,req))<>2
    or (select count(*) from sectalk_private.st_v8_offboarding_retired_provider_pins p where p.plan=plan_id)<>2
    or not exists(select 1 from public.st_v2_workspaces x where x.id=w)
    then raise exception 'Native deletion changed the wrong evidence or lost exact provider pin reservations'; end if;
  insert into public.st_v2_workspaces(id,name,owner) values(control,'Disposable pin reuse control',owner_id);
  pin:=pins[2];
  begin
    insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,provider_ref,wrapped)
      values(control,1,'byok','disposable_reuse','external_v2_'||pin||'_'||repeat('S',43));
    raise exception 'Cross-workspace registration reused the provider pin';
  exception when sqlstate 'PT409' then null; end;
  if has_function_privilege('anon','public.st_v8_offboarding_provider_key_retirement(uuid,text,text,uuid,text)','EXECUTE')
    or has_function_privilege('service_role','public.st_v8_offboarding_provider_key_retirement(uuid,text,text,uuid,text)','EXECUTE')
    then raise exception 'Provider-key retirement grants bypass independent native roles'; end if;
end $$;

select 'passed: complete native receipt-to-root binding, independent exact BYOK marker retirement, dependent-row denial, and permanent cross-workspace pin reservation';
rollback;
