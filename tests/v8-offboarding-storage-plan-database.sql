begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); outsider_id uuid:=gen_random_uuid(); actor uuid;
  session_id uuid; factor_id uuid; claims jsonb:='{}'; workspace_id uuid; other_workspace uuid;
  request_id uuid:=gen_random_uuid(); case_id uuid; hold_id uuid:=gen_random_uuid();
  file_id uuid:=gen_random_uuid(); room_id uuid:=gen_random_uuid(); room_file_id uuid:=gen_random_uuid();
  pending_id uuid:=gen_random_uuid(); missing_id uuid:=gen_random_uuid(); untracked text;
  workspace_object text; room_object text; plan jsonb; confirmed jsonb; revoked jsonb;
begin
  foreach actor in array array[owner_id,reviewer_id,outsider_id] loop
    session_id:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'st_spr_'||left(actor::text,8),'Storage review fixture');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',session_id,'aal','aal2'));
  end loop;
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values(owner_id,'enterprise','active',now()+interval '1 day'),(outsider_id,'enterprise','active',now()+interval '1 day');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  workspace_id:=public.st_v2_create_workspace('Scoped workspace Storage review');
  perform set_config('request.jwt.claims',claims->>outsider_id::text,true);
  other_workspace:=public.st_v2_create_workspace('Unrelated Storage control');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace_id,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(workspace_id,reviewer_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v6_room_create(room_id,workspace_id,'Retained room','public','blank');
  reset role;
  workspace_object:=workspace_id::text||'/'||file_id::text;
  room_object:=workspace_id::text||'/rooms/'||room_id::text||'/'||room_file_id::text;
  untracked:=workspace_id::text||'/unassigned-object';
  insert into sectalk_private.st_v6_workspace_files(workspace,id,uploader,filename,size_bytes,fingerprint,published_at)
    values(workspace_id,file_id,owner_id,'owner-secret-name.txt',9,decode(repeat('a',64),'hex'),now()),
    (workspace_id,missing_id,owner_id,'missing.txt',9,decode(repeat('b',64),'hex'),now());
  insert into sectalk_private.st_v6_workspace_files(workspace,id,uploader,filename,size_bytes)
    values(workspace_id,pending_id,owner_id,'pending.txt',9);
  insert into sectalk_private.st_v6_room_files(workspace,room,id,uploader,filename,size_bytes,sha256,published_at,deleted_at)
    values(workspace_id,room_id,room_file_id,owner_id,'retained.txt',19,repeat('c',64),now(),now());
  insert into storage.objects(bucket_id,name,version,metadata) values
    ('sectalk-workspace-files',workspace_object,gen_random_uuid()::text,'{"size":8}'),
    ('sectalk-workspace-files',room_object,gen_random_uuid()::text,'{"size":19}'),
    ('sectalk-workspace-files',untracked,gen_random_uuid()::text,'{"size":9}'),
    ('sectalk-workspace-files',other_workspace::text||'/'||file_id::text,gen_random_uuid()::text,'{"size":9}');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_storage_plan(workspace_id);
    raise exception 'Storage review available before staging';
  exception when insufficient_privilege then null; end;
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'requested',workspace_id::text,
    'Native Storage review for a specifically staged workspace.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'approved',workspace_id::text);
  case_id:=(public.st_v8_workspace_offboarding(workspace_id)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action)
    values(case_id,workspace_id,owner_id,'downloaded');

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(workspace_id,request_id,'read_only',workspace_id::text);
  plan:=public.st_v8_offboarding_storage_plan(workspace_id,'capture',null,workspace_id::text);
  if plan->'counts' is distinct from '{"published":0,"retained":1,"removed":0,"pending":1,"missing":1,"mismatch":1,"untracked":1}'::jsonb
    or plan->>'clean'<>'false' or plan ? 'items' or plan::text like '%owner-secret%' then
    raise exception 'Scope, classification or redaction failed: %',plan;
  end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform public.st_v8_offboarding_storage_plan(workspace_id,'confirm',(plan->>'plan')::uuid,workspace_id::text,plan->>'sha256');
    raise exception 'Reviewer confirmed an unresolved object inventory';
  exception when sqlstate 'PT409' then null; end;
  perform set_config('request.jwt.claims',claims->>outsider_id::text,true);
  begin
    perform public.st_v8_offboarding_storage_plan(workspace_id);
    raise exception 'Unrelated workspace owner saw the staged Storage review';
  exception when insufficient_privilege then null; end;
  reset role;

  -- Synthetic Storage metadata changes under a rollback transaction only.
  update storage.objects set name=other_workspace::text||'/unassigned-control'
    where bucket_id='sectalk-workspace-files' and name=untracked;
  update storage.objects set metadata='{"size":9}' where bucket_id='sectalk-workspace-files' and name=workspace_object;
  update sectalk_private.st_v6_workspace_files set deleted_at=now() where workspace=workspace_id and id in (pending_id,missing_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  plan:=public.st_v8_offboarding_storage_plan(workspace_id,'capture',null,workspace_id::text);
  if plan->'counts' is distinct from '{"published":1,"retained":1,"removed":2,"pending":0,"missing":0,"mismatch":0,"untracked":0}'::jsonb
    or plan->>'clean'<>'true' then raise exception 'Expected a clean canonical inventory: %',plan; end if;
  begin
    perform public.st_v8_offboarding_storage_plan(workspace_id,'confirm',(plan->>'plan')::uuid,workspace_id::text,plan->>'sha256');
    raise exception 'Owner confirmed their own inventory';
  exception when sqlstate 'PT409' then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform public.st_v8_offboarding_storage_plan(workspace_id,'confirm',(plan->>'plan')::uuid,workspace_id::text,repeat('0',64));
    raise exception 'Reviewer confirmed an incorrect digest';
  exception when sqlstate 'PT409' then null; end;
  confirmed:=public.st_v8_offboarding_storage_plan(workspace_id,'confirm',(plan->>'plan')::uuid,workspace_id::text,plan->>'sha256');
  if confirmed->>'reviewedAt' is null or confirmed->>'current'<>'true' then raise exception 'No current receipt'; end if;
  if public.st_v8_offboarding_storage_plan(workspace_id,'confirm',(plan->>'plan')::uuid,workspace_id::text,plan->>'sha256')
    is distinct from confirmed then raise exception 'Confirmation retry changed the receipt'; end if;
  reset role;

  update storage.objects set version=gen_random_uuid()::text where bucket_id='sectalk-workspace-files' and name=workspace_object;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,workspace_id,owner_id,'Retain synthetic records during Storage review.',owner_id);
  set local role authenticated;
  revoked:=public.st_v8_offboarding_storage_plan(workspace_id);
  if revoked->>'current'<>'false' or revoked->>'held'<>'true' then
    raise exception 'Same-size replacement and new hold did not invalidate live review';
  end if;
  begin
    perform public.st_v8_offboarding_storage_plan(workspace_id,'confirm',(plan->>'plan')::uuid,workspace_id::text,plan->>'sha256');
    raise exception 'Active hold did not block review';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release the disposable Storage review hold.' where h.id=hold_id;
  insert into storage.objects(bucket_id,name,version,metadata)
    select 'sectalk-workspace-files',workspace_id::text||'/untracked-overflow-'||n,
      gen_random_uuid()::text,'{"size":1}'::jsonb from generate_series(1,501) n;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  if public.st_v8_offboarding_storage_plan(workspace_id)->>'limitExceeded'<>'true' then
    raise exception 'Truncated inventory was reported as complete';
  end if;
  begin
    perform public.st_v8_offboarding_storage_plan(workspace_id,'capture',null,workspace_id::text);
    raise exception 'Oversize manifest was captured';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  delete from sectalk_private.st_v8_offboarding_reviewers q where q.workspace=workspace_id and q.actor=reviewer_id;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_storage_plan(workspace_id);
    raise exception 'Owner used an inactive independent reviewer';
  exception when insufficient_privilege then null; end;
  reset role;
  if exists(select 1 from pg_roles r where r.rolname in ('anon','service_role')
      and has_function_privilege(r.rolname,'public.st_v8_offboarding_storage_plan(uuid,text,uuid,text,text)','EXECUTE'))
    or has_function_privilege('authenticated','sectalk_private.st_v8_offboarding_storage_snapshot(uuid)','EXECUTE') then
    raise exception 'Unintended Storage review grants';
  end if;
end $$;

select 'passed: staged Storage scope, unresolved objects, exact independent review, drift, hold and revoked role';
rollback;
