begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); outsider_id uuid:=gen_random_uuid();
  actor uuid; uid uuid; factor uuid; claims jsonb:='{}'; w uuid; request_id uuid:=gen_random_uuid();
  case_id uuid; hold_id uuid:=gen_random_uuid(); audit_id bigint; original record; preserved record; anchor_link uuid;
  chain_before sectalk_private.st_v6_audit_chain_head; chain_after sectalk_private.st_v6_audit_chain_head;
  plan jsonb; renewed jsonb; receipt jsonb; old_snapshot jsonb; root_before jsonb; root_after jsonb;
  error_constraint text;
  ordinary_root uuid:=gen_random_uuid(); ordinary_actor uuid:=gen_random_uuid(); ordinary_audit bigint;
  staging_only boolean:=to_regclass('sectalk_private.st_v8_workspace_audit_actors') is not null;
begin
  foreach actor in array array[owner_id,reviewer_id,outsider_id] loop
    uid:=gen_random_uuid(); factor:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'audit_'||left(actor::text,8),'Disposable audit actor');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(uid,actor,'aal2',factor);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),uid,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',uid,'aal','aal2'));
  end loop;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  w:=public.st_v2_create_workspace('Disposable workspace audit custody');
  reset role;
  select a.id into strict audit_id from public.st_v2_workspace_audit a where a.workspace_id=w and a.event='workspace.created';
  if staging_only then
    insert into auth.users(id,email) values(ordinary_actor,ordinary_actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(ordinary_actor,'audit_'||left(ordinary_actor::text,8),'Disposable retired actor');
    insert into public.st_v2_workspaces(id,name,owner) values(ordinary_root,'Disposable ordinary root',ordinary_actor);
    insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(ordinary_root,ordinary_actor,'workspace.created')
      returning id into ordinary_audit;
    select * into strict original from sectalk_private.st_v8_offboarding_audit_custody_manifest(ordinary_root);
    delete from public.st_v2_workspaces where id=ordinary_root;
    delete from auth.users where id=ordinary_actor;
    select * into strict preserved from sectalk_private.st_v8_offboarding_audit_custody_manifest(ordinary_root);
    if preserved is distinct from original or not preserved.valid
      or exists(select 1 from public.st_v2_workspaces a where a.id=ordinary_root)
      or exists(select 1 from public.st_profiles a where a.id=ordinary_actor)
      or not exists(select 1 from public.st_v2_workspace_audit a where (a.id,a.actor,a.workspace_id)=(ordinary_audit,ordinary_actor,ordinary_root))
      then raise exception 'Ordinary workspace/actor removal did not preserve the exact original audit'; end if;
    begin
      update public.st_v2_workspace_audit a set target=owner_id where a.id=ordinary_audit;
      raise exception 'Retained audit was changed after ordinary root removal';
    exception when sqlstate 'PT409' then null; end;
    begin
      insert into public.st_v2_workspaces(id,name,owner) values(ordinary_root,'Reused workspace ID',owner_id);
      raise exception 'Retained workspace identity was reassigned';
    exception when sqlstate 'PT409' then null; end;
    begin
      insert into auth.users(id,email) values(ordinary_actor,ordinary_actor||'@example.invalid');
      insert into public.st_profiles(id,handle,name) values(ordinary_actor,'audit_'||left(ordinary_actor::text,8),'Reused actor ID');
      raise exception 'Retained audit actor identity was reassigned';
    exception when sqlstate 'PT409' then null; end;
    begin
      insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(w,ordinary_actor,'workspace.created');
      raise exception 'A retired profile was attributed to a new audit event';
    exception when foreign_key_violation then null; end;
  else
    begin
      delete from public.st_v2_workspaces a where a.id=w;
      raise exception 'Unreviewed root DELETE removed the protected workspace audit';
    exception when foreign_key_violation then
      get stacked diagnostics error_constraint=constraint_name;
      if error_constraint is distinct from 'st_v8_workspace_audit_custody_live_workspace_fkey' then raise; end if;
    end;
  end if;
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(w,reviewer_id);
  set local role authenticated;
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Review the original audit chain and custody linkage.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  case_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(case_id,w,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  reset role;
  if staging_only then
    begin
      delete from public.st_v2_workspaces a where a.id=w;
      raise exception 'Unreviewed root DELETE bypassed staged audit custody';
    exception when foreign_key_violation or sqlstate 'PT423' then null; end;
  end if;
  set local role authenticated;
  plan:=public.st_v8_offboarding_workspace_audit_custody(w,'capture',w::text);
  if plan->>'plan' is null or plan->>'linked' is distinct from 'true' or plan->>'verified' is distinct from 'true'
    or plan->>'auditSha256' is null then raise exception 'Captured audit custody is incomplete'; end if;
  begin
    perform public.st_v8_offboarding_workspace_audit_custody(w,'detach',w::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'The owner detached the workspace before independent approval';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_offboarding_workspace_audit_custody(w,'approve',w::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'The owner self-approved audit custody';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>outsider_id::text,true);
  begin
    perform public.st_v8_offboarding_workspace_audit_custody(w);
    raise exception 'The outsider read audit custody';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_workspace_audit_custody(w,'approve',w::text,(plan->>'plan')::uuid,plan->>'sha256');
  reset role;
  old_snapshot:=sectalk_private.st_v8_offboarding_workspace_root_snapshot(w);
  update public.st_v2_workspace_audit a set target=owner_id where a.id=audit_id;
  root_before:=sectalk_private.st_v8_offboarding_workspace_root_snapshot(w);
  if root_before->'summary' is distinct from old_snapshot->'summary'
    or root_before->>'revision' is not distinct from old_snapshot->>'revision'
    or root_before#>>'{summary,unclassifiedConstraints}' is distinct from '0'
    then raise exception 'The root census did not classify or detect the changed exact audit'; end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_workspace_audit_custody(w,'detach',w::text,(plan->>'plan')::uuid,plan->>'sha256');
    raise exception 'The owner executed a stale same-count audit approval';
  exception when sqlstate 'PT409' then null; end;
  renewed:=public.st_v8_offboarding_workspace_audit_custody(w,'capture',w::text);
  if renewed->>'auditSha256' is not distinct from plan->>'auditSha256' or renewed->>'eventCount' is distinct from plan->>'eventCount'
    then raise exception 'Same-count audit revision was invisible to the captured plan'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_workspace_audit_custody(w,'approve',w::text,(renewed->>'plan')::uuid,renewed->>'sha256');
  reset role;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,w,owner_id,'Preserve this disposable original audit trail.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_workspace_audit_custody(w,'detach',w::text,(renewed->>'plan')::uuid,renewed->>'sha256');
    raise exception 'The owner detached the audit despite a live preservation hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release the disposable hold for subsequent custody proof.' where h.id=hold_id;
  root_before:=sectalk_private.st_v8_offboarding_workspace_root_snapshot(w);
  select * into strict original from sectalk_private.st_v8_offboarding_audit_custody_manifest(w);
  select * into strict chain_before from sectalk_private.st_v6_audit_chain_head;
  set local role authenticated;
  receipt:=public.st_v8_offboarding_workspace_audit_custody(w,'detach',w::text,(renewed->>'plan')::uuid,renewed->>'sha256');
  if receipt->>'detachedAt' is null or receipt->>'linked' is distinct from 'false' or receipt is distinct from
    public.st_v8_offboarding_workspace_audit_custody(w,'detach',w::text,(renewed->>'plan')::uuid,renewed->>'sha256')
    then raise exception 'Exact independent custody or safe retry failed'; end if;
  reset role;
  root_after:=sectalk_private.st_v8_offboarding_workspace_root_snapshot(w);
  select * into strict preserved from sectalk_private.st_v8_offboarding_audit_custody_manifest(w);
  select * into strict chain_after from sectalk_private.st_v6_audit_chain_head;
  if preserved is distinct from original or not preserved.valid or chain_after is distinct from chain_before
    or (root_before#>>'{summary,deleteActions,restrict}')::int-(root_after#>>'{summary,deleteActions,restrict}')::int<>1
    or not exists(select 1 from sectalk_private.st_v8_workspace_audit_custody c where c.workspace=w and c.live_workspace is null)
    or not exists(select 1 from public.st_v2_workspace_audit a where (a.id,a.workspace_id,a.target)=(audit_id,w,owner_id))
    or not exists(select 1 from public.st_v2_workspaces a where a.id=w)
    then raise exception 'Detachment changed original audit bytes or did not release exactly one restrictive FK'; end if;

  set local role authenticated;
  hold_id:=gen_random_uuid();
  perform public.st_v6_place_workspace_hold(w,hold_id,null,owner_id,null,null,'This late native legal hold must restore the audit link.');
  receipt:=public.st_v8_offboarding_workspace_audit_custody(w);
  if receipt->>'linked' is distinct from 'true' or receipt->>'held' is distinct from 'true'
    or receipt->>'current' is distinct from 'false' then raise exception 'Native late audit write did not invalidate and relink custody'; end if;
  reset role;
  select live_workspace into strict anchor_link from sectalk_private.st_v8_workspace_audit_custody a where a.workspace=w;
  if anchor_link is distinct from w then raise exception 'Physical root restriction was not restored'; end if;
  if has_function_privilege('anon','public.st_v8_offboarding_workspace_audit_custody(uuid,text,text,uuid,text)','EXECUTE')
    or has_function_privilege('service_role','public.st_v8_offboarding_workspace_audit_custody(uuid,text,text,uuid,text)','EXECUTE')
    or exists(select 1 from unnest(array['anon','authenticated','service_role']) r
      where has_table_privilege(r,'sectalk_private.st_v8_workspace_audit_custody','SELECT,INSERT,UPDATE,DELETE')
      or has_function_privilege(r,'sectalk_private.st_v8_offboarding_audit_custody_manifest(uuid)','EXECUTE'))
    then raise exception 'The audit retention internals are exposed to a Data API role'; end if;
end $$;

select 'passed: exact independently reviewed workspace audit custody, original chain retained, restrictive root link released and restored by a late native hold';
rollback;
