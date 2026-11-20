begin;

do $$
declare
  owner_id uuid:=gen_random_uuid();
  admin_id uuid:=gen_random_uuid();
  actor_id uuid;
  session_key uuid;
  factor_id uuid;
  owner_claim text;
  admin_claim text;
  tenant_id uuid;
  room_scope uuid:=gen_random_uuid();
  post_key uuid:=gen_random_uuid();
  valid_hold uuid:=gen_random_uuid();
  wrong_hold uuid:=gen_random_uuid();
  report_key uuid;
  case_key uuid;
  ticket_id uuid;
  fixture_snapshot uuid;
  artifact_id uuid;
  original_created timestamptz;
  material jsonb;
  reason text:='QA exact evidence preservation and chain verification';
begin
  foreach actor_id in array array[owner_id,admin_id] loop
    session_key:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email) values(actor_id,actor_id||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor_id,'evqa_'||left(actor_id::text,8),'Evidence QA');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor_id,actor_id,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_key,actor_id,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_key,'totp',now(),now());
    perform set_config('request.jwt.claims',jsonb_build_object('sub',actor_id,'role','authenticated',
      'session_id',session_key,'aal','aal2')::text,true);
    if actor_id=owner_id then
      owner_claim:=current_setting('request.jwt.claims');
      set local role authenticated;
      tenant_id:=public.st_v2_create_workspace('Evidence rollback fixture');
      reset role;
    else admin_claim:=current_setting('request.jwt.claims');
    end if;
  end loop;
  insert into public.st_v2_members(workspace_id,user_id,role) values(tenant_id,admin_id,'admin');
  perform set_config('request.jwt.claims',owner_claim,true);
  set local role authenticated;
  perform public.st_v6_room_create(room_scope,tenant_id,'Exact evidence source','public','blank');
  perform public.st_v6_room_post(room_scope,post_key,'Immutable evidence vault fixture');
  reset role;
  select p.created_at into original_created from public.st_v6_room_posts p where p.id=post_key and p.room_id=room_scope;
  set local role authenticated;
  perform public.st_v6_place_workspace_hold(tenant_id,wrong_hold,room_scope,owner_id,null,original_created,reason);
  perform public.st_v6_place_workspace_hold(tenant_id,valid_hold,room_scope,owner_id,original_created,null,reason);
  reset role;
  perform set_config('request.jwt.claims',admin_claim,true);
  set local role authenticated;
  perform public.st_v6_room_membership(room_scope,'join');
  report_key:=public.st_v6_submit_room_report(room_scope,post_key,'threat','Reporter-only notes remain hidden',true);
  case_key:=public.st_v7_request_compliance_export(tenant_id,'QA-EVIDENCE',reason,
    jsonb_build_array(jsonb_build_object('kind','room_report','id',report_key::text)));
  begin
    perform public.st_v7_begin_evidence_operation('capture',case_key,report_key,valid_hold,null,reason);
    raise exception 'Unapproved case created a vault ticket';
  exception when insufficient_privilege then null; end;
  reset role;
  perform set_config('request.jwt.claims',owner_claim,true);
  set local role authenticated;
  perform public.st_v7_review_compliance_export(case_key,'approved',reason);
  reset role;
  perform set_config('request.jwt.claims',admin_claim,true);
  set local role authenticated;
  begin
    perform public.st_v7_begin_evidence_operation('capture',case_key,report_key,wrong_hold,null,reason);
    raise exception 'Exclusive hold deadline escaped scope check';
  exception when insufficient_privilege then null; end;
  ticket_id:=public.st_v7_begin_evidence_operation('capture',case_key,report_key,valid_hold,null,reason);
  reset role;
  if has_table_privilege('authenticated','sectalk_private.st_v7_evidence_snapshots','select')
    or has_table_privilege('authenticated','sectalk_private.st_v7_evidence_custody','insert')
    or has_function_privilege('authenticated','public.st_v7_read_evidence_operation(uuid)','execute') then
    raise exception 'Private evidence or service ticket lookup exposed';
  end if;
  material:=public.st_v7_read_evidence_operation(ticket_id);
  if material is null or material->>'sha256'<>encode(sha256(convert_to(material->>'payload','UTF8')),'hex') then
    raise exception 'Evidence ticket is not bound to the chosen record bytes';
  end if;
  fixture_snapshot:=(material->>'snapshot')::uuid;
  artifact_id:=public.st_v6_begin_export_object(admin_id,'evidence',fixture_snapshot,null,'fixture-snapshot.json','application/json',
    (material->>'bytes')::integer,material->>'sha256');
  insert into storage.objects(bucket_id,name) values('sectalk-exports',artifact_id::text);
  if not public.st_v6_finish_export_object(artifact_id) or not public.st_v7_finish_evidence_operation(ticket_id,artifact_id) then
    raise exception 'Exact approved artifact could not be retained';
  end if;
  begin
    update sectalk_private.st_v7_evidence_snapshots s set sha256=repeat('f',64) where s.id=fixture_snapshot;
    raise exception 'Evidence snapshot metadata could be overwritten';
  exception when insufficient_privilege then null; end;
  begin
    delete from storage.objects o where o.bucket_id='sectalk-exports' and o.name=artifact_id::text;
    raise exception 'An active hold did not prevent private object deletion';
  exception when insufficient_privilege then null; end;
  begin
    update storage.objects o set metadata='{"size":0}' where o.bucket_id='sectalk-exports' and o.name=artifact_id::text;
    raise exception 'An active hold did not prevent private object replacement';
  exception when insufficient_privilege then null; end;
  begin
    update sectalk_private.st_v7_evidence_custody c set payload='modified' where c.snapshot_id=fixture_snapshot;
    raise exception 'Custody could be altered';
  exception when insufficient_privilege then null; end;

  set local role authenticated;
  ticket_id:=public.st_v7_begin_evidence_operation('download',null,null,null,fixture_snapshot,null);
  reset role;
  perform set_config('request.jwt.claims',owner_claim,true);
  set local role authenticated;
  perform public.st_v6_release_workspace_hold(tenant_id,valid_hold,reason);
  reset role;
  if public.st_v7_read_evidence_operation(ticket_id) is not null
    or public.st_v7_finish_evidence_operation(ticket_id,artifact_id)
    or not exists(select 1 from sectalk_private.st_v6_export_objects a where a.id=artifact_id and a.expires_at<=clock_timestamp()) then
    raise exception 'Hold release did not deny a pending download and expire the artifact';
  end if;
  if exists(select 1 from (
      select e.previous_sha256,e.sha256,e.payload,lag(e.sha256,1,repeat('0',64)) over (order by e.sequence) expected_parent
      from sectalk_private.st_v7_evidence_custody e where e.snapshot_id=fixture_snapshot
    ) a where a.previous_sha256<>a.expected_parent or a.sha256<>encode(sha256(convert_to(a.previous_sha256||a.payload,'UTF8')),'hex'))
    or (select string_agg(e.payload::jsonb->>'event',',' order by e.sequence) from sectalk_private.st_v7_evidence_custody e
      where e.snapshot_id=fixture_snapshot)<>'captured,hold_released' then
    raise exception 'Custody chain was incomplete or incorrectly hashed';
  end if;
  insert into sectalk_private.st_v6_export_objects(actor_id,kind,scope_id,filename,media_type,bytes,sha256)
    select admin_id,'evidence',gen_random_uuid(),'quota-fixture.json','application/json',1,repeat('a',64)
    from generate_series(1,20);
  if public.st_v6_begin_export_object(admin_id,'audit',tenant_id,null,'audit-fixture.json','application/json',1,repeat('b',64)) is null then
    raise exception 'Held evidence exhausted the existing transient export quota';
  end if;
end $$;

select 'passed: time-scoped hold checks, exact approved digest, immutable custody and Storage, in-flight release, and retention cleanup' as result;
rollback;
