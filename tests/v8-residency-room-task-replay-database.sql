begin;
set local timezone='UTC';
set local datestyle='ISO, YMD';

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); destination_owner uuid:=gen_random_uuid();
  actor_id uuid; sid uuid; factor uuid; claims jsonb:='{}';
  ws uuid; foreign_ws uuid; source_room uuid:=gen_random_uuid(); foreign_room uuid:=gen_random_uuid();
  anchor uuid:=gen_random_uuid(); first_post uuid:=gen_random_uuid(); second_post uuid:=gen_random_uuid();
  expected public.st_v6_tasks;
  approval uuid:=gen_random_uuid(); handoff uuid:=gen_random_uuid(); review_id uuid:=gen_random_uuid();
  held uuid:=gen_random_uuid(); secret_id uuid; before_time timestamptz:=now()-interval '1 minute';
  signing_key bytea:=decode(repeat('d',64),'hex'); owner_tag text; wire text; packet jsonb; result jsonb;
  records jsonb:='[]'; changes jsonb:='[]'; entry jsonb; revision text; member_id uuid;
begin
  select least(first_post,second_post),greatest(first_post,second_post) into first_post,second_post;
  foreach actor_id in array array[owner_id,reviewer_id] loop
    sid:=gen_random_uuid(); factor:=gen_random_uuid();
    insert into auth.users(id,email,email_confirmed_at) values(actor_id,actor_id||'@example.invalid',now());
    insert into public.st_profiles(id,handle,name) values(actor_id,'rrp_'||left(actor_id::text,8),'Synthetic room recovery principal');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor,actor_id,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(sid,actor_id,'aal2',factor);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),sid,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor_id::text,jsonb_build_object(
      'sub',actor_id,'role','authenticated','session_id',sid,'aal','aal2'));
  end loop;

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  ws:=public.st_v2_create_workspace('Disposable room recovery source');
  perform public.st_v6_room_create(source_room,ws,'Approved project room','public','blank');
  -- The paired root was migrated by its matched ordinary author, independently of the new reply owner.
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  foreign_ws:=public.st_v2_create_workspace('Foreign room replay control');
  perform public.st_v6_room_create(foreign_room,foreign_ws,'Foreign room','public','blank');
  perform public.st_v6_task_create(second_post,foreign_room,null,'Foreign collision');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(ws,reviewer_id,'admin');
  insert into public.st_v6_room_members(room_id,user_id,role) values(source_room,reviewer_id,'member');
  insert into sectalk_private.st_v8_offboarding_reviewers values(ws,reviewer_id);
  insert into public.st_v6_room_posts(room_id,id,sender,body,kind)
    values(source_room,anchor,reviewer_id,'Approved anchor message','message');
  insert into sectalk_private.st_v8_content_exports(id,workspace,requester,reviewer,approved_at,expires_at)
    values(approval,ws,owner_id,reviewer_id,now(),now()+interval '1 hour');
  insert into sectalk_private.st_v8_content_export_entries
    select approval,1,e.kind,e.scope_id,e.record_id,encode(sha256(convert_to(e.item::text,'UTF8')),'hex')
    from sectalk_private.st_v8_content_export_records(ws,owner_id,reviewer_id,'room_message',source_room,anchor) e;
  if not found then raise exception 'The approved source anchor fixture is missing'; end if;
  insert into sectalk_private.st_v8_residency_write_handoffs(workspace,approval,handoff,source_project,destination_project,phase,changed_at)
    values(ws,approval,handoff,'synthetic-origin','synthetic-destination','held',before_time);
  insert into sectalk_private.st_v8_residency_rollback_holds(workspace,approval,handoff,side)
    values(ws,approval,handoff,'source');
  secret_id:=vault.create_secret(encode(signing_key,'hex'));
  insert into sectalk_private.st_v8_residency_rollback_manifest_admissions
    values(handoff,secret_id,repeat('3',64),now()+interval '1 hour');

  foreach member_id in array array[first_post,second_post] loop
    entry:=jsonb_build_object('kind','room_task','id',member_id,'room',source_room,'roomName','Approved project room',
      'name','Reviewed destination task '||member_id,'priority','high','labels',jsonb_build_array('release'),
      'dueAt',now()+interval '1 day','createdAt',now(),'updatedAt',now(),'createdAuditAt',now());
    revision:=encode(sha256(convert_to(to_jsonb(sectalk_private.st_v8_rollback_room_task(destination_owner,entry))::text,
      'UTF8')),'hex');
    records:=records||jsonb_build_array(entry||jsonb_build_object('digest',revision));
    changes:=changes||jsonb_build_array(jsonb_build_object('id',member_id,'kind','room_task','state','added','after',revision));
  end loop;
  insert into sectalk_private.st_v8_residency_rollback_manifests(handoff,workspace,review,review_sha256,packet_sha256,plan_sha256,changes)
    values(handoff,ws,review_id,repeat('1',64),repeat('2',64),repeat('3',64),changes);
  owner_tag:=encode(extensions.hmac(convert_to('sectalk-room-task-replay-owner-v1:'||handoff::text||':'||owner_id::text||
    '@example.invalid','UTF8'),signing_key,'sha256'),'hex');
  wire:=jsonb_build_object('format','sectalk-residency-room-task-replay-v1','workspace',ws,'handoff',handoff,
    'source','synthetic-origin','destination','synthetic-destination','review',review_id,'digest',repeat('1',64),'plan',repeat('3',64),
    'destinationOwner',destination_owner,'ownerTag',owner_tag,'records',records,
    'expires',floor(extract(epoch from clock_timestamp()+interval '4 minutes')))::text;
  packet:=jsonb_build_object('payload',wire,'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),'hex'));
  if has_function_privilege('anon','public.st_v8_residency_rollback_room_tasks(uuid,text,text,jsonb)','EXECUTE')
    or has_table_privilege('authenticated','sectalk_private.st_v8_residency_rollback_room_task_batches','SELECT')
    or has_table_privilege('service_role','sectalk_private.st_v8_residency_rollback_room_task_batches','SELECT') then
    raise exception 'The task recovery surface exposed an anonymous or direct table grant'; end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_residency_rollback_room_tasks(ws,'stage',ws::text,jsonb_set(packet,'{signature}',to_jsonb(repeat('e',64))));
    raise exception 'A tampered task batch was accepted';
  exception when insufficient_privilege then null; end;
  wire:=jsonb_set(wire::jsonb,'{records,0,name}',to_jsonb('Changed task title'::text))::text;
  begin
    perform public.st_v8_residency_rollback_room_tasks(ws,'stage',ws::text,jsonb_build_object('payload',wire,
      'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),'hex')));
    raise exception 'A different task revision was accepted';
  exception when insufficient_privilege then null; end;
  result:=public.st_v8_residency_rollback_room_tasks(ws,'stage',ws::text,packet);
  if result->>'state' is distinct from 'staged' or jsonb_array_length(result->'records')<>2
    then raise exception 'The approved task batch did not stage'; end if;
  begin
    perform public.st_v8_residency_rollback_room_tasks(ws,'apply',ws::text);
    raise exception 'The owner applied without independent review';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform public.st_v8_residency_rollback_room_tasks(ws,'apply',ws::text);
    raise exception 'A foreign task ID collision did not block the entire batch';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  if exists(select 1 from public.st_v6_tasks t where t.room_id=source_room and t.id in (first_post,second_post))
    then raise exception 'The collided batch left a partial write'; end if;
  delete from public.st_v6_tasks where id=second_post and room_id=foreign_room;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(held,ws,owner_id,'Synthetic task preservation hold',reviewer_id);
  set local role authenticated;
  begin
    perform public.st_v8_residency_rollback_room_tasks(ws,'apply',ws::text);
    raise exception 'The task batch bypassed the preservation hold';
  exception when sqlstate 'PT423' then null; end;
  reset role;
  delete from sectalk_private.st_v6_workspace_holds where id=held;
  set local role authenticated;
  if public.st_v8_residency_rollback_room_tasks(ws,'apply',ws::text)->>'state' is distinct from 'applied'
    or public.st_v8_residency_rollback_room_tasks(ws,'apply',ws::text)->>'state' is distinct from 'applied'
    then raise exception 'The independent task reviewer could not apply or retry the batch'; end if;
  result:=public.st_v8_residency_source_replay_review(ws);
  if (select count(*) from jsonb_array_elements(result->'records') e where (e->>'kind',e->>'result')=('room_task','matched'))<>2
    or result::text like '%Reviewed destination task%' then
    raise exception 'Both native room tasks must contribute redacted exact source evidence'; end if;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  if public.st_v8_residency_source_evidence(ws)->>'coverage' is distinct from 'ready'
    then raise exception 'The matched room tasks did not count toward source sign-off'; end if;
  begin
    perform public.st_v6_task_create(gen_random_uuid(),source_room,null,'Ordinary held task');
    raise exception 'Ordinary task writes resumed on the source';
  exception when sqlstate 'PT423' then null; end;
  reset role;
  for entry in select record from jsonb_array_elements(records) record loop
    expected:=sectalk_private.st_v8_rollback_room_task(owner_id,entry);
    if (select to_jsonb(t) from public.st_v6_tasks t where t.id=expected.id) is distinct from to_jsonb(expected)
      or not sectalk_private.st_v8_rollback_room_task_independent(expected.id,owner_id,expected.priority,now())
      then raise exception 'The recovery changed the task revision or original creation audit'; end if;
  end loop;
  if exists(select 1 from sectalk_private.st_v8_residency_channel_write_permits)
    or (select count(*) from public.st_v2_workspace_audit a where a.workspace_id=ws and a.target=handoff and a.event in
      ('workspace.residency_room_task_replay_staged','workspace.residency_room_task_replay_applied'))<>2
    then raise exception 'Task recovery leaked write permits or duplicated audit receipts'; end if;
  insert into public.st_v6_task_audit(task_id,actor_id,action,detail) values(first_post,owner_id,'updated','{}');
  set local role authenticated;
  result:=public.st_v8_residency_source_replay_review(ws);
  if not coalesce(result->'records' @> jsonb_build_array(jsonb_build_object('id',first_post,'result','source_changed')),false)
    or public.st_v8_residency_source_evidence(ws)->>'coverage' is distinct from 'incomplete'
    then raise exception 'Native dependency drift did not block source sign-off'; end if;
  reset role;
end $$;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor_id uuid; sid uuid; factor uuid; claims jsonb:='{}';
  ws uuid; paired_room uuid:=gen_random_uuid(); unpaired_room uuid:=gen_random_uuid();
  approval uuid:=gen_random_uuid(); handoff uuid:=gen_random_uuid(); cell uuid:=gen_random_uuid(); secret_id uuid;
  task_id uuid:=gen_random_uuid(); other_task uuid:=gen_random_uuid(); member_task uuid:=gen_random_uuid();
  dependent_task uuid:=gen_random_uuid();
  destination text:='synthetic-destination'; signing_key bytea:=decode(repeat('c',64),'hex');
  review jsonb; packet jsonb; wire jsonb;
begin
  foreach actor_id in array array[owner_id,reviewer_id] loop
    sid:=gen_random_uuid(); factor:=gen_random_uuid();
    insert into auth.users(id,email,email_confirmed_at) values(actor_id,actor_id||'@example.invalid',now());
    insert into public.st_profiles(id,handle,name) values(actor_id,'rrd_'||left(actor_id::text,8),'Synthetic destination principal');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor,actor_id,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(sid,actor_id,'aal2',factor);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),sid,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor_id::text,jsonb_build_object(
      'sub',actor_id,'role','authenticated','session_id',sid,'aal','aal2'));
  end loop;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  ws:=public.st_v2_create_workspace('Disposable room recovery destination');
  perform public.st_v6_room_create(paired_room,ws,'Imported project room','private','blank');
  perform public.st_v6_room_create(unpaired_room,ws,'Unpaired room','private','blank');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(ws,reviewer_id,'admin');
  insert into public.st_v6_room_members(room_id,user_id,role) values(paired_room,reviewer_id,'member');
  insert into sectalk_private.st_v8_offboarding_reviewers values(ws,reviewer_id);
  insert into sectalk_private.st_v8_residency_cells values(cell,'eu',destination,'Synthetic room rollback destination','fixture',null);
  insert into sectalk_private.st_v8_residency_content_admissions values(cell,ws,'synthetic-origin',approval,
    repeat('3',64),1,now()+interval '1 hour');
  insert into sectalk_private.st_v8_residency_staged_content(cell,workspace,source_project,approval,records)
    values(cell,ws,'synthetic-origin',approval,'[]');
  insert into sectalk_private.st_v8_residency_room_imports(cell,workspace,source_project,approval,room,room_name,
    actor,evidence_count,imported_at)
    values(cell,ws,'synthetic-origin',approval,paired_room,'Imported project room',owner_id,1,now()-interval '2 minutes');
  insert into sectalk_private.st_v8_residency_write_handoffs(workspace,approval,handoff,source_project,destination_project,phase,changed_at)
    values(ws,approval,handoff,'synthetic-origin',destination,'activated',now()-interval '1 minute');
  insert into sectalk_private.st_v8_residency_rollback_baselines(handoff,snapshot)
    values(handoff,sectalk_private.st_v8_residency_rollback_snapshot(ws));
  set local role authenticated;
  perform public.st_v6_task_create(task_id,paired_room,null,'Reviewed owner task',null,now()+interval '1 day','high',array['release']);
  perform public.st_v6_task_create(other_task,unpaired_room,null,'Unpaired owner task');
  perform public.st_v6_task_create(dependent_task,paired_room,null,'Task with an assignee');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v6_task_create(member_task,paired_room,null,'Other author task');
  reset role;
  insert into public.st_v6_task_people(task_id,user_id,kind) values(dependent_task,reviewer_id,'assignee');
  insert into sectalk_private.st_v8_residency_rollback_holds(workspace,approval,handoff,side)
    values(ws,approval,handoff,'destination');
  secret_id:=vault.create_secret(encode(signing_key,'hex'));
  insert into sectalk_private.st_v8_residency_rollback_manifest_admissions
    values(handoff,secret_id,repeat('3',64),now()+interval '1 hour');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_residency_rollback_room_tasks(ws,'issue',ws::text);
    raise exception 'The task packet issued without independent review';
  exception when sqlstate 'PT409' then null; end;
  review:=public.st_v8_residency_rollback_reconcile(ws,'capture',null,ws::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_residency_rollback_reconcile(ws,'confirm',(review->>'id')::uuid,ws::text,review->>'digest');
  begin
    perform public.st_v8_residency_rollback_room_tasks(ws,'issue',ws::text);
    raise exception 'The destination reviewer issued the task packet';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  packet:=public.st_v8_residency_rollback_room_tasks(ws,'issue',ws::text)->'packet';
  wire:=(packet->>'payload')::jsonb;
  if jsonb_array_length(wire->'records') is distinct from 1
    or wire#>>'{records,0,id}' is distinct from task_id::text
    or wire#>>'{records,0,priority}' is distinct from 'high'
    or wire#>>'{records,0,labels,0}' is distinct from 'release'
    then raise exception 'The signed room task batch omitted the eligible exact record or included ineligible tasks'; end if;
  begin
    perform public.st_v6_task_create(gen_random_uuid(),paired_room,null,'Ordinary held destination task');
    raise exception 'Ordinary task writes resumed on the destination';
  exception when sqlstate 'PT423' then null; end;
  reset role;
end $$;

select 'passed: reviewed room task proof and publication, hold and collision boundaries, exact audit, and later dependency drift';
rollback;
