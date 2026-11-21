begin;
set local timezone='UTC';
set local datestyle='ISO, YMD';

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor_id uuid; sid uuid; factor uuid;
  claims jsonb:='{}'; ws uuid; source_room uuid:=gen_random_uuid(); anchor uuid:=gen_random_uuid();
  file_id uuid:=gen_random_uuid(); target_object uuid:=gen_random_uuid(); staged_object uuid:=gen_random_uuid();
  live_object uuid:=gen_random_uuid(); approved_digest text; live_version text:=gen_random_uuid()::text;
  approval uuid:=gen_random_uuid(); handoff uuid:=gen_random_uuid(); review_id uuid:=gen_random_uuid();
  secret_id uuid; signing_key bytea:=decode(repeat('d',64),'hex'); owner_tag text;
  claim jsonb; wire text; bad_wire text; packet jsonb; result jsonb; expires bigint;
  changes jsonb; file_sha text:=repeat('4',64); file_revision text:=repeat('5',64); object_revision text:=repeat('6',64);
begin
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
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(ws,reviewer_id,'admin');
  insert into public.st_v6_room_members(room_id,user_id,role) values(source_room,reviewer_id,'member');
  insert into sectalk_private.st_v8_offboarding_reviewers values(ws,reviewer_id);
  insert into public.st_v6_room_posts(room_id,id,sender,body,kind)
    values(source_room,anchor,reviewer_id,'Approved anchor message','message')
;
  insert into sectalk_private.st_v8_content_exports(id,workspace,requester,reviewer,approved_at,expires_at)
    values(approval,ws,owner_id,reviewer_id,now(),now()+interval '1 hour');
  insert into sectalk_private.st_v8_content_export_entries
    select approval,1,e.kind,e.scope_id,e.record_id,encode(sha256(convert_to(e.item::text,'UTF8')),'hex')
    from sectalk_private.st_v8_content_export_records(ws,owner_id,reviewer_id,'room_message',source_room,anchor) e;
  if not found then raise exception 'The approved source anchor fixture is missing'; end if;

  insert into sectalk_private.st_v8_residency_write_handoffs(workspace,approval,handoff,source_project,destination_project,phase,changed_at)
    values(ws,approval,handoff,'synthetic-origin','synthetic-destination','held',now()-interval '1 minute');
  insert into sectalk_private.st_v8_residency_rollback_holds(workspace,approval,handoff,side) values(ws,approval,handoff,'source');
  secret_id:=vault.create_secret(encode(signing_key,'hex'));
  insert into sectalk_private.st_v8_residency_rollback_manifest_admissions values(handoff,secret_id,repeat('3',64),now()+interval '1 hour');
  changes:=jsonb_build_array(jsonb_build_object('kind','room_file','id',file_id,'state','added','after',file_revision),
    jsonb_build_object('kind','storage_object','id',target_object,'state','added','after',object_revision));
  insert into sectalk_private.st_v8_residency_rollback_manifests(handoff,workspace,review,review_sha256,packet_sha256,plan_sha256,changes)
    values(handoff,ws,review_id,repeat('1',64),repeat('2',64),repeat('3',64),changes);
  owner_tag:=encode(extensions.hmac(convert_to('sectalk-file-replay-owner-v1:'||handoff::text||':'||
    owner_id::text||'@example.invalid','UTF8'),signing_key,'sha256'),'hex');
  expires:=floor(extract(epoch from clock_timestamp()+interval '4 minutes'));
  claim:=jsonb_build_object('format','sectalk-residency-room-file-copy-v1','workspace',ws,'handoff',handoff,
    'source','synthetic-origin','destination','synthetic-destination','approval',approval,'plan',repeat('3',64),
    'review',review_id,'digest',repeat('1',64),'file',file_id,'fileRevision',file_revision,
    'object',target_object,'objectRevision',object_revision,'ownerTag',owner_tag,'room',source_room,
    'roomName','Approved project room','filename','reviewed.txt','bytes',12,'sha256',file_sha,'expires',expires);
  wire:=claim::text;
  packet:=jsonb_build_object('payload',wire,'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),'hex'));

  insert into storage.objects(id,bucket_id,name,version,metadata) values(staged_object,'sectalk-residency-recovery',
    ws::text||'/'||handoff::text||'/'||file_id::text||'/'||file_sha,gen_random_uuid()::text,'{"size":12}');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  foreach bad_wire in array array[
    jsonb_set(claim,'{room}',to_jsonb(gen_random_uuid()))::text,
    jsonb_set(claim,'{roomName}',to_jsonb('Unpaired room'::text))::text,
    jsonb_set(claim,'{expires}',to_jsonb(expires-600))::text,
    jsonb_set(claim,'{objectRevision}',to_jsonb(repeat('a',64)))::text
  ] loop
    begin
      perform public.st_v8_residency_source_file_admission(ws,file_id,
        jsonb_build_object('payload',bad_wire,'signature',encode(extensions.hmac(convert_to(bad_wire,'UTF8'),signing_key,'sha256'),'hex')),
        file_sha,12);
      raise exception 'Incorrect signed room file scope was accepted';
    exception when insufficient_privilege then null; end;
  end loop;
  begin
    perform public.st_v8_residency_source_file_admission(ws,file_id,packet,repeat('f',64),12);
    raise exception 'Changed file bytes were authorized';
  exception when insufficient_privilege then null; end;
  result:=public.st_v8_residency_source_file_stage(ws,file_id,packet,file_sha,12);
  if result->>'state' is distinct from 'staged' or public.st_v8_residency_source_file_stage(ws,file_id,packet,file_sha,12)<>result then
    raise exception 'Room copy staging did not converge on retry';
  end if;
  result:=public.st_v8_residency_source_file_review(ws)->'files'->0;
  if (result->>'state',result->>'room') is distinct from ('staged',source_room::text) then
    raise exception 'The owner did not see the staged room identity';
  end if;
  approved_digest:=result->>'digest';
  begin
    perform public.st_v8_residency_source_file_review(ws,file_id,ws::text,approved_digest);
    raise exception 'The owner approved their own room file';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  if public.st_v8_residency_source_file_review(ws,file_id,ws::text,approved_digest)#>>'{files,0,state}' is distinct from 'approved' then
    raise exception 'The independently reviewed room file was not approved';
  end if;
  begin
    perform public.st_v8_residency_source_file_restore(ws,file_id,approved_digest);
    raise exception 'The reviewer published the owner file';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  result:=public.st_v8_residency_source_file_restore(ws,file_id,approved_digest);
  if (result->>'state',result->>'room') is distinct from ('ready',source_room::text) then
    raise exception 'Publication did not return the approved original room';
  end if;
  reset role;
  insert into storage.objects(id,bucket_id,name,version,metadata,user_metadata)
    values(live_object,'sectalk-workspace-files',ws::text||'/rooms/'||source_room::text||'/'||file_id::text,
      live_version,'{"size":12}',jsonb_build_object('sectalkRollbackApproval',repeat('f',64),'sectalkRollbackSha256',file_sha));
  set local role authenticated;
  begin
    perform public.st_v8_residency_source_file_restore(ws,file_id,approved_digest,'publish');
    raise exception 'A conflicting live Storage object was accepted';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  if exists(select 1 from sectalk_private.st_v6_room_files f where (f.room,f.id)=(source_room,file_id)) then
    raise exception 'The failed Storage publication left a room file registration';
  end if;
  update storage.objects o set user_metadata=jsonb_build_object(
    'sectalkRollbackApproval',approved_digest,'sectalkRollbackSha256',file_sha) where o.id=live_object;
  set local role authenticated;
  result:=public.st_v8_residency_source_file_restore(ws,file_id,approved_digest,'publish');
  if result->>'state' is distinct from 'restored'
    or public.st_v8_residency_source_file_restore(ws,file_id,approved_digest,'publish')<>result
    or public.st_v8_residency_source_file_review(ws)#>>'{files,0,state}' is distinct from 'restored' then
    raise exception 'The independently approved room restore or idempotent receipt failed';
  end if;
  result:=public.st_v8_residency_source_replay_review(ws);
  if (select count(*) from jsonb_array_elements(result->'records') c where c->>'result'='matched')<>2 then
    raise exception 'The restored room file and Storage revision were not both reconciled: %',result;
  end if;
  reset role;
  if not exists(select 1 from sectalk_private.st_v6_room_files f
      where (f.room,f.workspace,f.id,f.uploader,f.sha256)=(source_room,ws,file_id,owner_id,file_sha)
        and f.published_at is not null)
    or exists(select 1 from sectalk_private.st_v6_workspace_files f where (f.workspace,f.id)=(ws,file_id))
    or exists(select 1 from sectalk_private.st_v8_residency_file_write_permits where tx=pg_current_xact_id()) then
    raise exception 'Publication did not stay scoped to the original room or left a write permit';
  end if;
  begin
    insert into sectalk_private.st_v6_room_files(room,workspace,id,uploader,filename,size_bytes,sha256)
      values(source_room,ws,gen_random_uuid(),owner_id,'unauthorized.txt',12,file_sha);
    raise exception 'Ordinary room file writes reopened after restoration';
  exception when sqlstate 'PT423' then null; end;
  update storage.objects o set version=gen_random_uuid()::text where o.id=live_object;
  set local role authenticated;
  result:=public.st_v8_residency_source_replay_review(ws);
  if (select count(*) from jsonb_array_elements(result->'records') c where c->>'result'='source_changed')<>2 then
    raise exception 'Changed source Storage revision did not invalidate both room evidence entries';
  end if;
end $$;

select 'passed: signed room file admission, independent scope, exact publication, idempotency, held writes and source evidence drift';
rollback;
