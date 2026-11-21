begin;
set local timezone='UTC';
set local datestyle='ISO, YMD';

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); destination_owner uuid:=gen_random_uuid();
  actor_id uuid; sid uuid; factor uuid; claims jsonb:='{}';
  ws uuid; foreign_ws uuid; source_room uuid:=gen_random_uuid(); foreign_room uuid:=gen_random_uuid();
  anchor uuid:=gen_random_uuid(); first_post uuid:=gen_random_uuid(); second_post uuid:=gen_random_uuid();
  approval uuid:=gen_random_uuid(); handoff uuid:=gen_random_uuid(); review_id uuid:=gen_random_uuid();
  held uuid:=gen_random_uuid(); source_marker uuid; secret_id uuid; before_time timestamptz:=now()-interval '1 minute';
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
  perform public.st_v6_room_post(source_room,anchor,'Approved anchor message','message',null);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  foreign_ws:=public.st_v2_create_workspace('Foreign room replay control');
  perform public.st_v6_room_create(foreign_room,foreign_ws,'Foreign room','public','blank');
  perform public.st_v6_room_post(foreign_room,second_post,'Foreign collision','message',null);
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(ws,reviewer_id,'admin');
  insert into public.st_v6_room_members(room_id,user_id,role) values(source_room,reviewer_id,'member');
  insert into sectalk_private.st_v8_offboarding_reviewers values(ws,reviewer_id);
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
    entry:=jsonb_build_object('kind','room_message','id',member_id,'room',source_room,'roomName','Approved project room',
      'body','Reviewed destination room message '||member_id,'createdAt',now());
    revision:=encode(sha256(convert_to(to_jsonb(sectalk_private.st_v8_rollback_room_message(destination_owner,entry))::text,
      'UTF8')),'hex');
    records:=records||jsonb_build_array(entry||jsonb_build_object('digest',revision));
    changes:=changes||jsonb_build_array(jsonb_build_object('id',member_id,'kind','room_message','state','added','after',revision));
  end loop;
  insert into sectalk_private.st_v8_residency_rollback_manifests(handoff,workspace,review,review_sha256,packet_sha256,plan_sha256,changes)
    values(handoff,ws,review_id,repeat('1',64),repeat('2',64),repeat('3',64),changes);
  owner_tag:=encode(extensions.hmac(convert_to('sectalk-room-replay-owner-v1:'||handoff::text||':'||owner_id::text||
    '@example.invalid','UTF8'),signing_key,'sha256'),'hex');
  wire:=jsonb_build_object('format','sectalk-residency-room-replay-v1','workspace',ws,'handoff',handoff,
    'source','synthetic-origin','destination','synthetic-destination','review',review_id,'digest',repeat('1',64),'plan',repeat('3',64),
    'destinationOwner',destination_owner,'ownerTag',owner_tag,'records',records,
    'expires',floor(extract(epoch from clock_timestamp()+interval '4 minutes')))::text;
  packet:=jsonb_build_object('payload',wire,'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),'hex'));
  if has_function_privilege('anon','public.st_v8_residency_rollback_rooms(uuid,text,text,jsonb)','EXECUTE')
    or has_table_privilege('authenticated','sectalk_private.st_v8_residency_rollback_room_batches','SELECT')
    or has_table_privilege('service_role','sectalk_private.st_v8_residency_rollback_room_batches','SELECT') then
    raise exception 'Room replay receipts or functions were exposed outside their intended surface'; end if;

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_residency_rollback_rooms(ws,'stage',ws::text,jsonb_set(packet,'{signature}',to_jsonb(repeat('e',64))));
    raise exception 'A tampered packet was accepted';
  exception when insufficient_privilege then null; end;
  result:=public.st_v8_residency_rollback_rooms(ws,'stage',ws::text,packet);
  if result->>'state' is distinct from 'staged' or jsonb_array_length(result->'records')<>2
    then raise exception 'The scoped signed packet did not stage'; end if;
  if public.st_v8_residency_rollback_rooms(ws,'stage',ws::text,packet)->>'state' is distinct from 'staged'
    then raise exception 'An exact stage retry did not converge'; end if;
  begin
    perform public.st_v8_residency_rollback_rooms(ws,'apply',ws::text);
    raise exception 'The owner applied their own recovery batch';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform public.st_v8_residency_rollback_rooms(ws,'apply',ws::text);
    raise exception 'A foreign message collision was accepted';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  if exists(select 1 from public.st_v6_room_posts p where p.room_id=source_room and p.id in (first_post,second_post)) then
    raise exception 'The collision left a partial batch'; end if;
  delete from public.st_v6_room_posts p where (p.room_id,p.id)=(foreign_room,second_post);
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(held,ws,owner_id,'Preserve synthetic source room evidence.',owner_id);
  set local role authenticated;
  begin
    perform public.st_v8_residency_rollback_rooms(ws,'apply',ws::text);
    raise exception 'A preservation hold was ignored';
  exception when sqlstate 'PT423' then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release the synthetic room recovery hold.' where h.id=held;
  set local role authenticated;
  result:=public.st_v8_residency_rollback_rooms(ws,'apply',ws::text);
  if result->>'state' is distinct from 'applied' then raise exception 'The independent reviewer could not apply the batch'; end if;
  if public.st_v8_residency_rollback_rooms(ws,'apply',ws::text)->>'state' is distinct from 'applied' then
    raise exception 'An exact apply retry did not converge'; end if;
  result:=public.st_v8_residency_source_replay_review(ws);
  if result->>'state' is distinct from 'held'
    or (select count(*) from jsonb_array_elements(result->'records') e where (e->>'kind',e->>'result')=('room_message','matched'))<>2
    or result::text like '%Reviewed destination room message%' then
    raise exception 'The source comparison did not establish exact recovered room revisions without returning plaintext'; end if;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  if public.st_v8_residency_source_evidence(ws)->>'coverage' is distinct from 'ready' then
    raise exception 'Matched room messages did not contribute to source sign-off'; end if;
  begin
    source_marker:=gen_random_uuid();
    perform public.st_v6_room_post(source_room,source_marker,'Ordinary post during hold','message',null);
    raise exception 'Ordinary writes resumed during room rollback';
  exception when sqlstate 'PT423' then null; end;
  reset role;
  if (select count(*) from public.st_v6_room_posts p where p.room_id=source_room and p.id in (first_post,second_post)
      and p.sender=owner_id and p.created_at=now() and p.parent_id is null and p.edited_at is null)<>2
    or (select count(*) from public.st_v2_workspace_audit a where a.workspace_id=ws and a.target=handoff
      and a.event in ('workspace.residency_room_replay_applied','workspace.residency_room_replay_staged'))<>2
    or exists(select 1 from sectalk_private.st_v8_residency_channel_write_permits)
    then raise exception 'Publication did not retain exact authorship, timestamps and one audit event per action'; end if;
  update public.st_v6_room_posts p set body='Message removed',removed_at=now()
    where (p.room_id,p.id)=(source_room,first_post);
  set local role authenticated;
  result:=public.st_v8_residency_source_replay_review(ws);
  if not coalesce(result->'records' @> jsonb_build_array(jsonb_build_object('id',first_post,'result','source_changed')),false)
    or public.st_v8_residency_source_evidence(ws)->>'coverage' is distinct from 'incomplete' then
    raise exception 'Later source moderation did not invalidate recovery evidence'; end if;
  reset role;
end $$;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor_id uuid; sid uuid; factor uuid; claims jsonb:='{}';
  ws uuid; paired_room uuid:=gen_random_uuid(); unpaired_room uuid:=gen_random_uuid();
  approval uuid:=gen_random_uuid(); handoff uuid:=gen_random_uuid(); cell uuid:=gen_random_uuid(); secret_id uuid;
  post_id uuid:=gen_random_uuid(); member_post uuid:=gen_random_uuid(); reply_id uuid:=gen_random_uuid();
  edited_post uuid:=gen_random_uuid(); other_post uuid:=gen_random_uuid();
  signing_key bytea:=decode(repeat('c',64),'hex'); review jsonb; packet jsonb; wire jsonb;
  destination text:='room-replay-'||left(handoff::text,8);
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
  insert into public.st_v6_room_posts(room_id,id,sender,body,kind,parent_id,edited_at)
    values(paired_room,post_id,owner_id,'An eligible exact owner message','message',null,null),
      (paired_room,member_post,reviewer_id,'A different author','message',null,null),
      (paired_room,reply_id,owner_id,'A reply awaiting separate recovery','message',post_id,null),
      (paired_room,edited_post,owner_id,'An edited post awaiting separate recovery','message',null,now()),
      (unpaired_room,other_post,owner_id,'A room without an approved pairing','message',null,null);
  insert into sectalk_private.st_v8_residency_rollback_holds(workspace,approval,handoff,side)
    values(ws,approval,handoff,'destination');
  secret_id:=vault.create_secret(encode(signing_key,'hex'));
  insert into sectalk_private.st_v8_residency_rollback_manifest_admissions
    values(handoff,secret_id,repeat('3',64),now()+interval '1 hour');
  set local role authenticated;
  begin
    perform public.st_v8_residency_rollback_rooms(ws,'issue',ws::text);
    raise exception 'The destination owner issued without independent review';
  exception when sqlstate 'PT409' then null; end;
  review:=public.st_v8_residency_rollback_reconcile(ws,'capture',null,ws::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_residency_rollback_reconcile(ws,'confirm',(review->>'id')::uuid,ws::text,review->>'digest');
  begin
    perform public.st_v8_residency_rollback_rooms(ws,'issue',ws::text);
    raise exception 'A destination reviewer could issue the owner packet';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  packet:=public.st_v8_residency_rollback_rooms(ws,'issue',ws::text)->'packet';
  wire:=(packet->>'payload')::jsonb;
  if jsonb_array_length(wire->'records') is distinct from 1
    or not coalesce(wire->'records' @> jsonb_build_array(jsonb_build_object('id',post_id,'room',paired_room,
      'body','An eligible exact owner message')),false)
    or wire->>'digest' is distinct from review->>'digest'
    or packet->>'signature' is distinct from encode(extensions.hmac(convert_to(packet->>'payload','UTF8'),
      signing_key,'sha256'),'hex') then raise exception 'The destination packet did not pin only the exact independent revision'; end if;
  reset role;
  update public.st_v6_room_posts p set body='Message removed',removed_at=now() where (p.room_id,p.id)=(paired_room,post_id);
  set local role authenticated;
  begin
    perform public.st_v8_residency_rollback_rooms(ws,'issue',ws::text);
    raise exception 'A stale destination review issued a new packet after moderation';
  exception when sqlstate 'PT409' then null; end;
end $$;

select 'passed: independent destination issuance, signed source replay, atomic collisions, holds, exact revisions and later drift';
rollback;
