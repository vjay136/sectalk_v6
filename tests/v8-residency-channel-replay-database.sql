begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid();
  actor_id uuid; session_id uuid; factor_id uuid; claims jsonb:='{}';
  workspace uuid; foreign_space uuid; foreign_channel uuid; recovery_channel uuid:=gen_random_uuid();
  message_id uuid:=gen_random_uuid(); approval_id uuid:=gen_random_uuid(); handoff_id uuid:=gen_random_uuid();
  records jsonb; result jsonb; changes jsonb; external_change uuid:=gen_random_uuid();
  evidence_id uuid; evidence_digest text; hold_id uuid:=gen_random_uuid();
begin
  foreach actor_id in array array[owner_id,reviewer_id] loop
    session_id:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email) values(actor_id,actor_id||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor_id,'rpl_'||left(actor_id::text,8),'Synthetic replay actor');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor_id,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor_id,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor_id::text,jsonb_build_object(
      'sub',actor_id,'role','authenticated','session_id',session_id,'aal','aal2'));
  end loop;

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  workspace:=public.st_v2_create_workspace('Disposable replay origin');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  foreign_space:=public.st_v2_create_workspace('Disposable ID collision control');
  reset role;
  select c.id into strict foreign_channel from public.st_v2_channels c where c.workspace_id=foreign_space and c.name='general';
  insert into public.st_v2_posts(id,channel_id,sender,body) values(message_id,foreign_channel,reviewer_id,'Foreign control');
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(workspace,reviewer_id);
  insert into sectalk_private.st_v8_content_exports(id,workspace,requester,reviewer,approved_at,expires_at)
    values(approval_id,workspace,owner_id,reviewer_id,now(),now()+interval '1 hour');
  insert into sectalk_private.st_v8_residency_write_handoffs(workspace,approval,handoff,source_project,destination_project,phase)
    values(workspace,approval_id,handoff_id,'synthetic-origin','synthetic-destination','held');
  insert into sectalk_private.st_v8_residency_rollback_holds(workspace,approval,handoff,side)
    values(workspace,approval_id,handoff_id,'source');
  records:=jsonb_build_array(
    jsonb_build_object('kind','channel','id',recovery_channel,'name','rollback-fixture','createdAt',now(),'digest',repeat('5',64)),
    jsonb_build_object('kind','channel_message','id',message_id,'channel',recovery_channel,'body','Reviewed synthetic message','createdAt',now(),'digest',repeat('6',64)));
  select jsonb_agg(jsonb_build_object('id',e->>'id','kind',e->>'kind','state','added','after',e->>'digest'))
    into changes from jsonb_array_elements(records) e;
  changes:=changes||jsonb_build_array(jsonb_build_object('id',external_change,'kind','storage_object','state','removed'));
  insert into sectalk_private.st_v8_residency_rollback_manifests(handoff,workspace,review,review_sha256,packet_sha256,plan_sha256,changes)
    values(handoff_id,workspace,gen_random_uuid(),repeat('1',64),repeat('2',64),repeat('3',64),changes);
  insert into sectalk_private.st_v8_residency_rollback_channel_batches(handoff,packet_sha256,records,staged_by)
    values(handoff_id,repeat('4',64),records,owner_id);

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  result:=public.st_v8_residency_source_replay_review(workspace);
  if result->>'state' is distinct from 'held' or not coalesce(
    result->'records' @> jsonb_build_array(jsonb_build_object('id',message_id,'result','not_replayed')),false)
    then raise exception 'Staged records appeared applied'; end if;
  begin
    perform public.st_v8_residency_rollback_channels(workspace,'apply',workspace::text);
    raise exception 'A foreign ID collision was accepted';
  exception when sqlstate 'PT409' then null;
  end;
  reset role;
  if exists(select 1 from public.st_v2_channels c where c.id=recovery_channel)
    or not exists(select 1 from public.st_v2_posts p where p.id=message_id and p.channel_id=foreign_channel and p.body='Foreign control')
    then raise exception 'The failed batch changed live data'; end if;
  delete from public.st_v2_posts p where p.id=message_id and p.channel_id=foreign_channel;

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  result:=public.st_v8_residency_rollback_channels(workspace,'apply',workspace::text);
  if result->>'state' is distinct from 'applied' then raise exception 'The exact source batch did not apply'; end if;
  result:=public.st_v8_residency_rollback_channels(workspace,'apply',workspace::text);
  if result->>'state' is distinct from 'applied' then raise exception 'The exact retry did not converge'; end if;
  result:=public.st_v8_residency_source_replay_review(workspace);
  if jsonb_array_length(result->'records') is distinct from 3 or result->>'reviewDigest' is distinct from repeat('1',64)
    or not coalesce(result->'records' @> jsonb_build_array(
      jsonb_build_object('id',recovery_channel,'result','matched'),
      jsonb_build_object('id',message_id,'result','matched'),
      jsonb_build_object('id',external_change,'result','not_replayed')),false)
    or result::text like '%Reviewed synthetic message%'
    then raise exception 'Source evidence did not distinguish applied and unresolved records'; end if;
  if public.st_v8_residency_source_replay_review(foreign_space)->>'state' is distinct from 'inactive'
    then raise exception 'Source evidence is visible in a different workspace'; end if;
  if public.st_v8_residency_source_evidence(workspace)->>'coverage' is distinct from 'incomplete'
    then raise exception 'Missing records did not block signing'; end if;
  reset role;
  if not exists(select 1 from public.st_v2_channels c join public.st_v2_posts p on p.channel_id=c.id
    where c.id=recovery_channel and c.owner=owner_id and p.id=message_id and p.sender=owner_id and p.body='Reviewed synthetic message')
    or (select count(*) from public.st_v2_workspace_audit a where a.workspace_id=workspace
      and a.event='workspace.residency_channel_replay_applied' and a.target=handoff_id)<>1
    or exists(select 1 from sectalk_private.st_v8_residency_channel_write_permits)
    or sectalk_private.st_v8_residency_rollback_side(workspace) is distinct from 'source'
    then raise exception 'Replay did not preserve the native rows, one audit event and held state'; end if;

  -- The synthetic manifest now models a second scenario with just the two exact applied changes.
  update sectalk_private.st_v8_residency_rollback_manifests m set changes=m.changes - 2 where m.handoff=handoff_id;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  result:=public.st_v8_residency_source_evidence(workspace);
  if result->>'coverage' is distinct from 'ready' then raise exception 'Complete manifest was not ready'; end if;
  evidence_digest:=result->>'evidenceDigest';
  result:=public.st_v8_residency_source_evidence(workspace,'capture',workspace::text,null,evidence_digest);
  if result->>'coverage' is distinct from 'pending' then raise exception 'Source evidence capture did not persist'; end if;
  evidence_id:=(result->>'evidenceId')::uuid;
  begin
    perform public.st_v8_residency_source_evidence(workspace,'confirm',workspace::text,evidence_id,evidence_digest);
    raise exception 'An owner signed off their own evidence';
  exception when insufficient_privilege then null;
  end;
  reset role;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,workspace,owner_id,'Preserve synthetic source evidence.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  if public.st_v8_residency_source_evidence(workspace)->>'coverage' is distinct from 'preservation_hold'
    then raise exception 'A preservation hold did not pause evidence review'; end if;
  begin
    perform public.st_v8_residency_source_evidence(workspace,'confirm',workspace::text,evidence_id,evidence_digest);
    raise exception 'An active preservation hold allowed source sign-off';
  exception when sqlstate 'PT409' then null;
  end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release the synthetic evidence hold.' where h.id=hold_id;
  set local role authenticated;
  begin
    perform public.st_v8_residency_source_evidence(workspace,'confirm',workspace::text,evidence_id,repeat('f',64));
    raise exception 'A wrong evidence digest was accepted';
  exception when sqlstate 'PT409' then null;
  end;
  result:=public.st_v8_residency_source_evidence(workspace,'confirm',workspace::text,evidence_id,evidence_digest);
  if result->>'coverage' is distinct from 'reviewed' then raise exception 'Independent sign-off did not persist'; end if;
  if public.st_v8_residency_source_evidence(workspace,'confirm',workspace::text,evidence_id,evidence_digest) is distinct from result
    then raise exception 'Duplicate source sign-off was not idempotent'; end if;
  reset role;
  if (select count(*) from public.st_v2_workspace_audit a where a.workspace_id=workspace and a.target=evidence_id
    and a.event in ('workspace.residency_source_evidence_captured','workspace.residency_source_evidence_confirmed'))<>2
    then raise exception 'Sign-off did not preserve the two audit events'; end if;
  update public.st_v2_posts set body='Message quarantined',quarantined_at=now() where id=message_id;
  set local role authenticated;
  result:=public.st_v8_residency_source_evidence(workspace);
  if not coalesce(result->'records' @> jsonb_build_array(
    jsonb_build_object('id',message_id,'result','source_changed')),false) or result->>'coverage' is distinct from 'incomplete'
    then raise exception 'A later source quarantine was missed'; end if;
  begin
    perform public.st_v8_residency_source_evidence(workspace,'confirm',workspace::text,evidence_id,evidence_digest);
    raise exception 'Source drift incorrectly preserved an executable sign-off';
  exception when sqlstate 'PT409' then null;
  end;
  reset role;
  if sectalk_private.st_v8_residency_rollback_side(workspace) is distinct from 'source'
    then raise exception 'Evidence sign-off changed source authority'; end if;
end $$;

select 'passed: channel replay, collision atomicity, independent source sign-off, retry and quarantine drift';
rollback;
