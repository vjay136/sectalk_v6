begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; workspace_id uuid; w uuid; request_id uuid:=gen_random_uuid(); case_id uuid;
  channel_id uuid; archived_room uuid:=gen_random_uuid(); message_id uuid:=gen_random_uuid();
  channel_plan jsonb; room_plan jsonb; reviewed jsonb; replacement jsonb; status jsonb;
  event_id bigint; event_hash bytea;
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
  workspace_id:=public.st_v2_create_workspace('Disposable archived channel source');
  reset role;
  w:=workspace_id;
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(w,reviewer_id);
  insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values(w,1);
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,wrapped) values(w,1,'managed',repeat('a',80));
  set local role authenticated;
  channel_id:=public.st_v2_create_channel(w,'archive-reconciliation-history');
  perform public.st_v2_post(channel_id,message_id,'Disposable archive record for reconciliation.');
  perform public.st_v6_manage_channel(channel_id,'archive');
  perform public.st_v6_room_create(archived_room,w,'Archived reconciliation room','public','blank');
  perform public.st_v6_manage_room(archived_room,'archive');
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Review exact archive custody.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  case_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(case_id,w,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  perform public.st_v8_offboarding_archived_channel(w,channel_id,'copy',w::text);
  channel_plan:=public.st_v8_offboarding_archived_channel(w,channel_id,'capture',w::text);
  perform public.st_v8_offboarding_archived_room(w,archived_room,'copy',w::text);
  room_plan:=public.st_v8_offboarding_archived_room(w,archived_room,'capture',w::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_archived_channel(w,channel_id,'approve',w::text,(channel_plan->>'plan')::uuid,channel_plan->>'sha256');
  perform public.st_v8_offboarding_archived_room(w,archived_room,'approve',w::text,(room_plan->>'plan')::uuid,room_plan->>'sha256');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_offboarding_archived_channel(w,channel_id,'delete',w::text,(channel_plan->>'plan')::uuid,channel_plan->>'sha256');
  perform public.st_v8_offboarding_archived_room(w,archived_room,'delete',w::text,(room_plan->>'plan')::uuid,room_plan->>'sha256');
  reviewed:=public.st_v8_offboarding_reconciliation(w,'capture',w::text);
  if reviewed#>>'{summary,verifiedDeletionReceipts,archivedChannelReceipts}' is distinct from '1'
    or reviewed#>>'{summary,verifiedDeletionReceipts,archivedChannelMessageReceipts}' is distinct from '1'
    or reviewed#>>'{summary,verifiedDeletionReceipts,archivedRoomReceipts}' is distinct from '1'
    or reviewed#>>'{summary,archiveFindings,archivedChannelReceiptFindings}' is distinct from '0'
    or reviewed#>>'{summary,archiveFindings,archivedRoomReceiptFindings}' is distinct from '0'
    or reviewed->>'current' is distinct from 'true'
    or reviewed->>'providerBytes' is distinct from 'unverified'
    or reviewed->>'backupErasure' is distinct from 'unverified'
    or reviewed->>'fullTenantErasure' is distinct from 'unverified'
    then raise exception 'Exact archive receipts or scope boundary missing from reconciliation'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  status:=public.st_v8_offboarding_reconciliation(w,'confirm',w::text,(reviewed->>'plan')::uuid,reviewed->>'sha256');
  if status->>'reviewedAt' is null then raise exception 'Initial native review failed'; end if;

  reset role;
  insert into sectalk_private.st_v7_search_document(kind,object_id,fingerprint,first_terms,second_terms)
    values('channel',message_id,decode(repeat('0',64),'hex'),to_tsvector('synthetic stale search'),to_tsvector(''));
  set local role authenticated;
  status:=public.st_v8_offboarding_reconciliation(w);
  if status->>'current' is distinct from 'false'
    or status#>>'{summary,verifiedDeletionReceipts,archivedChannelReceipts}' is distinct from '0'
    or status#>>'{summary,verifiedDeletionReceipts,archivedRoomReceipts}' is distinct from '1'
    or status#>>'{summary,archiveFindings,archivedChannelReceiptFindings}' is distinct from '1'
    then raise exception 'Unexpected live search row was omitted or counted as a successful receipt'; end if;
  begin
    perform public.st_v8_offboarding_reconciliation(w,'confirm',w::text,(reviewed->>'plan')::uuid,reviewed->>'sha256');
    raise exception 'Confirmed a reconciliation with an archive discrepancy';
  exception when sqlstate 'PT409' then null; end;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_reconciliation(w,'capture',w::text);
    raise exception 'Captured a reconciliation with an archive discrepancy';
  exception when sqlstate 'PT409' then null; end;

  reset role;
  delete from sectalk_private.st_v7_search_document d where (d.kind,d.object_id)=('channel',message_id);
  if not exists(select 1 from sectalk_private.st_v8_offboarding_archive_findings_observed i
    where i.reconciliation=(reviewed->>'plan')::uuid and i.actor=reviewer_id
      and i.findings->>'archivedChannelReceiptFindings'='1') then raise exception 'The observed discrepancy was not retained'; end if;
  set local role authenticated;
  status:=public.st_v8_offboarding_reconciliation(w);
  if status->>'current' is distinct from 'false' or status#>>'{summary,archiveFindings,archivedChannelReceiptFindings}'<>'0'
    then raise exception 'The old reviewed receipt revived after resolving the discrepancy'; end if;
  replacement:=public.st_v8_offboarding_reconciliation(w,'capture',w::text);
  if replacement->>'current' is distinct from 'true' or replacement->>'reviewedAt' is not null
    or replacement->>'plan' is not distinct from reviewed->>'plan' or replacement->>'sha256' is distinct from reviewed->>'sha256'
    then raise exception 'Repair requires a new independent review of the same exact source'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  status:=public.st_v8_offboarding_reconciliation(w,'confirm',w::text,(replacement->>'plan')::uuid,replacement->>'sha256');
  if status->>'reviewedAt' is null or status->>'current' is distinct from 'true' then raise exception 'New independent review failed'; end if;
  reset role;
  select h.audit_id,decode(h.sha256,'hex') into strict event_id,event_hash
    from sectalk_private.st_v8_offboarding_retained_channel_archive h where h.plan=(channel_plan->>'plan')::uuid;
  perform sectalk_private.st_v6_audit_append('sectalk_private.st_v6_channel_audit',event_id,'INSERT',event_hash,null);
  perform sectalk_private.st_v6_audit_append('sectalk_private.st_v6_channel_audit',event_id,'DELETE',event_hash,event_hash);
  set local role authenticated;
  status:=public.st_v8_offboarding_reconciliation(w);
  if status->>'current' is distinct from 'false'
    or status#>>'{summary,archiveFindings,archivedChannelReceiptFindings}' is distinct from '1'
    then raise exception 'Accepted a second audit journal lifecycle for the same retained event'; end if;
  reset role;
end $$;

select 'passed: exact native archive custody, stale search discrepancy, fresh review after repair, repeated journal lifecycle rejected';
rollback;
