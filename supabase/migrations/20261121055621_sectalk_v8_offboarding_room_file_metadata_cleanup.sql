begin;

create table sectalk_private.st_v8_room_file_cleanup_tickets (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null,
  copy_id uuid not null,
  workspace uuid not null,
  room uuid not null,
  file uuid not null,
  actor uuid not null,
  native_session uuid not null,
  action text not null check(action in ('review','remove')),
  source_sha256 text not null,
  expires_at timestamptz not null default clock_timestamp()+interval '45 seconds'
);
create table sectalk_private.st_v8_room_file_recovery_reviews (
  copy_id uuid primary key references sectalk_private.st_v8_offboarding_room_storage_copy_receipts,
  request_id uuid not null,
  reviewer uuid not null,
  source_sha256 text not null check(source_sha256~'^[a-f0-9]{64}$'),
  reviewed_at timestamptz not null default clock_timestamp()
);
create table sectalk_private.st_v8_offboarding_room_file_retirements (
  workspace uuid not null,
  room uuid not null,
  file uuid not null,
  copy_id uuid not null unique references sectalk_private.st_v8_room_file_recovery_reviews,
  request_id uuid not null,
  owner_id uuid not null,
  source_sha256 text not null check(source_sha256~'^[a-f0-9]{64}$'),
  provider_absence_observed_at timestamptz not null,
  removed_at timestamptz not null default clock_timestamp(),
  primary key(workspace,room,file)
);
create index st_v8_room_file_cleanup_tickets_expiry on sectalk_private.st_v8_room_file_cleanup_tickets(expires_at);
create trigger st_v8_room_file_recovery_review_immutable before update or delete on sectalk_private.st_v8_room_file_recovery_reviews
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_room_file_retirement_immutable before update or delete on sectalk_private.st_v8_offboarding_room_file_retirements
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_room_file_cleanup_tickets enable row level security;
alter table sectalk_private.st_v8_room_file_recovery_reviews enable row level security;
alter table sectalk_private.st_v8_offboarding_room_file_retirements enable row level security;
revoke all on sectalk_private.st_v8_room_file_cleanup_tickets,sectalk_private.st_v8_room_file_recovery_reviews,
  sectalk_private.st_v8_offboarding_room_file_retirements from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_room_file_no_retired_id()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if exists(select 1 from sectalk_private.st_v8_offboarding_room_file_retirements x
    where (x.workspace,x.room,x.file)=(new.workspace,new.room,new.id)) then
    raise exception 'The retired room file identity cannot be reused' using errcode='PT409';
  end if;
  return new;
end $$;
create trigger st_v8_room_file_no_retired_id before insert on sectalk_private.st_v6_room_files
  for each row execute function sectalk_private.st_v8_room_file_no_retired_id();

-- This source intentionally uses an historical reviewed Storage plan. A missing
-- object has already invalidated the original live provider inventory.
create function sectalk_private.st_v8_room_file_cleanup_source(
  r sectalk_private.st_v8_offboarding_requests,p_copy uuid
) returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  select jsonb_build_object('room',f.room,'file',f.id,'bytes',f.size_bytes,'sha256',f.sha256,
    'sourceSha256',encode(sha256(convert_to(jsonb_build_array('sectalk-room-metadata-cleanup-v1',
      r.workspace,r.id,c.id,p.id,x.id,x.object_id,x.object_version,f.workspace,f.room,f.id,f.size_bytes,f.sha256,f.created_at,
      f.published_at,e.sha256)::text,'UTF8')),'hex'))
  from sectalk_private.st_v8_offboarding_room_storage_copy_receipts x
  join sectalk_private.st_v8_offboarding_storage_plans p
    on (p.id,p.request,p.requester,p.reviewer)=(x.plan,r.id,r.requester,r.reviewer)
  join sectalk_private.st_v8_content_exports c
    on (c.id,c.workspace,c.requester,c.reviewer)=(x.export_id,r.workspace,r.requester,r.reviewer)
  join sectalk_private.st_v8_content_export_entries e
    on (e.export_id,e.kind,e.scope_id,e.record_id)=(c.id,'room_file',x.room,x.file)
  join sectalk_private.st_v6_room_files f on (f.workspace,f.room,f.id)=(x.workspace,x.room,x.file)
  join public.st_v6_rooms room on (room.workspace_id,room.id)=(f.workspace,f.room)
  where x.id=p_copy and (x.workspace,x.actor)=(r.workspace,r.requester)
    and r.state='read_only' and r.integration_shutdown is not null
    and p.reviewed_at is not null and p.captured_at>statement_timestamp()-interval '24 hours'
    and c.include_room_files and c.approved_at is not null and c.withdrawn_at is null and c.expires_at>statement_timestamp()
    and room.kind='public' and room.encryption_mode='standard' and room.classification in ('public','internal') and not room.archived
    and f.published_at is not null and f.deleted_at is null and f.lease is null and f.upload_until is null
    and (f.size_bytes,f.sha256)=(x.bytes,x.sha256)
    and public.st_v6_room_file_command(f.room,r.requester,'get',f.id,null,null,null) is not null
    and public.st_v6_room_file_command(f.room,r.reviewer,'get',f.id,null,null,null) is not null
    and (f.uploader=r.requester or sectalk_private.open_pair(f.uploader,r.requester))
    and (f.uploader=r.reviewer or sectalk_private.open_pair(f.uploader,r.reviewer))
    and not sectalk_private.st_v8_offboarding_holds(r.workspace)
    and not exists(select 1 from sectalk_private.st_v7_compliance_cases q where q.workspace_id=r.workspace
      and q.id<>r.case_id and q.state in ('pending','approved') and q.expires_at>statement_timestamp())
    and not exists(select 1 from sectalk_private.st_v7_file_egress_policies q
      where q.workspace=r.workspace and q.policy->>'mode' is distinct from 'inherit')
    and not exists(select 1 from sectalk_private.st_v6_malware_hashes h where h.sha256=decode(f.sha256,'hex'))
    and not public.st_v7_upload_digest_blocked(f.sha256)
    and e.sha256=encode(sha256(convert_to(jsonb_build_object('room',f.room,'file',f.id,'filename',f.filename,
      'bytes',f.size_bytes,'publishedAt',f.published_at,'sha256',f.sha256,'roomKind',room.kind,
      'classification',room.classification)::text,'UTF8')),'hex')
    and exists(select 1 from jsonb_array_elements(p.snapshot->'items') i
      where (i->>'name',i->>'status',i->>'object_id',i->>'version',i->>'fingerprint')=
        (f.workspace::text||'/rooms/'||f.room::text||'/'||f.id::text,'published',x.object_id::text,x.object_version,x.sha256))
    and not exists(select 1 from sectalk_private.st_v8_offboarding_room_storage_copy_receipts newer
      where (newer.workspace,newer.room,newer.file)=(x.workspace,x.room,x.file) and newer.verified_at>x.verified_at
        and (newer.object_id,newer.object_version,newer.sha256) is distinct from (x.object_id,x.object_version,x.sha256))
    and not exists(select 1 from storage.objects o where (o.bucket_id,o.name)=
      ('sectalk-workspace-files',f.workspace::text||'/rooms/'||f.room::text||'/'||f.id::text));
$$;

create function public.st_v8_room_file_cleanup_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
begin
  if not coalesce(sectalk_private.st_v8_file_sso_allows(p_workspace),false) then raise insufficient_privilege; end if;
  return jsonb_build_object('held',sectalk_private.st_v8_offboarding_holds(p_workspace),
    'candidates',coalesce((select jsonb_agg(to_jsonb(q) order by q.room,q.file) from (
      select x.id as copy,x.room,x.file,candidate.source->>'sourceSha256' as "sourceSha256",
        a.reviewed_at as "reviewedAt"
      from sectalk_private.st_v8_offboarding_room_storage_copy_receipts x
      cross join lateral (select sectalk_private.st_v8_room_file_cleanup_source(r,x.id) as source offset 0) candidate
      left join sectalk_private.st_v8_room_file_recovery_reviews a on a.copy_id=x.id and a.reviewer=r.reviewer
        and a.source_sha256=candidate.source->>'sourceSha256'
      where x.workspace=p_workspace and sectalk_private.st_v8_standard_room_session_allowed(x.room)
        and candidate.source is not null order by x.verified_at desc,x.id limit 100
    ) q),'[]'),
    'retired',coalesce((select jsonb_agg(to_jsonb(q) order by q."removedAt" desc,q.file) from (
      select x.room,x.file,x.provider_absence_observed_at as "observedAt",x.removed_at as "removedAt"
      from sectalk_private.st_v8_offboarding_room_file_retirements x
      where (x.workspace,x.request_id)=(p_workspace,r.id) and sectalk_private.st_v8_standard_room_session_allowed(x.room)
        and sectalk_private.st_v6_room_role(x.room,auth.uid()) is not null
      order by x.removed_at desc,x.file limit 100
    ) q),'[]'));
end $$;

create function public.st_v8_begin_room_file_cleanup(p_workspace uuid,p_copy uuid,p_action text,p_confirmation text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  source jsonb; context jsonb; token uuid; room uuid; file uuid;
begin
  if p_confirmation is distinct from p_workspace::text or p_action is null or p_action not in ('review','remove')
    or auth.uid() is distinct from (case when p_action='review' then r.reviewer else r.requester end) then raise insufficient_privilege; end if;
  source:=sectalk_private.st_v8_room_file_cleanup_source(r,p_copy);
  if source is null then raise exception 'An exact approved room file with an absent Storage path is required' using errcode='PT409'; end if;
  room:=(source->>'room')::uuid;
  file:=(source->>'file')::uuid;
  context:=public.st_v8_scoped_file_context('room',room);
  if context->>'access' is distinct from 'allowed'
    or (public.st_v7_explain_file_egress('room',room,file,'download')->>'allowed') is distinct from 'true' then raise insufficient_privilege; end if;
  if p_action='remove' and not exists(select 1 from sectalk_private.st_v8_room_file_recovery_reviews x
    where (x.copy_id,x.request_id,x.reviewer,x.source_sha256)=(p_copy,r.id,r.reviewer,source->>'sourceSha256'))
    then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_room_file_metadata_cleanup',12);
  delete from sectalk_private.st_v8_room_file_cleanup_tickets t where t.expires_at<=clock_timestamp();
  insert into sectalk_private.st_v8_room_file_cleanup_tickets(request_id,copy_id,workspace,room,file,actor,native_session,action,source_sha256)
    values(r.id,p_copy,p_workspace,room,file,auth.uid(),(context->>'session')::uuid,p_action,source->>'sourceSha256')
    returning id into token;
  return jsonb_build_object('ticket',token,'room',room,'file',file,'bytes',source->'bytes');
end $$;

-- A trusted server calls this only after successful verified-byte review or a
-- provider read returning the explicit NoSuchKey absence response, respectively.
create function public.st_v8_finish_room_file_cleanup(
  p_ticket uuid,p_sha256 text default null,p_bytes integer default null,p_observed_at timestamptz default null
) returns boolean language plpgsql security definer set search_path='' as $$
declare t sectalk_private.st_v8_room_file_cleanup_tickets; r sectalk_private.st_v8_offboarding_requests;
  source jsonb; current_file jsonb;
begin
  delete from sectalk_private.st_v8_room_file_cleanup_tickets x where x.id=p_ticket and x.expires_at>clock_timestamp() returning * into t;
  if t.id is null then return false; end if;
  perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-workspace-hold:'||t.workspace::text,0));
  perform pg_advisory_xact_lock(hashtextextended('room_file:'||t.room::text,0));
  perform 1 from public.st_v2_workspaces x where x.id=t.workspace for share;
  select x.* into r from sectalk_private.st_v8_offboarding_requests x where (x.id,x.workspace)=(t.request_id,t.workspace) for share;
  if r.id is null or t.actor is distinct from (case when t.action='review' then r.reviewer else r.requester end)
    or sectalk_private.st_v8_offboarding_role(r.workspace,r.requester) is distinct from 'owner'
    or sectalk_private.st_v8_offboarding_role(r.workspace,r.reviewer) is distinct from 'reviewer' then return false; end if;
  perform 1 from sectalk_private.st_v8_offboarding_reviewers x where (x.workspace,x.actor)=(t.workspace,r.reviewer) for share;
  if not found then return false; end if;
  perform 1 from public.st_v2_members x where x.workspace_id=t.workspace and x.user_id in (r.requester,r.reviewer)
    order by x.user_id for share;
  perform 1 from public.st_v6_rooms x where (x.workspace_id,x.id)=(t.workspace,t.room) for share;
  if not found then return false; end if;
  perform 1 from sectalk_private.st_v6_room_files x where (x.workspace,x.room,x.id)=(t.workspace,t.room,t.file) for update;
  if not found then return false; end if;
  perform 1 from sectalk_private.st_v8_content_exports x join sectalk_private.st_v8_offboarding_room_storage_copy_receipts c on c.export_id=x.id
    where c.id=t.copy_id and x.withdrawn_at is null and x.expires_at>clock_timestamp() for share of x;
  if not found then return false; end if;
  perform 1 from auth.sessions n join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
    join auth.mfa_amr_claims a on a.session_id=n.id and a.authentication_method='totp'
    where (n.id,n.user_id)=(t.native_session,t.actor) and n.aal='aal2' and f.status='verified' and f.factor_type='totp'
      and a.updated_at>clock_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp()
    for share of n,f,a;
  if not found or exists(select 1 from sectalk_private.st_v7_account_lockdowns l where l.user_id=t.actor and l.released_at is null)
    or exists(select 1 from sectalk_private.st_v8_workspace_standard_room_sso policy where policy.workspace=t.workspace
      and not exists(select 1 from sectalk_private.st_v7_workspace_sso_sessions session join sectalk_private.st_v7_workspace_sso setup
        on setup.workspace=session.workspace
        where (session.workspace,session.principal,session.session)=(t.workspace,t.actor,t.native_session)
          and (session.protocol,session.provider)=(policy.protocol,policy.provider)
          and (setup.protocol,setup.provider)=(policy.protocol,policy.provider)
          and sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol)=setup.provider)) then return false; end if;
  source:=sectalk_private.st_v8_room_file_cleanup_source(r,t.copy_id);
  current_file:=public.st_v8_scoped_file_command('room',t.room,t.actor,t.native_session,'get',t.file,null,null,null);
  if source->>'sourceSha256' is distinct from t.source_sha256 or current_file is null
    or t.expires_at<=clock_timestamp() then return false; end if;
  if t.action='review' then
    if (p_sha256,p_bytes::text) is distinct from (source->>'sha256',source->>'bytes') or p_observed_at is not null then return false; end if;
    insert into sectalk_private.st_v8_room_file_recovery_reviews(copy_id,request_id,reviewer,source_sha256)
      values(t.copy_id,r.id,t.actor,t.source_sha256) on conflict do nothing;
    return exists(select 1 from sectalk_private.st_v8_room_file_recovery_reviews x
      where (x.copy_id,x.request_id,x.reviewer,x.source_sha256)=(t.copy_id,r.id,r.reviewer,t.source_sha256));
  end if;
  if p_sha256 is not null or p_bytes is not null or p_observed_at is null or p_observed_at>clock_timestamp()+interval '3 seconds'
    or p_observed_at<clock_timestamp()-interval '10 seconds' or p_observed_at<t.expires_at-interval '45 seconds'
    or not exists(select 1 from sectalk_private.st_v8_room_file_recovery_reviews x
      where (x.copy_id,x.request_id,x.reviewer,x.source_sha256)=(t.copy_id,r.id,r.reviewer,t.source_sha256)) then return false; end if;
  insert into sectalk_private.st_v8_offboarding_room_file_retirements(workspace,room,file,copy_id,request_id,owner_id,
    source_sha256,provider_absence_observed_at)
    values(t.workspace,t.room,t.file,t.copy_id,r.id,t.actor,t.source_sha256,p_observed_at);
  delete from sectalk_private.st_v6_room_files x where (x.workspace,x.room,x.id)=(t.workspace,t.room,t.file);
  if not found then raise exception 'The exact room registration was not removed' using errcode='PT409'; end if;
  return true;
end $$;

revoke all on function sectalk_private.st_v8_room_file_no_retired_id(),
  sectalk_private.st_v8_room_file_cleanup_source(sectalk_private.st_v8_offboarding_requests,uuid),
  public.st_v8_room_file_cleanup_status(uuid),public.st_v8_begin_room_file_cleanup(uuid,uuid,text,text),
  public.st_v8_finish_room_file_cleanup(uuid,text,integer,timestamptz) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_room_file_cleanup_status(uuid),
  public.st_v8_begin_room_file_cleanup(uuid,uuid,text,text) to authenticated;
grant execute on function public.st_v8_finish_room_file_cleanup(uuid,text,integer,timestamptz) to service_role;
notify pgrst,'reload schema';
commit;
