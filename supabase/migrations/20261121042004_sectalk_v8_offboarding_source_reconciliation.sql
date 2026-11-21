begin;

create table sectalk_private.st_v8_offboarding_reconciliations (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null,
  workspace uuid not null,
  owner_id uuid not null,
  reviewer_id uuid not null check(reviewer_id<>owner_id),
  observed_at timestamptz not null default statement_timestamp(),
  expires_at timestamptz not null,
  summary jsonb not null check(jsonb_typeof(summary)='object'),
  sha256 text not null check(sha256~'^[0-9a-f]{64}$')
);
create index st_v8_offboarding_reconciliation_latest
  on sectalk_private.st_v8_offboarding_reconciliations(request_id,observed_at desc,id desc);
create table sectalk_private.st_v8_offboarding_reconciliation_receipts (
  reconciliation uuid primary key references sectalk_private.st_v8_offboarding_reconciliations,
  reviewer uuid not null,
  reviewed_at timestamptz not null default statement_timestamp()
);
create trigger st_v8_offboarding_reconciliation_immutable before update or delete on sectalk_private.st_v8_offboarding_reconciliations
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_offboarding_reconciliation_receipt_immutable before update or delete on sectalk_private.st_v8_offboarding_reconciliation_receipts
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_reconciliations enable row level security;
alter table sectalk_private.st_v8_offboarding_reconciliation_receipts enable row level security;
revoke all on sectalk_private.st_v8_offboarding_reconciliations,sectalk_private.st_v8_offboarding_reconciliation_receipts
  from public,anon,authenticated,service_role;

-- A closed, bounded registry. It deliberately returns no identities or raw records.
create function sectalk_private.st_v8_offboarding_reconcile_live(p_workspace uuid,p_request uuid)
returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  with families(name) as (values
    ('workspace'),('members'),('channels'),('rooms'),('workspaceItems'),('channelPosts'),('roomPosts'),('roomTasks'),
    ('managedChannelPayloads'),('managedRoomPayloads'),('roomReports'),('channelReports'),('managedRoomEvidence'),
    ('preservedVersions'),('holds'),('meetings'),('meetingRecordings'),('tenantKeyVersions'),('tenantKeyState'),('artifactEnvelopes'),
    ('workspaceTaskReceipts'),('channelPostReceipts'),('roomPostReceipts'),('roomTaskReceipts'),('batchReceipts')
  ), live(name,row_data) as (
    (select 'workspace',to_jsonb(t) from public.st_v2_workspaces t where t.id=p_workspace)
    union all (select 'members',to_jsonb(t) from public.st_v2_members t where t.workspace_id=p_workspace order by t.user_id limit 501)
    union all (select 'channels',to_jsonb(t) from public.st_v2_channels t where t.workspace_id=p_workspace order by t.id limit 501)
    union all (select 'rooms',to_jsonb(t) from public.st_v6_rooms t where t.workspace_id=p_workspace order by t.id limit 501)
    union all (select 'workspaceItems',to_jsonb(t) from public.st_v2_items t where t.workspace_id=p_workspace order by t.id limit 501)
    union all (select 'channelPosts',to_jsonb(t) from public.st_v2_posts t join public.st_v2_channels c on c.id=t.channel_id
      where c.workspace_id=p_workspace order by t.id limit 501)
    union all (select 'roomPosts',to_jsonb(t) from public.st_v6_room_posts t join public.st_v6_rooms r on r.id=t.room_id
      where r.workspace_id=p_workspace order by t.room_id,t.id limit 501)
    union all (select 'roomTasks',to_jsonb(t) from public.st_v6_tasks t join public.st_v6_rooms r on r.id=t.room_id
      where r.workspace_id=p_workspace order by t.id limit 501)
    union all (select 'managedChannelPayloads',to_jsonb(t) from sectalk_private.st_v8_channel_payloads t
      where t.workspace=p_workspace order by t.post limit 501)
    union all (select 'managedRoomPayloads',to_jsonb(t) from sectalk_private.st_v8_managed_room_posts t
      where t.workspace=p_workspace order by t.room,t.id limit 501)
    union all (select 'roomReports',to_jsonb(t) from sectalk_private.st_v6_room_reports t
      where t.workspace_id=p_workspace order by t.id limit 501)
    union all (select 'channelReports',to_jsonb(t) from sectalk_private.st_v7_channel_reports t
      where t.workspace_id=p_workspace order by t.id limit 501)
    union all (select 'managedRoomEvidence',to_jsonb(t) from sectalk_private.st_v8_managed_room_evidence t
      where t.workspace=p_workspace order by t.report limit 501)
    union all (select 'preservedVersions',to_jsonb(t) from sectalk_private.st_v6_preserved_post_versions t
      join sectalk_private.st_v6_workspace_holds h on h.id=t.hold_id where h.workspace_id=p_workspace order by t.id limit 501)
    union all (select 'holds',to_jsonb(t) from sectalk_private.st_v6_workspace_holds t where t.workspace_id=p_workspace order by t.id limit 501)
    union all (select 'meetings',to_jsonb(t) from public.st_v3_meetings t where t.workspace_id=p_workspace order by t.id limit 501)
    union all (select 'meetingRecordings',to_jsonb(t) from sectalk_private.st_v6_recording t
      join public.st_v3_meetings m on m.id=t.meeting_id where m.workspace_id=p_workspace order by t.id limit 501)
    union all (select 'tenantKeyVersions',to_jsonb(t) from sectalk_private.st_v7_tenant_key_versions t
      where t.workspace=p_workspace order by t.version limit 501)
    union all (select 'tenantKeyState',to_jsonb(t) from sectalk_private.st_v7_tenant_key_state t where t.workspace=p_workspace)
    union all (select 'artifactEnvelopes',to_jsonb(t) from sectalk_private.st_v7_artifact_envelopes t
      where t.workspace=p_workspace order by t.artifact limit 501)
    union all (select 'workspaceTaskReceipts',jsonb_build_array(t.id,t.sha256,d.happened_at) from sectalk_private.st_v8_offboarding_task_deletions t
      join sectalk_private.st_v8_offboarding_task_decisions d on (d.deletion,d.action)=(t.id,'deleted')
      where t.request=p_request and t.workspace=p_workspace order by t.id limit 501)
    union all (select 'channelPostReceipts',jsonb_build_array(t.id,t.sha256,d.happened_at) from sectalk_private.st_v8_offboarding_post_deletions t
      join sectalk_private.st_v8_offboarding_post_decisions d on (d.deletion,d.action)=(t.id,'deleted')
      where t.request=p_request and t.workspace=p_workspace order by t.id limit 501)
    union all (select 'roomPostReceipts',jsonb_build_array(t.id,t.sha256,d.happened_at) from sectalk_private.st_v8_offboarding_room_post_deletions t
      join sectalk_private.st_v8_offboarding_room_post_decisions d on (d.deletion,d.action)=(t.id,'deleted')
      where t.request=p_request and t.workspace=p_workspace order by t.id limit 501)
    union all (select 'roomTaskReceipts',jsonb_build_array(t.id,t.sha256,d.happened_at) from sectalk_private.st_v8_offboarding_room_task_deletions t
      join sectalk_private.st_v8_offboarding_room_task_decisions d on (d.deletion,d.action)=(t.id,'deleted')
      where t.request=p_request and t.workspace=p_workspace order by t.id limit 501)
    union all (select 'batchReceipts',jsonb_build_array(t.id,t.sha256,d.happened_at) from sectalk_private.st_v8_offboarding_source_batches t
      join sectalk_private.st_v8_offboarding_source_batch_decisions d on (d.batch,d.action)=(t.id,'deleted')
      where t.request_id=p_request and t.workspace=p_workspace order by t.id limit 501)
  ), row_digests as (
    select name,encode(sha256(convert_to(row_data::text,'UTF8')),'hex') as digest from live
  ), counts as (
    select f.name,count(d.digest) as n,encode(sha256(convert_to(coalesce(string_agg(d.digest,'' order by d.digest),''),'UTF8')),'hex') as digest
    from families f left join row_digests d using(name) group by f.name
  ), storage_state as materialized (
    select sectalk_private.st_v8_offboarding_storage_snapshot(p_workspace) as snapshot
  )
  select jsonb_build_object('summary',jsonb_build_object(
      'nativeRows',(select jsonb_object_agg(name,n) from counts where name not like '%Receipts'),
      'verifiedDeletionReceipts',(select jsonb_object_agg(name,n) from counts where name like '%Receipts'),
      'storageMetadata',s.snapshot->'counts',
      'overflow',(select coalesce(jsonb_agg(name order by name),'[]') from counts where n>500)
        ||case when (s.snapshot->>'limitExceeded')::boolean then '["storageMetadata"]'::jsonb else '[]' end),
    'revision',encode(sha256(convert_to(jsonb_build_array(
      (select jsonb_object_agg(name,digest) from counts),s.snapshot)::text,'UTF8')),'hex'))
  from storage_state s;
$$;

create function public.st_v8_offboarding_reconciliation(
  p_workspace uuid,p_action text default 'status',p_confirmation text default null,p_plan uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_reconciliations; v jsonb; summary jsonb; digest text; reviewed_at timestamptz;
  held boolean; bounded boolean;
begin
  if p_workspace is null or p_action is null or p_action not in ('status','capture','confirm') then raise insufficient_privilege; end if;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if p_action<>'status' then
    if p_confirmation is distinct from p_workspace::text
      or actor is distinct from (case when p_action='confirm' then r.reviewer else r.requester end) then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
    perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
    select x.* into r from sectalk_private.st_v8_offboarding_requests x
      where x.workspace=p_workspace and x.state='read_only' and x.integration_shutdown is not null for share;
    perform 1 from sectalk_private.st_v8_offboarding_reviewers x where (x.workspace,x.actor)=(p_workspace,r.reviewer) for share;
    perform 1 from public.st_v2_members m where m.workspace_id=p_workspace and m.user_id in (r.requester,r.reviewer)
      order by m.user_id for share;
    r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
    if actor is distinct from (case when p_action='confirm' then r.reviewer else r.requester end)
      or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
  end if;
  perform sectalk_private.limit_action('v8_offboarding_reconciliation',12);
  v:=sectalk_private.st_v8_offboarding_reconcile_live(p_workspace,r.id);
  summary:=v->'summary';
  bounded:=jsonb_array_length(summary->'overflow')=0;
  held:=sectalk_private.st_v8_offboarding_holds(p_workspace);
  if p_action<>'status' then
    perform 1 from auth.sessions n
      join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
      join auth.mfa_amr_claims proof on proof.session_id=n.id and proof.authentication_method='totp'
      where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',actor) and n.aal='aal2'
        and f.status='verified' and f.factor_type='totp' and proof.updated_at>clock_timestamp()-interval '5 minutes'
        and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp()
      for share of n,f,proof;
    if not found then raise insufficient_privilege; end if;
  end if;
  digest:=encode(sha256(convert_to(jsonb_build_array('sectalk-native-source-reconciliation-v1',p_workspace,
    r.id,r.requester,r.reviewer,r.snapshot_sha256,summary,v->>'revision')::text,'UTF8')),'hex');
  select x.* into plan from sectalk_private.st_v8_offboarding_reconciliations x
    where (x.request_id,x.workspace,x.owner_id,x.reviewer_id)=(r.id,p_workspace,r.requester,r.reviewer)
    order by x.observed_at desc,x.id desc limit 1;

  if p_action='capture' then
    if p_plan is not null or p_sha256 is not null then raise exception 'Capture a new source reconciliation' using errcode='22023'; end if;
    if not bounded then raise exception 'A covered source family exceeds the reconciliation limit' using errcode='PT409'; end if;
    if plan.id is null or plan.sha256<>digest or plan.expires_at<=clock_timestamp() then
      insert into sectalk_private.st_v8_offboarding_reconciliations(request_id,workspace,owner_id,reviewer_id,expires_at,summary,sha256)
        values(r.id,p_workspace,r.requester,r.reviewer,clock_timestamp()+interval '30 minutes',summary,digest) returning * into plan;
    end if;
  elsif p_action='confirm' then
    if plan.id is null or p_plan is distinct from plan.id or p_sha256 is distinct from plan.sha256
      or digest<>plan.sha256 or not bounded or plan.expires_at<=clock_timestamp() then
      raise exception 'Confirm the latest exact, current source reconciliation' using errcode='PT409'; end if;
    if not coalesce(sectalk_private.st_v7_billing_admin_session(),false) or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
      then raise insufficient_privilege; end if;
    insert into sectalk_private.st_v8_offboarding_reconciliation_receipts(reconciliation,reviewer)
      values(plan.id,actor) on conflict do nothing;
  end if;
  select x.reviewed_at into reviewed_at from sectalk_private.st_v8_offboarding_reconciliation_receipts x
    where (x.reconciliation,x.reviewer)=(plan.id,r.reviewer);
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'observedAt',plan.observed_at,'reviewedAt',reviewed_at,
    'expiresAt',plan.expires_at,'held',held,'summary',summary,'current',coalesce(not held and bounded and plan.sha256=digest
      and plan.expires_at>clock_timestamp(),false),
    'providerBytes','unverified','backupErasure','unverified','fullTenantErasure','unverified');
end $$;

revoke all on function sectalk_private.st_v8_offboarding_reconcile_live(uuid,uuid),
  public.st_v8_offboarding_reconciliation(uuid,text,text,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_reconciliation(uuid,text,text,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
