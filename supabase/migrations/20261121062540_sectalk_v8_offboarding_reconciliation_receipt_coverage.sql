begin;

-- Extend the census without changing existing receipt custody or provider state.
create function sectalk_private.st_v8_offboarding_reconcile_receipts(p_workspace uuid,p_request uuid)
returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  with base as materialized (
    select sectalk_private.st_v8_offboarding_reconcile_live(p_workspace,p_request) as snapshot
  ), families(name,kind) as (values
    ('roomThreadReceipts','deletion'),('workspaceRegistrationReceipts','deletion'),('roomRegistrationReceipts','deletion'),
    ('workspaceFileCopyReceipts','recovery'),('roomFileCopyReceipts','recovery'),
    ('workspaceFileRecoveryReviews','recovery'),('roomFileRecoveryReviews','recovery'),
    ('workspaceRetiredPathsPresent','metadata'),('roomRetiredPathsPresent','metadata')
  ), proof(name,row_data) as (
    (select 'roomThreadReceipts',jsonb_build_array(to_jsonb(plan),to_jsonb(approved),to_jsonb(removed))
      from sectalk_private.st_v8_offboarding_room_thread_deletions plan
      join sectalk_private.st_v8_offboarding_room_thread_decisions approved
        on (approved.deletion,approved.action,approved.actor)=(plan.id,'approved',plan.reviewer)
      join sectalk_private.st_v8_offboarding_room_thread_decisions removed
        on (removed.deletion,removed.action,removed.actor)=(plan.id,'deleted',plan.owner_id)
      where (plan.request,plan.workspace)=(p_request,p_workspace) order by plan.id limit 501)
    union all (select 'workspaceRegistrationReceipts',jsonb_build_array(to_jsonb(r),to_jsonb(a),to_jsonb(c))
      from sectalk_private.st_v8_offboarding_workspace_file_retirements r
      join sectalk_private.st_v8_workspace_file_recovery_reviews a
        on (a.copy_id,a.request_id,a.source_sha256)=(r.copy_id,r.request_id,r.source_sha256)
      join sectalk_private.st_v8_offboarding_storage_copy_receipts c on (c.id,c.workspace,c.file)=(r.copy_id,r.workspace,r.file)
      join sectalk_private.st_v8_offboarding_storage_plans p on (p.id,p.request,p.requester,p.reviewer)=
        (c.plan,r.request_id,r.owner_id,a.reviewer) and c.actor=r.owner_id and p.reviewed_at is not null
      where (r.request_id,r.workspace)=(p_request,p_workspace) order by r.file limit 501)
    union all (select 'roomRegistrationReceipts',jsonb_build_array(to_jsonb(r),to_jsonb(a),to_jsonb(c))
      from sectalk_private.st_v8_offboarding_room_file_retirements r
      join sectalk_private.st_v8_room_file_recovery_reviews a
        on (a.copy_id,a.request_id,a.source_sha256)=(r.copy_id,r.request_id,r.source_sha256)
      join sectalk_private.st_v8_offboarding_room_storage_copy_receipts c
        on (c.id,c.workspace,c.room,c.file)=(r.copy_id,r.workspace,r.room,r.file)
      join sectalk_private.st_v8_offboarding_storage_plans p on (p.id,p.request,p.requester,p.reviewer)=
        (c.plan,r.request_id,r.owner_id,a.reviewer) and c.actor=r.owner_id and p.reviewed_at is not null
      where (r.request_id,r.workspace)=(p_request,p_workspace) order by r.room,r.file limit 501)
    union all (select 'workspaceFileCopyReceipts',to_jsonb(c)
      from sectalk_private.st_v8_offboarding_storage_copy_receipts c
      join sectalk_private.st_v8_offboarding_storage_plans p on (p.id,p.request,p.requester)=(c.plan,p_request,c.actor)
      where c.workspace=p_workspace and p.reviewed_at is not null order by c.id limit 501)
    union all (select 'roomFileCopyReceipts',to_jsonb(c)
      from sectalk_private.st_v8_offboarding_room_storage_copy_receipts c
      join sectalk_private.st_v8_offboarding_storage_plans p on (p.id,p.request,p.requester)=(c.plan,p_request,c.actor)
      where c.workspace=p_workspace and p.reviewed_at is not null order by c.id limit 501)
    union all (select 'workspaceFileRecoveryReviews',jsonb_build_array(to_jsonb(a),to_jsonb(c))
      from sectalk_private.st_v8_workspace_file_recovery_reviews a
      join sectalk_private.st_v8_offboarding_storage_copy_receipts c on c.id=a.copy_id
      join sectalk_private.st_v8_offboarding_storage_plans p on (p.id,p.request,p.reviewer)=(c.plan,p_request,a.reviewer)
      where (c.workspace,a.request_id)=(p_workspace,p_request) order by a.copy_id limit 501)
    union all (select 'roomFileRecoveryReviews',jsonb_build_array(to_jsonb(a),to_jsonb(c))
      from sectalk_private.st_v8_room_file_recovery_reviews a
      join sectalk_private.st_v8_offboarding_room_storage_copy_receipts c on c.id=a.copy_id
      join sectalk_private.st_v8_offboarding_storage_plans p on (p.id,p.request,p.reviewer)=(c.plan,p_request,a.reviewer)
      where (c.workspace,a.request_id)=(p_workspace,p_request) order by a.copy_id limit 501)
    union all (select 'workspaceRetiredPathsPresent',jsonb_build_array(r.copy_id,o.id,o.version,o.updated_at,o.metadata->>'size')
      from sectalk_private.st_v8_offboarding_workspace_file_retirements r
      join storage.objects o on (o.bucket_id,o.name)=('sectalk-workspace-files',r.workspace::text||'/'||r.file::text)
      where (r.request_id,r.workspace)=(p_request,p_workspace) order by r.file limit 501)
    union all (select 'roomRetiredPathsPresent',jsonb_build_array(r.copy_id,o.id,o.version,o.updated_at,o.metadata->>'size')
      from sectalk_private.st_v8_offboarding_room_file_retirements r
      join storage.objects o on (o.bucket_id,o.name)=('sectalk-workspace-files',r.workspace::text||'/rooms/'||r.room::text||'/'||r.file::text)
      where (r.request_id,r.workspace)=(p_request,p_workspace) order by r.room,r.file limit 501)
  ), digests as (
    select name,encode(sha256(convert_to(row_data::text,'UTF8')),'hex') as digest from proof
  ), counts as (
    select f.name,f.kind,count(d.digest) as n,
      encode(sha256(convert_to(coalesce(string_agg(d.digest,'' order by d.digest),''),'UTF8')),'hex') as digest
    from families f left join digests d using(name) group by f.name,f.kind
  )
  select jsonb_build_object('summary',(base.snapshot->'summary')||jsonb_build_object(
    'verifiedDeletionReceipts',(base.snapshot#>'{summary,verifiedDeletionReceipts}')
      ||(select jsonb_object_agg(name,n) from counts where kind='deletion'),
    'recoveryEvidence',(select jsonb_object_agg(name,n) from counts where kind='recovery'),
    'storageMetadata',(base.snapshot#>'{summary,storageMetadata}')
      ||(select jsonb_object_agg(name,n) from counts where kind='metadata'),
    'overflow',(base.snapshot#>'{summary,overflow}')||(select coalesce(jsonb_agg(name order by name),'[]') from counts where n>500)),
    'revision',encode(sha256(convert_to(jsonb_build_array('sectalk-reconciled-receipts-v1',base.snapshot->>'revision',
      (select jsonb_object_agg(name,digest) from counts))::text,'UTF8')),'hex'))
  from base;
$$;

revoke all on function sectalk_private.st_v8_offboarding_reconcile_receipts(uuid,uuid) from public,anon,authenticated,service_role;

create or replace function public.st_v8_offboarding_reconciliation(
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
  v:=sectalk_private.st_v8_offboarding_reconcile_receipts(p_workspace,r.id);
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
    order by x.capture_order desc nulls last,x.observed_at desc,x.id desc limit 1;

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

notify pgrst,'reload schema';
commit;
