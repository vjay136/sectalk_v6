begin;

create table sectalk_private.st_v8_offboarding_archive_findings_observed (
  reconciliation uuid primary key references sectalk_private.st_v8_offboarding_reconciliations,
  actor uuid not null,
  findings jsonb not null check(jsonb_typeof(findings)='object'),
  observed_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v8_offboarding_archive_findings_observed enable row level security;
revoke all on sectalk_private.st_v8_offboarding_archive_findings_observed from public,anon,authenticated,service_role;
create trigger st_v8_archive_findings_immutable before update or delete on sectalk_private.st_v8_offboarding_archive_findings_observed
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

-- Validate the original journal entries without disclosing the retained source rows.
create function sectalk_private.st_v8_offboarding_has_archive_journal(p_source text,p_row jsonb)
returns boolean language sql stable set search_path='' as $$
  select case when p_row->>'id' ~ '^[0-9]{1,18}$' then
    (select count(distinct j.operation)=2
      from sectalk_private.st_v6_audit_chain j
      where (j.source,j.source_id,j.row_hash)=(p_source,(p_row->>'id')::bigint,sectalk_private.st_v6_audit_row_hash(p_row))
        and j.operation in ('INSERT','DELETE'))
    and not exists(select 1 from sectalk_private.st_v6_audit_chain j
      where (j.source,j.source_id)=(p_source,(p_row->>'id')::bigint)
        and (j.operation not in ('INSERT','DELETE') or j.row_hash<>sectalk_private.st_v6_audit_row_hash(p_row)))
    else false end
$$;

create function sectalk_private.st_v8_offboarding_reconcile_archives(r sectalk_private.st_v8_offboarding_requests)
returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  with base as materialized (
    select sectalk_private.st_v8_offboarding_reconcile_receipts(r.workspace,r.id) as snapshot
  ), channels as materialized (
    select jsonb_build_array(to_jsonb(p),to_jsonb(a),to_jsonb(d),to_jsonb(h),retired.manifest) as receipt,
      jsonb_array_length(p.message_manifest) as messages,
      coalesce(a.actor=r.reviewer and d.actor=r.requester and (p.owner_id,p.reviewer_id)=(r.requester,r.reviewer)
        and a.happened_at<=d.happened_at
        and h.sha256=p.archive_sha256 and h.audit_row->>'channel_id'=p.channel::text
        and h.audit_row->>'actor'=p.owner_id::text and h.audit_row->>'action'='archive'
        and not exists(select 1 from sectalk_private.st_v6_channel_audit x where x.id=h.audit_id)
        and sectalk_private.st_v8_offboarding_has_archive_journal('sectalk_private.st_v6_channel_audit',h.audit_row)
        and exists(select 1 from sectalk_private.st_v8_offboarding_archived_channel_copies c
          where (c.request_id,c.channel,c.owner_id,c.sha256)=(r.id,p.channel,r.requester,p.copy_sha256)
            and c.issued_at<=a.happened_at)
        and not exists(select 1 from public.st_v2_channels x where x.id=p.channel)
        and retired.manifest=p.message_manifest and retired.scope_matches
        and not exists(select 1 from sectalk_private.st_v8_offboarding_retired_channel_posts j
          where j.plan=p.id and (exists(select 1 from public.st_v2_posts x where x.id=j.post)
            or exists(select 1 from sectalk_private.st_v7_search_document x where (x.kind,x.object_id)=('channel',j.post)))),
        false) as verified
    from sectalk_private.st_v8_offboarding_archived_channel_plans p
    join sectalk_private.st_v8_offboarding_archived_channel_decisions d on (d.plan,d.action)=(p.id,'removed')
    left join sectalk_private.st_v8_offboarding_archived_channel_decisions a on (a.plan,a.action)=(p.id,'approved')
    left join sectalk_private.st_v8_offboarding_retained_channel_archive h on h.plan=p.id
    cross join lateral (
      select coalesce(jsonb_agg(jsonb_build_object('id',j.post,'sha256',j.sha256) order by j.post),'[]') as manifest,
        coalesce(bool_and(j.channel=p.channel),true) as scope_matches
      from sectalk_private.st_v8_offboarding_retired_channel_posts j where j.plan=p.id
    ) retired
    where (p.workspace,p.request_id)=(r.workspace,r.id) order by p.id limit 501
  ), rooms as materialized (
    select jsonb_build_array(to_jsonb(p),to_jsonb(a),to_jsonb(d),to_jsonb(h)) as receipt,
      coalesce(a.actor=r.reviewer and d.actor=r.requester and (p.owner_id,p.reviewer_id)=(r.requester,r.reviewer)
        and a.happened_at<=d.happened_at
        and h.room=p.room and h.sha256=p.archive_sha256
        and (h.proof#>>'{creatorMembership,room_id}',h.proof#>>'{creatorMembership,user_id}',h.proof#>>'{creatorMembership,role}')
          =(p.room::text,p.owner_id::text,'owner')
        and h.proof#>>'{auditEvents,0,action}'='room.created' and h.proof#>>'{auditEvents,1,action}'='room.archive'
        and jsonb_typeof(h.proof->'auditEvents')='array'
        and case when jsonb_typeof(h.proof->'auditEvents')='array' then jsonb_array_length(h.proof->'auditEvents')=2 else false end
        and not exists(select 1 from jsonb_array_elements(case when jsonb_typeof(h.proof->'auditEvents')='array'
          then h.proof->'auditEvents' else '[]'::jsonb end) x where
          (x->>'room_id',x->>'actor') is distinct from (p.room::text,p.owner_id::text)
          or not sectalk_private.st_v8_offboarding_has_archive_journal('public.st_v6_room_audit',x))
        and exists(select 1 from sectalk_private.st_v8_offboarding_archived_room_copies c
          where (c.request_id,c.room,c.owner_id,c.sha256)=(r.id,p.room,r.requester,p.copy_sha256)
            and c.issued_at<=a.happened_at)
        and not exists(select 1 from public.st_v6_rooms x where x.id=p.room)
        and not exists(select 1 from public.st_v6_room_audit x where x.room_id=p.room)
        and not exists(select 1 from public.st_v6_room_members x where x.room_id=p.room),
        false) as verified
    from sectalk_private.st_v8_offboarding_archived_room_plans p
    join sectalk_private.st_v8_offboarding_archived_room_decisions d on (d.plan,d.action)=(p.id,'removed')
    left join sectalk_private.st_v8_offboarding_archived_room_decisions a on (a.plan,a.action)=(p.id,'approved')
    left join sectalk_private.st_v8_offboarding_retained_room_proof h on h.plan=p.id
    where (p.workspace,p.request_id)=(r.workspace,r.id) order by p.id limit 501
  ), totals as (
    select
      (select count(*) from channels where verified) as verified_channels,
      (select coalesce(sum(messages),0) from channels where verified) as verified_messages,
      (select count(*) from rooms where verified) as verified_rooms,
      (select count(*) from channels where not verified) as channel_findings,
      (select count(*) from rooms where not verified) as room_findings,
      (select count(*)>500 from channels) as channels_overflow,
      (select count(*)>500 from rooms) as rooms_overflow,
      (select encode(sha256(convert_to(coalesce(string_agg(row_hash,'' order by row_hash),''),'UTF8')),'hex') from (
        select encode(sha256(convert_to(jsonb_build_array('channel',c.receipt,c.verified)::text,'UTF8')),'hex') as row_hash from channels c
        union all
        select encode(sha256(convert_to(jsonb_build_array('room',t.receipt,t.verified)::text,'UTF8')),'hex') from rooms t
      ) q) as receipt_digest
  )
  select jsonb_build_object('summary',(base.snapshot->'summary')||jsonb_build_object(
    'verifiedDeletionReceipts',(base.snapshot#>'{summary,verifiedDeletionReceipts}')||jsonb_build_object(
      'archivedChannelReceipts',t.verified_channels,'archivedChannelMessageReceipts',t.verified_messages,
      'archivedRoomReceipts',t.verified_rooms),
    'archiveFindings',jsonb_build_object('archivedChannelReceiptFindings',t.channel_findings,'archivedRoomReceiptFindings',t.room_findings),
    'overflow',(base.snapshot#>'{summary,overflow}')
      ||case when t.channels_overflow then '["archivedChannelReceipts"]'::jsonb else '[]'::jsonb end
      ||case when t.rooms_overflow then '["archivedRoomReceipts"]'::jsonb else '[]'::jsonb end),
    'revision',encode(sha256(convert_to(jsonb_build_array('sectalk-reconciled-archives-v1',base.snapshot->>'revision',
      t.receipt_digest)::text,'UTF8')),'hex'))
  from base cross join totals t;
$$;

revoke all on function sectalk_private.st_v8_offboarding_has_archive_journal(text,jsonb),
  sectalk_private.st_v8_offboarding_reconcile_archives(sectalk_private.st_v8_offboarding_requests)
  from public,anon,authenticated,service_role;

create or replace function public.st_v8_offboarding_reconciliation(
  p_workspace uuid,p_action text default 'status',p_confirmation text default null,p_plan uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_reconciliations; v jsonb; summary jsonb; digest text; reviewed_at timestamptz;
  held boolean; bounded boolean; consistent boolean; archive_invalidated boolean;
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
  v:=sectalk_private.st_v8_offboarding_reconcile_archives(r);
  summary:=v->'summary';
  bounded:=jsonb_array_length(summary->'overflow')=0;
  consistent:=not exists(select 1 from jsonb_each_text(summary->'archiveFindings') a where a.value::integer>0);
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
  if p_action='status' and plan.id is not null and not consistent then
    insert into sectalk_private.st_v8_offboarding_archive_findings_observed(reconciliation,actor,findings)
      values(plan.id,actor,summary->'archiveFindings') on conflict do nothing;
  end if;
  archive_invalidated:=exists(select 1 from sectalk_private.st_v8_offboarding_archive_findings_observed x
    where x.reconciliation=plan.id);

  if p_action='capture' then
    if p_plan is not null or p_sha256 is not null then raise exception 'Capture a new source reconciliation' using errcode='22023'; end if;
    if not bounded then raise exception 'A covered source family exceeds the reconciliation limit' using errcode='PT409'; end if;
    if not consistent then raise exception 'Resolve archive receipt findings before capturing a source review' using errcode='PT409'; end if;
    if plan.id is null or plan.sha256<>digest or plan.expires_at<=clock_timestamp() or archive_invalidated then
      insert into sectalk_private.st_v8_offboarding_reconciliations(request_id,workspace,owner_id,reviewer_id,expires_at,summary,sha256)
        values(r.id,p_workspace,r.requester,r.reviewer,clock_timestamp()+interval '30 minutes',summary,digest) returning * into plan;
      archive_invalidated:=false;
    end if;
  elsif p_action='confirm' then
    if plan.id is null or p_plan is distinct from plan.id or p_sha256 is distinct from plan.sha256
      or digest<>plan.sha256 or not bounded or not consistent or archive_invalidated or plan.expires_at<=clock_timestamp() then
      raise exception 'Confirm the latest exact, current source reconciliation' using errcode='PT409'; end if;
    if not coalesce(sectalk_private.st_v7_billing_admin_session(),false) or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
      then raise insufficient_privilege; end if;
    insert into sectalk_private.st_v8_offboarding_reconciliation_receipts(reconciliation,reviewer)
      values(plan.id,actor) on conflict do nothing;
  end if;
  select x.reviewed_at into reviewed_at from sectalk_private.st_v8_offboarding_reconciliation_receipts x
    where (x.reconciliation,x.reviewer)=(plan.id,r.reviewer);
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'observedAt',plan.observed_at,'reviewedAt',reviewed_at,
    'expiresAt',plan.expires_at,'held',held,'summary',summary,'archiveReviewInvalidated',archive_invalidated,
    'current',coalesce(not held and bounded and consistent and not archive_invalidated and plan.sha256=digest
      and plan.expires_at>clock_timestamp(),false),
    'providerBytes','unverified','backupErasure','unverified','fullTenantErasure','unverified');
end $$;

notify pgrst,'reload schema';
commit;
