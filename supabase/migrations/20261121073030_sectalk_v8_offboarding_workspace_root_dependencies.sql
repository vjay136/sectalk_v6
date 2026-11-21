begin;

-- Measure the consequence of removing the root without removing any rows.
-- Each count is a foreign-key reference; a row with several references can count more than once.
create function sectalk_private.st_v8_offboarding_workspace_root_snapshot(p_workspace uuid)
returns jsonb language plpgsql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  dependency record; exposure text; affected bigint; row_digest text;
  impact jsonb:='{"cascade":0,"restrict":0,"setNull":0,"setDefault":0}';
  groups jsonb:='{"content":0,"access":0,"preservation":0,"billing":0,"integrations":0,"policies":0,"operations":0,"unclassified":0}';
  fingerprints jsonb:='[]'; scan_incomplete integer:=0; unknown integer:=0; bounded_count integer:=0;
begin
  for dependency in
    select n.nspname,c.relname,f.conname,a.attname,f.confdeltype,f.convalidated,f.condeferrable,f.condeferred,
      cardinality(f.conkey)=1 and cardinality(f.confkey)=1 and t.attname='id'
        and c.relkind in ('r','p') as supported,
      case (n.nspname||'.'||c.relname)
        when 'public.st_v2_channels' then 'content'
        when 'public.st_v6_rooms' then 'content'
        when 'public.st_v2_items' then 'content'
        when 'public.st_v3_meetings' then 'content'
        else
          case
            when n.nspname='public' and c.relname=any(array['st_v2_members','st_v2_invites','st_v6_workspace_groups'])
              then 'access'
            when n.nspname='public' and c.relname='st_v2_workspace_audit' then 'preservation'
            when n.nspname='public' and c.relname=any(array['st_v6_workspace_policy','st_v6_workspace_reaction_policy'])
              then 'policies'
            when n.nspname='public' and c.relname='st_v3_notifications' then 'operations'
            when n.nspname='sectalk_private' and c.relname=any(array[
              'st_v6_workspace_link_invites','st_v7_managed_accounts','st_v7_org_domains','st_v7_school_classes',
              'st_v7_sso_departures','st_v7_workspace_sso','st_v7_custom_role_heads','st_v8_workspace_audit_sso',
              'st_v8_workspace_billing_sso','st_v8_workspace_channel_structure_sso','st_v8_workspace_custom_role_admin_sso',
              'st_v8_workspace_directory_sso','st_v8_workspace_file_sso','st_v8_workspace_groups_sso',
              'st_v8_workspace_integration_admin_sso','st_v8_workspace_invitation_admin_sso','st_v8_workspace_legal_hold_sso',
              'st_v8_workspace_managed_content_sso','st_v8_workspace_member_media_sso','st_v8_workspace_organization_sso','st_v8_workspace_compliance_sso',
              'st_v8_workspace_planner_sso','st_v8_workspace_policy_admin_sso','st_v8_workspace_room_structure_sso',
              'st_v8_workspace_schedule_sso','st_v8_workspace_standard_channel_sso','st_v8_workspace_standard_room_sso'
            ]) then 'access'
            when n.nspname='sectalk_private' and c.relname=any(array[
              'st_v6_break_glass_requests','st_v6_workspace_holds','st_v6_workspace_policy_versions',
              'st_v6_workspace_retired_file_ids','st_v7_compliance_cases','st_v7_dlp_acknowledgements',
              'st_v7_dlp_delivery_receipts','st_v7_policy_snapshots','st_v7_profile_rule_history','st_v7_siem_batches',
              'st_v7_soc_response_grants','st_v7_tenant_destroy_reviewers','st_v7_workspace_email_versions',
              'st_v8_content_exports','st_v8_offboarding_requests','st_v8_offboarding_reviewers'
            ]) then 'preservation'
            when n.nspname='sectalk_private' and c.relname=any(array[
              'st_v7_usage_events','st_v7_workspace_trials','st_v8_enterprise_billing_operators',
              'st_v8_enterprise_orders','st_v8_workspace_seat_changes','st_v8_workspace_seats'
            ]) then 'billing'
            when n.nspname='sectalk_private' and c.relname=any(array[
              'st_v6_integration_keys','st_v6_webhooks','st_v8_scim_keys','st_v8_scim_users',
              'st_v8_residency_cell_authorizations','st_v8_residency_requests','st_v8_residency_routing_rehearsals',
              'st_v8_residency_source_pauses','st_v8_residency_verifiers','st_v8_residency_active_routes',
              'st_v8_residency_route_revocations','st_v8_residency_rollback_holds'
            ]) then 'integrations'
            when n.nspname='sectalk_private' and c.relname=any(array[
              'st_v6_recording_policy','st_v6_room_retention_policy','st_v6_summary_policy','st_v6_tenant_feature_pauses',
              'st_v6_thread_summary_policy','st_v6_workspace_file_history_policy','st_v6_workspace_link_policy',
              'st_v6_workspace_notification_policy','st_v6_workspace_presence_policy','st_v7_file_egress_policies',
              'st_v7_org_preferences','st_v7_profile_rule_evaluation','st_v7_profile_rule_workspace','st_v7_workspace_ai_policy',
              'st_v7_workspace_dlp','st_v7_workspace_email_active','st_v8_channel_encryption_policy',
              'st_v8_room_encryption_policy','st_v8_tenant_rotation_schedules','workspace_read_receipt_policy'
            ]) then 'policies'
            when n.nspname='sectalk_private' and c.relname=any(array[
              'st_v6_call_qos','st_v6_emergency_notices','st_v6_tenant_metadata_cache'
            ]) then 'operations'
            else 'unclassified'
          end
      end as category
    from pg_constraint f
    join pg_class c on c.oid=f.conrelid
    join pg_namespace n on n.oid=c.relnamespace
    join pg_attribute a on a.attrelid=c.oid and a.attnum=f.conkey[1]
    join pg_attribute t on t.attrelid=f.confrelid and t.attnum=f.confkey[1]
    where f.contype='f' and f.confrelid='public.st_v2_workspaces'::regclass and f.conparentid=0
    order by n.nspname,c.relname,f.conname
  loop
    exposure:=case dependency.confdeltype
      when 'c' then 'cascade' when 'a' then 'restrict' when 'r' then 'restrict'
      when 'n' then 'setNull' when 'd' then 'setDefault' end;
    if dependency.category='unclassified' then unknown:=unknown+1; end if;
    affected:=0;
    row_digest:=null;
    if not coalesce(dependency.supported,false) or exposure is null then
      scan_incomplete:=scan_incomplete+1;
    else
      execute format(
        'select count(*),encode(sha256(convert_to(coalesce(string_agg(row_sha,'''' order by row_sha),''''),''UTF8'')),''hex'')
         from (select encode(sha256(convert_to(to_jsonb(x)::text,''UTF8'')),''hex'') as row_sha
               from %I.%I x where x.%I=$1 order by row_sha limit 501) scoped',
         dependency.nspname,dependency.relname,dependency.attname)
        into affected,row_digest using p_workspace;
      groups:=jsonb_set(groups,array[dependency.category],to_jsonb((groups->>dependency.category)::bigint+affected));
      impact:=jsonb_set(impact,array[exposure],to_jsonb((impact->>exposure)::bigint+affected));
      if affected>500 then bounded_count:=bounded_count+1; end if;
    end if;
    fingerprints:=fingerprints||jsonb_build_array(jsonb_build_array(dependency.nspname,dependency.relname,
      dependency.conname,dependency.attname,dependency.confdeltype,dependency.convalidated,dependency.condeferrable,
      dependency.condeferred,dependency.category,affected,row_digest));
  end loop;
  return jsonb_build_object(
    'summary',jsonb_build_object('categories',groups,'deleteActions',impact,
      'unsupportedConstraints',scan_incomplete,'unclassifiedConstraints',unknown,'overflowFamilies',bounded_count,
      'directReferencesClear',scan_incomplete=0 and unknown=0 and bounded_count=0
        and not exists(select 1 from jsonb_each_text(impact) q where q.value::bigint>0)),
    'revision',encode(sha256(convert_to(fingerprints::text,'UTF8')),'hex'));
end $$;

create function sectalk_private.st_v8_offboarding_reconcile_workspace_root(r sectalk_private.st_v8_offboarding_requests)
returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  with base as materialized (select sectalk_private.st_v8_offboarding_reconcile_archives(r) as snapshot),
    root as materialized (select sectalk_private.st_v8_offboarding_workspace_root_snapshot(r.workspace) as snapshot)
  select jsonb_build_object('summary',(base.snapshot->'summary')||jsonb_build_object(
    'workspaceRootDependencies',root.snapshot->'summary',
    'overflow',(base.snapshot#>'{summary,overflow}')||case when (root.snapshot#>>'{summary,overflowFamilies}')::integer>0
      then '["workspaceRootReferences"]'::jsonb else '[]'::jsonb end),
    'revision',encode(sha256(convert_to(jsonb_build_array('sectalk-workspace-root-reconciliation-v1',
      base.snapshot->>'revision',root.snapshot->>'revision')::text,'UTF8')),'hex'))
  from base cross join root;
$$;

revoke all on function sectalk_private.st_v8_offboarding_workspace_root_snapshot(uuid),
  sectalk_private.st_v8_offboarding_reconcile_workspace_root(sectalk_private.st_v8_offboarding_requests)
  from public,anon,authenticated,service_role;

create or replace function public.st_v8_offboarding_reconciliation(
  p_workspace uuid,p_action text default 'status',p_confirmation text default null,p_plan uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_reconciliations; v jsonb; summary jsonb; digest text; reviewed_at timestamptz;
  held boolean; bounded boolean; consistent boolean; archive_invalidated boolean; root_supported boolean;
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
  v:=sectalk_private.st_v8_offboarding_reconcile_workspace_root(r);
  summary:=v->'summary';
  bounded:=jsonb_array_length(summary->'overflow')=0;
  consistent:=not exists(select 1 from jsonb_each_text(summary->'archiveFindings') a where a.value::integer>0);
  root_supported:=coalesce((summary#>>'{workspaceRootDependencies,unsupportedConstraints}')::integer=0,false);
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
    if not root_supported then raise exception 'A workspace foreign key could not be evaluated' using errcode='PT409'; end if;
    if plan.id is null or plan.sha256<>digest or plan.expires_at<=clock_timestamp() or archive_invalidated then
      insert into sectalk_private.st_v8_offboarding_reconciliations(request_id,workspace,owner_id,reviewer_id,expires_at,summary,sha256)
        values(r.id,p_workspace,r.requester,r.reviewer,clock_timestamp()+interval '30 minutes',summary,digest) returning * into plan;
      archive_invalidated:=false;
    end if;
  elsif p_action='confirm' then
    if plan.id is null or p_plan is distinct from plan.id or p_sha256 is distinct from plan.sha256
      or digest<>plan.sha256 or not bounded or not consistent or not root_supported or archive_invalidated or plan.expires_at<=clock_timestamp() then
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
    'current',coalesce(not held and bounded and consistent and root_supported and not archive_invalidated and plan.sha256=digest
      and plan.expires_at>clock_timestamp(),false),
    'providerBytes','unverified','backupErasure','unverified','fullTenantErasure','unverified');
end $$;

notify pgrst,'reload schema';
commit;
