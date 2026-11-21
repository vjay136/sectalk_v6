begin;

create or replace function sectalk_private.st_v8_offboarding_workspace_root_snapshot(p_workspace uuid)
returns jsonb language plpgsql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  dependency record; exposure text; affected bigint; row_digest text; audit record;
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
              'st_v8_workspace_directory_sso','st_v8_workspace_entry_sso','st_v8_workspace_file_sso','st_v8_workspace_groups_sso',
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
              'st_v8_content_exports','st_v8_offboarding_requests','st_v8_offboarding_reviewers','st_v8_workspace_audit_custody'
            ]) then 'preservation'
            when n.nspname='sectalk_private' and c.relname=any(array[
              'st_v7_usage_events','st_v7_workspace_trials','st_v8_enterprise_billing_operators',
              'st_v8_enterprise_orders','st_v8_workspace_seat_changes','st_v8_workspace_seats'
            ]) then 'billing'
            when n.nspname='sectalk_private' and c.relname=any(array[
              'st_v6_integration_keys','st_v6_webhooks','st_v8_scim_keys','st_v8_scim_users',
              'st_v8_residency_cell_authorizations','st_v8_residency_requests','st_v8_residency_routing_rehearsals',
              'st_v8_residency_source_pauses','st_v8_residency_verifiers','st_v8_residency_active_routes',
              'st_v8_residency_route_revocations','st_v8_residency_rollback_holds',
              'st_v8_residency_activation_admissions','st_v8_residency_channel_history','st_v8_residency_channel_imports',
              'st_v8_residency_comparison_receipts','st_v8_residency_file_verifications','st_v8_residency_room_history',
              'st_v8_residency_room_imports','st_v8_residency_task_imports','st_v8_residency_write_handoffs',
              'st_v8_residency_retired_destinations','st_v8_residency_source_reactivations'
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
  select * into audit from sectalk_private.st_v8_offboarding_audit_custody_manifest(p_workspace);
  if audit.event_count>10000 then bounded_count:=bounded_count+1;
  elsif audit.event_count>0 and not audit.valid then scan_incomplete:=scan_incomplete+1; end if;
  fingerprints:=fingerprints||jsonb_build_array(jsonb_build_array('preserved-workspace-audit',
    audit.event_count,audit.valid,audit.sha256));
  return jsonb_build_object(
    'summary',jsonb_build_object('categories',groups,'deleteActions',impact,
      'unsupportedConstraints',scan_incomplete,'unclassifiedConstraints',unknown,'overflowFamilies',bounded_count,
      'directReferencesClear',scan_incomplete=0 and unknown=0 and bounded_count=0
        and not exists(select 1 from jsonb_each_text(impact) q where q.value::bigint>0)),
    'revision',encode(sha256(convert_to(fingerprints::text,'UTF8')),'hex'));
end $$;

create or replace function sectalk_private.st_v8_offboarding_reconcile_workspace_root(r sectalk_private.st_v8_offboarding_requests)
returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  with base as materialized (select sectalk_private.st_v8_offboarding_reconcile_archives(r) as snapshot),
    root as materialized (select sectalk_private.st_v8_offboarding_workspace_root_snapshot(r.workspace) as snapshot),
    families(name,section) as (values
      ('residencyRecoveryPaths','storage'),('residencyRecoveryFileReceipts','native'),
      ('residencyDestinationRetirements','native'),('residencySourceReactivations','native')
    ), scoped(name,row_data) as (
      (select 'residencyRecoveryPaths',to_jsonb(o)-'last_accessed_at' from storage.objects o
        where o.bucket_id='sectalk-residency-recovery' and o.name like r.workspace::text||'/%'
        order by o.name,o.id limit 501)
      union all (select 'residencyRecoveryFileReceipts',to_jsonb(c)
        from sectalk_private.st_v8_residency_source_file_copies c
        join sectalk_private.st_v8_residency_write_handoffs h on h.handoff=c.handoff
        where h.workspace=r.workspace order by c.handoff,c.file limit 501)
      union all (select 'residencyDestinationRetirements',to_jsonb(d)
        from sectalk_private.st_v8_residency_retired_destinations d where d.workspace=r.workspace
        order by d.receipt limit 501)
      union all (select 'residencySourceReactivations',to_jsonb(a)
        from sectalk_private.st_v8_residency_source_reactivations a where a.workspace=r.workspace
        order by a.handoff limit 501)
    ), digests as (
      select name,encode(sha256(convert_to(row_data::text,'UTF8')),'hex') as digest from scoped
    ), counts as (
      select f.name,f.section,count(d.digest) as rows,
        encode(sha256(convert_to(coalesce(string_agg(d.digest,'' order by d.digest),''),'UTF8')),'hex') as digest
      from families f left join digests d using(name) group by f.name,f.section
    )
  select jsonb_build_object('summary',(base.snapshot->'summary')||jsonb_build_object(
    'workspaceRootDependencies',root.snapshot->'summary',
    'nativeRows',(base.snapshot#>'{summary,nativeRows}')||
      (select jsonb_object_agg(name,rows) from counts where section='native'),
    'storageMetadata',(base.snapshot#>'{summary,storageMetadata}')||
      (select jsonb_object_agg(name,rows) from counts where section='storage'),
    'overflow',(base.snapshot#>'{summary,overflow}')||case when (root.snapshot#>>'{summary,overflowFamilies}')::integer>0
      then '["workspaceRootReferences"]'::jsonb else '[]'::jsonb end||
      (select coalesce(jsonb_agg(name order by name),'[]') from counts where rows>500)),
    'revision',encode(sha256(convert_to(jsonb_build_array('sectalk-workspace-root-reconciliation-v2',
      base.snapshot->>'revision',root.snapshot->>'revision',(select jsonb_object_agg(name,digest) from counts))::text,'UTF8')),'hex'))
  from base cross join root;
$$;

notify pgrst,'reload schema';
commit;
