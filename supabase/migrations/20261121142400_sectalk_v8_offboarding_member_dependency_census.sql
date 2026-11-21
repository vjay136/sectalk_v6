begin;

create or replace function sectalk_private.st_v8_offboarding_reconcile_workspace_root(r sectalk_private.st_v8_offboarding_requests)
returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  with base as materialized (select sectalk_private.st_v8_offboarding_reconcile_archives(r) as snapshot),
    root as materialized (select sectalk_private.st_v8_offboarding_workspace_root_snapshot(r.workspace) as snapshot),
    families(name,section) as (values
      ('residencyRecoveryPaths','storage'),('residencyRecoveryFileReceipts','native'),
      ('residencyDestinationRetirements','native'),('residencySourceReactivations','native'),
      ('residencyRecoveryRoomBatches','native'),('residencyRecoveryRoomTaskBatches','native'),
      ('impersonationWatchEntries','native'),('delegatedBillingAccounts','native'),('workspaceGroupMembers','native'),
      ('schoolClassPeople','native'),('customRoleAssignments','native')
    ), scoped(name,row_data) as (
      (select 'residencyRecoveryPaths',to_jsonb(o)-'last_accessed_at' from storage.objects o
        where o.bucket_id='sectalk-residency-recovery' and o.name like r.workspace::text||'/%'
        order by o.name,o.id limit 501)
      union all (select 'residencyRecoveryFileReceipts',to_jsonb(c)
        from sectalk_private.st_v8_residency_source_file_copies c
        join sectalk_private.st_v8_residency_write_handoffs h on h.handoff=c.handoff
        where h.workspace=r.workspace order by c.handoff,c.file limit 501)
      union all (select 'residencyRecoveryRoomBatches',to_jsonb(b)
        from sectalk_private.st_v8_residency_rollback_room_batches b
        join sectalk_private.st_v8_residency_write_handoffs h on h.handoff=b.handoff
        where h.workspace=r.workspace order by b.handoff limit 501)
      union all (select 'residencyRecoveryRoomTaskBatches',to_jsonb(b)
        from sectalk_private.st_v8_residency_rollback_room_task_batches b
        join sectalk_private.st_v8_residency_write_handoffs h on h.handoff=b.handoff
        where h.workspace=r.workspace order by b.handoff limit 501)
      union all (select 'residencyDestinationRetirements',to_jsonb(d)
        from sectalk_private.st_v8_residency_retired_destinations d where d.workspace=r.workspace
        order by d.receipt limit 501)
      union all (select 'residencySourceReactivations',to_jsonb(a)
        from sectalk_private.st_v8_residency_source_reactivations a where a.workspace=r.workspace
        order by a.handoff limit 501)
      union all (select 'impersonationWatchEntries',to_jsonb(w)
        from sectalk_private.st_v6_impersonation_watch w where w.workspace_id=r.workspace
        order by w.member_id limit 501)
      union all (select 'delegatedBillingAccounts',to_jsonb(b)
        from sectalk_private.st_v7_billing_admins b where b.workspace=r.workspace
        order by b.account limit 501)
      union all (select 'workspaceGroupMembers',to_jsonb(m)
        from public.st_v6_workspace_group_members m where m.workspace_id=r.workspace
        order by m.group_id,m.user_id limit 501)
      union all (select 'schoolClassPeople',to_jsonb(p)
        from sectalk_private.st_v7_school_class_people p where p.workspace=r.workspace
        order by p.class,p.person limit 501)
      union all (select 'customRoleAssignments',to_jsonb(a)
        from sectalk_private.st_v7_custom_role_assignments a where a.workspace=r.workspace
        order by a.role_id,a.account limit 501)
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
    'revision',encode(sha256(convert_to(jsonb_build_array('sectalk-workspace-root-reconciliation-v3',
      base.snapshot->>'revision',root.snapshot->>'revision',(select jsonb_object_agg(name,digest) from counts))::text,'UTF8')),'hex'))
  from base cross join root;
$$;

notify pgrst,'reload schema';
commit;
