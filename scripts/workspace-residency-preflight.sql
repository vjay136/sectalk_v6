\set ON_ERROR_STOP on
begin isolation level repeatable read read only;
set local lock_timeout = '1500ms';
set local statement_timeout = '20s';

-- Scope inventory
with recursive
workspace as (
  select id, owner from public.st_v2_workspaces where id = :'workspace_id'::uuid
),
actors as (
  select owner as id from workspace
  union
  select member.user_id from public.st_v2_members member join workspace on workspace.id = member.workspace_id
),
other_workspaces as (
  select other.id from public.st_v2_workspaces other join actors on actors.id = other.owner
  where other.id <> :'workspace_id'::uuid
  union
  select member.workspace_id from public.st_v2_members member join actors on actors.id = member.user_id
  where member.workspace_id <> :'workspace_id'::uuid
),
direct_chats as (
  select chat.id from public.st_chats chat join actors on actors.id = chat.member_a
  union
  select chat.id from public.st_chats chat join actors on actors.id = chat.member_b
),
private_groups as (
  select member.group_id from sectalk_private.st_group_members member join actors on actors.id = member.actor
  union
  select chat.id from sectalk_private.st_group_chats chat join actors on actors.id = chat.owner
),
application_tables as (
  select relation.oid, ns.nspname, relation.relname
  from pg_catalog.pg_class relation join pg_catalog.pg_namespace ns on ns.oid = relation.relnamespace
  where ns.nspname in ('public', 'sectalk_private') and relation.relkind in ('r', 'p')
),
foreign_keys as (
  select con.conrelid as child, con.confrelid as parent
  from pg_catalog.pg_constraint con join application_tables relation on relation.oid = con.conrelid
  where con.contype = 'f'
),
referencing_workspace(oid) as (
  select 'public.st_v2_workspaces'::regclass::oid
  union
  select fk.child from foreign_keys fk join referencing_workspace scoped on scoped.oid = fk.parent
),
scope_columns as (
  select distinct relation.oid, relation.nspname, relation.relname
  from application_tables relation join pg_catalog.pg_attribute attr on attr.attrelid = relation.oid
  where attr.attnum > 0 and not attr.attisdropped and attr.atttypid = 'uuid'::regtype
    and attr.attname in ('workspace', 'workspace_id', 'tenant', 'tenant_id', 'org_id', 'organization_id', 'scope_id')
    and not exists (select 1 from referencing_workspace scoped where scoped.oid = relation.oid)
),
external_edges as (
  select distinct child.nspname || '.' || child.relname as child, ns.nspname || '.' || parent.relname as parent
  from foreign_keys fk join referencing_workspace scoped on scoped.oid = fk.child
  join application_tables child on child.oid = fk.child
  join pg_catalog.pg_class parent on parent.oid = fk.parent
  join pg_catalog.pg_namespace ns on ns.oid = parent.relnamespace
  where not exists (select 1 from referencing_workspace ancestor where ancestor.oid = fk.parent)
),
file_manifest as (
  select file.id, file.size_bytes, file.published_at, file.deleted_at,
    file.workspace::text || '/' || file.id::text as object_key
  from sectalk_private.st_v6_workspace_files file join workspace on workspace.id = file.workspace
),
scoped_storage as (
  select object.name, object.metadata->>'size' as actual_size
  from storage.objects object join workspace on object.name like workspace.id::text || '/%'
  where object.bucket_id = 'sectalk-workspace-files'
),
file_alignment as (
  select count(*) filter (where manifest.published_at is not null and manifest.deleted_at is null) as published,
    count(*) filter (where manifest.id is not null and manifest.published_at is null and manifest.deleted_at is null) as pending,
    count(*) filter (where manifest.deleted_at is not null and object.name is not null) as retained,
    count(*) filter (where manifest.published_at is not null and manifest.deleted_at is null and object.name is null) as missing,
    count(*) filter (where manifest.published_at is not null and manifest.deleted_at is null
      and object.name is not null and object.actual_size is distinct from manifest.size_bytes::text) as mismatched,
    count(*) filter (where manifest.id is null) as unmatched
  from file_manifest manifest full join scoped_storage object on object.name = manifest.object_key
)
select case when exists (select 1 from workspace) then jsonb_build_object(
  'status', 'scope_review_required',
  'sharedProjectRouting', true,
  'eligibleForAutomatedCutover', false,
  'otherWorkspacesInProject', (select count(*) from public.st_v2_workspaces where id <> :'workspace_id'::uuid),
  'memberIdentities', (select count(*) from actors),
  'otherWorkspacesSharingIdentities', (select count(*) from other_workspaces),
  'globalDirectChatsInvolvingIdentities', (select count(*) from direct_chats),
  'globalPrivateGroupsInvolvingIdentities', (select count(*) from private_groups),
  'foreignKeyReachableRelations', (select coalesce(jsonb_agg(table_info.nspname || '.' || table_info.relname
    order by table_info.nspname, table_info.relname), '[]'::jsonb)
    from referencing_workspace scoped join application_tables table_info on table_info.oid = scoped.oid),
  'unconstrainedScopeCandidates', (select coalesce(jsonb_agg(nspname || '.' || relname order by nspname, relname), '[]'::jsonb)
    from scope_columns),
  'outsideForeignKeys', (select coalesce(jsonb_agg(to_jsonb(edge) order by edge.child, edge.parent), '[]'::jsonb)
    from external_edges edge),
  'workspaceFileMetadata', (select jsonb_build_object(
    'privateBucket', exists (select 1 from storage.buckets where id = 'sectalk-workspace-files' and not public),
    'published', published, 'pending', pending, 'retained', retained,
    'missing', missing, 'mismatchedSize', mismatched, 'unmatched', unmatched
  ) from file_alignment)
) else jsonb_build_object('status', 'workspace_not_found', 'eligibleForAutomatedCutover', false) end;
commit;
