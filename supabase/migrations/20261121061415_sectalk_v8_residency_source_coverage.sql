begin;

create function public.st_v8_residency_source_coverage(p_workspace uuid,p_approval uuid)
returns jsonb language plpgsql stable security definer set search_path='' set timezone='UTC' as $$
declare actor uuid:=auth.uid(); approval sectalk_private.st_v8_content_exports; totals jsonb; fingerprint text; pinned integer;
begin
  if p_workspace is null or p_approval is null or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false) then raise insufficient_privilege; end if;

  select * into approval from sectalk_private.st_v8_content_exports c
    where (c.workspace,c.id)=(p_workspace,p_approval) and c.approved_at is not null and c.withdrawn_at is null
      and c.expires_at>statement_timestamp() and actor in (c.requester,c.reviewer)
      and sectalk_private.st_v8_offboarding_role(c.workspace,c.requester)='owner'
      and sectalk_private.st_v8_offboarding_role(c.workspace,c.reviewer)='reviewer';
  if not found then raise insufficient_privilege; end if;

  with pinned_entries as materialized (
    select e.* from sectalk_private.st_v8_content_export_entries e where e.export_id=p_approval
  ), pinned_revisions as (
    select e.kind,e.scope_id,e.record_id, exists(
      select 1 from (
        select s.item from sectalk_private.st_v8_content_export_records(p_workspace,approval.requester,
          approval.reviewer,e.kind,e.scope_id,e.record_id) s where e.kind not in ('workspace_file','room_file')
        union all select s.item from sectalk_private.st_v8_offboarding_file_records(p_workspace,approval.requester,
          approval.reviewer,e.record_id) s where e.kind='workspace_file' and approval.include_workspace_files
        union all select s.item from sectalk_private.st_v8_offboarding_room_file_records(p_workspace,approval.requester,
          approval.reviewer,e.scope_id,e.record_id) s where e.kind='room_file' and approval.include_room_files
      ) revision where encode(sha256(convert_to(revision.item::text,'UTF8')),'hex')=e.sha256
    ) as current
    from pinned_entries e
  ), live_records as (
    (select 'workspace_task' as kind,i.workspace_id as scope_id,i.id as record_id from public.st_v2_items i
      where i.workspace_id=p_workspace and i.kind='task' limit 501)
    union all (select 'channel_message',c.id,p.id from public.st_v2_channels c join public.st_v2_posts p on p.channel_id=c.id
      where c.workspace_id=p_workspace limit 501)
    union all (select 'room_message',r.id,p.id from public.st_v6_rooms r join public.st_v6_room_posts p on p.room_id=r.id
      where r.workspace_id=p_workspace and p.removed_at is null limit 501)
    union all (select 'room_task',r.id,t.id from public.st_v6_rooms r join public.st_v6_tasks t on t.room_id=r.id
      where r.workspace_id=p_workspace limit 501)
    union all (select 'workspace_file',f.workspace,f.id from sectalk_private.st_v6_workspace_files f
      where f.workspace=p_workspace and f.deleted_at is null limit 501)
    union all (select 'room_file',f.room,f.id from sectalk_private.st_v6_room_files f
      where f.workspace=p_workspace and f.deleted_at is null limit 501)
  ), source_counts as (
    select live.kind,count(*) as observed,count(*) filter(where e.record_id is null) as unapproved
    from live_records live left join pinned_entries e using(kind,scope_id,record_id) group by live.kind
  ), pinned_counts as (
    select p.kind,count(*) as approved,count(*) filter(where p.current) as current from pinned_revisions p group by p.kind
  ), families as (
    select k.kind,coalesce(s.observed,0) as observed,coalesce(s.unapproved,0) as unapproved,
      coalesce(s.observed,0)=501 as capped,coalesce(p.approved,0) as approved,coalesce(p.current,0) as current
    from unnest(array['workspace_task','room_task','channel_message','room_message','workspace_file','room_file']) k(kind)
    left join source_counts s on s.kind=k.kind left join pinned_counts p on p.kind=k.kind
  )
  select (select jsonb_agg(jsonb_build_object('kind',f.kind,'observed',f.observed,'unapproved',f.unapproved,
      'capped',f.capped,'approved',f.approved,'current',f.current,'drifted',f.approved-f.current) order by f.kind) from families f),
    count(*),encode(sha256(convert_to(jsonb_build_object('format','sectalk-workspace-content-v1','workspace',p_workspace,
      'approval',p_approval,'entries',coalesce(jsonb_agg(jsonb_build_array(e.position,e.kind,e.scope_id,e.record_id,e.sha256)
      order by e.position),'[]'))::text,'UTF8')),'hex') into totals,pinned,fingerprint from pinned_entries e;

  if pinned is distinct from approval.record_count or fingerprint is distinct from approval.manifest_sha256
    then raise exception 'The approved source manifest changed' using errcode='PT409'; end if;
  return jsonb_build_object('measuredAt',statement_timestamp(),'approvedRecords',pinned,'families',totals);
end $$;

revoke all on function public.st_v8_residency_source_coverage(uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_source_coverage(uuid,uuid) to authenticated;
notify pgrst,'reload schema';
commit;
