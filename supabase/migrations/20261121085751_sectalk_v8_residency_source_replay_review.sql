begin;

create function public.st_v8_residency_source_replay_review(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  actor_id uuid:=auth.uid();
  actor_role text;
  transfer sectalk_private.st_v8_residency_write_handoffs;
  approval sectalk_private.st_v8_content_exports;
  manifest sectalk_private.st_v8_residency_rollback_manifests;
  results jsonb;
begin
  actor_role:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
  if p_workspace is null or actor_id is null or actor_role not in ('owner','reviewer')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false) then
    raise insufficient_privilege;
  end if;
  if sectalk_private.st_v8_residency_rollback_side(p_workspace) is distinct from 'source' then
    return '{"state":"inactive"}'::jsonb;
  end if;
  select f.* into strict transfer from sectalk_private.st_v8_residency_write_handoffs f where f.workspace=p_workspace;
  select c.* into approval from sectalk_private.st_v8_content_exports c
    where (c.id,c.workspace)=(transfer.approval,p_workspace)
      and c.approved_at is not null and c.withdrawn_at is null
      and sectalk_private.st_v8_offboarding_role(p_workspace,c.requester)='owner'
      and sectalk_private.st_v8_offboarding_role(p_workspace,c.reviewer)='reviewer';
  if not found or actor_id is distinct from (case actor_role when 'owner' then approval.requester else approval.reviewer end) then
    raise insufficient_privilege;
  end if;
  select m.* into manifest from sectalk_private.st_v8_residency_rollback_manifests m
    where m.handoff=transfer.handoff and m.workspace=p_workspace;
  if not found then return '{"state":"awaiting_manifest"}'::jsonb; end if;

  with board as (
    select (e->>'id')::uuid as id,e
    from sectalk_private.st_v8_residency_rollback_board_batches b
    cross join lateral jsonb_array_elements(b.tasks) e
    where b.handoff=transfer.handoff and b.applied_at is not null
      and (b.staged_by,b.applied_by)=(approval.requester,approval.reviewer)
  ), chat as (
    select (e->>'id')::uuid as id,e
    from sectalk_private.st_v8_residency_rollback_channel_batches b
    cross join lateral jsonb_array_elements(b.records) e
    where b.handoff=transfer.handoff and b.applied_at is not null
      and (b.staged_by,b.applied_by)=(approval.requester,approval.reviewer)
  ), evidence as (
    select e->>'kind' as kind,(e->>'id')::uuid as id,e->>'state' as change,e->>'after' as revision
    from jsonb_array_elements(manifest.changes) e
  ), checked as (
    select d.kind,d.id,d.change,d.revision,
      case
        when b.id is not null then case when coalesce(
          case when d.change='added' then
            to_jsonb(i)=to_jsonb(sectalk_private.st_v8_rollback_board_added_row(
              p_workspace,coalesce((b.e->>'sourceAuthor')::uuid,approval.requester),b.e))
          else i.completed=(b.e->>'completed')::boolean and exists(
            select 1 from sectalk_private.st_v8_content_export_entries c
            join lateral sectalk_private.st_v8_content_export_records(p_workspace,approval.requester,approval.reviewer,
              'workspace_task',p_workspace,i.id) s on c.sha256=encode(sha256(convert_to(
                jsonb_set(s.item,'{completed}',to_jsonb(not i.completed))::text,'UTF8')),'hex')
            where (c.export_id,c.kind,c.scope_id,c.record_id)=(approval.id,'workspace_task',p_workspace,i.id))
          end,false) then 'matched' else 'source_changed' end
        when a.id is not null then case when coalesce(
          (case d.kind when 'channel' then to_jsonb(c) else to_jsonb(p) end)=
          sectalk_private.st_v8_rollback_channel_row(p_workspace,
            coalesce((a.e->>'sourceAuthor')::uuid,approval.requester),a.e)
          and (d.kind='channel' or p.channel_id=parent.id and parent.workspace_id=p_workspace
            and parent.visibility='workspace' and parent.encryption_mode='standard' and not parent.archived
            and not exists(select 1 from sectalk_private.st_v7_channel_reports r where r.post_id=p.id)),
          false) then 'matched' else 'source_changed' end
        else 'not_replayed'
      end as result
    from evidence d
    left join board b on d.kind='workspace_task' and d.id=b.id and d.revision=b.e->>'after'
      and d.change=(case when b.e->>'kind'='added' then 'added' else 'changed' end)
    left join public.st_v2_items i on i.id=b.id and i.workspace_id=p_workspace and i.kind='task'
    left join chat a on d.kind=a.e->>'kind' and d.id=a.id and d.revision=a.e->>'digest' and d.change='added'
    left join public.st_v2_channels c on d.kind='channel' and c.id=a.id and c.workspace_id=p_workspace
    left join public.st_v2_posts p on d.kind='channel_message' and p.id=a.id
    left join public.st_v2_channels parent on parent.id=p.channel_id
  )
  select coalesce(jsonb_agg(jsonb_build_object('kind',kind,'id',id,'change',change,'revision',revision,'result',result)
    order by kind,id),'[]'::jsonb) into results from checked;

  return jsonb_build_object('state','held','reviewDigest',manifest.review_sha256,'records',results);
end $$;

revoke all on function public.st_v8_residency_source_replay_review(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_source_replay_review(uuid) to authenticated;
notify pgrst,'reload schema';
commit;
