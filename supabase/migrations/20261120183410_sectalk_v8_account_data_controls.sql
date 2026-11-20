begin;

create function public.st_v8_personal_data_export(p_owner uuid,p_before timestamptz default null,p_before_id uuid default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare bundle jsonb;
begin
  bundle:=public.st_v7_personal_data_export(p_owner,p_before,p_before_id);
  if p_before is not null then return bundle; end if;

  return bundle || jsonb_build_object('personalSettings',jsonb_build_object(
    'ownBlockedContacts',coalesce((select jsonb_agg(b.target order by b.target) from (
      select b.target from public.st_blocks b where b.actor=p_owner order by b.target limit 201
    ) b),'[]'::jsonb),
    'savedSearches',coalesce((select jsonb_agg(to_jsonb(s) order by s.created_at desc,s.id) from (
      select s.id,s.query,s.kind,s.created_at from public.st_v6_saved_searches s where s.user_id=p_owner
      order by s.created_at desc,s.id limit 201
    ) s),'[]'::jsonb),
    'currentWorkspaces',coalesce((select jsonb_agg(to_jsonb(w) order by w.joined_at desc,w.id) from (
      select m.workspace_id id,m.role,m.joined_at from public.st_v2_members m where m.user_id=p_owner
        and m.suspended_at is null order by m.joined_at desc,m.workspace_id limit 201
    ) w),'[]'::jsonb),
    'listsLimit',201));
end;
$$;

create function public.st_v8_personal_deletion_status(p_owner uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare request jsonb;
begin
  request:=public.st_v7_personal_deletion(p_owner,'status');
  if request->>'status'<>'needs_review' then return request || '{"blockers":[]}'::jsonb; end if;

  return request || jsonb_build_object('blockers',to_jsonb(array_remove(array[
    case when exists(select 1 from public.st_v2_workspaces w where w.owner=p_owner) then 'workspace_owner' end,
    case when exists(select 1 from public.st_v2_subscriptions s where s.user_id=p_owner and s.plan<>'free'
      and s.status not in ('canceled','incomplete_expired')) then 'subscription' end,
    case when exists(select 1 from sectalk_private.st_v6_workspace_holds h where h.member_id=p_owner and h.released_at is null)
      or exists(select 1 from sectalk_private.st_v6_preserved_post_versions p join sectalk_private.st_v6_workspace_holds h
        on h.id=p.hold_id where p.sender=p_owner and h.released_at is null)
      or exists(select 1 from public.st_v6_room_posts p where p.sender=p_owner)
      or exists(select 1 from public.st_v2_posts p where p.sender=p_owner)
      or exists(select 1 from sectalk_private.st_group_chats g where g.owner=p_owner) then 'retained_content' end,
    case when exists(select 1 from storage.objects o where o.owner_id::text=p_owner::text)
      or exists(select 1 from public.st_v5_files f where f.uploader=p_owner)
      or exists(select 1 from sectalk_private.st_v7_group_files f where f.uploader=p_owner) then 'retained_files' end,
    case when exists(select 1 from sectalk_private.st_v7_devices d where d.owner=p_owner) then 'retained_devices' end
  ],null)));
end;
$$;

revoke all on function public.st_v8_personal_data_export(uuid,timestamptz,uuid),public.st_v8_personal_deletion_status(uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_personal_data_export(uuid,timestamptz,uuid),public.st_v8_personal_deletion_status(uuid)
  to authenticated;

commit;
