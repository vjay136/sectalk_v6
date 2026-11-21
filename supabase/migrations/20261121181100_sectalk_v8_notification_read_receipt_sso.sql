begin;

create policy st_v8_workspace_entry_sso on public.st_v3_notifications as restrictive
  for select to authenticated using(sectalk_private.st_v8_entry_sso_allows(workspace_id));

create or replace function sectalk_private.st_v3_mark_notification(p_id bigint,p_category text)
returns void language sql security definer set search_path='' as $$
  update public.st_v3_notifications n set read_at=clock_timestamp()
    where auth.uid() is not null and n.recipient=auth.uid() and (p_id is null or n.id=p_id) and n.read_at is null
      and p_category in ('meeting','mention') and split_part(n.kind,'.',1)=p_category
      and sectalk_private.st_v2_role(n.workspace_id,auth.uid()) is not null
      and sectalk_private.st_v8_entry_sso_allows(n.workspace_id)
      and (n.meeting_id is null or sectalk_private.st_v8_meeting_schedule_sso_allows(n.meeting_id))
      and (n.room_id is null or (sectalk_private.st_v6_room_role(n.room_id) is not null
        and exists(select 1 from public.st_v6_room_posts p
          where (p.room_id,p.id)=(n.room_id,n.room_post_id) and p.removed_at is null)))
$$;

commit;
