begin;

create or replace function public.st_v6_read_receipt_settings(p_workspace uuid default null,p_room uuid default null)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid(); workspace uuid:=p_workspace; personal boolean; org boolean; room boolean;
begin
  if not sectalk_private.st_v2_active(actor) then return '{}'::jsonb; end if;
  if p_room is not null then
    select r.workspace_id into workspace from public.st_v6_rooms r where r.id=p_room;
    if workspace is null or (p_workspace is not null and p_workspace<>workspace)
      or not sectalk_private.st_v8_room_structure_sso_allows(workspace)
      or (sectalk_private.st_v6_room_role(p_room) is null and not sectalk_private.st_v6_room_workspace_manager(p_room))
      then return '{}'::jsonb; end if;
    select enabled into room from sectalk_private.room_read_receipt_policy where room_id=p_room;
  end if;
  if workspace is not null then
    if sectalk_private.st_v2_role(workspace,actor) is null or not sectalk_private.st_v8_entry_sso_allows(workspace)
      then return '{}'::jsonb; end if;
    select enabled into org from sectalk_private.workspace_read_receipt_policy where workspace_id=workspace;
  end if;
  select enabled into personal from sectalk_private.read_receipt_preferences where user_id=actor;
  return jsonb_build_object('personal_enabled',coalesce(personal,true),
    'workspace_enabled',coalesce(org,true),'room_enabled',coalesce(room,true));
end $$;

create or replace function public.st_v6_set_read_receipt_policy(p_enabled boolean,p_workspace uuid default null,p_room uuid default null)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if p_enabled is null or not sectalk_private.st_v2_active(actor) or num_nonnulls(p_workspace,p_room)>1
    then raise exception 'Read receipt settings unavailable'; end if;
  perform sectalk_private.limit_action('v6_read_receipt_policy',20);
  if p_workspace is not null then
    perform id from public.st_v2_workspaces where id=p_workspace for no key update;
    if not found or not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
      then raise exception 'Read receipt settings unavailable'; end if;
    if not sectalk_private.st_v8_entry_sso_allows(p_workspace) then raise insufficient_privilege; end if;
    insert into sectalk_private.workspace_read_receipt_policy as policy
      select p_workspace,p_enabled,clock_timestamp() where not p_enabled or exists(
        select 1 from sectalk_private.workspace_read_receipt_policy where workspace_id=p_workspace)
      on conflict(workspace_id) do update set enabled=excluded.enabled,changed_at=excluded.changed_at
      where policy.enabled<>excluded.enabled;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(p_workspace,actor,'workspace.read_receipt_policy');
    end if;
  elsif p_room is not null then
    perform sectalk_private.st_v8_room_structure_require(p_room);
    perform id from public.st_v6_rooms where id=p_room for no key update;
    if not found or not (coalesce(sectalk_private.st_v6_room_role(p_room) in ('owner','moderator'),false)
      or sectalk_private.st_v6_room_workspace_manager(p_room)) then raise exception 'Read receipt settings unavailable'; end if;
    insert into sectalk_private.room_read_receipt_policy as policy
      select p_room,p_enabled,clock_timestamp() where not p_enabled or exists(
        select 1 from sectalk_private.room_read_receipt_policy where room_id=p_room)
      on conflict(room_id) do update set enabled=excluded.enabled,changed_at=excluded.changed_at
      where policy.enabled<>excluded.enabled;
    if found then
      insert into public.st_v6_room_audit(room_id,actor,action) values(p_room,actor,'room.read_receipt_policy');
    end if;
  else
    perform id from public.st_profiles where id=actor for no key update;
    insert into sectalk_private.read_receipt_preferences as policy
      select actor,p_enabled,clock_timestamp() where not p_enabled or exists(
        select 1 from sectalk_private.read_receipt_preferences where user_id=actor)
      on conflict(user_id) do update set enabled=excluded.enabled,changed_at=excluded.changed_at
      where policy.enabled<>excluded.enabled;
  end if;
end $$;

create or replace function public.st_v6_room_read_counts(p_room uuid,p_posts uuid[])
returns table(post_id uuid,amount bigint)
language sql stable security definer set search_path='' as $$
  select receipt.post_id,count(*)
  from sectalk_private.room_read_receipts receipt
  join public.st_v6_room_posts post on post.room_id=receipt.room_id and post.id=receipt.post_id
  join public.st_v6_rooms room on room.id=post.room_id
  left join sectalk_private.workspace_read_receipt_policy org on org.workspace_id=room.workspace_id
  left join sectalk_private.room_read_receipt_policy policy on policy.room_id=room.id
  left join sectalk_private.read_receipt_preferences reader on reader.user_id=receipt.reader
  where cardinality(p_posts) between 1 and 151 and receipt.room_id=p_room and receipt.post_id=any(p_posts)
    and post.sender=auth.uid() and post.removed_at is null and sectalk_private.st_v6_room_role(p_room) is not null
    and sectalk_private.st_v8_room_structure_sso_allows(room.workspace_id)
    and sectalk_private.st_v6_room_role(p_room,receipt.reader) is not null
    and (org.enabled is null or org.enabled and receipt.shared_at>=org.changed_at)
    and (policy.enabled is null or policy.enabled and receipt.shared_at>=policy.changed_at)
    and (reader.enabled is null or reader.enabled and receipt.shared_at>=reader.changed_at)
  group by receipt.post_id
$$;

create policy st_v8_thread_follows_structure on public.st_v6_thread_follows as restrictive
  for all to authenticated
  using(sectalk_private.st_v8_room_structure_room_allows(room_id))
  with check(sectalk_private.st_v8_room_structure_room_allows(room_id));

commit;
