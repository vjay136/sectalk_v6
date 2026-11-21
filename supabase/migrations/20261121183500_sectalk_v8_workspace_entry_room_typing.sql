begin;

-- Workspace entry binds the requesting session. Peer eligibility is still evaluated using the peer membership.
create or replace function sectalk_private.st_v6_room_can_type(p_room uuid,p_user uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v6_rooms r
    cross join lateral (select sectalk_private.st_v6_room_role(p_room,p_user) as role) membership
    where r.id=p_room and not r.archived and membership.role<>'read_only'
      and (p_user is distinct from auth.uid() or sectalk_private.st_v8_entry_sso_allows(r.workspace_id))
      and (membership.role in ('owner','moderator') or (not r.locked and r.kind not in ('announcement','broadcast')))
      and not exists(select 1 from public.st_v6_room_timeouts t
        where t.room_id=p_room and t.user_id=p_user and t.until_at>statement_timestamp())
  )
$$;

create or replace function public.st_v6_room_typing_status(p_room uuid,p_parent uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid(); typing_at timestamptz; share boolean;
begin
  if sectalk_private.st_v6_room_role(p_room) is null
    or not exists(select 1 from public.st_v6_rooms r where r.id=p_room and not r.archived
      and sectalk_private.st_v8_entry_sso_allows(r.workspace_id)) then return '{}'::jsonb; end if;
  if p_parent is not null and not exists(select 1 from public.st_v6_room_posts
    where room_id=p_room and id=p_parent and parent_id is null and removed_at is null) then return '{}'::jsonb; end if;
  select share_typing into share from sectalk_private.room_typing where room_id=p_room and user_id=actor;
  select expires_at into typing_at from sectalk_private.room_typing typing
    where typing.room_id=p_room and typing.user_id<>actor and typing.share_typing
      and typing.parent_id is not distinct from p_parent and expires_at>statement_timestamp()
      and sectalk_private.st_v6_room_can_type(p_room,typing.user_id)
      and sectalk_private.open_pair(actor,typing.user_id)
    order by expires_at desc limit 1;
  return jsonb_build_object('typing_until',typing_at,'share_own_typing',coalesce(share,true));
end $$;

commit;
