begin;

alter table public.st_v2_chat_state add column share_typing boolean not null default true;
alter table public.st_v2_typing add column last_started_at timestamptz;

create function public.st_v6_set_typing_policy(p_chat uuid,p_share boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_typing_policy',20);
  perform id from public.st_chats where id=p_chat and actor in (member_a,member_b) for update;
  if not found or p_share is null or not sectalk_private.st_v2_chat_write(p_chat,actor)
    then raise exception 'Conversation unavailable'; end if;

  insert into public.st_v2_chat_state as state(chat_id,user_id,share_typing) values(p_chat,actor,p_share)
    on conflict(chat_id,user_id) do update set share_typing=excluded.share_typing
    where state.share_typing is distinct from excluded.share_typing;
  if not found then return; end if;

  if not p_share then
    update public.st_v2_typing set expires_at=statement_timestamp()
    where chat_id=p_chat and user_id=actor and expires_at>clock_timestamp();
  end if;
  perform realtime.send(jsonb_build_object('chat_id',p_chat),'chat_activity','st:account:'||actor::text,true);
end $$;
revoke all on function public.st_v6_set_typing_policy(uuid,boolean) from public,anon,authenticated;
grant execute on function public.st_v6_set_typing_policy(uuid,boolean) to authenticated;

create or replace function public.st_v2_typing(p_chat uuid,p_active boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); pulse_at timestamptz;
begin
  perform sectalk_private.limit_action('v2_typing',75);
  -- Use the same lock as the policy setter so a concurrent pulse cannot outlive opt-out.
  perform id from public.st_chats where id=p_chat and actor in (member_a,member_b) for update;
  if not found or p_active is null or not sectalk_private.st_v2_chat_write(p_chat,actor) then return; end if;
  if exists(select 1 from public.st_v2_chat_state
    where chat_id=p_chat and user_id=actor and not share_typing) then return; end if;

  pulse_at:=clock_timestamp();
  if p_active then
    insert into public.st_v2_typing as typing(chat_id,user_id,expires_at,last_started_at)
      values(p_chat,actor,pulse_at+interval '5 seconds',pulse_at)
    on conflict(chat_id,user_id) do update
      set expires_at=excluded.expires_at,last_started_at=excluded.last_started_at
      where typing.last_started_at is null or typing.last_started_at<=pulse_at-interval '2 seconds';
  else
    update public.st_v2_typing set expires_at=statement_timestamp()
    where chat_id=p_chat and user_id=actor and expires_at>pulse_at;
  end if;
end $$;

create or replace function public.st_v2_chat_status(p_chat uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare me uuid:=auth.uid(); own public.st_v2_chat_state; peer public.st_v2_chat_state; typing_at timestamptz; available boolean;
begin
  if not sectalk_private.member(p_chat,me) then return '{}'::jsonb; end if;
  select * into own from public.st_v2_chat_state where chat_id=p_chat and user_id=me;
  available:=sectalk_private.st_v2_chat_write(p_chat,me);
  if available then
    select * into peer from public.st_v2_chat_state where chat_id=p_chat and user_id<>me;
    if coalesce(peer.share_typing,true) then
      select expires_at into typing_at from public.st_v2_typing
        where chat_id=p_chat and user_id<>me and expires_at>statement_timestamp();
    end if;
  end if;
  return jsonb_build_object('muted',coalesce(own.muted,false),'read_at',peer.last_read_at,
    'read_id',peer.last_read_id,'read_sequence',peer.last_read_sequence,'typing_until',typing_at,
    'share_own_typing',available and coalesce(own.share_typing,true),
    'share_own_edit_history',coalesce(own.share_edit_history,true),
    'share_peer_edit_history',available and coalesce(peer.share_edit_history,true));
end $$;

commit;
