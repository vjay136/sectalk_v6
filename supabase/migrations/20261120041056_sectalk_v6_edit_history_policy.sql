begin;

-- A participant can change the audience only for previous versions of their own messages.
alter table public.st_v2_chat_state add column share_edit_history boolean not null default true;

create function sectalk_private.st_v6_can_read_edit_history(p_message uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(
    select 1 from public.st_messages m
    left join public.st_v2_chat_state author
      on author.chat_id=m.chat_id and author.user_id=m.sender
    where m.id=p_message and m.revoked_at is null
      and sectalk_private.st_v2_chat_write(m.chat_id,auth.uid())
      and not exists(select 1 from public.st_v5_hidden_messages h
        where h.message_id=m.id and h.user_id=auth.uid())
      and (m.sender=auth.uid() or coalesce(author.share_edit_history,true))
  )
$$;
revoke all on function sectalk_private.st_v6_can_read_edit_history(uuid) from public,anon,authenticated;
grant execute on function sectalk_private.st_v6_can_read_edit_history(uuid) to authenticated;
alter policy st_v2_edits_read on public.st_v2_message_edits
  using(sectalk_private.st_v6_can_read_edit_history(message_id));

create function public.st_v6_set_edit_history(p_chat uuid,p_share boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_edit_history',20);
  perform id from public.st_chats where id=p_chat and actor in (member_a,member_b) for update;
  if not found or p_share is null or not sectalk_private.st_v2_chat_write(p_chat,actor)
    then raise exception 'Conversation unavailable'; end if;
  insert into public.st_v2_chat_state(chat_id,user_id,share_edit_history) values(p_chat,actor,p_share)
    on conflict(chat_id,user_id) do update set share_edit_history=excluded.share_edit_history;
end $$;
revoke all on function public.st_v6_set_edit_history(uuid,boolean) from public,anon,authenticated;
grant execute on function public.st_v6_set_edit_history(uuid,boolean) to authenticated;

create or replace function public.st_v2_edit_message(p_message uuid,p_body text)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); scope uuid; original public.st_messages;
begin
  perform sectalk_private.limit_action('v2_edit',25);
  select chat_id into scope from public.st_messages where id=p_message and sender=actor;
  if not found then raise exception 'Message can no longer be edited'; end if;
  perform id from public.st_chats where id=scope for update;
  select * into original from public.st_messages where id=p_message and chat_id=scope and sender=actor for update;
  if not found or not sectalk_private.st_v2_chat_write(scope,actor)
    or original.revoked_at is not null or original.created_at<clock_timestamp()-interval '24 hours'
    or exists(select 1 from public.st_v5_hidden_messages h where h.message_id=p_message and h.user_id=actor)
    or exists(select 1 from public.st_v5_files f where f.message_id=p_message)
    then raise exception 'Message can no longer be edited'; end if;
  if original.body=btrim(p_body) then return; end if;
  insert into public.st_v2_message_edits(message_id,body) values(p_message,original.body);
  update public.st_messages set body=btrim(p_body),edited_at=clock_timestamp() where id=p_message;
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
    select expires_at into typing_at from public.st_v2_typing where chat_id=p_chat and user_id<>me and expires_at>now();
  end if;
  return jsonb_build_object('muted',coalesce(own.muted,false),'read_at',peer.last_read_at,
    'read_id',peer.last_read_id,'read_sequence',peer.last_read_sequence,'typing_until',typing_at,
    'share_own_edit_history',coalesce(own.share_edit_history,true),
    'share_peer_edit_history',available and coalesce(peer.share_edit_history,true));
end $$;

create or replace function sectalk_private.st_v2_chat_notify()
returns trigger language plpgsql security definer set search_path='' as $$
declare cid uuid; chat public.st_chats;
begin
  if tg_op='DELETE' then cid:=old.chat_id; else cid:=new.chat_id; end if;
  if tg_table_name='st_v2_chat_state' then
    if tg_op='UPDATE' then
      if old.last_read_id is not distinct from new.last_read_id and old.share_edit_history=new.share_edit_history
        then return null; end if;
    elsif new.last_read_id is null and new.share_edit_history then return null;
    end if;
  end if;
  select * into chat from public.st_chats where id=cid;
  if not found then return null; end if;
  perform realtime.send(jsonb_build_object('chat_id',cid),'chat_activity','st:account:'||chat.member_a::text,true);
  perform realtime.send(jsonb_build_object('chat_id',cid),'chat_activity','st:account:'||chat.member_b::text,true);
  return null;
end $$;

commit;
