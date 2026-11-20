begin;

create or replace function public.st_v2_pin(p_chat uuid,p_message uuid)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); chat public.st_chats;
begin
  perform sectalk_private.limit_action('v2_pin',20);
  select * into chat from public.st_chats where id=p_chat and actor in (member_a,member_b) for update;
  if not found or chat.status<>'accepted' or not sectalk_private.open_pair(chat.member_a,chat.member_b)
    then raise exception 'Conversation unavailable'; end if;
  if p_message is null then
    delete from public.st_v2_pins where chat_id=p_chat;
    return;
  end if;
  perform m.id from public.st_messages m where m.chat_id=p_chat and m.id=p_message and m.revoked_at is null
    and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=actor)
    for share of m;
  if not found then raise exception 'Message unavailable'; end if;
  insert into public.st_v2_pins(chat_id,message_id,pinned_by,pinned_at) values(p_chat,p_message,actor,clock_timestamp())
    on conflict(chat_id) do update set message_id=excluded.message_id,pinned_by=excluded.pinned_by,pinned_at=excluded.pinned_at;
end $$;

commit;
