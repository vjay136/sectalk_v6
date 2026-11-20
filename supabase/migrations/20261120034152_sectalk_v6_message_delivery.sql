begin;

alter table public.st_messages add column delivered_at timestamptz;

create function public.st_v6_ack_message_delivery(p_chat uuid,p_messages uuid[])
returns setof uuid language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_message_delivery',60);
  if p_messages is null or cardinality(p_messages) not between 1 and 100
    then raise exception 'Choose 1 to 100 messages'; end if;
  perform c.id from public.st_chats c where c.id=p_chat and actor in(c.member_a,c.member_b) for share;
  if not found or not sectalk_private.st_v2_chat_write(p_chat,actor) then return; end if;

  return query update public.st_messages m set delivered_at=clock_timestamp()
  where m.chat_id=p_chat and m.id=any(p_messages) and m.sender<>actor
    and m.delivered_at is null and m.revoked_at is null
    and not exists(select 1 from public.st_v5_hidden_messages h where h.user_id=actor and h.message_id=m.id)
  returning m.id;
end $$;

revoke all on function public.st_v6_ack_message_delivery(uuid,uuid[]) from public,anon,authenticated;
grant execute on function public.st_v6_ack_message_delivery(uuid,uuid[]) to authenticated;

commit;
