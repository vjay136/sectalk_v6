begin;

create or replace function public.st_v2_send_reply(p_chat uuid,p_id uuid,p_body text,p_reply uuid)
returns void language plpgsql security definer set search_path='' as $$
declare previous public.st_messages;
begin
  if p_reply is null or p_id=p_reply or not sectalk_private.st_v2_chat_write(p_chat,auth.uid())
    then raise exception 'Original message unavailable'; end if;
  perform id from public.st_chats where id=p_chat for update;
  select * into previous from public.st_messages where id=p_id;
  if found then
    if previous.chat_id=p_chat and previous.sender=auth.uid() and previous.body=btrim(p_body) and previous.reply_to=p_reply
      then return; end if;
    raise exception 'Message ID already in use';
  end if;
  perform m.id from public.st_messages m where m.id=p_reply and m.chat_id=p_chat and m.revoked_at is null
    and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=auth.uid())
    for share of m;
  if not found then raise exception 'Original message unavailable'; end if;
  perform public.st_send(p_chat,p_id,p_body);
  update public.st_messages set reply_to=p_reply where id=p_id;
end $$;

create function public.st_v6_reply_quotes(p_chat uuid,p_ids uuid[])
returns table(id uuid,sender uuid,body text)
language sql stable security invoker set search_path='' as $$
  select m.id,m.sender,left(m.body,240)
  from public.st_messages m
  where cardinality(p_ids) between 1 and 50 and m.id=any(p_ids) and m.chat_id=p_chat and m.revoked_at is null
    and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=(select auth.uid()))
$$;
revoke all on function public.st_v6_reply_quotes(uuid,uuid[]) from public,anon,authenticated;
grant execute on function public.st_v6_reply_quotes(uuid,uuid[]) to authenticated;

commit;
