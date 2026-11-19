begin;

-- The account topic carries refresh hints only. Payloads never contain chat text or call SDP.
create policy st_account_broadcast_read on realtime.messages
for select to authenticated
using (
  extension = 'broadcast'
  and (select auth.uid()) is not null
  and (select realtime.topic()) = 'st:account:' || (select auth.uid())::text
);

create policy st_account_broadcast_scope on realtime.messages
as restrictive for select to public
using (
  coalesce((select realtime.topic()), '') not like 'st:account:%'
  or (
    extension = 'broadcast'
    and (select auth.uid()) is not null
    and (select realtime.topic()) = 'st:account:' || (select auth.uid())::text
  )
);

create policy st_account_broadcast_server_only on realtime.messages
as restrictive for insert to public
with check (coalesce((select realtime.topic()), '') not like 'st:account:%');

create function sectalk_private.notify_live_change()
returns trigger
language plpgsql
security definer
set search_path=''
as $$
declare
  recipient_a uuid;
  recipient_b uuid;
  notification text;
  hint jsonb;
begin
  case tg_table_name
  when 'st_chats' then
    recipient_a := new.member_a;
    recipient_b := new.member_b;
    notification := 'inbox';
    hint := jsonb_build_object('chat_id', new.id);
  when 'st_calls' then
    recipient_a := new.caller;
    recipient_b := new.callee;
    notification := 'call';
    hint := '{}'::jsonb;
  when 'st_signals' then
    select case when caller = new.sender then callee else caller end
      into recipient_a from public.st_calls where id = new.call_id;
    notification := 'signal';
    hint := jsonb_build_object('call_id', new.call_id);
  else
    return new;
  end case;

  if recipient_a is not null then
    perform realtime.send(hint, notification, 'st:account:' || recipient_a::text, true);
  end if;
  if recipient_b is not null then
    perform realtime.send(hint, notification, 'st:account:' || recipient_b::text, true);
  end if;
  return new;
end;
$$;

revoke execute on function sectalk_private.notify_live_change() from public, anon, authenticated;

create trigger st_chat_broadcast after insert or update on public.st_chats
for each row execute function sectalk_private.notify_live_change();
create trigger st_call_broadcast after insert or update on public.st_calls
for each row execute function sectalk_private.notify_live_change();
create trigger st_signal_broadcast after insert on public.st_signals
for each row execute function sectalk_private.notify_live_change();

commit;