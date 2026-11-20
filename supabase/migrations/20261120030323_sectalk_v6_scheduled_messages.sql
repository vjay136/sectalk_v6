begin;

create table public.st_v6_scheduled_messages (
  id uuid primary key,
  chat_id uuid not null references public.st_chats on delete cascade,
  sender uuid not null references public.st_profiles on delete cascade,
  body text,
  send_at timestamptz not null,
  state text not null default 'pending' check(state in ('pending','sent','cancelled','failed')),
  completed_at timestamptz,
  check((state='pending' and body is not null and char_length(body) between 1 and 4000 and completed_at is null)
    or (state<>'pending' and body is null and completed_at is not null))
);
create index st_v6_scheduled_due on public.st_v6_scheduled_messages(send_at,id) where state='pending';
create index st_v6_scheduled_sender_chat on public.st_v6_scheduled_messages(sender,chat_id,send_at desc,id desc);
create index st_v6_scheduled_pending_sender on public.st_v6_scheduled_messages(sender) where state='pending';
alter table public.st_v6_scheduled_messages enable row level security;
revoke all on public.st_v6_scheduled_messages from public,anon,authenticated;
grant select on public.st_v6_scheduled_messages to authenticated;
create policy st_v6_scheduled_owner on public.st_v6_scheduled_messages for select to authenticated
  using(sender=(select auth.uid()));

-- The API and scheduler share the authorization, insert, and live inbox trigger.
create function sectalk_private.st_v6_write_message(p_actor uuid,p_chat uuid,p_id uuid,p_body text)
returns text language plpgsql security definer set search_path='' as $$
declare conversation public.st_chats;
begin
  select * into conversation from public.st_chats where id=p_chat and p_actor in (member_a,member_b) for update;
  if not found or conversation.status<>'accepted' or not sectalk_private.open_pair(conversation.member_a,conversation.member_b)
    then return 'unavailable'; end if;
  insert into public.st_messages(id,chat_id,sender,body,created_at)
    values(p_id,p_chat,p_actor,btrim(p_body),clock_timestamp()) on conflict(id) do nothing;
  if found then
    update public.st_chats set updated_at=clock_timestamp() where id=p_chat;
  elsif not exists(select 1 from public.st_messages where id=p_id and chat_id=p_chat and sender=p_actor and body=btrim(p_body)) then
    return 'collision';
  end if;
  return 'sent';
end $$;
revoke all on function sectalk_private.st_v6_write_message(uuid,uuid,uuid,text) from public,anon,authenticated;

create or replace function public.st_send(p_chat uuid,p_id uuid,p_body text)
returns void language plpgsql security definer set search_path='' as $$
declare outcome text;
begin
  perform sectalk_private.limit_action('message',60);
  outcome:=sectalk_private.st_v6_write_message(auth.uid(),p_chat,p_id,p_body);
  if outcome='unavailable' then raise exception 'This conversation is unavailable'; end if;
  if outcome='collision' then raise exception 'Message ID already in use'; end if;
end $$;

create function public.st_v6_schedule_message(p_chat uuid,p_id uuid,p_body text,p_send_at timestamptz)
returns text language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); preview text:=btrim(p_body); saved public.st_v6_scheduled_messages; started_at timestamptz:=clock_timestamp();
begin
  -- This also serializes two schedule requests by the same sender for the pending quota.
  perform sectalk_private.limit_action('v6_schedule_message',15);
  select * into saved from public.st_v6_scheduled_messages where id=p_id and sender=actor;
  if found then
    if saved.chat_id=p_chat and saved.send_at=p_send_at and (saved.body=preview or saved.state<>'pending')
      then return saved.state; end if;
    raise exception 'Schedule ID already in use';
  end if;
  if not sectalk_private.st_v2_chat_write(p_chat,actor) then raise exception 'This conversation is unavailable'; end if;
  if p_id is null or preview is null or char_length(preview) not between 1 and 4000
    then raise exception 'Enter a message between 1 and 4000 characters'; end if;
  if p_send_at is null or p_send_at<=started_at or p_send_at>started_at+interval '30 days'
    then raise exception 'Choose a future send time within 30 days'; end if;
  if (select count(*) from public.st_v6_scheduled_messages where sender=actor and state='pending')>=50
    then raise exception 'You already have 50 scheduled messages'; end if;
  insert into public.st_v6_scheduled_messages(id,chat_id,sender,body,send_at)
    values(p_id,p_chat,actor,preview,p_send_at) on conflict(id) do nothing;
  if not found then raise exception 'Schedule ID already in use'; end if;
  return 'pending';
end $$;

create function public.st_v6_cancel_scheduled_message(p_id uuid)
returns text language plpgsql security definer set search_path='' as $$
declare outcome text; actor uuid:=auth.uid();
begin
  if actor is null then raise exception 'Sign in first'; end if;
  update public.st_v6_scheduled_messages set state='cancelled',body=null,completed_at=clock_timestamp()
    where id=p_id and sender=actor and state='pending' returning state into outcome;
  if not found then
    select state into outcome from public.st_v6_scheduled_messages where id=p_id and sender=actor;
    if not found then raise exception 'Scheduled message unavailable'; end if;
  end if;
  return outcome;
end $$;

create function sectalk_private.st_v6_dispatch_scheduled_messages()
returns integer language plpgsql security definer set search_path='' as $$
declare queued public.st_v6_scheduled_messages; outcome text; handled integer:=0;
begin
  for queued in select * from public.st_v6_scheduled_messages
    where state='pending' and send_at<=statement_timestamp()
    order by send_at,id limit 50 for update skip locked
  loop
    outcome:=sectalk_private.st_v6_write_message(queued.sender,queued.chat_id,queued.id,queued.body);
    update public.st_v6_scheduled_messages set
      state=case when outcome='sent' then 'sent' else 'failed' end,body=null,completed_at=clock_timestamp()
      where id=queued.id;
    handled:=handled+1;
  end loop;
  return handled;
end $$;

revoke all on function public.st_v6_schedule_message(uuid,uuid,text,timestamptz),public.st_v6_cancel_scheduled_message(uuid),
  sectalk_private.st_v6_dispatch_scheduled_messages() from public,anon,authenticated;
grant execute on function public.st_v6_schedule_message(uuid,uuid,text,timestamptz),public.st_v6_cancel_scheduled_message(uuid) to authenticated;

alter publication supabase_realtime add table public.st_v6_scheduled_messages;
select cron.schedule('sectalk-v6-scheduled-messages','* * * * *','select sectalk_private.st_v6_dispatch_scheduled_messages()');

commit;
