begin;

alter table public.st_messages add column sequence bigint;
with ordered as (
  select id,row_number() over(partition by chat_id order by created_at,id) as number
  from public.st_messages
)
update public.st_messages m set sequence=ordered.number from ordered where m.id=ordered.id;
alter table public.st_messages alter column sequence set not null,
  add constraint st_v6_message_sequence_range check(sequence between 1 and 9007199254740991),
  add constraint st_v6_message_chat_sequence unique(chat_id,sequence);

create table sectalk_private.st_v6_chat_sequence (
  chat_id uuid primary key references public.st_chats on delete cascade,
  last_sequence bigint not null
);
alter table sectalk_private.st_v6_chat_sequence enable row level security;
revoke all on sectalk_private.st_v6_chat_sequence from public,anon,authenticated;
insert into sectalk_private.st_v6_chat_sequence(chat_id,last_sequence)
select chat_id,max(sequence) from public.st_messages group by chat_id;

create function sectalk_private.st_v6_assign_message_sequence()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  -- Use the same lock order as the normal message writer.
  perform id from public.st_chats where id=new.chat_id for no key update;
  insert into sectalk_private.st_v6_chat_sequence as cursor(chat_id,last_sequence) values(new.chat_id,1)
    on conflict(chat_id) do update set last_sequence=cursor.last_sequence+1
    returning last_sequence into new.sequence;
  return new;
end $$;
revoke all on function sectalk_private.st_v6_assign_message_sequence() from public,anon,authenticated;
create trigger st_v6_assign_message_sequence before insert on public.st_messages
for each row execute function sectalk_private.st_v6_assign_message_sequence();

create function sectalk_private.st_v6_keep_message_sequence()
returns trigger language plpgsql set search_path='' as $$
begin
  if new.chat_id<>old.chat_id or new.sequence<>old.sequence then raise exception 'Message ordering cannot change'; end if;
  return new;
end $$;
revoke all on function sectalk_private.st_v6_keep_message_sequence() from public,anon,authenticated;
create trigger st_v6_keep_message_sequence before update of chat_id,sequence on public.st_messages
for each row execute function sectalk_private.st_v6_keep_message_sequence();

create or replace function sectalk_private.st_v6_write_message(p_actor uuid,p_chat uuid,p_id uuid,p_body text)
returns text language plpgsql security definer set search_path='' as $$
declare conversation public.st_chats; existing public.st_messages;
begin
  select * into conversation from public.st_chats where id=p_chat and p_actor in (member_a,member_b) for update;
  if not found or conversation.status<>'accepted' or not sectalk_private.open_pair(conversation.member_a,conversation.member_b)
    then return 'unavailable'; end if;
  -- A failed insert rolls back its counter allocation, including simultaneous reuse in a different chat.
  begin
    insert into public.st_messages(id,chat_id,sender,body,created_at)
      values(p_id,p_chat,p_actor,btrim(p_body),clock_timestamp());
  exception when unique_violation then
    select * into existing from public.st_messages where id=p_id;
    if found and existing.chat_id=p_chat and existing.sender=p_actor and existing.body=btrim(p_body) then return 'sent'; end if;
    return 'collision';
  end;
  update public.st_chats set updated_at=clock_timestamp() where id=p_chat;
  return 'sent';
end $$;

alter table public.st_v2_chat_state add column last_read_sequence bigint;
update public.st_v2_chat_state s set last_read_sequence=(
  select m.sequence from public.st_messages m where m.chat_id=s.chat_id
    and (m.created_at,m.id)<=(s.last_read_at,s.last_read_id)
    order by m.sequence desc limit 1
) where s.last_read_id is not null;

create or replace function public.st_v2_read(p_chat uuid,p_message uuid)
returns void language plpgsql security definer set search_path='' as $$
declare m public.st_messages;
begin
  if not sectalk_private.st_v2_chat_write(p_chat,auth.uid()) then return; end if;
  select * into m from public.st_messages where id=p_message and chat_id=p_chat and sender<>auth.uid();
  if not found then return; end if;
  insert into public.st_v2_chat_state as s(chat_id,user_id,last_read_at,last_read_id,last_read_sequence)
  values(p_chat,auth.uid(),m.created_at,m.id,m.sequence) on conflict(chat_id,user_id) do update
  set last_read_at=excluded.last_read_at,last_read_id=excluded.last_read_id,last_read_sequence=excluded.last_read_sequence
  where s.last_read_sequence is null or s.last_read_sequence<excluded.last_read_sequence;
end $$;

create or replace function public.st_v2_chat_status(p_chat uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare me uuid:=auth.uid(); own public.st_v2_chat_state; peer public.st_v2_chat_state; typing_at timestamptz;
begin
  if not sectalk_private.member(p_chat,me) then return '{}'::jsonb; end if;
  select * into own from public.st_v2_chat_state where chat_id=p_chat and user_id=me;
  if sectalk_private.st_v2_chat_write(p_chat,me) then
    select * into peer from public.st_v2_chat_state where chat_id=p_chat and user_id<>me;
    select expires_at into typing_at from public.st_v2_typing where chat_id=p_chat and user_id<>me and expires_at>now();
  end if;
  return jsonb_build_object('muted',coalesce(own.muted,false),'read_at',peer.last_read_at,
    'read_id',peer.last_read_id,'read_sequence',peer.last_read_sequence,'typing_until',typing_at);
end $$;

create or replace function public.st_v2_inbox_status()
returns table(chat_id uuid,muted boolean,unread boolean,latest_id uuid,latest_at timestamptz)
language sql stable security definer set search_path='' as $$
  select c.id,coalesce(s.muted,false),
    m.id is not null and (s.last_read_sequence is null or m.sequence>s.last_read_sequence),
    m.id,m.created_at
  from (
    select id,member_a,member_b from public.st_chats
    where auth.uid() in (member_a,member_b) and status='accepted'
    order by updated_at desc limit 250
  ) c
  left join public.st_v2_chat_state s on s.chat_id=c.id and s.user_id=auth.uid()
  left join lateral (
    select id,created_at,sequence from public.st_messages where chat_id=c.id and sender<>auth.uid()
      and sectalk_private.open_pair(c.member_a,c.member_b)
    order by sequence desc limit 1
  ) m on true
$$;

create or replace function public.st_v2_search_messages(p_chat uuid,p_query text)
returns setof public.st_messages language plpgsql security invoker set search_path='' as $$
begin
  if char_length(btrim(p_query)) not between 2 and 150 then return; end if;
  return query select * from public.st_messages
    where chat_id=p_chat and strpos(lower(body),lower(btrim(p_query)))>0
    order by sequence desc limit 30;
end $$;

commit;
