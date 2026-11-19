begin;

alter table public.st_messages add column edited_at timestamptz;
alter table public.st_messages add column reply_to uuid references public.st_messages on delete set null;
create index st_v2_message_reply on public.st_messages(reply_to) where reply_to is not null;

create table public.st_v2_message_edits (
  id bigint generated always as identity primary key,
  message_id uuid not null references public.st_messages on delete cascade,
  body text not null,
  created_at timestamptz not null default now()
);
create index st_v2_edits_message on public.st_v2_message_edits(message_id,id desc);
create table public.st_v2_chat_state (
  chat_id uuid not null references public.st_chats on delete cascade,
  user_id uuid not null references public.st_profiles,
  last_read_at timestamptz,
  last_read_id uuid,
  muted boolean not null default false,
  primary key(chat_id,user_id)
);
create table public.st_v2_reactions (
  message_id uuid not null references public.st_messages on delete cascade,
  chat_id uuid not null references public.st_chats on delete cascade,
  user_id uuid not null references public.st_profiles,
  reaction text not null check(reaction in ('👍','❤️','✅','👀')),
  primary key(message_id,user_id,reaction)
);
create index st_v2_reactions_chat on public.st_v2_reactions(chat_id);
create table public.st_v2_pins (
  chat_id uuid primary key references public.st_chats on delete cascade,
  message_id uuid not null references public.st_messages on delete cascade,
  pinned_by uuid not null references public.st_profiles,
  pinned_at timestamptz not null default now()
);
create table public.st_v2_typing (
  chat_id uuid not null references public.st_chats on delete cascade,
  user_id uuid not null references public.st_profiles,
  expires_at timestamptz not null,
  primary key(chat_id,user_id)
);

alter table public.st_v2_message_edits enable row level security;
alter table public.st_v2_chat_state enable row level security;
alter table public.st_v2_reactions enable row level security;
alter table public.st_v2_pins enable row level security;
alter table public.st_v2_typing enable row level security;
revoke all on public.st_v2_message_edits,public.st_v2_chat_state,public.st_v2_reactions,public.st_v2_pins,public.st_v2_typing from public,anon,authenticated;
grant select on public.st_v2_message_edits,public.st_v2_reactions,public.st_v2_pins to authenticated;
-- Mutes are private. The shared receipt RPC returns only a cursor.
grant select on public.st_v2_chat_state to authenticated;
create policy st_v2_edits_read on public.st_v2_message_edits for select to authenticated using(
  exists(select 1 from public.st_messages m where m.id=message_id)
);
create policy st_v2_state_read on public.st_v2_chat_state for select to authenticated using(user_id=(select auth.uid()));
create policy st_v2_reaction_read on public.st_v2_reactions for select to authenticated using(sectalk_private.member(chat_id,(select auth.uid())));
create policy st_v2_pin_read on public.st_v2_pins for select to authenticated using(sectalk_private.member(chat_id,(select auth.uid())));

create function sectalk_private.st_v2_chat_write(c uuid,u uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_chats where id=c and u in(member_a,member_b) and status='accepted'
    and sectalk_private.open_pair(member_a,member_b))
$$;

create function public.st_v2_edit_message(p_message uuid,p_body text)
returns void language plpgsql security definer set search_path='' as $$
declare old_row public.st_messages;
begin
  perform sectalk_private.limit_action('v2_edit',25);
  select * into old_row from public.st_messages where id=p_message and sender=auth.uid() for update;
  if not found or not sectalk_private.st_v2_chat_write(old_row.chat_id,auth.uid())
    or old_row.created_at<now()-interval '24 hours' then raise exception 'Message can no longer be edited'; end if;
  if old_row.body=btrim(p_body) then return; end if;
  insert into public.st_v2_message_edits(message_id,body) values(p_message,old_row.body);
  update public.st_messages set body=btrim(p_body),edited_at=clock_timestamp() where id=p_message;
end $$;

create function public.st_v2_send_reply(p_chat uuid,p_id uuid,p_body text,p_reply uuid)
returns void language plpgsql security definer set search_path='' as $$
declare previous public.st_messages;
begin
  if p_id=p_reply or not sectalk_private.st_v2_chat_write(p_chat,auth.uid())
    or not exists(select 1 from public.st_messages where id=p_reply and chat_id=p_chat)
    then raise exception 'Original message unavailable'; end if;
  perform id from public.st_chats where id=p_chat for update;
  select * into previous from public.st_messages where id=p_id;
  if found and previous.reply_to is distinct from p_reply then raise exception 'Message ID already in use'; end if;
  perform public.st_send(p_chat,p_id,p_body);
  update public.st_messages set reply_to=p_reply where id=p_id and reply_to is null;
end $$;

create function public.st_v2_inbox_status()
returns table(chat_id uuid,muted boolean,unread boolean,latest_id uuid,latest_at timestamptz)
language sql stable security definer set search_path='' as $$
  select c.id,coalesce(s.muted,false),
    m.id is not null and (s.last_read_at is null or (m.created_at,m.id)>(s.last_read_at,s.last_read_id)),
    m.id,m.created_at
  from (
    select id,member_a,member_b from public.st_chats
    where auth.uid() in (member_a,member_b) and status='accepted'
    order by updated_at desc limit 250
  ) c
  left join public.st_v2_chat_state s on s.chat_id=c.id and s.user_id=auth.uid()
  left join lateral (
    select id,created_at from public.st_messages where chat_id=c.id and sender<>auth.uid()
      and sectalk_private.open_pair(c.member_a,c.member_b)
    order by created_at desc,id desc limit 1
  ) m on true
$$;

create function public.st_v2_search_messages(p_chat uuid,p_query text)
returns setof public.st_messages language plpgsql security invoker set search_path='' as $$
begin
  if char_length(btrim(p_query)) not between 2 and 150 then return; end if;
  return query select * from public.st_messages
    where chat_id=p_chat and strpos(lower(body),lower(btrim(p_query)))>0
    order by created_at desc,id desc limit 30;
end $$;

create function public.st_v2_read(p_chat uuid,p_message uuid)
returns void language plpgsql security definer set search_path='' as $$
declare m public.st_messages;
begin
  if not sectalk_private.st_v2_chat_write(p_chat,auth.uid()) then return; end if;
  select * into m from public.st_messages where id=p_message and chat_id=p_chat and sender<>auth.uid();
  if not found then return; end if;
  insert into public.st_v2_chat_state as s(chat_id,user_id,last_read_at,last_read_id)
  values(p_chat,auth.uid(),m.created_at,m.id) on conflict(chat_id,user_id) do update
  set last_read_at=excluded.last_read_at,last_read_id=excluded.last_read_id
  where s.last_read_at is null or (s.last_read_at,s.last_read_id)<(excluded.last_read_at,excluded.last_read_id);
end $$;

create function public.st_v2_chat_status(p_chat uuid)
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
    'read_id',peer.last_read_id,'typing_until',typing_at);
end $$;

create function public.st_v2_mute(p_chat uuid,p_muted boolean)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('v2_mute',20);
  if not sectalk_private.member(p_chat,auth.uid()) then raise exception 'Conversation unavailable'; end if;
  insert into public.st_v2_chat_state(chat_id,user_id,muted) values(p_chat,auth.uid(),p_muted)
  on conflict(chat_id,user_id) do update set muted=excluded.muted;
end $$;

create function public.st_v2_react(p_message uuid,p_reaction text,p_enabled boolean)
returns void language plpgsql security definer set search_path='' as $$
declare cid uuid;
begin
  perform sectalk_private.limit_action('v2_reaction',40);
  select chat_id into cid from public.st_messages where id=p_message;
  if not sectalk_private.st_v2_chat_write(cid,auth.uid()) then raise exception 'Conversation unavailable'; end if;
  if p_enabled then
    insert into public.st_v2_reactions values(p_message,cid,auth.uid(),p_reaction) on conflict do nothing;
  else
    delete from public.st_v2_reactions where message_id=p_message and user_id=auth.uid() and reaction=p_reaction;
  end if;
end $$;

create function public.st_v2_pin(p_chat uuid,p_message uuid)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('v2_pin',20);
  if not sectalk_private.st_v2_chat_write(p_chat,auth.uid()) then raise exception 'Conversation unavailable'; end if;
  if p_message is null then
    delete from public.st_v2_pins where chat_id=p_chat;
  else
    if not exists(select 1 from public.st_messages where chat_id=p_chat and id=p_message) then raise exception 'Message unavailable'; end if;
    insert into public.st_v2_pins values(p_chat,p_message,auth.uid(),clock_timestamp())
      on conflict(chat_id) do update set message_id=excluded.message_id,pinned_by=excluded.pinned_by,pinned_at=excluded.pinned_at;
  end if;
end $$;

create function public.st_v2_typing(p_chat uuid,p_active boolean)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('v2_typing',75);
  if not sectalk_private.st_v2_chat_write(p_chat,auth.uid()) then return; end if;
  insert into public.st_v2_typing as t values(p_chat,auth.uid(),
    case when p_active then clock_timestamp()+interval '5 seconds' else clock_timestamp() end)
  on conflict(chat_id,user_id) do update set expires_at=excluded.expires_at
  where case when p_active then t.expires_at < clock_timestamp()+interval '3 seconds'
             else t.expires_at>clock_timestamp() end;
end $$;

create function sectalk_private.st_v2_chat_notify()
returns trigger language plpgsql security definer set search_path='' as $$
declare cid uuid; chat public.st_chats;
begin
  if tg_op='DELETE' then cid:=old.chat_id; else cid:=new.chat_id; end if;
  if tg_table_name='st_v2_chat_state' then
    if tg_op='UPDATE' then
      if old.last_read_id is not distinct from new.last_read_id then return null; end if;
    elsif new.last_read_id is null then return null;
    end if;
  end if;
  select * into chat from public.st_chats where id=cid;
  if not found then return null; end if;
  perform realtime.send(jsonb_build_object('chat_id',cid),'chat_activity','st:account:'||chat.member_a::text,true);
  perform realtime.send(jsonb_build_object('chat_id',cid),'chat_activity','st:account:'||chat.member_b::text,true);
  return null;
end $$;

create trigger st_v2_receipt_notify after insert or update on public.st_v2_chat_state for each row execute function sectalk_private.st_v2_chat_notify();
create trigger st_v2_reaction_notify after insert or delete on public.st_v2_reactions for each row execute function sectalk_private.st_v2_chat_notify();
create trigger st_v2_pin_notify after insert or update or delete on public.st_v2_pins for each row execute function sectalk_private.st_v2_chat_notify();
create trigger st_v2_typing_notify after insert or update on public.st_v2_typing for each row execute function sectalk_private.st_v2_chat_notify();
create trigger st_v2_edit_notify after update of edited_at on public.st_messages for each row execute function sectalk_private.st_v2_chat_notify();

revoke execute on function sectalk_private.st_v2_chat_write(uuid,uuid),sectalk_private.st_v2_chat_notify() from public,anon,authenticated;

do $$
declare sig text;
begin
  for sig in select p.oid::regprocedure::text from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.proname in ('st_v2_edit_message','st_v2_search_messages','st_v2_read',
      'st_v2_chat_status','st_v2_mute','st_v2_react','st_v2_pin','st_v2_typing','st_v2_send_reply','st_v2_inbox_status')
  loop
    execute 'revoke all on function '||sig||' from public,anon,authenticated';
    execute 'grant execute on function '||sig||' to authenticated';
  end loop;
end $$;

commit;
