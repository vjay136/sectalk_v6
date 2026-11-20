begin;

alter table public.st_messages add column expires_at timestamptz,
  add constraint st_v6_direct_disappearance_bounds check(expires_at is null or
    expires_at-created_at between interval '60 seconds' and interval '7 days');
create index st_v6_direct_disappearance_due on public.st_messages(expires_at,id)
  where expires_at is not null and revoked_at is null;

create policy st_v6_message_deadline on public.st_messages as restrictive for select to authenticated
  using(expires_at is null or expires_at>statement_timestamp());

create policy st_v6_saved_durable_message on public.st_v6_saved_messages as restrictive for insert to authenticated
  with check(exists(select 1 from public.st_messages m where m.id=message_id and m.expires_at is null));

create function public.st_v6_direct_timer_policy()
returns jsonb language sql immutable security invoker set search_path='' as $$
  select '{"min_seconds":60,"max_seconds":604800}'::jsonb
$$;

create function public.st_v6_send_disappearing_message(
  p_chat uuid,p_id uuid,p_body text,p_seconds integer,p_reply uuid default null
) returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  body text:=btrim(p_body);
  sent_at timestamptz;
  existing public.st_messages;
  bounds jsonb:=public.st_v6_direct_timer_policy();
begin
  if actor is null or p_id is null or p_id=p_reply or body is null or char_length(body) not between 1 and 4000
    or p_seconds is null or p_seconds not between (bounds->>'min_seconds')::integer and (bounds->>'max_seconds')::integer then
    raise exception 'Choose a timer between 1 minute and 7 days and enter a message' using errcode='22023';
  end if;
  if not sectalk_private.st_v2_chat_write(p_chat,actor) then
    raise exception 'This conversation is unavailable' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('message',60);
  perform 1 from public.st_chats c where c.id=p_chat for update;
  if not sectalk_private.st_v2_chat_write(p_chat,actor) then
    raise exception 'This conversation is unavailable' using errcode='42501';
  end if;

  select m.* into existing from public.st_messages m where m.id=p_id;
  if found then
    if existing.chat_id=p_chat and existing.sender=actor and existing.body=body
      and existing.reply_to is not distinct from p_reply and existing.revoked_at is null
      and existing.expires_at-existing.created_at=make_interval(secs=>p_seconds)
      and existing.expires_at>clock_timestamp() then return; end if;
    raise exception 'Message ID already in use' using errcode='22023';
  end if;

  if p_reply is not null then
    perform m.id from public.st_messages m where m.id=p_reply and m.chat_id=p_chat and m.revoked_at is null
      and (m.expires_at is null or m.expires_at>clock_timestamp())
      and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=actor)
      for share of m;
    if not found then raise exception 'Original message unavailable' using errcode='42501'; end if;
  end if;
  sent_at:=clock_timestamp();
  insert into public.st_messages(id,chat_id,sender,body,created_at,reply_to,expires_at)
    values(p_id,p_chat,actor,body,sent_at,p_reply,sent_at+make_interval(secs=>p_seconds));
  update public.st_chats set updated_at=clock_timestamp() where id=p_chat;
end $$;

create function sectalk_private.st_v6_no_disappearing_attachment()
returns trigger language plpgsql set search_path='' as $$
begin
  if exists(select 1 from public.st_messages m where m.id=new.message_id and m.expires_at is not null) then
    raise exception 'Disappearing messages support text only' using errcode='22023';
  end if;
  return new;
end $$;
create trigger st_v6_no_disappearing_attachment before insert or update of message_id on public.st_v5_files
  for each row execute function sectalk_private.st_v6_no_disappearing_attachment();

create function sectalk_private.st_v6_expire_direct_messages()
returns integer language plpgsql set search_path='' as $$
declare expired uuid; removed integer:=0;
begin
  for expired in select m.id from public.st_messages m where m.expires_at<=statement_timestamp()
    and m.revoked_at is null order by m.expires_at,m.id limit 500 for update skip locked
  loop
    perform sectalk_private.st_v6_tombstone_direct(expired);
    delete from public.st_v6_saved_messages where message_id=expired;
    removed:=removed+1;
  end loop;
  return removed;
end $$;

drop function public.st_v6_reply_quotes(uuid,uuid[]);
create function public.st_v6_reply_quotes(p_chat uuid,p_ids uuid[])
returns table(id uuid,sender uuid,body text,expires_at timestamptz)
language sql stable security invoker set search_path='' as $$
  select m.id,m.sender,left(m.body,240),m.expires_at from public.st_messages m
  where cardinality(p_ids) between 1 and 50 and m.id=any(p_ids) and m.chat_id=p_chat and m.revoked_at is null
    and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=(select auth.uid()))
$$;

revoke all on function public.st_v6_direct_timer_policy(),public.st_v6_send_disappearing_message(uuid,uuid,text,integer,uuid),
  sectalk_private.st_v6_expire_direct_messages(),sectalk_private.st_v6_no_disappearing_attachment(),
  public.st_v6_reply_quotes(uuid,uuid[]) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_direct_timer_policy(),public.st_v6_send_disappearing_message(uuid,uuid,text,integer,uuid),
  public.st_v6_reply_quotes(uuid,uuid[]) to authenticated;

select cron.schedule('sectalk-v6-disappear-direct-messages','* * * * *','select sectalk_private.st_v6_expire_direct_messages()');

create or replace function public.st_v6_forward_direct(p_source_chat uuid,p_source_message uuid,p_destination uuid,p_id uuid)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); snapshot text; outcome text;
begin
  if actor is null or p_id is null or p_source_chat is null or p_destination is null or p_source_chat=p_destination
    then raise exception 'Forwarding is unavailable'; end if;
  perform sectalk_private.limit_action('message',60);
  perform id from public.st_chats where id in (p_source_chat,p_destination) and actor in (member_a,member_b) order by id for update;
  if not exists(select 1 from public.st_chats c where c.id=p_source_chat and actor in (c.member_a,c.member_b)
    and c.status='accepted' and sectalk_private.open_pair(c.member_a,c.member_b))
    then raise exception 'Forwarding is unavailable'; end if;

  select m.body into snapshot from public.st_messages m
  where m.id=p_source_message and m.chat_id=p_source_chat and m.revoked_at is null and m.expires_at is null
    and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=actor)
    and not exists(select 1 from public.st_v5_files f where f.message_id=m.id)
  for share of m;
  if not found then raise exception 'Forwarding is unavailable'; end if;

  outcome:=sectalk_private.st_v6_write_message(actor,p_destination,p_id,snapshot,true);
  if outcome='unavailable' then raise exception 'Forwarding is unavailable'; end if;
  if outcome='collision' then raise exception 'Message ID already in use'; end if;
end $$;

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
    or original.expires_at is not null or original.revoked_at is not null or original.created_at<clock_timestamp()-interval '24 hours'
    or exists(select 1 from public.st_v5_hidden_messages h where h.message_id=p_message and h.user_id=actor)
    or exists(select 1 from public.st_v5_files f where f.message_id=p_message)
    then raise exception 'Message can no longer be edited'; end if;
  if original.body=btrim(p_body) then return; end if;
  insert into public.st_v2_message_edits(message_id,body) values(p_message,original.body);
  update public.st_messages set body=btrim(p_body),edited_at=clock_timestamp() where id=p_message;
end $$;

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
  perform m.id from public.st_messages m where m.chat_id=p_chat and m.id=p_message and m.revoked_at is null and m.expires_at is null
    and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=actor)
    for share of m;
  if not found then raise exception 'Message unavailable'; end if;
  insert into public.st_v2_pins(chat_id,message_id,pinned_by,pinned_at) values(p_chat,p_message,actor,clock_timestamp())
    on conflict(chat_id) do update set message_id=excluded.message_id,pinned_by=excluded.pinned_by,pinned_at=excluded.pinned_at;
end $$;

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
  perform m.id from public.st_messages m where m.id=p_reply and m.chat_id=p_chat and m.revoked_at is null and (m.expires_at is null or m.expires_at>clock_timestamp())
    and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=auth.uid())
    for share of m;
  if not found then raise exception 'Original message unavailable'; end if;
  perform public.st_send(p_chat,p_id,p_body);
  update public.st_messages set reply_to=p_reply where id=p_id;
end $$;

create or replace function public.st_report(p_chat uuid,p_message uuid,p_category text,p_details text)
returns uuid language plpgsql security definer set search_path='' as $$
declare peer uuid; snapshot text; report_id uuid;
begin
  perform sectalk_private.limit_action('report',5);
  select case when member_a=auth.uid() then member_b else member_a end into peer
  from public.st_chats where id=p_chat and auth.uid() in (member_a,member_b);
  if not found then raise exception 'This conversation is unavailable'; end if;
  if p_message is not null then
    select case when expires_at is null then body end into snapshot from public.st_messages where id=p_message and chat_id=p_chat and sender=peer and (expires_at is null or expires_at>clock_timestamp());
    if not found then raise exception 'Evidence must be a message from this contact'; end if;
  end if;
  insert into public.st_reports(reporter,subject,chat_id,message_id,category,details,evidence)
  values(auth.uid(),peer,p_chat,p_message,p_category,btrim(p_details),snapshot) returning id into report_id;
  return report_id;
end $$;

create or replace function public.st_v2_search_messages(p_chat uuid,p_query text)
returns setof public.st_messages language plpgsql security invoker set search_path='' as $$
begin
  if char_length(btrim(p_query)) not between 2 and 150 then return; end if;
  return query select * from public.st_messages
    where chat_id=p_chat and expires_at is null and strpos(lower(body),lower(btrim(p_query)))>0
    order by sequence desc limit 30;
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
      and (expires_at is null or (expires_at>statement_timestamp() and revoked_at is null)) and sectalk_private.open_pair(c.member_a,c.member_b)
    order by sequence desc limit 1
  ) m on true
$$;

create or replace function public.st_v6_search(p_query text,p_kind text)
returns table(kind text,id uuid,scope_id uuid,title text,snippet text,at timestamptz)
language plpgsql stable security invoker set search_path='' as $$
declare needle text:=lower(btrim(p_query));
begin
  if needle is null or char_length(needle) not between 2 and 120 then return; end if;
  return query
  select r.category,r.obj,r.scope,r.heading,
    (case when clip.start_at>1 then '…' else '' end) ||
    substring(r.preview from clip.start_at for 180) ||
    (case when char_length(r.preview)>=clip.start_at+180 then '…' else '' end),r.ts
  from (
    (select 'direct'::text as category,m.id as obj,m.chat_id as scope,
        'Direct message'::text as heading,m.body as preview,m.created_at as ts
      from public.st_messages m
      where (p_kind is null or p_kind='direct') and m.revoked_at is null and m.expires_at is null
        and not exists(select 1 from public.st_v5_hidden_messages h
          where h.message_id=m.id and h.user_id=(select auth.uid()))
        and strpos(lower(m.body),needle)>0
      order by m.created_at desc,m.id desc limit 30)
    union all
    (select 'channel',p.id,c.workspace_id,'#'||c.name,p.body,p.created_at
      from public.st_v2_posts p join public.st_v2_channels c on p.channel_id=c.id
      where (p_kind is null or p_kind='channel') and strpos(lower(p.body),needle)>0
      order by p.created_at desc,p.id desc limit 30)
    union all
    (select 'board',i.id,i.workspace_id,i.title,i.details,i.created_at from public.st_v2_items i
      where (p_kind is null or p_kind='board') and (strpos(lower(i.title),needle)>0 or strpos(lower(i.details),needle)>0)
      order by i.created_at desc,i.id desc limit 30)
    union all
    (select 'meeting',m.id,m.workspace_id,m.title,m.agenda,m.starts_at from public.st_v3_meetings m
      where (p_kind is null or p_kind='meeting') and (strpos(lower(m.title),needle)>0 or strpos(lower(m.agenda),needle)>0)
      order by m.starts_at desc,m.id desc limit 30)
  ) r
  cross join lateral (select greatest(1,strpos(lower(r.preview),needle)-30) as start_at) clip
  order by r.ts desc,r.obj desc limit 40;
end $$;

create or replace function public.st_v6_search(p_query text,p_kind text,p_filters jsonb)
returns table(kind text,id uuid,scope_id uuid,title text,snippet text,at timestamptz)
language plpgsql stable security invoker set search_path='' as $$
declare
  needle text:=lower(btrim(coalesce(p_query,'')));
  match_pattern text:='%'||replace(replace(replace(needle,chr(92),repeat(chr(92),2)),'%',chr(92)||'%'),'_',chr(92)||'_')||'%';
  terms tsquery:=case when needle ~ '[[:alnum:]]' then phraseto_tsquery('simple',needle) end;
  room_filter uuid:=nullif(p_filters->>'room','')::uuid;
  sender_filter text:=nullif(lower(p_filters->>'sender'),'');
  date_from timestamptz:=nullif(p_filters->>'from','')::timestamptz;
  date_until timestamptz:=nullif(p_filters->>'until','')::timestamptz;
  status_filter text:=nullif(p_filters->>'status','');
  has_file boolean:=coalesce((p_filters->>'has_file')::boolean,false);
  mentions_me boolean:=coalesce((p_filters->>'mentions_me')::boolean,false);
  sender_id uuid;
  mention_pattern text;
begin
  if auth.uid() is null or char_length(needle)=1 or char_length(needle)>120
    or (date_from is not null and date_until is not null and date_from>=date_until)
    or (needle='' and p_kind is null and room_filter is null and sender_filter is null
      and date_from is null and date_until is null and status_filter is null and not has_file and not mentions_me)
  then return; end if;

  if sender_filter is not null then
    select p.id into sender_id from public.st_profiles p where p.handle=sender_filter;
    if not found then return; end if;
  end if;
  if mentions_me then
    select '(^|[^a-z0-9_@])@'||p.handle||'([^a-z0-9_]|$)' into mention_pattern
      from public.st_profiles p where p.id=(select auth.uid());
    if not found then return; end if;
  end if;

  return query
  select r.category,r.obj,r.scope,r.heading,
    (case when clip.start_at>1 then '…' else '' end) || substring(r.preview from clip.start_at for 180) ||
    (case when char_length(r.preview)>=clip.start_at+180 then '…' else '' end),r.ts
  from (
    select 'direct'::text as category,m.id as obj,m.chat_id as scope,'Direct message'::text as heading,
      m.body as preview,m.created_at as ts
    from public.st_messages m
    where (p_kind is null or p_kind='direct') and room_filter is null and status_filter is null
      and m.revoked_at is null and m.expires_at is null and (sender_id is null or m.sender=sender_id)
      and (needle='' or lower(m.body) like match_pattern or to_tsvector('simple',m.body) @@ terms)
      and (not has_file or exists(select 1 from public.st_v5_files f where f.message_id=m.id and f.chat_id=m.chat_id))
      and (not mentions_me or m.body ~* mention_pattern)
      and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=(select auth.uid()))
    union all
    select 'channel',p.id,c.workspace_id,'#'||c.name,p.body,p.created_at
    from public.st_v2_posts p join public.st_v2_channels c on p.channel_id=c.id
    where (p_kind is null or p_kind='channel') and room_filter is null and status_filter is null
      and (needle='' or lower(p.body) like match_pattern or to_tsvector('simple',p.body) @@ terms)
      and not has_file and (sender_id is null or p.sender=sender_id) and (not mentions_me or p.body ~* mention_pattern)
    union all
    select 'room',p.id,r.id,'#'||r.name,p.body,p.created_at
    from public.st_v6_room_posts p join public.st_v6_rooms r on p.room_id=r.id
    where (p_kind is null or p_kind='room') and (room_filter is null or r.id=room_filter) and status_filter is null
      and not has_file and p.removed_at is null and (sender_id is null or p.sender=sender_id)
      and (needle='' or lower(p.body) like match_pattern or to_tsvector('simple',p.body) @@ terms)
      and (not mentions_me or p.body ~* mention_pattern)
    union all
    select 'board',i.id,i.workspace_id,i.title,i.details,i.created_at from public.st_v2_items i
    where (p_kind is null or p_kind='board') and room_filter is null and not has_file and not mentions_me
      and (sender_id is null or i.created_by=sender_id)
      and (needle='' or lower(i.title) like match_pattern or lower(i.details) like match_pattern
        or to_tsvector('simple',i.title) @@ terms or to_tsvector('simple',i.details) @@ terms)
      and (status_filter is null or (i.kind='task' and status_filter=(case when i.completed then 'done' else 'todo' end)))
    union all
    select 'task',t.id,coalesce(t.room_id,t.chat_id),t.title,''::text,t.created_at from public.st_v6_tasks t
    where (p_kind is null or p_kind='task') and (room_filter is null or t.room_id=room_filter)
      and not has_file and not mentions_me and (sender_id is null or t.author_id=sender_id)
      and (needle='' or lower(t.title) like match_pattern or to_tsvector('simple',t.title) @@ terms)
      and (status_filter is null or t.status=status_filter)
    union all
    select 'meeting',m.id,m.workspace_id,m.title,m.agenda,m.starts_at from public.st_v3_meetings m
    where (p_kind is null or p_kind='meeting') and room_filter is null and not has_file and not mentions_me
      and (needle='' or lower(m.title) like match_pattern or lower(m.agenda) like match_pattern
        or to_tsvector('simple',m.title) @@ terms or to_tsvector('simple',m.agenda) @@ terms)
      and (sender_id is null or m.host_id=sender_id) and (status_filter is null or m.status=status_filter)
    union all
    select 'room_name',r.id,r.workspace_id,r.name,''::text,r.created_at from public.st_v6_rooms r
    where (p_kind is null or p_kind='room_name') and not r.archived and not has_file and not mentions_me
      and (room_filter is null or r.id=room_filter) and sender_id is null and status_filter is null
      and (needle='' or lower(r.name) like match_pattern or to_tsvector('simple',r.name) @@ terms)
    union all
    select 'file',f.id,f.chat_id,f.filename,''::text,f.created_at from public.st_v5_files f
    join public.st_messages m on m.id=f.message_id and m.chat_id=f.chat_id
    where (p_kind is null or p_kind='file') and room_filter is null and status_filter is null and not mentions_me
      and m.revoked_at is null and m.expires_at is null and (sender_id is null or f.uploader=sender_id)
      and (needle='' or lower(f.filename) like match_pattern or to_tsvector('simple',f.filename) @@ terms)
      and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=(select auth.uid()))
    union all
    select 'person',p.id,p.id,p.name,'@'||p.handle,'epoch'::timestamptz from public.st_v6_search_people p
    where (p_kind is null or p_kind='person') and needle<>'' and sender_id is null and status_filter is null
      and room_filter is null and date_from is null and date_until is null and not has_file and not mentions_me
      and (lower(p.name||' '||p.handle) like match_pattern or to_tsvector('simple',p.name||' '||p.handle) @@ terms)
  ) r
  cross join lateral (select greatest(1,strpos(lower(r.preview),needle)-30) as start_at) clip
  where (date_from is null or r.ts>=date_from) and (date_until is null or r.ts<date_until)
  order by r.ts desc,r.obj desc,r.scope desc,r.category limit 40;
end $$;

create or replace function public.st_v6_task_create(p_id uuid,p_room uuid,p_chat uuid,p_title text,p_source uuid default null,
  p_due_at timestamptz default null,p_priority text default 'normal',p_labels text[] default '{}')
returns uuid language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); normalized text[]; snapshot text; source_created timestamptz; inserted uuid;
begin
  perform sectalk_private.limit_action('v6_task_create',12);
  if num_nonnulls(p_room,p_chat)<>1 or not sectalk_private.st_v6_task_scope_write(p_room,p_chat)
    then raise exception 'Task scope unavailable'; end if;
  normalized:=sectalk_private.st_v6_task_labels(p_labels);
  if p_source is not null then
    if p_room is not null then
      select m.body,m.created_at into snapshot,source_created from public.st_v6_room_posts m where m.room_id=p_room
        and m.id=p_source and m.removed_at is null for share;
    else
      select m.body,m.created_at into snapshot,source_created from public.st_messages m where m.chat_id=p_chat and m.id=p_source
        and m.revoked_at is null and m.expires_at is null and not exists(select 1 from public.st_v5_hidden_messages h
          where h.user_id=actor and h.message_id=m.id) for share;
    end if;
    if snapshot is null then raise exception 'Source message unavailable'; end if;
  end if;
  insert into public.st_v6_tasks(id,room_id,chat_id,author_id,title,due_at,priority,labels)
    values(p_id,p_room,p_chat,actor,btrim(p_title),p_due_at,p_priority,normalized)
    on conflict(id) do nothing returning id into inserted;
  if inserted is null then
    if exists(select 1 from public.st_v6_tasks t left join sectalk_private.st_v6_task_sources s on s.task_id=t.id
      where t.id=p_id and t.author_id=actor and t.room_id is not distinct from p_room and t.chat_id is not distinct from p_chat
        and t.title=btrim(p_title) and t.due_at is not distinct from p_due_at and t.priority=p_priority and t.labels=normalized
        and s.message_id is not distinct from p_source) then return p_id; end if;
    raise exception 'Task ID already in use';
  end if;
  if p_source is not null then
    insert into sectalk_private.st_v6_task_sources(task_id,message_id,message_created_at,snapshot) values(p_id,p_source,source_created,snapshot);
  end if;
  insert into public.st_v6_task_audit(task_id,actor_id,action,detail)
    values(p_id,actor,'created',jsonb_build_object('status','todo','priority',p_priority));
  return p_id;
end $$;

commit;
