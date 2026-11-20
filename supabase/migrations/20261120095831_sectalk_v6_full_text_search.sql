begin;

create extension if not exists pg_trgm with schema extensions;

create index st_v6_search_direct_lexemes on public.st_messages using gin(to_tsvector('simple',body)) where revoked_at is null;
create index st_v6_search_direct_fragments on public.st_messages using gin(lower(body) extensions.gin_trgm_ops) where revoked_at is null;
create index st_v6_search_room_lexemes on public.st_v6_room_posts using gin(to_tsvector('simple',body)) where removed_at is null;
create index st_v6_search_room_fragments on public.st_v6_room_posts using gin(lower(body) extensions.gin_trgm_ops) where removed_at is null;
create index st_v6_search_task_lexemes on public.st_v6_tasks using gin(to_tsvector('simple',title));
create index st_v6_search_task_fragments on public.st_v6_tasks using gin(lower(title) extensions.gin_trgm_ops);
create index st_v6_search_room_name_lexemes on public.st_v6_rooms using gin(to_tsvector('simple',name)) where not archived;
create index st_v6_search_room_name_fragments on public.st_v6_rooms using gin(lower(name) extensions.gin_trgm_ops) where not archived;
create index st_v6_search_file_lexemes on public.st_v5_files using gin(to_tsvector('simple',filename));
create index st_v6_search_file_fragments on public.st_v5_files using gin(lower(filename) extensions.gin_trgm_ops);
create index st_v6_search_people_lexemes on public.st_profiles using gin(to_tsvector('simple',name||' '||handle));
create index st_v6_search_people_fragments on public.st_profiles using gin(lower(name||' '||handle) extensions.gin_trgm_ops);

alter table public.st_v6_saved_searches drop constraint st_v6_saved_searches_kind_check,
  add constraint st_v6_saved_searches_kind_check check
    (kind in ('all','direct','channel','room','board','task','meeting','room_name','file','person'));

create function sectalk_private.st_v6_search_visible_person(p_person uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select u.id is not null and sectalk_private.st_v2_active(u.id) and sectalk_private.st_v2_active(p_person)
    and sectalk_private.open_pair(u.id,p_person)
    and (u.id=p_person or sectalk_private.st_v2_shared_profile(p_person,u.id)
      or exists(select 1 from public.st_chats c where c.member_a=least(u.id,p_person)
        and c.member_b=greatest(u.id,p_person) and c.status='accepted'))
  from (select auth.uid() as id) u
$$;
revoke all on function sectalk_private.st_v6_search_visible_person(uuid) from public,anon,authenticated;
grant execute on function sectalk_private.st_v6_search_visible_person(uuid) to authenticated;

create view public.st_v6_search_people with (security_invoker=true) as
  select p.id,p.name,p.handle from public.st_profiles p
  where sectalk_private.st_v6_search_visible_person(p.id);
revoke all on public.st_v6_search_people from public,anon,authenticated;
grant select on public.st_v6_search_people to authenticated;

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
      and m.revoked_at is null and (sender_id is null or m.sender=sender_id)
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
      and m.revoked_at is null and (sender_id is null or f.uploader=sender_id)
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

commit;
