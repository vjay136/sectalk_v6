begin;

alter table public.st_v6_saved_searches
  add column filters jsonb not null default '{}'::jsonb,
  drop constraint st_v6_saved_searches_user_id_query_kind_key,
  drop constraint st_v6_saved_searches_query_check,
  drop constraint st_v6_saved_searches_kind_check,
  add constraint st_v6_saved_searches_query_check check(
    query=btrim(query) and (char_length(query) between 2 and 120 or (query='' and (kind<>'all' or filters<>'{}'::jsonb)))
  ),
  add constraint st_v6_saved_searches_kind_check check(kind in ('all','direct','channel','room','board','task','meeting')),
  add constraint st_v6_saved_searches_filters_check check(jsonb_typeof(filters)='object' and octet_length(filters::text)<=512),
  add unique(user_id,query,kind,filters);
grant insert(filters) on public.st_v6_saved_searches to authenticated;

create function public.st_v6_search(p_query text,p_kind text,p_filters jsonb)
returns table(kind text,id uuid,scope_id uuid,title text,snippet text,at timestamptz)
language plpgsql stable security invoker set search_path='' as $$
declare
  needle text:=lower(btrim(coalesce(p_query,'')));
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
      and (not has_file or exists(select 1 from public.st_v5_files f where f.message_id=m.id and f.chat_id=m.chat_id))
      and (not mentions_me or m.body ~* mention_pattern)
      and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=(select auth.uid()))
    union all
    select 'channel',p.id,c.workspace_id,'#'||c.name,p.body,p.created_at
    from public.st_v2_posts p join public.st_v2_channels c on p.channel_id=c.id
    where (p_kind is null or p_kind='channel') and room_filter is null and status_filter is null
      and not has_file and (sender_id is null or p.sender=sender_id) and (not mentions_me or p.body ~* mention_pattern)
    union all
    select 'room',p.id,r.id,'#'||r.name,p.body,p.created_at
    from public.st_v6_room_posts p join public.st_v6_rooms r on p.room_id=r.id
    where (p_kind is null or p_kind='room') and (room_filter is null or r.id=room_filter) and status_filter is null
      and not has_file and p.removed_at is null and (sender_id is null or p.sender=sender_id)
      and (not mentions_me or p.body ~* mention_pattern)
    union all
    select 'board',i.id,i.workspace_id,i.title,i.details,i.created_at from public.st_v2_items i
    where (p_kind is null or p_kind='board') and room_filter is null and not has_file and not mentions_me
      and (sender_id is null or i.created_by=sender_id)
      and (status_filter is null or (i.kind='task' and status_filter=(case when i.completed then 'done' else 'todo' end)))
    union all
    select 'task',t.id,coalesce(t.room_id,t.chat_id),t.title,''::text,t.created_at from public.st_v6_tasks t
    where (p_kind is null or p_kind='task') and (room_filter is null or t.room_id=room_filter)
      and not has_file and not mentions_me and (sender_id is null or t.author_id=sender_id)
      and (status_filter is null or t.status=status_filter)
    union all
    select 'meeting',m.id,m.workspace_id,m.title,m.agenda,m.starts_at from public.st_v3_meetings m
    where (p_kind is null or p_kind='meeting') and room_filter is null and not has_file and not mentions_me
      and (sender_id is null or m.host_id=sender_id) and (status_filter is null or m.status=status_filter)
  ) r
  cross join lateral (select greatest(1,strpos(lower(r.preview),needle)-30) as start_at) clip
  where (date_from is null or r.ts>=date_from) and (date_until is null or r.ts<date_until)
    and (needle='' or strpos(lower(r.preview),needle)>0
      or (r.category in ('board','task','meeting') and strpos(lower(r.heading),needle)>0))
  order by r.ts desc,r.obj desc,r.scope desc,r.category limit 40;
end $$;

revoke all on function public.st_v6_search(text,text,jsonb) from public,anon,authenticated;
grant execute on function public.st_v6_search(text,text,jsonb) to authenticated;

commit;
