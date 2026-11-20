begin;

create table sectalk_private.st_v7_search_pending (
  kind text not null,
  object_id uuid not null,
  position bigint generated always as identity,
  primary key(kind,object_id)
);
create index st_v7_search_pending_position on sectalk_private.st_v7_search_pending(position);
create table sectalk_private.st_v7_search_document (
  kind text not null,
  object_id uuid not null,
  fingerprint bytea not null,
  first_terms tsvector not null,
  second_terms tsvector not null,
  primary key(kind,object_id)
);
create table sectalk_private.st_v7_search_scan (
  singleton boolean primary key default true check(singleton),
  mode text check(mode in ('backfill','rebuild')),
  source_no integer not null default 1,
  after_id uuid,
  finished_at timestamptz
);
insert into sectalk_private.st_v7_search_scan(mode) values('backfill');
alter table sectalk_private.st_v7_search_pending enable row level security;
alter table sectalk_private.st_v7_search_document enable row level security;
alter table sectalk_private.st_v7_search_scan enable row level security;

-- This closed source list excludes encrypted group messages and all private attachment bodies.
create view sectalk_private.st_v7_search_sources as
  select 'direct'::text kind,id,body first_field,''::text second_field from public.st_messages where revoked_at is null and expires_at is null
  union all select 'channel',id,body,'' from public.st_v2_posts
  union all select 'room',id,body,'' from public.st_v6_room_posts where removed_at is null
  union all select 'board',id,title,details from public.st_v2_items
  union all select 'task',id,title,'' from public.st_v6_tasks
  union all select 'meeting',id,title,agenda from public.st_v3_meetings
  union all select 'room_name',id,name,'' from public.st_v6_rooms where not archived
  union all select 'file',id,filename,'' from public.st_v5_files
  union all select 'person',id,name||' '||handle,'' from public.st_profiles;
revoke all on sectalk_private.st_v7_search_pending,sectalk_private.st_v7_search_document,sectalk_private.st_v7_search_scan,
  sectalk_private.st_v7_search_sources from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_enqueue_search()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if tg_op='DELETE' then
    insert into sectalk_private.st_v7_search_pending(kind,object_id) values(tg_argv[0],old.id) on conflict do nothing;
    return old;
  end if;
  insert into sectalk_private.st_v7_search_pending(kind,object_id) values(tg_argv[0],new.id) on conflict do nothing;
  return new;
end
$$;

create trigger st_v7_search_direct after insert or delete or update of body,revoked_at,expires_at on public.st_messages
for each row execute function sectalk_private.st_v7_enqueue_search('direct');
create trigger st_v7_search_channel after insert or delete or update of body on public.st_v2_posts
for each row execute function sectalk_private.st_v7_enqueue_search('channel');
create trigger st_v7_search_room after insert or delete or update of body,removed_at on public.st_v6_room_posts
for each row execute function sectalk_private.st_v7_enqueue_search('room');
create trigger st_v7_search_board after insert or delete or update of title,details on public.st_v2_items
for each row execute function sectalk_private.st_v7_enqueue_search('board');
create trigger st_v7_search_task after insert or delete or update of title on public.st_v6_tasks
for each row execute function sectalk_private.st_v7_enqueue_search('task');
create trigger st_v7_search_meeting after insert or delete or update of title,agenda on public.st_v3_meetings
for each row execute function sectalk_private.st_v7_enqueue_search('meeting');
create trigger st_v7_search_room_name after insert or delete or update of name,archived on public.st_v6_rooms
for each row execute function sectalk_private.st_v7_enqueue_search('room_name');
create trigger st_v7_search_file after insert or delete or update of filename on public.st_v5_files
for each row execute function sectalk_private.st_v7_enqueue_search('file');
create trigger st_v7_search_person after insert or delete or update of name,handle on public.st_profiles
for each row execute function sectalk_private.st_v7_enqueue_search('person');

create function sectalk_private.st_v7_search_fingerprint(p_first text,p_second text)
returns bytea language sql immutable set search_path=''
return extensions.digest(jsonb_build_array(p_first,p_second)::text,'sha256');

create function sectalk_private.st_v7_search_work(p_batch integer default 200)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  box constant text[]:=array['direct','channel','room','board','task','meeting','room_name','file','person'];
  job sectalk_private.st_v7_search_pending;
  scan sectalk_private.st_v7_search_scan;
  max_items integer:=least(500,greatest(1,coalesce(p_batch,200)));
  processed integer:=0;
  page_size integer;
  page_ids uuid[];
  high uuid;
  first_field text;
  second_field text;
begin
  for job in select * from sectalk_private.st_v7_search_pending order by position limit max_items for update skip locked loop
    select s.first_field,s.second_field into first_field,second_field from sectalk_private.st_v7_search_sources s
      where s.kind=job.kind and s.id=job.object_id;
    if not found then
      delete from sectalk_private.st_v7_search_document d where (d.kind,d.object_id)=(job.kind,job.object_id);
    else
      insert into sectalk_private.st_v7_search_document as d(kind,object_id,fingerprint,first_terms,second_terms)
        values(job.kind,job.object_id,sectalk_private.st_v7_search_fingerprint(first_field,second_field),
          to_tsvector('simple',coalesce(first_field,'')),to_tsvector('simple',coalesce(second_field,'')))
        on conflict(kind,object_id) do update set fingerprint=excluded.fingerprint,first_terms=excluded.first_terms,
          second_terms=excluded.second_terms where d.fingerprint<>excluded.fingerprint or d.first_terms<>excluded.first_terms
            or d.second_terms<>excluded.second_terms;
    end if;
    delete from sectalk_private.st_v7_search_pending p where (p.kind,p.object_id)=(job.kind,job.object_id);
    processed:=processed+1;
  end loop;

  select * into scan from sectalk_private.st_v7_search_scan where singleton for update skip locked;
  if scan.mode is null then return jsonb_build_object('processed',processed,'scanned',0); end if;
  select array_agg(id order by id) into page_ids from (
    select id from (
      (select s.id from sectalk_private.st_v7_search_sources s
       where s.kind=box[scan.source_no] and (scan.after_id is null or s.id>scan.after_id)
       order by s.id limit max_items)
      union
      (select d.object_id from sectalk_private.st_v7_search_document d where scan.mode='rebuild'
       and d.kind=box[scan.source_no] and (scan.after_id is null or d.object_id>scan.after_id)
       order by d.object_id limit max_items)
    ) candidates order by id limit max_items
  ) page;
  page_size:=coalesce(cardinality(page_ids),0);
  high:=page_ids[page_size];
  insert into sectalk_private.st_v7_search_pending(kind,object_id)
    select box[scan.source_no],id from unnest(page_ids) id
    where scan.mode='rebuild' or not exists(select 1 from sectalk_private.st_v7_search_document d
      where d.kind=box[scan.source_no] and d.object_id=id)
    order by id on conflict do nothing;
  if page_size=max_items then
    update sectalk_private.st_v7_search_scan set after_id=high where singleton;
  elsif scan.source_no<cardinality(box) then
    update sectalk_private.st_v7_search_scan set after_id=null,source_no=scan.source_no+1 where singleton;
  else
    update sectalk_private.st_v7_search_scan set mode=null,after_id=null,finished_at=clock_timestamp() where singleton;
  end if;
  return jsonb_build_object('processed',processed,'scanned',page_size);
end
$$;

-- Even a standalone caller learns only the match against its own supplied fields.
-- The digest match selects the cache only when it is identical to the fields that the invoker can currently read.
create function sectalk_private.st_v7_search_lexeme_match(p_kind text,p_object uuid,p_first text,p_second text,p_terms tsquery)
returns boolean language plpgsql stable security definer set search_path='' as $$
declare answer boolean;
begin
  if p_terms is null then return false; end if;
  select d.first_terms @@ p_terms or d.second_terms @@ p_terms into answer
    from sectalk_private.st_v7_search_document d
    where d.kind=p_kind and d.object_id=p_object and d.fingerprint=sectalk_private.st_v7_search_fingerprint(p_first,p_second);
  return coalesce(answer,to_tsvector('simple',coalesce(p_first,'')) @@ p_terms
    or to_tsvector('simple',coalesce(p_second,'')) @@ p_terms);
end
$$;

create function public.st_v7_search_index_operation(p_action text default 'status')
returns jsonb language plpgsql security definer set search_path='' as $$
declare run jsonb;
begin
  if public.st_v6_queue_operations_status()<>'verified' then
    raise exception using errcode='42501',message='Fresh queue operator verification required';
  end if;
  if p_action in ('backfill','rebuild') then
    perform sectalk_private.limit_action('managed_search_scan',10);
    update sectalk_private.st_v7_search_scan set mode=p_action,source_no=1,after_id=null,finished_at=null
      where singleton and mode is null;
  elsif p_action='process' then
    perform sectalk_private.limit_action('managed_search_batch',10);
    run:=sectalk_private.st_v7_search_work(200);
  elsif p_action is distinct from 'status' then
    raise exception using errcode='22023',message='Invalid search queue action';
  end if;
  return (select jsonb_build_object('pending',(select count(*) from sectalk_private.st_v7_search_pending),
    'mode',mode,'finished_at',finished_at,'processed',run->'processed','scanned',run->'scanned')
    from sectalk_private.st_v7_search_scan where singleton);
end
$$;

revoke all on function sectalk_private.st_v7_enqueue_search(),sectalk_private.st_v7_search_fingerprint(text,text),
  sectalk_private.st_v7_search_work(integer),sectalk_private.st_v7_search_lexeme_match(text,uuid,text,text,tsquery),
  public.st_v7_search_index_operation(text) from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v7_search_lexeme_match(text,uuid,text,text,tsquery),
  public.st_v7_search_index_operation(text) to authenticated;

select cron.schedule('sectalk-v7-managed-search-index','* * * * *','select sectalk_private.st_v7_search_work(200)');

create or replace function public.st_v6_search(p_query text,p_kind text,p_filters jsonb)
returns table(kind text,id uuid,scope_id uuid,title text,snippet text,at timestamptz)
language sql stable security invoker set search_path=''
begin atomic
  with raw_filters as materialized (
    select lower(btrim(coalesce(p_query,''))) as needle,
      nullif(p_filters->>'room','')::uuid as room_filter,
      nullif(lower(p_filters->>'sender'),'') as sender_filter,
      nullif(p_filters->>'from','')::timestamptz as date_from,
      nullif(p_filters->>'until','')::timestamptz as date_until,
      nullif(p_filters->>'status','') as status_filter,
      coalesce((p_filters->>'has_file')::boolean,false) as has_file,
      coalesce((p_filters->>'mentions_me')::boolean,false) as mentions_me
  ), candidates as (
    select raw_filters.*,
      '%'||replace(replace(replace(needle,chr(92),repeat(chr(92),2)),'%',chr(92)||'%'),'_',chr(92)||'_')||'%' as match_pattern,
      case when needle ~ '[[:alnum:]]' then phraseto_tsquery('simple',needle) end as terms,
      (select p.id from public.st_profiles p where p.handle=sender_filter) as sender_id,
      (select '(^|[^a-z0-9_@])@'||p.handle||'([^a-z0-9_]|$)' from public.st_profiles p where p.id=auth.uid()) as mention_pattern
    from raw_filters
    where auth.uid() is not null and char_length(needle)<>1 and char_length(needle)<=120
      and (date_from is null or date_until is null or date_from<date_until)
      and (needle<>'' or p_kind is not null or room_filter is not null or sender_filter is not null
        or date_from is not null or date_until is not null or status_filter is not null or has_file or mentions_me)
  ), filters as (
    select * from candidates where (sender_filter is null or sender_id is not null) and (not mentions_me or mention_pattern is not null)
  )

  select r.category,r.obj,r.scope,r.heading,
    (case when clip.start_at>1 then '…' else '' end) || substring(r.preview from clip.start_at for 180) ||
    (case when char_length(r.preview)>=clip.start_at+180 then '…' else '' end),r.ts
  from filters cross join lateral (
    select 'direct'::text as category,m.id as obj,m.chat_id as scope,'Direct message'::text as heading,
      m.body as preview,m.created_at as ts
    from public.st_messages m
    where (p_kind is null or p_kind='direct') and room_filter is null and status_filter is null
      and m.revoked_at is null and m.expires_at is null and (sender_id is null or m.sender=sender_id)
      and (needle='' or lower(m.body) like match_pattern or sectalk_private.st_v7_search_lexeme_match('direct',m.id,m.body,'',terms))
      and (not has_file or exists(select 1 from public.st_v5_files f where f.message_id=m.id and f.chat_id=m.chat_id))
      and (not mentions_me or m.body ~* mention_pattern)
      and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=(select auth.uid()))
    union all
    select 'channel',p.id,c.workspace_id,'#'||c.name,p.body,p.created_at
    from public.st_v2_posts p join public.st_v2_channels c on p.channel_id=c.id
    where (p_kind is null or p_kind='channel') and room_filter is null and status_filter is null
      and (needle='' or lower(p.body) like match_pattern or sectalk_private.st_v7_search_lexeme_match('channel',p.id,p.body,'',terms))
      and not has_file and (sender_id is null or p.sender=sender_id) and (not mentions_me or p.body ~* mention_pattern)
    union all
    select 'room',p.id,r.id,'#'||r.name,p.body,p.created_at
    from public.st_v6_room_posts p join public.st_v6_rooms r on p.room_id=r.id
    where (p_kind is null or p_kind='room') and (room_filter is null or r.id=room_filter) and status_filter is null
      and not has_file and p.removed_at is null and (sender_id is null or p.sender=sender_id)
      and (needle='' or lower(p.body) like match_pattern or sectalk_private.st_v7_search_lexeme_match('room',p.id,p.body,'',terms))
      and (not mentions_me or p.body ~* mention_pattern)
    union all
    select 'board',i.id,i.workspace_id,i.title,i.details,i.created_at from public.st_v2_items i
    where (p_kind is null or p_kind='board') and room_filter is null and not has_file and not mentions_me
      and (sender_id is null or i.created_by=sender_id)
      and (needle='' or lower(i.title) like match_pattern or lower(i.details) like match_pattern
        or sectalk_private.st_v7_search_lexeme_match('board',i.id,i.title,i.details,terms))
      and (status_filter is null or (i.kind='task' and status_filter=(case when i.completed then 'done' else 'todo' end)))
    union all
    select 'task',t.id,coalesce(t.room_id,t.chat_id),t.title,''::text,t.created_at from public.st_v6_tasks t
    where (p_kind is null or p_kind='task') and (room_filter is null or t.room_id=room_filter)
      and not has_file and not mentions_me and (sender_id is null or t.author_id=sender_id)
      and (needle='' or lower(t.title) like match_pattern or sectalk_private.st_v7_search_lexeme_match('task',t.id,t.title,'',terms))
      and (status_filter is null or t.status=status_filter)
    union all
    select 'meeting',m.id,m.workspace_id,m.title,m.agenda,m.starts_at from public.st_v3_meetings m
    where (p_kind is null or p_kind='meeting') and room_filter is null and not has_file and not mentions_me
      and (needle='' or lower(m.title) like match_pattern or lower(m.agenda) like match_pattern
        or sectalk_private.st_v7_search_lexeme_match('meeting',m.id,m.title,m.agenda,terms))
      and (sender_id is null or m.host_id=sender_id) and (status_filter is null or m.status=status_filter)
    union all
    select 'room_name',r.id,r.workspace_id,r.name,''::text,r.created_at from public.st_v6_rooms r
    where (p_kind is null or p_kind='room_name') and not r.archived and not has_file and not mentions_me
      and (room_filter is null or r.id=room_filter) and sender_id is null and status_filter is null
      and (needle='' or lower(r.name) like match_pattern or sectalk_private.st_v7_search_lexeme_match('room_name',r.id,r.name,'',terms))
    union all
    select 'file',f.id,f.chat_id,f.filename,''::text,f.created_at from public.st_v5_files f
    join public.st_messages m on m.id=f.message_id and m.chat_id=f.chat_id
    where (p_kind is null or p_kind='file') and room_filter is null and status_filter is null and not mentions_me
      and m.revoked_at is null and m.expires_at is null and (sender_id is null or f.uploader=sender_id)
      and (needle='' or lower(f.filename) like match_pattern or sectalk_private.st_v7_search_lexeme_match('file',f.id,f.filename,'',terms))
      and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=(select auth.uid()))
    union all
    select 'person',p.id,p.id,p.name,'@'||p.handle,'epoch'::timestamptz from public.st_v6_search_people p
    where (p_kind is null or p_kind='person') and needle<>'' and sender_id is null and status_filter is null
      and room_filter is null and date_from is null and date_until is null and not has_file and not mentions_me
      and (lower(p.name||' '||p.handle) like match_pattern or sectalk_private.st_v7_search_lexeme_match('person',p.id,p.name||' '||p.handle,'',terms))
  ) r
  cross join lateral (select greatest(1,strpos(lower(r.preview),needle)-30) as start_at) clip
  where (date_from is null or r.ts>=date_from) and (date_until is null or r.ts<date_until)
  order by r.ts desc,r.obj desc,r.scope desc,r.category limit 40;
end;

commit;
