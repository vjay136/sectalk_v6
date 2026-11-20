begin;

create function public.st_v6_search(p_query text,p_kind text)
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
      where (p_kind is null or p_kind='direct') and m.revoked_at is null
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

revoke all on function public.st_v6_search(text,text) from public,anon,authenticated;
grant execute on function public.st_v6_search(text,text) to authenticated;

create or replace function public.st_v3_search(p_query text,p_kind text)
returns table(kind text,id uuid,scope_id uuid,title text,snippet text,at timestamptz)
language sql stable security invoker set search_path='' as $$
  select * from public.st_v6_search(p_query,p_kind)
$$;

create or replace function public.st_v6_ready()
returns boolean language sql stable security invoker set search_path='' as $$
  select to_regclass('public.st_v6_saved_messages') is not null
    and to_regclass('public.st_v6_rooms') is not null
    and to_regclass('public.st_v6_saved_searches') is not null
    and to_regclass('public.st_v6_thread_follows') is not null
    and to_regclass('public.st_v6_tasks') is not null
    and to_regprocedure('public.st_v6_search(text,text)') is not null
$$;

commit;
