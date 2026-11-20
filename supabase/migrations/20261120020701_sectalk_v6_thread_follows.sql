begin;

create table public.st_v6_thread_follows (
  room_id uuid not null,
  post_id uuid not null,
  user_id uuid not null default auth.uid() references public.st_profiles on delete cascade,
  followed_at timestamptz not null default now(),
  primary key(room_id,post_id,user_id),
  foreign key(room_id,post_id) references public.st_v6_room_posts(room_id,id) on delete cascade
);
create index st_v6_thread_follows_actor on public.st_v6_thread_follows(user_id,room_id,followed_at desc);
alter table public.st_v6_thread_follows enable row level security;
revoke all on public.st_v6_thread_follows from public,anon,authenticated;
grant select,delete on public.st_v6_thread_follows to authenticated;
grant insert(room_id,post_id) on public.st_v6_thread_follows to authenticated;
create policy st_v6_thread_follows_read on public.st_v6_thread_follows for select to authenticated using(
  user_id=(select auth.uid()) and sectalk_private.st_v6_room_role(room_id) is not null
);
create policy st_v6_thread_follows_add on public.st_v6_thread_follows for insert to authenticated with check(
  user_id=(select auth.uid()) and exists(select 1 from public.st_v6_room_posts p
    where p.room_id=st_v6_thread_follows.room_id and p.id=post_id and p.parent_id is null)
);
create policy st_v6_thread_follows_remove on public.st_v6_thread_follows for delete to authenticated
  using(user_id=(select auth.uid()));

create function public.st_v6_room_thread_state(p_room uuid,p_roots uuid[])
returns table(post_id uuid, replies bigint, following boolean, excerpt text)
language sql stable security invoker set search_path='' as $$
  with follows as materialized (
    select f.post_id from public.st_v6_thread_follows f where f.room_id=p_room and f.user_id=auth.uid()
    order by followed_at desc,f.post_id limit 100
  ), requested as (
    select f.post_id from follows f
    union
    select unnest(p_roots[1:80])
  )
  select p.id,
    (select count(*) from public.st_v6_room_posts reply where reply.room_id=p_room and reply.parent_id=p.id),
    exists(select 1 from follows f where f.post_id=p.id),
    left(p.body,100)
  from public.st_v6_room_posts p join requested r on r.post_id=p.id
  where p.room_id=p_room and p.parent_id is null
$$;
revoke all on function public.st_v6_room_thread_state(uuid,uuid[]) from public,anon,authenticated;
grant execute on function public.st_v6_room_thread_state(uuid,uuid[]) to authenticated;

create or replace function public.st_v6_ready()
returns boolean language sql stable security invoker set search_path='' as $$
  select to_regclass('public.st_v6_saved_messages') is not null
    and to_regclass('public.st_v6_rooms') is not null
    and to_regclass('public.st_v6_saved_searches') is not null
    and to_regclass('public.st_v6_thread_follows') is not null
$$;

commit;
