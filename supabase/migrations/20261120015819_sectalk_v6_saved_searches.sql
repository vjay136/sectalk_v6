begin;

create table public.st_v6_saved_searches (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references public.st_profiles on delete cascade,
  query text not null check(char_length(btrim(query)) between 2 and 120 and query=btrim(query)),
  kind text not null check(kind in ('all','direct','channel','board','meeting')),
  created_at timestamptz not null default now(),
  unique(user_id,query,kind)
);
create index st_v6_saved_searches_recent on public.st_v6_saved_searches(user_id,created_at desc,id desc);
alter table public.st_v6_saved_searches enable row level security;
revoke all on public.st_v6_saved_searches from public,anon,authenticated;
grant select,delete on public.st_v6_saved_searches to authenticated;
grant insert(query,kind) on public.st_v6_saved_searches to authenticated;
create policy st_v6_searches_read on public.st_v6_saved_searches for select to authenticated using(user_id=(select auth.uid()));
create policy st_v6_searches_insert on public.st_v6_saved_searches for insert to authenticated with check(user_id=(select auth.uid()));
create policy st_v6_searches_remove on public.st_v6_saved_searches for delete to authenticated using(user_id=(select auth.uid()));

create or replace function public.st_v6_ready()
returns boolean language sql stable security invoker set search_path='' as $$
  select to_regclass('public.st_v6_saved_messages') is not null
    and to_regclass('public.st_v6_rooms') is not null
    and to_regclass('public.st_v6_saved_searches') is not null
$$;

commit;
