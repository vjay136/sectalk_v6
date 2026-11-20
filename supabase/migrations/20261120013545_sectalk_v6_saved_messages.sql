begin;

create table public.st_v6_saved_messages (
  user_id uuid not null default auth.uid() references public.st_profiles on delete cascade,
  message_id uuid not null references public.st_messages on delete cascade,
  saved_at timestamptz not null default now(),
  primary key(user_id,message_id)
);
create index st_v6_saved_recent on public.st_v6_saved_messages(user_id,saved_at desc,message_id desc);
alter table public.st_v6_saved_messages enable row level security;
revoke all on public.st_v6_saved_messages from public,anon,authenticated;
grant select, delete on public.st_v6_saved_messages to authenticated;
grant insert(message_id) on public.st_v6_saved_messages to authenticated;

create policy st_v6_saved_read on public.st_v6_saved_messages for select to authenticated using(
  user_id=(select auth.uid())
  and exists(select 1 from public.st_messages m where m.id=message_id and m.revoked_at is null)
  and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=st_v6_saved_messages.message_id
    and h.user_id=(select auth.uid()))
);
create policy st_v6_saved_insert on public.st_v6_saved_messages for insert to authenticated with check(
  user_id=(select auth.uid())
  and exists(select 1 from public.st_messages m where m.id=message_id and m.revoked_at is null)
  and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=st_v6_saved_messages.message_id
    and h.user_id=(select auth.uid()))
);
create policy st_v6_saved_remove on public.st_v6_saved_messages for delete to authenticated
  using(user_id=(select auth.uid()));

-- The public readiness probe discloses a boolean and reads no account data.
create function public.st_v6_ready()
returns boolean language sql stable security invoker set search_path='' as $$
  select to_regclass('public.st_v6_saved_messages') is not null
$$;
revoke all on function public.st_v6_ready() from public,anon,authenticated;
grant execute on function public.st_v6_ready() to anon,authenticated;

commit;
