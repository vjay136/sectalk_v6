begin;

create table public.st_v8_moderation_queue_signal (
  id boolean primary key default true check(id),
  revision uuid not null default gen_random_uuid()
);
insert into public.st_v8_moderation_queue_signal default values;
alter table public.st_v8_moderation_queue_signal enable row level security;
revoke all on public.st_v8_moderation_queue_signal from public,anon,authenticated,service_role;
grant select on public.st_v8_moderation_queue_signal to authenticated;

create function sectalk_private.st_v8_can_watch_moderation_queue()
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v6_case_redaction_staff() is true;
$$;
revoke all on function sectalk_private.st_v8_can_watch_moderation_queue() from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v8_can_watch_moderation_queue() to authenticated;
create policy st_v8_moderation_queue_signal_staff on public.st_v8_moderation_queue_signal
  for select to authenticated using((select sectalk_private.st_v8_can_watch_moderation_queue()));

create function sectalk_private.st_v8_signal_moderation_queue()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  update public.st_v8_moderation_queue_signal set revision=gen_random_uuid() where id;
  return null;
end $$;
revoke all on function sectalk_private.st_v8_signal_moderation_queue() from public,anon,authenticated,service_role;
create trigger st_v8_moderation_report_signal after insert or update of status,requested_priority or delete
  on public.st_reports for each statement execute function sectalk_private.st_v8_signal_moderation_queue();

alter publication supabase_realtime add table public.st_v8_moderation_queue_signal;

commit;
