begin;

create table sectalk_private.st_v6_file_downloads (
  id bigint generated always as identity primary key,
  file_id uuid not null,
  actor_id uuid not null,
  ticket_id uuid not null,
  requested_at timestamptz not null default clock_timestamp()
);
create index st_v6_file_downloads_file on sectalk_private.st_v6_file_downloads(file_id,requested_at desc);
alter table sectalk_private.st_v6_file_downloads enable row level security;
revoke all on sectalk_private.st_v6_file_downloads from public,anon,authenticated;

create function public.st_v6_file_can_read(p_file uuid)
returns boolean language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_file_download',80);
  return sectalk_private.st_v2_active(actor) and exists(
    select 1 from public.st_v5_files f where f.id=p_file and (
      (sectalk_private.member(f.chat_id,actor) and exists(select 1 from public.st_messages m
        where m.id=f.message_id and m.revoked_at is null and not exists(select 1 from public.st_v5_hidden_messages h
          where h.user_id=actor and h.message_id=m.id)))
      or (public.st_staff_status()='verified' and exists(select 1 from sectalk_private.st_v5_attachment_reports e where e.file_id=f.id))
    )
  );
end $$;
revoke all on function public.st_v6_file_can_read(uuid) from public,anon,authenticated;
grant execute on function public.st_v6_file_can_read(uuid) to authenticated;

create function public.st_v6_log_file_download(p_file uuid,p_actor uuid,p_ticket uuid)
returns void language sql security definer set search_path='' as $$
  insert into sectalk_private.st_v6_file_downloads(file_id,actor_id,ticket_id) values(p_file,p_actor,p_ticket)
$$;
revoke all on function public.st_v6_log_file_download(uuid,uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_log_file_download(uuid,uuid,uuid) to service_role;

drop policy st_v5_attachment_read on storage.objects;
alter policy st_v5_attachment_guard_read on storage.objects using(bucket_id<>'sectalk-chat-files');

commit;
