begin;

alter table sectalk_private.st_v6_file_downloads
  add column event text not null default 'download',
  alter column ticket_id drop not null,
  add constraint st_v6_file_access_shape check(
    (event='download' and ticket_id is not null) or (event='view' and ticket_id is null)
  );

-- Reopening the same details dialog within five minutes is one metadata view.
create unique index st_v6_file_detail_views_window on sectalk_private.st_v6_file_downloads(
  file_id,actor_id,date_bin(interval '5 minutes',requested_at,'2000-01-01 00:00:00+00'::timestamptz)
) where event='view';

create function public.st_v6_view_file_details(p_file uuid)
returns table(filename text,size_bytes integer,shared_at timestamptz,can_view_history boolean)
language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare details record;
begin
  if actor is null or not sectalk_private.st_v2_active(actor) then return; end if;
  perform sectalk_private.limit_action('v6_file_detail_view',30);
  select f.filename,f.size_bytes,m.created_at as shared_at,f.uploader=actor as owner
    into details from public.st_v5_files f join public.st_messages m on m.id=f.message_id
    where f.id=p_file and m.revoked_at is null and sectalk_private.member(f.chat_id,actor)
      and not exists(select 1 from public.st_v5_hidden_messages h
        where h.user_id=actor and h.message_id=m.id);
  if not found then return; end if;
  insert into sectalk_private.st_v6_file_downloads(file_id,actor_id,event)
    values(p_file,actor,'view') on conflict do nothing;
  return query select details.filename,details.size_bytes,details.shared_at,details.owner;
end
$$;

create function public.st_v6_file_access_history(p_file uuid)
returns table(event text,participant text,occurred_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare context record;
begin
  if actor is null or not sectalk_private.st_v2_active(actor) then
    raise exception 'Attachment access history is unavailable' using errcode='42501';
  end if;
  select c.member_a,c.member_b,m.created_at as shared_at into context
    from public.st_v5_files f join public.st_chats c on c.id=f.chat_id
    join public.st_messages m on m.id=f.message_id
    where f.id=p_file and f.uploader=actor and actor in (c.member_a,c.member_b);
  if not found then raise exception 'Attachment access history is unavailable' using errcode='42501'; end if;

  return query
    select activity.event,activity.participant,activity.occurred_at from (
      select 'share'::text as event,'owner'::text as participant,context.shared_at as occurred_at,0::bigint as audit_order
      union all
      select d.event,case when d.actor_id=actor then 'owner' else 'recipient' end,d.requested_at,d.id
      from sectalk_private.st_v6_file_downloads d
      -- Moderator evidence activity remains in the private audit and is unavailable to the uploader.
      where d.file_id=p_file and d.actor_id in (context.member_a,context.member_b)
    ) activity order by activity.occurred_at desc,activity.audit_order desc limit 50;
end
$$;

revoke all on function public.st_v6_view_file_details(uuid),public.st_v6_file_access_history(uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_view_file_details(uuid),public.st_v6_file_access_history(uuid) to authenticated;

commit;
