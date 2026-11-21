begin;

create or replace function public.st_v3_media_access(p_meeting uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(
    select 1
    from public.st_v3_meetings m
    join public.st_v3_attendance a on m.id=a.meeting_id
    where m.id=p_meeting and m.media_protection=0
      and a.user_id=auth.uid() and a.status='admitted'
      and m.status='live' and m.ends_at>now()
      and sectalk_private.st_v8_entry_sso_allows(m.workspace_id)
      and sectalk_private.st_v3_meeting_visible(m.id,auth.uid())
      and sectalk_private.st_v2_active(auth.uid()) and sectalk_private.st_v3_is_host(m.id,m.host_id)
      and sectalk_private.st_v2_active(m.host_id) and sectalk_private.open_pair(m.host_id,auth.uid())
  )
$$;

commit;
