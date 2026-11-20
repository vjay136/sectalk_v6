begin;

create function public.st_v6_call_ice_session(p_call uuid)
returns timestamptz
language plpgsql
security definer
set search_path=''
as $$
declare
  actor uuid:=auth.uid();
  end_time timestamptz;
begin
  perform sectalk_private.limit_action('v6_call_ice',12);
  select c.expires_at into end_time
    from public.st_calls c join public.st_chats ch on ch.id=c.chat_id
    where c.id=p_call and ch.status='accepted' and sectalk_private.call_access(c.id,actor);
  return end_time;
end $$;

revoke all on function public.st_v6_call_ice_session(uuid) from public, anon, authenticated;
grant execute on function public.st_v6_call_ice_session(uuid) to authenticated;

commit;
