begin;

create index st_v6_digest_missed_calls
  on public.st_calls(callee,created_at desc,id desc)
  where end_reason='missed' or status='ringing';
create index st_v6_digest_mentions
  on public.st_v3_notifications(recipient,created_at desc,id desc)
  where room_id is not null;

create function public.st_v6_notification_digest(p_days integer)
returns table(
  kind text,id text,occurred_at timestamptz,label text,
  workspace_id uuid,room_id uuid,chat_id uuid,video boolean
)
language sql stable security invoker set search_path='' as $$
  with viewer as (
    select auth.uid() as id,now()-make_interval(hours=>case p_days when 1 then 24 when 7 then 168 end) as since
    where p_days in (1,7)
  ), missed_calls as (
    select 'call.missed'::text as kind,c.id::text,c.created_at,coalesce(profile.name,'Contact'),
      null::uuid,null::uuid,c.chat_id,c.video
    from viewer
    join public.st_calls c on c.callee=viewer.id
    left join public.st_profiles profile on profile.id=c.caller
    where c.created_at>=viewer.since
      and (c.end_reason='missed' or (c.status='ringing' and c.expires_at<=now()))
    order by c.created_at desc,c.id desc
    limit 50
  ), mentions as (
    select n.kind,n.id::text,n.created_at,r.name,n.workspace_id,n.room_id,null::uuid,null::boolean
    from viewer
    join public.st_v3_notifications n on n.recipient=viewer.id
    join public.st_v6_rooms r on (r.id,r.workspace_id)=(n.room_id,n.workspace_id)
    where n.room_id is not null and n.created_at>=viewer.since
    order by n.created_at desc,n.id desc
    limit 50
  )
  select * from missed_calls
  union all
  select * from mentions
  order by 3 desc,2 desc
$$;

revoke all on function public.st_v6_notification_digest(integer) from public,anon,authenticated;
grant execute on function public.st_v6_notification_digest(integer) to authenticated;

commit;
