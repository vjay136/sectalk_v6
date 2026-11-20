begin;

alter table public.st_v3_notifications
  drop constraint st_v3_notifications_kind_check,
  add column room_id uuid,
  add column room_post_id uuid,
  add constraint st_v3_notifications_room_post_fk foreign key(room_id,room_post_id)
    references public.st_v6_room_posts(room_id,id) match full on delete cascade,
  add constraint st_v3_notifications_kind_check check(
    (kind in ('meeting.scheduled','meeting.started','meeting.admitted','meeting.declined') and room_id is null)
    or (kind in ('mention.user','mention.group','mention.here','mention.channel')
      and room_id is not null and meeting_id is null)
  );

create unique index st_v6_notification_room_mentions
  on public.st_v3_notifications(room_id,room_post_id,recipient);

alter policy st_v3_notification_read on public.st_v3_notifications
  using(recipient=(select auth.uid()) and sectalk_private.st_v2_role(workspace_id,(select auth.uid())) is not null
    and (room_id is null or exists(
      select 1 from public.st_v6_room_posts post
      where (post.room_id,post.id)=(st_v3_notifications.room_id,st_v3_notifications.room_post_id)
        and post.removed_at is null
    )));

create function sectalk_private.st_v3_mark_notification(p_id bigint,p_category text)
returns void language sql security definer set search_path='' as $$
  update public.st_v3_notifications set read_at=clock_timestamp()
    where auth.uid() is not null and recipient=auth.uid() and (p_id is null or id=p_id) and read_at is null
      and p_category in ('meeting','mention') and split_part(kind,'.',1)=p_category
      and sectalk_private.st_v2_role(workspace_id,auth.uid()) is not null
      and (room_id is null or sectalk_private.st_v6_room_role(room_id) is not null)
$$;

create function public.st_v3_mark_notification(p_id bigint,p_category text)
returns void language sql set search_path=''
return sectalk_private.st_v3_mark_notification(p_id,p_category);

create or replace function public.st_v3_mark_notification(p_id bigint)
returns void language sql security invoker set search_path=''
return sectalk_private.st_v3_mark_notification(p_id,'meeting');

revoke all on function public.st_v3_mark_notification(bigint,text),
  sectalk_private.st_v3_mark_notification(bigint,text) from public,anon,authenticated;
grant execute on function public.st_v3_mark_notification(bigint,text),
  sectalk_private.st_v3_mark_notification(bigint,text) to authenticated;

create or replace function sectalk_private.st_v6_room_post_alert()
returns trigger language plpgsql security definer set search_path='' as $$
declare
  can_broadcast boolean:=coalesce(sectalk_private.st_v6_room_role(new.room_id) in ('owner','moderator'),false);
  alert record;
begin
  for alert in
  with tokens as materialized (
    select lower(replace(match[2],'""','"')) as group_name,
      lower(match[3]) as explicit_handle,lower(match[4]) as handle
    from regexp_matches(new.body,
      '(^|[^[:alnum:]_@])@(?:group:"((?:[^"]|""){1,80})"|user:([a-z0-9_]{3,24})|(?!(?:group|user):)([a-z0-9_]{3,24}))(?![[:alnum:]_@])',
      'gi') as match
  ), audiences as materialized (
    select r.workspace_id,recipients.user_id
    from public.st_v6_rooms r
    cross join lateral (
      select m.user_id from public.st_v6_room_members m where r.kind<>'admin' and m.room_id=r.id
      union all
      select m.user_id from public.st_v2_members m
        where r.kind='admin' and m.workspace_id=r.workspace_id and m.role in ('owner','admin')
    ) recipients
    where r.id=new.room_id and recipients.user_id<>new.sender and not r.archived
      and sectalk_private.st_v2_active(recipients.user_id)
      and sectalk_private.st_v2_role(r.workspace_id,recipients.user_id) is not null
      and not exists(select 1 from public.st_v6_room_bans b where b.room_id=r.id and b.user_id=recipients.user_id)
      and sectalk_private.open_pair(new.sender,recipients.user_id)
      and not sectalk_private.st_v6_room_alert_quiet(recipients.user_id,r.id)
  ), group_recipients as (
    select distinct membership.user_id
    from tokens
    join public.st_v6_workspace_groups item on item.workspace_id=(select workspace_id from public.st_v6_rooms where id=new.room_id)
      and item.kind='group' and item.archived_at is null and lower(item.name)=tokens.group_name
    join public.st_v6_workspace_group_members membership on (membership.workspace_id,membership.group_id)=(item.workspace_id,item.id)
    where can_broadcast
  ), notices as (
    insert into public.st_v3_notifications(recipient,workspace_id,room_id,room_post_id,kind)
    select audience.user_id,audience.workspace_id,new.room_id,new.id,mention.kind
    from audiences audience
    join public.st_profiles profile on profile.id=audience.user_id
    cross join lateral (values (case
      when exists(select 1 from tokens where explicit_handle=profile.handle
        or (handle=profile.handle and handle not in ('channel','here')))
        then 'mention.user'
      when can_broadcast and exists(select 1 from group_recipients where user_id=audience.user_id)
        then 'mention.group'
      when can_broadcast and exists(select 1 from tokens where handle='here') and exists(
        select 1 from public.st_v3_presence presence
        where presence.user_id=audience.user_id and presence.state='online' and presence.expires_at>clock_timestamp()
      ) then 'mention.here'
      when can_broadcast and exists(select 1 from tokens where handle='channel') then 'mention.channel'
    end)) mention(kind)
    where mention.kind is not null
    on conflict (room_id,room_post_id,recipient) do nothing
    returning recipient,kind
  )
  select audience.user_id,notices.kind
  from audiences audience
  left join notices on notices.recipient=audience.user_id
  loop
    perform realtime.send(jsonb_strip_nulls(jsonb_build_object('room_id',new.room_id,'mention_kind',alert.kind)),
      'room_activity','st:account:'||alert.user_id,true);
  end loop;
  return new;
end
$$;

commit;
