begin;

alter table public.st_messages add column forwarded boolean not null default false;
alter table public.st_v6_room_posts add column forwarded boolean not null default false;
alter table public.st_v6_rooms add column forwarding_allowed boolean not null default true;

create function sectalk_private.st_v6_write_message(p_actor uuid,p_chat uuid,p_id uuid,p_body text,p_forwarded boolean)
returns text language plpgsql security definer set search_path='' as $$
declare conversation public.st_chats; existing public.st_messages;
begin
  select * into conversation from public.st_chats where id=p_chat and p_actor in (member_a,member_b) for update;
  if not found or conversation.status<>'accepted' or not sectalk_private.open_pair(conversation.member_a,conversation.member_b)
    then return 'unavailable'; end if;
  -- A failed insert rolls back its counter allocation, including simultaneous reuse in a different chat.
  begin
    insert into public.st_messages(id,chat_id,sender,body,created_at,forwarded)
      values(p_id,p_chat,p_actor,btrim(p_body),clock_timestamp(),p_forwarded);
  exception when unique_violation then
    select * into existing from public.st_messages where id=p_id;
    if found and existing.chat_id=p_chat and existing.sender=p_actor and existing.body=btrim(p_body)
      and existing.forwarded=p_forwarded then return 'sent'; end if;
    return 'collision';
  end;
  update public.st_chats set updated_at=clock_timestamp() where id=p_chat;
  return 'sent';
end $$;

create or replace function sectalk_private.st_v6_write_message(p_actor uuid,p_chat uuid,p_id uuid,p_body text)
returns text language sql security definer set search_path='' as $$
  select sectalk_private.st_v6_write_message(p_actor,p_chat,p_id,p_body,false)
$$;

create function sectalk_private.st_v6_write_room_post(p_room uuid,p_id uuid,p_body text,p_kind text,p_parent uuid,p_forwarded boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); r public.st_v6_rooms; actor_room_role text;
begin
  select * into r from public.st_v6_rooms where id=p_room for update;
  actor_room_role:=sectalk_private.st_v6_room_role(p_room);
  if not found or r.archived or actor_room_role is null or actor_room_role='read_only'
    or (r.locked and actor_room_role not in ('owner','moderator'))
    or ((r.kind in ('announcement','broadcast') or p_kind='announcement') and actor_room_role not in ('owner','moderator'))
    or (r.kind='announcement' and p_kind is distinct from 'announcement')
    or (p_kind='announcement' and p_parent is not null)
    or exists(select 1 from public.st_v6_room_timeouts where room_id=p_room and user_id=actor and until_at>now())
    then raise exception 'Posting is unavailable'; end if;
  if exists(select 1 from public.st_v6_room_posts where room_id=p_room and id=p_id) then
    if exists(select 1 from public.st_v6_room_posts where room_id=p_room and id=p_id and sender=actor
      and body=btrim(p_body) and kind=p_kind and parent_id is not distinct from p_parent and forwarded=p_forwarded) then return; end if;
    raise exception 'Message ID already in use';
  end if;
  if p_parent is not null and not exists(select 1 from public.st_v6_room_posts where room_id=p_room and id=p_parent and parent_id is null)
    then raise exception 'Thread unavailable'; end if;
  if r.slow_seconds>0 and actor_room_role not in ('owner','moderator')
    and exists(select 1 from public.st_v6_room_posts where room_id=p_room and sender=actor and created_at>clock_timestamp()-make_interval(secs=>r.slow_seconds))
    then raise exception 'Slow mode is on. Wait before posting again.'; end if;
  insert into public.st_v6_room_posts(room_id,id,sender,body,kind,parent_id,forwarded)
    values(p_room,p_id,actor,btrim(p_body),p_kind,p_parent,p_forwarded);
  if p_kind='announcement' then
    insert into public.st_v6_room_audit(room_id,actor,action,target) values(p_room,actor,'post.announcement',p_id);
  end if;
end $$;

create or replace function public.st_v6_room_post(p_room uuid,p_id uuid,p_body text,p_kind text default 'message',p_parent uuid default null)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('v6_room_post',45);
  perform sectalk_private.st_v6_write_room_post(p_room,p_id,p_body,p_kind,p_parent,false);
end $$;

create function public.st_v6_forward_direct(p_source_chat uuid,p_source_message uuid,p_destination uuid,p_id uuid)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); snapshot text; outcome text;
begin
  if actor is null or p_id is null or p_source_chat is null or p_destination is null or p_source_chat=p_destination
    then raise exception 'Forwarding is unavailable'; end if;
  perform sectalk_private.limit_action('message',60);
  perform id from public.st_chats where id in (p_source_chat,p_destination) and actor in (member_a,member_b) order by id for update;
  if not exists(select 1 from public.st_chats c where c.id=p_source_chat and actor in (c.member_a,c.member_b)
    and c.status='accepted' and sectalk_private.open_pair(c.member_a,c.member_b))
    then raise exception 'Forwarding is unavailable'; end if;

  select m.body into snapshot from public.st_messages m
  where m.id=p_source_message and m.chat_id=p_source_chat and m.revoked_at is null
    and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=actor)
    and not exists(select 1 from public.st_v5_files f where f.message_id=m.id)
  for share of m;
  if not found then raise exception 'Forwarding is unavailable'; end if;

  outcome:=sectalk_private.st_v6_write_message(actor,p_destination,p_id,snapshot,true);
  if outcome='unavailable' then raise exception 'Forwarding is unavailable'; end if;
  if outcome='collision' then raise exception 'Message ID already in use'; end if;
end $$;

create function sectalk_private.st_v6_room_can_forward(p_room uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v6_rooms r where r.id=p_room and r.kind='public'
    and r.forwarding_allowed and not r.archived and not r.locked
    and sectalk_private.st_v6_room_role(r.id) in ('owner','moderator','member'))
$$;

create function public.st_v6_forward_room_destinations(p_room uuid)
returns table(id uuid,name text) language sql stable security definer set search_path='' as $$
  select destination.id,destination.name
  from public.st_v6_rooms source
  join public.st_v6_rooms destination on destination.workspace_id=source.workspace_id and destination.id<>source.id
  where source.id=p_room and sectalk_private.st_v6_room_can_forward(source.id)
    and sectalk_private.st_v6_room_can_forward(destination.id)
  order by destination.name,destination.id limit 250
$$;

create function public.st_v6_forward_room(p_source_room uuid,p_source_message uuid,p_destination uuid,p_id uuid)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); source_workspace uuid; snapshot text;
begin
  if actor is null or p_id is null or p_source_room is null or p_destination is null or p_source_room=p_destination
    then raise exception 'Forwarding is unavailable'; end if;
  if not sectalk_private.st_v6_room_can_forward(p_source_room) or not sectalk_private.st_v6_room_can_forward(p_destination)
    then raise exception 'Forwarding is unavailable'; end if;
  select workspace_id into source_workspace from public.st_v6_rooms where id=p_source_room;
  if not exists(select 1 from public.st_v6_rooms where id=p_destination and workspace_id=source_workspace)
    then raise exception 'Forwarding is unavailable'; end if;
  perform sectalk_private.limit_action('v6_room_post',45);
  perform id from public.st_v6_rooms where id in (p_source_room,p_destination) order by id for update;
  if not sectalk_private.st_v6_room_can_forward(p_source_room) or not sectalk_private.st_v6_room_can_forward(p_destination)
    then raise exception 'Forwarding is unavailable'; end if;

  select m.body into snapshot from public.st_v6_room_posts m
  where m.room_id=p_source_room and m.id=p_source_message and m.removed_at is null and m.kind='message'
  for share of m;
  if not found then raise exception 'Forwarding is unavailable'; end if;
  perform sectalk_private.st_v6_write_room_post(p_destination,p_id,snapshot,'message',null,true);
end $$;

create function public.st_v6_set_room_forwarding(p_room uuid,p_allowed boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_room_settings',20);
  if p_allowed is null or not coalesce(sectalk_private.st_v6_room_role(p_room) in ('owner','moderator'),false)
    then raise exception 'Room settings unavailable'; end if;
  update public.st_v6_rooms set forwarding_allowed=p_allowed where id=p_room and kind='public' and not archived
    and sectalk_private.st_v6_room_role(p_room) in ('owner','moderator');
  if not found then raise exception 'Room settings unavailable'; end if;
  insert into public.st_v6_room_audit(room_id,actor,action)
  values(p_room,actor,case when p_allowed then 'room.forwarding_enabled' else 'room.forwarding_disabled' end);
end $$;

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
    where not new.forwarded
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
        where presence.user_id=audience.user_id and sectalk_private.st_v6_shares_presence(audience.user_id)
          and presence.state='online' and presence.expires_at>clock_timestamp()
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

revoke all on function sectalk_private.st_v6_write_message(uuid,uuid,uuid,text,boolean),
  sectalk_private.st_v6_write_room_post(uuid,uuid,text,text,uuid,boolean),
  sectalk_private.st_v6_room_can_forward(uuid) from public,anon,authenticated;
revoke all on function public.st_v6_forward_direct(uuid,uuid,uuid,uuid),
  public.st_v6_forward_room_destinations(uuid),public.st_v6_forward_room(uuid,uuid,uuid,uuid),
  public.st_v6_set_room_forwarding(uuid,boolean) from public,anon,authenticated;
grant execute on function public.st_v6_forward_direct(uuid,uuid,uuid,uuid),
  public.st_v6_forward_room_destinations(uuid),public.st_v6_forward_room(uuid,uuid,uuid,uuid),
  public.st_v6_set_room_forwarding(uuid,boolean) to authenticated;

commit;
