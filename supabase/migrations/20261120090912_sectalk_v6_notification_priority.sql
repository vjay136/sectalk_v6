begin;

create function sectalk_private.st_v6_alert_priority(p_kind text)
returns table(category text,priority text)
language sql immutable set search_path='' as $$
  select rules.category,rules.priority
  from (values
    ('security.account','security','critical'),
    ('mention.user','mention','high'),
    ('mention.group','mention','high'),
    ('task.due','task','high'),
    ('mention.here','mention','normal'),
    ('mention.channel','mention','normal'),
    ('thread.reply','thread','normal'),
    ('task.completed','task','normal'),
    ('security.report','security','normal'),
    ('billing.subscription','billing','normal'),
    ('admin.room','admin','normal')
  ) rules(kind,category,priority)
  where rules.kind=p_kind
$$;

-- Only internal producers can use this policy. The event kind determines the priority
-- and the recipient comes from the source record or its checked audience.
create function sectalk_private.st_v6_deliver_account_alert(
  p_recipient uuid,p_kind text,p_quiet boolean,p_room uuid default null
)
returns boolean language plpgsql set search_path='' as $$
declare alert record;
begin
  select * into alert from sectalk_private.st_v6_alert_priority(p_kind);
  if not found or p_recipient is null then return false; end if;
  if alert.priority<>'critical' and (p_quiet is not false
    or not sectalk_private.st_v6_notification_enabled(p_recipient,alert.category)) then
    return false;
  end if;

  if alert.category='mention' then
    if p_room is null then return false; end if;
    perform realtime.send(jsonb_build_object('room_id',p_room,'mention_kind',p_kind,'priority',alert.priority),
      'room_activity','st:account:'||p_recipient,true);
  else
    perform realtime.send(jsonb_build_object('kind',p_kind,'priority',alert.priority),
      'category_alert','st:account:'||p_recipient,true);
  end if;
  return true;
end
$$;

revoke all on function sectalk_private.st_v6_alert_priority(text),
  sectalk_private.st_v6_deliver_account_alert(uuid,text,boolean,uuid) from public,anon,authenticated;

create or replace function sectalk_private.st_v6_task_notice_alert()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_v6_deliver_account_alert(new.recipient,'task.'||new.kind,
    case when t.room_id is not null then sectalk_private.st_v6_room_alert_quiet(new.recipient,t.room_id)
      else sectalk_private.st_v6_quiet_for(new.recipient,t.chat_id) end)
  from public.st_v6_tasks t
  where t.id=new.task_id and sectalk_private.st_v6_task_audience(t.room_id,t.chat_id,new.recipient);
  return new;
end
$$;

create or replace function sectalk_private.st_v6_safety_report_alert()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_v6_deliver_account_alert(new.reporter,'security.report',
    sectalk_private.st_v6_quiet_for(new.reporter,null));
  return new;
end
$$;

create or replace function sectalk_private.st_v6_account_notice_alert()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_v6_deliver_account_alert(new.user_id,'security.account',
    sectalk_private.st_v6_quiet_for(new.user_id,null));
  return new;
end
$$;

create or replace function sectalk_private.st_v6_billing_alert()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.plan<>'free' and (tg_op='INSERT' or
    (new.plan,new.status,new.cancel_at_period_end) is distinct from
    (old.plan,old.status,old.cancel_at_period_end)) then
    perform sectalk_private.st_v6_deliver_account_alert(new.user_id,'billing.subscription',
      sectalk_private.st_v6_quiet_for(new.user_id,null));
  end if;
  return new;
end
$$;

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
    select r.workspace_id,r.kind as room_kind,recipients.user_id
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
  select audience.user_id,audience.room_kind,notices.kind
  from audiences audience
  left join notices on notices.recipient=audience.user_id
  loop
    if alert.kind is not null
      and sectalk_private.st_v6_deliver_account_alert(alert.user_id,alert.kind,false,new.room_id) then
      continue;
    end if;
    if new.parent_id is not null then
      if not sectalk_private.st_v6_notification_enabled(alert.user_id,'thread') then continue; end if;
      if exists(select 1 from public.st_v6_thread_follows f
        where (f.room_id,f.post_id,f.user_id)=(new.room_id,new.parent_id,alert.user_id)) then
        perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,'thread.reply',false);
        continue;
      end if;
    end if;
    if alert.kind is null then
      if alert.room_kind='admin' then
        perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,'admin.room',false);
      else
        perform realtime.send(jsonb_build_object('room_id',new.room_id),
          'room_activity','st:account:'||alert.user_id,true);
      end if;
    end if;
  end loop;
  return new;
end
$$;


commit;
