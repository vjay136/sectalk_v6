begin;

create table sectalk_private.st_v6_notification_preferences (
  user_id uuid not null references public.st_profiles on delete cascade,
  category text not null check (category in ('dm','mention','thread','task','call','security','billing','admin')),
  enabled boolean not null,
  primary key(user_id,category)
);
alter table sectalk_private.st_v6_notification_preferences enable row level security;
revoke all on sectalk_private.st_v6_notification_preferences from public,anon,authenticated;

create function sectalk_private.st_v6_notification_enabled(actor uuid, category_name text)
returns boolean language sql stable set search_path='' as $$
  select coalesce((
    select p.enabled from sectalk_private.st_v6_notification_preferences p
    where p.user_id=actor and p.category=category_name
  ),true)
$$;

create function public.st_v6_notification_preferences()
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_object_agg(category,sectalk_private.st_v6_notification_enabled(auth.uid(),category))
  from unnest(array['dm','mention','thread','task','call','security','billing','admin']) category
  where auth.uid() is not null and exists (select 1 from public.st_profiles p where p.id=auth.uid())
$$;

create function public.st_v6_set_notification_preference(p_category text,p_enabled boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if actor is null or not exists (select 1 from public.st_profiles p where p.id=actor)
    or p_enabled is null or p_category is null
    or p_category not in ('dm','mention','thread','task','call','security','billing','admin') then
    raise exception 'Invalid notification preference';
  end if;
  perform sectalk_private.limit_action('v6_notification_preferences',40);
  insert into sectalk_private.st_v6_notification_preferences(user_id,category,enabled)
    values(actor,p_category,p_enabled)
    on conflict(user_id,category) do update set enabled=excluded.enabled;
  perform sectalk_private.st_v6_availability_hint(actor,false);
end
$$;

create function public.st_v6_direct_alert_quiet(p_chat uuid,p_category text)
returns boolean language sql stable security definer set search_path='' as $$
  select case when p_chat is not null and p_category in ('dm','call')
    and sectalk_private.st_v6_quiet_authorized(auth.uid(),p_chat)
    then not sectalk_private.st_v6_notification_enabled(auth.uid(),p_category)
      or sectalk_private.st_v6_quiet_for(auth.uid(),p_chat)
    else true end
$$;

create function sectalk_private.st_v6_task_notice_alert()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform realtime.send(jsonb_build_object('kind','task.'||new.kind),'category_alert','st:account:'||new.recipient,true)
  from public.st_v6_tasks t
  where t.id=new.task_id
    and sectalk_private.st_v6_task_audience(t.room_id,t.chat_id,new.recipient)
    and sectalk_private.st_v6_notification_enabled(new.recipient,'task')
    and case when t.room_id is not null
      then not sectalk_private.st_v6_room_alert_quiet(new.recipient,t.room_id)
      else not sectalk_private.st_v6_quiet_for(new.recipient,t.chat_id)
    end;
  return new;
end
$$;

create trigger st_v6_task_notice_alert after insert on public.st_v6_task_notices
for each row execute function sectalk_private.st_v6_task_notice_alert();

create function sectalk_private.st_v6_safety_report_alert()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if sectalk_private.st_v6_notification_enabled(new.reporter,'security')
    and not sectalk_private.st_v6_quiet_for(new.reporter,null) then
    perform realtime.send(jsonb_build_object('kind','security.report'),'category_alert','st:account:'||new.reporter,true);
  end if;
  return new;
end
$$;

create trigger st_v6_safety_report_alert after update of status on public.st_reports
for each row when (old.status is distinct from new.status)
execute function sectalk_private.st_v6_safety_report_alert();

create function sectalk_private.st_v6_account_notice_alert()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform realtime.send(jsonb_build_object('kind','security.account'),'category_alert','st:account:'||new.user_id,true);
  return new;
end
$$;

create trigger st_v6_account_notice_alert after insert on public.st_v5_account_notices
for each row execute function sectalk_private.st_v6_account_notice_alert();

create function sectalk_private.st_v6_billing_alert()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.plan<>'free' and (tg_op='INSERT' or
    (new.plan,new.status,new.cancel_at_period_end) is distinct from
    (old.plan,old.status,old.cancel_at_period_end))
    and sectalk_private.st_v6_notification_enabled(new.user_id,'billing')
    and not sectalk_private.st_v6_quiet_for(new.user_id,null) then
    perform realtime.send(jsonb_build_object('kind','billing.subscription'),'category_alert','st:account:'||new.user_id,true);
  end if;
  return new;
end
$$;

create trigger st_v6_billing_alert after insert or update of plan,status,cancel_at_period_end on public.st_v2_subscriptions
for each row execute function sectalk_private.st_v6_billing_alert();

revoke all on function sectalk_private.st_v6_notification_enabled(uuid,text),
  sectalk_private.st_v6_task_notice_alert(),sectalk_private.st_v6_safety_report_alert(),
  sectalk_private.st_v6_account_notice_alert(),sectalk_private.st_v6_billing_alert()
  from public,anon,authenticated;
revoke all on function public.st_v6_notification_preferences(),public.st_v6_set_notification_preference(text,boolean),
  public.st_v6_direct_alert_quiet(uuid,text) from public,anon,authenticated;
grant execute on function public.st_v6_notification_preferences(),public.st_v6_set_notification_preference(text,boolean),
  public.st_v6_direct_alert_quiet(uuid,text) to authenticated;

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
    if alert.kind is not null and sectalk_private.st_v6_notification_enabled(alert.user_id,'mention') then
      perform realtime.send(jsonb_build_object('room_id',new.room_id,'mention_kind',alert.kind),
        'room_activity','st:account:'||alert.user_id,true);
    elsif new.parent_id is not null and sectalk_private.st_v6_notification_enabled(alert.user_id,'thread')
      and exists(select 1 from public.st_v6_thread_follows f
        where (f.room_id,f.post_id,f.user_id)=(new.room_id,new.parent_id,alert.user_id)) then
      perform realtime.send(jsonb_build_object('kind','thread.reply'),
        'category_alert','st:account:'||alert.user_id,true);
    elsif alert.kind is null and (new.parent_id is null
      or sectalk_private.st_v6_notification_enabled(alert.user_id,'thread')) then
      if alert.room_kind='admin' then
        if sectalk_private.st_v6_notification_enabled(alert.user_id,'admin') then
          perform realtime.send(jsonb_build_object('kind','admin.room'),
            'category_alert','st:account:'||alert.user_id,true);
        end if;
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
