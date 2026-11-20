begin;

create table sectalk_private.st_v6_workspace_notification_policy (
  workspace_id uuid primary key references public.st_v2_workspaces on delete cascade,
  mandatory_categories text[] not null default '{}'
    check (mandatory_categories <@ array['mention','thread','task','admin']),
  max_quiet_minutes integer check (max_quiet_minutes between 0 and 1440)
);
alter table sectalk_private.st_v6_workspace_notification_policy enable row level security;
revoke all on sectalk_private.st_v6_workspace_notification_policy from public,anon,authenticated;

create function sectalk_private.st_v6_workspace_notification_settings(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare p sectalk_private.st_v6_workspace_notification_policy;
begin
  if not sectalk_private.st_v2_active(auth.uid())
    or sectalk_private.st_v2_role(p_workspace,auth.uid()) is null then
    raise exception 'Workspace notification policy unavailable';
  end if;
  select * into p from sectalk_private.st_v6_workspace_notification_policy where workspace_id=p_workspace;
  return jsonb_build_object('mandatory_categories',coalesce(p.mandatory_categories,'{}'),
    'max_quiet_minutes',p.max_quiet_minutes);
end
$$;

create function sectalk_private.st_v6_set_workspace_notification_policy(
  p_workspace uuid,p_categories text[],p_quiet_minutes integer
)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); categories text[];
begin
  if not sectalk_private.st_v2_active(actor)
    or not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false) then
    raise exception 'Workspace notification policy unavailable';
  end if;
  if p_categories is null or cardinality(p_categories)>4
    or (cardinality(p_categories)>0 and array_ndims(p_categories) is distinct from 1)
    or not coalesce(p_categories <@ array['mention','thread','task','admin'],false)
    or (p_quiet_minutes is not null and p_quiet_minutes not between 0 and 1440) then
    raise exception 'Choose valid workspace notification categories and a quiet limit of 0 to 1440 minutes';
  end if;
  perform sectalk_private.limit_action('v6_workspace_notification_policy',20);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if not found or not sectalk_private.st_v2_active(actor)
    or not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false) then
    raise exception 'Workspace notification policy unavailable';
  end if;
  categories:=array(select distinct category from unnest(p_categories) category order by category);
  insert into sectalk_private.st_v6_workspace_notification_policy as policy
    (workspace_id,mandatory_categories,max_quiet_minutes)
    values(p_workspace,categories,p_quiet_minutes)
  on conflict(workspace_id) do update
    set mandatory_categories=excluded.mandatory_categories,max_quiet_minutes=excluded.max_quiet_minutes
    where (policy.mandatory_categories,policy.max_quiet_minutes) is distinct from
      (excluded.mandatory_categories,excluded.max_quiet_minutes);
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,'workspace.notification_policy_changed',p_workspace);
  end if;
end
$$;

create function public.st_v6_workspace_notification_settings(p_workspace uuid)
returns jsonb language sql stable set search_path=''
return sectalk_private.st_v6_workspace_notification_settings(p_workspace);

create function public.st_v6_set_workspace_notification_policy(p_workspace uuid,p_categories text[],p_quiet_minutes integer)
returns void language sql set search_path=''
return sectalk_private.st_v6_set_workspace_notification_policy(p_workspace,p_categories,p_quiet_minutes);

revoke all on function public.st_v6_workspace_notification_settings(uuid),
  public.st_v6_set_workspace_notification_policy(uuid,text[],integer),
  sectalk_private.st_v6_workspace_notification_settings(uuid),
  sectalk_private.st_v6_set_workspace_notification_policy(uuid,text[],integer) from public,anon,authenticated;
grant execute on function public.st_v6_workspace_notification_settings(uuid),
  public.st_v6_set_workspace_notification_policy(uuid,text[],integer),
  sectalk_private.st_v6_workspace_notification_settings(uuid),
  sectalk_private.st_v6_set_workspace_notification_policy(uuid,text[],integer) to authenticated;

alter table sectalk_private.st_v6_quiet_rules
  add column mute_started_at timestamptz,
  add column snooze_started_at timestamptz;
alter table sectalk_private.st_v6_room_quiet_rules
  add column mute_started_at timestamptz,
  add column snooze_started_at timestamptz;

update sectalk_private.st_v6_quiet_rules set
  mute_started_at=case when muted then now() end,
  snooze_started_at=case when snooze_until>now() then now() end
where muted or snooze_until>now();
update sectalk_private.st_v6_room_quiet_rules set
  mute_started_at=case when muted then now() end,
  snooze_started_at=case when snooze_until>now() then now() end
where muted or snooze_until>now();

create function sectalk_private.st_v6_quiet_rule_start()
returns trigger language plpgsql set search_path='' as $$
begin
  if tg_op='INSERT' then
    new.mute_started_at:=case when new.muted then now() end;
    new.snooze_started_at:=case when new.snooze_until>now() then now() end;
  else
    if new.muted is distinct from old.muted then
      new.mute_started_at:=case when new.muted then now() end;
    end if;
    if new.snooze_until is distinct from old.snooze_until then
      new.snooze_started_at:=case when new.snooze_until>now()
        then case when old.snooze_until>now() then old.snooze_started_at else now() end end;
    end if;
  end if;
  return new;
end
$$;

create trigger st_v6_quiet_rule_start before insert or update of muted,snooze_until
on sectalk_private.st_v6_quiet_rules for each row execute function sectalk_private.st_v6_quiet_rule_start();
create trigger st_v6_quiet_rule_start before insert or update of muted,snooze_until
on sectalk_private.st_v6_room_quiet_rules for each row execute function sectalk_private.st_v6_quiet_rule_start();

create function sectalk_private.st_v6_workspace_quiet_schedule(
  p_days smallint[],p_start time,p_end time,p_zone text,p_now timestamptz,p_limit interval
)
returns boolean language sql stable set search_path='' as $$
  with local_clock as (
    select p_now at time zone p_zone as stamp
  ), occurrences as (
    select stamp,(stamp::date-case when p_start>p_end and stamp::time<p_end then 1 else 0 end)+p_start as started
    from local_clock
  ), anchors as (
    select stamp,started,started at time zone p_zone as standard_start,
      ((started-interval '1 day') at time zone p_zone)+interval '24 hours' as previous_offset_start
    from occurrences
  )
  select case when not sectalk_private.st_v6_quiet_window(p_days,p_start,p_end,p_zone,p_now) then false
    when p_limit is null then true
    -- A repeated local start uses its first occurrence so the cap does not restart.
    when previous_offset_start at time zone p_zone=started then p_now-least(standard_start,previous_offset_start)<p_limit
    when standard_start at time zone p_zone=started then p_now-standard_start<p_limit
    -- A start skipped by the clock change still uses the scheduled local cutoff.
    else stamp-started<p_limit end
  from anchors
$$;

create function sectalk_private.st_v6_workspace_alert_quiet(
  p_actor uuid,p_workspace uuid,p_room uuid,p_channel uuid
)
returns boolean language sql stable set search_path='' as $$
  with quiet_limit as (
    select make_interval(mins=>(select p.max_quiet_minutes
      from sectalk_private.st_v6_workspace_notification_policy p where p.workspace_id=p_workspace)) as duration
  ), rules as (
    select q.muted,q.mute_started_at,q.snooze_until,q.snooze_started_at,q.days,q.starts_at,q.ends_at,q.zone
    from sectalk_private.st_v6_quiet_rules q where q.user_id=p_actor and q.chat_id is null
    union all
    select q.muted,q.mute_started_at,q.snooze_until,q.snooze_started_at,q.days,q.starts_at,q.ends_at,q.zone
    from sectalk_private.st_v6_room_quiet_rules q
    where q.user_id=p_actor and (q.room_id=p_room or q.channel_id=p_channel)
  )
  select exists(select 1 from rules r cross join quiet_limit l where
    (r.muted and (l.duration is null or r.mute_started_at+l.duration>now()))
    or (r.snooze_until>now() and (l.duration is null or r.snooze_started_at+l.duration>now()))
    or sectalk_private.st_v6_workspace_quiet_schedule(r.days,r.starts_at,r.ends_at,r.zone,now(),l.duration))
$$;

create or replace function sectalk_private.st_v6_room_alert_quiet(actor uuid,room uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce((select sectalk_private.st_v6_workspace_alert_quiet(actor,r.workspace_id,room,null)
    from public.st_v6_rooms r where r.id=room),true)
$$;

create or replace function sectalk_private.st_v6_channel_alert_quiet(actor uuid,channel uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce((select sectalk_private.st_v6_workspace_alert_quiet(actor,c.workspace_id,null,channel)
    from public.st_v2_channels c where c.id=channel),true)
$$;

create function sectalk_private.st_v6_mandatory_workspace_alerts(p_workspace uuid)
returns text[] language sql stable set search_path='' as $$
  select coalesce((select mandatory_categories from sectalk_private.st_v6_workspace_notification_policy
    where workspace_id=p_workspace),'{}')
$$;

revoke all on function sectalk_private.st_v6_quiet_rule_start(),
  sectalk_private.st_v6_workspace_quiet_schedule(smallint[],time,time,text,timestamptz,interval),
  sectalk_private.st_v6_workspace_alert_quiet(uuid,uuid,uuid,uuid),
  sectalk_private.st_v6_mandatory_workspace_alerts(uuid) from public,anon,authenticated;

create or replace function sectalk_private.st_v6_deliver_account_alert(
  p_recipient uuid,p_kind text,p_quiet boolean,p_room uuid,p_admin_post uuid
)
returns boolean language plpgsql set search_path='' as $$
declare
  alert record;
  receipt uuid;
  envelope jsonb;
  mandatory boolean;
begin
  select * into alert from sectalk_private.st_v6_alert_priority(p_kind);
  if not found or p_recipient is null then return false; end if;
  mandatory:=alert.category=any(sectalk_private.st_v6_mandatory_workspace_alerts(
    (select workspace_id from public.st_v6_rooms where id=p_room)));
  if alert.priority<>'critical' and not mandatory and (p_quiet is not false
    or not sectalk_private.st_v6_notification_enabled(p_recipient,alert.category)) then
    return false;
  end if;
  if alert.category='mention' and p_room is null then return false; end if;

  if p_admin_post is not null then
    insert into sectalk_private.st_v6_admin_notification_receipts(room_id,post_id,recipient)
      values(p_room,p_admin_post,p_recipient)
      on conflict(room_id,post_id,recipient) do nothing returning id into receipt;
    if receipt is null then return false; end if;
  end if;
  envelope:=jsonb_strip_nulls(jsonb_build_object('priority',alert.priority,'receipt_id',receipt));

  if alert.category='mention' then
    perform realtime.send(envelope||jsonb_build_object('room_id',p_room,'mention_kind',p_kind),
      'room_activity','st:account:'||p_recipient,true);
  else
    perform realtime.send(envelope||jsonb_build_object('kind',p_kind),
      'category_alert','st:account:'||p_recipient,true);
  end if;
  return true;
end
$$;


create or replace function sectalk_private.st_v6_task_notice_alert()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_v6_deliver_account_alert(new.recipient,'task.'||new.kind,
    case when t.room_id is not null then sectalk_private.st_v6_room_alert_quiet(new.recipient,t.room_id)
      else sectalk_private.st_v6_quiet_for(new.recipient,t.chat_id) end,t.room_id)
  from public.st_v6_tasks t
  where t.id=new.task_id and sectalk_private.st_v6_task_audience(t.room_id,t.chat_id,new.recipient);
  return new;
end
$$;


create or replace function sectalk_private.st_v6_room_post_alert()
returns trigger language plpgsql security definer set search_path='' as $$
declare
  can_broadcast boolean:=coalesce(sectalk_private.st_v6_room_role(new.room_id) in ('owner','moderator'),false);
  alert record;
  admin_post uuid;
  mandatory text[]:=sectalk_private.st_v6_mandatory_workspace_alerts(
    (select workspace_id from public.st_v6_rooms where id=new.room_id));
begin
  insert into sectalk_private.st_v6_admin_notification_runs(room_id,post_id,shared_audience)
  select r.id,new.id,(select count(*)>1 from (
    select 1 from public.st_v2_members m
    where m.workspace_id=r.workspace_id and m.role in ('owner','admin') and m.suspended_at is null and m.user_id<>new.sender
      and sectalk_private.st_v2_active(m.user_id)
      and sectalk_private.open_pair(new.sender,m.user_id)
      and not exists(select 1 from public.st_v6_room_bans b where b.room_id=r.id and b.user_id=m.user_id)
    limit 2
  ) recipients)
  from public.st_v6_rooms r where r.id=new.room_id and r.kind='admin'
  returning post_id into admin_post;

  for alert in
  with tokens as materialized (
    select lower(replace(match[2],'""','"')) as group_name,
      lower(match[3]) as explicit_handle,lower(match[4]) as handle
    from regexp_matches(new.body,
      '(^|[^[:alnum:]_@])@(?:group:"((?:[^"]|""){1,80})"|user:([a-z0-9_]{3,24})|(?!(?:group|user):)([a-z0-9_]{3,24}))(?![[:alnum:]_@])',
      'gi') as match
    where not new.forwarded
  ), audiences as materialized (
    select r.workspace_id,r.kind as room_kind,recipients.user_id,
      sectalk_private.st_v6_workspace_alert_quiet(recipients.user_id,r.workspace_id,r.id,null) as quiet
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
    where mention.kind is not null and (not audience.quiet or 'mention'=any(mandatory))
    on conflict (room_id,room_post_id,recipient) do nothing
    returning recipient,kind
  )
  select audience.user_id,audience.room_kind,audience.quiet,notices.kind,
    new.parent_id is not null and exists(select 1 from public.st_v6_thread_follows f
      where (f.room_id,f.post_id,f.user_id)=(new.room_id,new.parent_id,audience.user_id)) as following
  from audiences audience
  left join notices on notices.recipient=audience.user_id
  loop
    if alert.kind is not null and 'mention'=any(mandatory) then
      perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,alert.kind,alert.quiet,new.room_id,admin_post);
    elsif alert.following and 'thread'=any(mandatory) then
      perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,'thread.reply',alert.quiet,new.room_id,admin_post);
    elsif alert.room_kind='admin' and 'admin'=any(mandatory) then
      perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,'admin.room',alert.quiet,new.room_id,admin_post);
    elsif not alert.quiet then
      if alert.kind is not null
        and sectalk_private.st_v6_deliver_account_alert(alert.user_id,alert.kind,false,new.room_id,admin_post) then
        continue;
      end if;
      if new.parent_id is not null then
        if not sectalk_private.st_v6_notification_enabled(alert.user_id,'thread') then continue; end if;
        if alert.following then
          perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,'thread.reply',false,new.room_id,admin_post);
          continue;
        end if;
      end if;
      if alert.kind is null then
        if alert.room_kind='admin' then
          perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,'admin.room',false,new.room_id,admin_post);
        else
          perform realtime.send(jsonb_build_object('room_id',new.room_id),
            'room_activity','st:account:'||alert.user_id,true);
        end if;
      end if;
    end if;
  end loop;
  return new;
end
$$;


commit;
