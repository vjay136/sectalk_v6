begin;

-- Clients can subscribe only to a topic bound to their current native session.
-- Each send rechecks the pinned workspace provider and receipt.
create policy st_v8_workspace_session_broadcast on realtime.messages
  for select to authenticated using (
    extension='broadcast' and (select auth.uid()) is not null
    and (select realtime.topic())='st:workspace-session:'||(select auth.uid())::text
      ||':'||(select auth.jwt()->>'session_id')
  );
create policy st_v8_workspace_session_broadcast_scope on realtime.messages
  as restrictive for select to public using (
    coalesce((select realtime.topic()),'') not like 'st:workspace-session:%' or (
      extension='broadcast' and (select auth.uid()) is not null
      and (select realtime.topic())='st:workspace-session:'||(select auth.uid())::text
        ||':'||(select auth.jwt()->>'session_id')
    )
  );
create policy st_v8_workspace_session_broadcast_server_only on realtime.messages
  as restrictive for insert to public with check (
    coalesce((select realtime.topic()),'') not like 'st:workspace-session:%'
  );

create function sectalk_private.st_v8_send_conversation_activity(
  p_room uuid,p_channel uuid,p_recipient uuid,p_event text,p_payload jsonb
) returns void language plpgsql set search_path='' as $$
declare
  space uuid;
  mode text;
  required_providers jsonb;
begin
  if num_nonnulls(p_room,p_channel)<>1 or p_recipient is null then return; end if;
  if p_room is not null then
    select r.workspace_id,r.encryption_mode into space,mode from public.st_v6_rooms r where r.id=p_room;
  else
    select c.workspace_id,c.encryption_mode into space,mode from public.st_v2_channels c where c.id=p_channel;
  end if;
  if space is null then return; end if;

  select coalesce(jsonb_agg(distinct jsonb_build_array(p.protocol,p.provider)),'[]') into required_providers
  from (
    select protocol,provider from sectalk_private.st_v8_workspace_entry_sso where workspace=space
    union all select protocol,provider from sectalk_private.st_v8_workspace_room_structure_sso
      where workspace=space and p_room is not null
    union all select protocol,provider from sectalk_private.st_v8_workspace_channel_structure_sso
      where workspace=space and p_channel is not null
    union all select protocol,provider from sectalk_private.st_v8_workspace_standard_room_sso
      where workspace=space and p_room is not null and mode='standard'
    union all select protocol,provider from sectalk_private.st_v8_workspace_standard_channel_sso
      where workspace=space and p_channel is not null and mode='standard'
    union all select protocol,provider from sectalk_private.st_v8_workspace_managed_content_sso
      where workspace=space and mode='managed'
  ) p;

  if required_providers='[]'::jsonb then
    perform realtime.send(p_payload,p_event,'st:account:'||p_recipient,true);
    return;
  end if;

  perform realtime.send(p_payload,p_event,'st:workspace-session:'||p_recipient||':'||s.id,true)
  from sectalk_private.st_v7_workspace_sso_sessions receipt
  join sectalk_private.st_v7_workspace_sso setup on (setup.workspace,setup.protocol,setup.provider)=
    (receipt.workspace,receipt.protocol,receipt.provider)
  join auth.sessions s on (s.id,s.user_id)=(receipt.session,receipt.principal)
  where (receipt.workspace,receipt.principal)=(space,p_recipient)
    and required_providers=jsonb_build_array(jsonb_build_array(receipt.protocol,receipt.provider))
    and sectalk_private.st_v7_workspace_sso_provider(space,setup.domain,setup.protocol)=setup.provider
    and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp();
end $$;
revoke all on function sectalk_private.st_v8_send_conversation_activity(uuid,uuid,uuid,text,jsonb)
  from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v6_room_post_alert()
returns trigger language plpgsql security definer set search_path='' as $$
declare
  can_broadcast boolean:=coalesce(sectalk_private.st_v6_room_role(new.room_id) in ('owner','moderator'),false);
  can_mention_all boolean:=sectalk_private.st_v6_room_all_mentions(new.room_id,auth.uid());
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
      when can_mention_all and exists(select 1 from tokens where handle='here') and exists(
        select 1 from public.st_v3_presence presence
        where presence.user_id=audience.user_id and sectalk_private.st_v6_shares_presence(audience.user_id)
          and presence.state='online' and presence.expires_at>clock_timestamp()
      ) then 'mention.here'
      when can_mention_all and exists(select 1 from tokens where handle='channel') then 'mention.channel'
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
      perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,alert.kind,alert.quiet,new.room_id,admin_post,'room:'||new.room_id||':'||new.id);
    elsif alert.following and 'thread'=any(mandatory) then
      perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,'thread.reply',alert.quiet,new.room_id,admin_post,'room:'||new.room_id||':'||new.id);
    elsif alert.room_kind='admin' and 'admin'=any(mandatory) then
      perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,'admin.room',alert.quiet,new.room_id,admin_post,'room:'||new.room_id||':'||new.id);
    elsif not alert.quiet then
      if alert.kind is not null
        and sectalk_private.st_v6_deliver_account_alert(alert.user_id,alert.kind,false,new.room_id,admin_post,'room:'||new.room_id||':'||new.id) then
        continue;
      end if;
      if new.parent_id is not null then
        if not sectalk_private.st_v6_notification_enabled(alert.user_id,'thread') then continue; end if;
        if alert.following then
          perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,'thread.reply',false,new.room_id,admin_post,'room:'||new.room_id||':'||new.id);
          continue;
        end if;
      end if;
      if alert.kind is null then
        if alert.room_kind='admin' then
          perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,'admin.room',false,new.room_id,admin_post,'room:'||new.room_id||':'||new.id);
        else
          perform sectalk_private.st_v8_send_conversation_activity(new.room_id,null,alert.user_id,'room_activity',
            jsonb_build_object('room_id',new.room_id));
        end if;
      end if;
    end if;
  end loop;
  return new;
end
$$;

create or replace function sectalk_private.st_v6_channel_post_alert()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_v8_send_conversation_activity(null,new.channel_id,m.user_id,'channel_activity',
    jsonb_build_object('channel_id',new.channel_id))
  from public.st_v2_channels c join public.st_v2_members m on m.workspace_id=c.workspace_id
  where c.id=new.channel_id and m.user_id<>new.sender and not c.archived
    and sectalk_private.st_v6_channel_content_access(c.id,m.user_id)
    and sectalk_private.open_pair(new.sender,m.user_id)
    and not sectalk_private.st_v6_channel_alert_quiet(m.user_id,c.id);
  return new;
end
$$;

create or replace function sectalk_private.st_v6_deliver_account_alert(
  p_recipient uuid,p_kind text,p_quiet boolean,p_room uuid,p_admin_post uuid,p_event_key text
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
    perform sectalk_private.st_v8_send_conversation_activity(p_room,null,p_recipient,'room_activity',
      envelope||jsonb_build_object('room_id',p_room,'mention_kind',p_kind));
  elsif p_room is not null then
    perform sectalk_private.st_v8_send_conversation_activity(p_room,null,p_recipient,'category_alert',
      envelope||jsonb_build_object('kind',p_kind));
  else
    perform realtime.send(envelope||jsonb_build_object('kind',p_kind),
      'category_alert','st:account:'||p_recipient,true);
  end if;
  if alert.category<>'task' then
    perform sectalk_private.st_v6_queue_web_push(p_recipient,p_kind,p_room,null,null,p_event_key);
  end if;
  return true;
end
$$;

commit;
