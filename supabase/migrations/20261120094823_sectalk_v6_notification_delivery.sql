begin;

create table sectalk_private.st_v6_notification_delivery_events (
  id uuid primary key default gen_random_uuid(),
  recipient uuid not null references public.st_profiles on delete cascade,
  event_key text not null check (length(event_key) between 1 and 200),
  kind text not null,
  room_id uuid references public.st_v6_rooms on delete cascade,
  chat_id uuid references public.st_chats on delete cascade,
  call_id uuid references public.st_calls on delete cascade,
  state text not null default 'pending' check (state in ('pending','sent','fallback','discarded')),
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  read_at timestamptz,
  unique(recipient,event_key)
);
create index st_v6_notification_fallback_recipient on sectalk_private.st_v6_notification_delivery_events(recipient,completed_at desc)
  where state='fallback';
create index st_v6_notification_delivery_retention on sectalk_private.st_v6_notification_delivery_events(completed_at)
  where completed_at is not null;
alter table sectalk_private.st_v6_notification_delivery_events enable row level security;
revoke all on sectalk_private.st_v6_notification_delivery_events from public,anon,authenticated,service_role;

alter table sectalk_private.st_v6_push_jobs
  add column event_id uuid references sectalk_private.st_v6_notification_delivery_events on delete cascade,
  add column state text not null default 'pending' check (state in ('pending','sent','dead','discarded')),
  drop constraint st_v6_push_jobs_subscription_id_fkey,
  alter column subscription_id drop not null,
  add foreign key(subscription_id) references sectalk_private.st_v6_push_subscriptions on delete set null;

-- Preserve pending pushes when upgrading from the initial single-channel queue.
insert into sectalk_private.st_v6_notification_delivery_events(id,recipient,event_key,kind,room_id,chat_id,call_id)
select q.id,s.recipient,'legacy:'||q.id,q.kind,q.room_id,q.chat_id,q.call_id
from sectalk_private.st_v6_push_jobs q join sectalk_private.st_v6_push_subscriptions s on s.id=q.subscription_id;
update sectalk_private.st_v6_push_jobs set event_id=id;
alter table sectalk_private.st_v6_push_jobs alter column event_id set not null;
create index st_v6_push_jobs_event on sectalk_private.st_v6_push_jobs(event_id);
drop index sectalk_private.st_v6_push_jobs_ready;
create index st_v6_push_jobs_ready on sectalk_private.st_v6_push_jobs(next_attempt_at,id) where state='pending';

create table sectalk_private.st_v6_notification_dead_letters (
  job_id uuid primary key references sectalk_private.st_v6_push_jobs on delete cascade,
  channel text not null check (channel='web_push'),
  reason text not null check (reason in ('provider_rejected','subscription_gone','retry_exhausted','expired')),
  failed_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v6_notification_dead_letters enable row level security;
revoke all on sectalk_private.st_v6_notification_dead_letters from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_queue_web_push(
  p_actor uuid,p_kind text,p_room uuid,p_chat uuid,p_call uuid,p_event_key text
)
returns void language sql set search_path='' as $$
  with subscriptions as materialized (
    select s.id from sectalk_private.st_v6_push_subscriptions s
    join auth.sessions a on a.id=s.session_id and a.user_id=s.recipient
    where s.recipient=p_actor and (a.not_after is null or a.not_after>now())
  ), inserted as (
    insert into sectalk_private.st_v6_notification_delivery_events(recipient,event_key,kind,room_id,chat_id,call_id)
    select p_actor,p_event_key,p_kind,p_room,p_chat,p_call
    where exists(select 1 from subscriptions)
      and sectalk_private.st_v6_web_push_allowed(p_actor,p_kind,p_room,p_chat,p_call)
    on conflict(recipient,event_key) do nothing returning id
  )
  insert into sectalk_private.st_v6_push_jobs(subscription_id,event_id,kind,room_id,chat_id,call_id,expires_at)
  select s.id,i.id,p_kind,p_room,p_chat,p_call,
    case when p_call is null then now()+interval '5 minutes' else now()+interval '30 seconds' end
  from inserted i cross join subscriptions s
$$;

create or replace function sectalk_private.st_v6_queue_web_push(
  p_actor uuid,p_kind text,p_room uuid default null,p_chat uuid default null,p_call uuid default null
)
returns void language sql set search_path=''
return sectalk_private.st_v6_queue_web_push(p_actor,p_kind,p_room,p_chat,p_call,gen_random_uuid()::text);

drop function public.st_v6_claim_web_push();
create function public.st_v6_claim_web_push()
returns table(job uuid,lease uuid,endpoint text,p256dh text,auth_secret text,ttl integer,terminal text)
language plpgsql security definer set search_path='' as $$
begin
  delete from sectalk_private.st_v6_notification_delivery_events e where e.completed_at<now()-interval '7 days';
  return query
  with candidates as materialized (
    select q.id from sectalk_private.st_v6_push_jobs q
    where q.state='pending' and q.next_attempt_at<=now()
    order by q.next_attempt_at,q.id
    limit 25 for update of q skip locked
  ), claimed as (
    update sectalk_private.st_v6_push_jobs q
    set lease_id=gen_random_uuid(),next_attempt_at=now()+interval '45 seconds',attempts=q.attempts+1
    from candidates where q.id=candidates.id
    returning q.*
  )
  select q.id,q.lease_id,
    case when result.terminal is null then s.endpoint end,
    case when result.terminal is null then s.p256dh end,
    case when result.terminal is null then s.auth_secret end,
    greatest(0,floor(extract(epoch from q.expires_at-now()))::integer),
    result.terminal
  from claimed q
  join sectalk_private.st_v6_notification_delivery_events delivery on delivery.id=q.event_id
  left join sectalk_private.st_v6_push_subscriptions s on s.id=q.subscription_id
  left join auth.sessions a on a.id=s.session_id and a.user_id=s.recipient
  cross join lateral (select case
    when a.id is null or a.not_after<=now() then 'discard'
    when not sectalk_private.st_v6_web_push_allowed(delivery.recipient,q.kind,q.room_id,q.chat_id,q.call_id) then 'discard'
    when q.expires_at<=now()+interval '1 second' then 'expired'
    when q.attempts>3 then 'exhausted'
    end as terminal) result;
end
$$;

create or replace function public.st_v6_finish_web_push(p_job uuid,p_lease uuid,p_result text)
returns void language plpgsql security definer set search_path='' as $$
declare
  queued sectalk_private.st_v6_push_jobs;
  delivery sectalk_private.st_v6_notification_delivery_events;
  reason text;
begin
  if p_result is null or p_result not in ('sent','gone','retry','rejected','discard','expired','exhausted') then return; end if;
  -- Deletion cascades to other browser jobs. Lock the subscription first in that case.
  if p_result='gone' then
    perform s.id from sectalk_private.st_v6_push_subscriptions s
    where s.id=(select q.subscription_id from sectalk_private.st_v6_push_jobs q where q.id=p_job)
    for update;
  end if;
  select e.* into delivery from sectalk_private.st_v6_notification_delivery_events e
  where e.id=(select q.event_id from sectalk_private.st_v6_push_jobs q where q.id=p_job)
  for update;
  if not found then return; end if;
  select * into queued from sectalk_private.st_v6_push_jobs q
  where q.id=p_job and q.lease_id=p_lease and q.state='pending' for update;
  if not found then return; end if;

  if p_result='retry' and queued.attempts<3 and queued.expires_at>now()+interval '15 seconds' then
    update sectalk_private.st_v6_push_jobs set next_attempt_at=now()+make_interval(secs=>15*queued.attempts),
      lease_id=null where id=p_job;
    return;
  end if;
  reason:=case p_result when 'gone' then 'subscription_gone' when 'rejected' then 'provider_rejected'
    when 'expired' then 'expired' when 'retry' then 'retry_exhausted' when 'exhausted' then 'retry_exhausted' end;
  update sectalk_private.st_v6_push_jobs
  set state=case when p_result='sent' then 'sent' when reason is not null then 'dead' else 'discarded' end,
    lease_id=null where id=p_job;
  if reason is not null then
    insert into sectalk_private.st_v6_notification_dead_letters(job_id,channel,reason)
      values(p_job,'web_push',reason);
  end if;
  if p_result='gone' then
    delete from sectalk_private.st_v6_push_subscriptions where id=queued.subscription_id;
  end if;
  if exists(select 1 from sectalk_private.st_v6_push_jobs q where q.event_id=delivery.id and q.state='pending') then
    return;
  end if;

  update sectalk_private.st_v6_notification_delivery_events e set
    state=case
      when exists(select 1 from sectalk_private.st_v6_push_jobs q where q.event_id=e.id and q.state='sent') then 'sent'
      when exists(select 1 from sectalk_private.st_v6_push_jobs q where q.event_id=e.id and q.state='dead')
        and sectalk_private.st_v6_web_push_allowed(e.recipient,e.kind,e.room_id,e.chat_id,e.call_id) then 'fallback'
      else 'discarded' end,
    completed_at=clock_timestamp()
  where e.id=delivery.id;
end
$$;

create function public.st_v6_notification_fallbacks()
returns table(id uuid,kind text,occurred_at timestamptz,read_at timestamptz)
language sql stable security definer set search_path='' as $$
  select e.id,e.kind,e.completed_at,e.read_at
  from sectalk_private.st_v6_notification_delivery_events e
  where e.recipient=auth.uid() and e.state='fallback'
    and e.completed_at>=now()-interval '7 days'
    and sectalk_private.st_v6_web_push_allowed(e.recipient,e.kind,e.room_id,e.chat_id,e.call_id)
  order by e.completed_at desc,e.id desc limit 100
$$;

create function public.st_v6_read_notification_fallback(p_id uuid)
returns void language sql security definer set search_path='' as $$
  update sectalk_private.st_v6_notification_delivery_events e
  set read_at=clock_timestamp()
  where e.id=p_id and e.recipient=auth.uid() and e.state='fallback' and e.read_at is null
$$;

create function public.st_v6_notification_dead_letter_summary()
returns table(channel text,reason text,total bigint)
language sql stable security definer set search_path='' as $$
  select l.channel,l.reason,count(*) from sectalk_private.st_v6_notification_dead_letters l
  where l.failed_at>now()-interval '7 days' group by l.channel,l.reason order by l.channel,l.reason
$$;

revoke all on function sectalk_private.st_v6_queue_web_push(uuid,text,uuid,uuid,uuid,text),
  public.st_v6_claim_web_push(),public.st_v6_finish_web_push(uuid,uuid,text),
  public.st_v6_notification_fallbacks(),public.st_v6_read_notification_fallback(uuid),
  public.st_v6_notification_dead_letter_summary() from public,anon,authenticated,service_role;
grant execute on function public.st_v6_claim_web_push(),public.st_v6_finish_web_push(uuid,uuid,text),
  public.st_v6_notification_dead_letter_summary() to service_role;
grant execute on function public.st_v6_notification_fallbacks(),public.st_v6_read_notification_fallback(uuid) to authenticated;

create or replace function sectalk_private.st_v6_push_direct_alert()
returns trigger language plpgsql security definer set search_path='' as $$
declare recipient uuid;
begin
  if tg_table_name='st_calls' then
    if new.status='ringing' then
      perform sectalk_private.st_v6_queue_web_push(new.callee,'call.incoming',null,new.chat_id,new.id,'call:'||new.id);
    end if;
  else
    select case when c.member_a=new.sender then c.member_b else c.member_a end into recipient
    from public.st_chats c where c.id=new.chat_id and new.sender in (c.member_a,c.member_b);
    if recipient is not null then
      perform sectalk_private.st_v6_queue_web_push(recipient,'dm.message',null,new.chat_id,null,'dm:'||new.id);
    end if;
  end if;
  return new;
end
$$;

create or replace function sectalk_private.st_v6_push_task_notice()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_v6_queue_web_push(new.recipient,'task.'||new.kind,t.room_id,t.chat_id,null,'task:'||new.id)
  from public.st_v6_tasks t where t.id=new.task_id and sectalk_private.st_v6_task_audience(t.room_id,t.chat_id,new.recipient);
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
    perform realtime.send(envelope||jsonb_build_object('room_id',p_room,'mention_kind',p_kind),
      'room_activity','st:account:'||p_recipient,true);
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




revoke all on function sectalk_private.st_v6_deliver_account_alert(uuid,text,boolean,uuid,uuid,text)
  from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v6_deliver_account_alert(
  p_recipient uuid,p_kind text,p_quiet boolean,p_room uuid,p_admin_post uuid
)
returns boolean language sql set search_path=''
return sectalk_private.st_v6_deliver_account_alert(p_recipient,p_kind,p_quiet,p_room,p_admin_post,gen_random_uuid()::text);

create or replace function sectalk_private.st_v6_account_notice_alert()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_v6_deliver_account_alert(new.user_id,'security.account',
    sectalk_private.st_v6_quiet_for(new.user_id,null),null,null,'account:'||new.id);
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
