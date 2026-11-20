begin;

create table sectalk_private.st_v6_push_subscriptions (
  id uuid primary key default gen_random_uuid(),
  recipient uuid not null references public.st_profiles on delete cascade,
  session_id uuid not null references auth.sessions on delete cascade,
  endpoint text not null unique check (length(endpoint) between 20 and 2048),
  p256dh text not null check (p256dh ~ '^[A-Za-z0-9_-]{87}$'),
  auth_secret text not null check (auth_secret ~ '^[A-Za-z0-9_-]{22}$')
);
create index st_v6_push_subscription_recipient on sectalk_private.st_v6_push_subscriptions(recipient);
create index st_v6_push_subscription_session on sectalk_private.st_v6_push_subscriptions(session_id);

create table sectalk_private.st_v6_push_jobs (
  id uuid primary key default gen_random_uuid(),
  subscription_id uuid not null references sectalk_private.st_v6_push_subscriptions on delete cascade,
  kind text not null,
  room_id uuid references public.st_v6_rooms on delete cascade,
  chat_id uuid references public.st_chats on delete cascade,
  call_id uuid references public.st_calls on delete cascade,
  expires_at timestamptz not null,
  next_attempt_at timestamptz not null default now(),
  lease_id uuid,
  attempts integer not null default 0
);
create index st_v6_push_jobs_subscription on sectalk_private.st_v6_push_jobs(subscription_id);
create index st_v6_push_jobs_room on sectalk_private.st_v6_push_jobs(room_id) where room_id is not null;
create index st_v6_push_jobs_chat on sectalk_private.st_v6_push_jobs(chat_id) where chat_id is not null;
create index st_v6_push_jobs_call on sectalk_private.st_v6_push_jobs(call_id) where call_id is not null;
create index st_v6_push_jobs_ready on sectalk_private.st_v6_push_jobs(next_attempt_at,id);
alter table sectalk_private.st_v6_push_subscriptions enable row level security;
alter table sectalk_private.st_v6_push_jobs enable row level security;
revoke all on sectalk_private.st_v6_push_subscriptions,sectalk_private.st_v6_push_jobs
  from public,anon,authenticated,service_role;

create function public.st_v6_push_subscription(
  p_actor uuid,p_session uuid,p_action text,p_endpoint text default null,p_p256dh text default null,p_auth text default null
)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  if not exists(select 1 from auth.sessions s where s.id=p_session and s.user_id=p_actor
    and (s.not_after is null or s.not_after>now())) then return false; end if;
  if p_action='status' then
    return exists(select 1 from sectalk_private.st_v6_push_subscriptions where session_id=p_session and recipient=p_actor);
  elsif p_action='delete' then
    delete from sectalk_private.st_v6_push_subscriptions
    where session_id=p_session and recipient=p_actor and endpoint=p_endpoint;
    return true;
  elsif p_action<>'save' or p_action is null or not sectalk_private.st_v2_active(p_actor) then
    return false;
  end if;

  perform id from public.st_profiles where id=p_actor for update;
  if not found then return false; end if;
  if (select count(*) from sectalk_private.st_v6_push_subscriptions
      where recipient=p_actor and endpoint<>p_endpoint)>=5 then return false; end if;
  insert into sectalk_private.st_v6_push_subscriptions as subscription(recipient,session_id,endpoint,p256dh,auth_secret)
    values(p_actor,p_session,p_endpoint,p_p256dh,p_auth)
    on conflict(endpoint) do update set p256dh=excluded.p256dh,auth_secret=excluded.auth_secret,
      session_id=excluded.session_id
    where subscription.recipient=p_actor and subscription.session_id=p_session;
  return found;
end
$$;

create function sectalk_private.st_v6_web_push_allowed(
  p_actor uuid,p_kind text,p_room uuid,p_chat uuid,p_call uuid
)
returns boolean language plpgsql stable set search_path='' as $$
declare category text; space uuid; quiet boolean;
begin
  if p_kind='security.account' then return true; end if;
  if not sectalk_private.st_v2_active(p_actor) then return false; end if;
  if p_kind in ('dm.message','call.incoming') then
    category:=split_part(p_kind,'.',1);
  else
    select a.category into category from sectalk_private.st_v6_alert_priority(p_kind) a;
  end if;
  if category is null then return false; end if;
  if p_call is not null and not exists(select 1 from public.st_calls c
    where c.id=p_call and c.chat_id=p_chat and c.callee=p_actor and c.status='ringing' and c.expires_at>now()) then
    return false;
  end if;
  if p_room is not null then
    select r.workspace_id into space from public.st_v6_rooms r
    where r.id=p_room and not r.archived and sectalk_private.st_v6_task_audience(r.id,null,p_actor);
    if not found then return false; end if;
    if category=any(sectalk_private.st_v6_mandatory_workspace_alerts(space)) then return true; end if;
    quiet:=sectalk_private.st_v6_room_alert_quiet(p_actor,p_room);
  elsif p_chat is not null then
    if not sectalk_private.st_v2_chat_write(p_chat,p_actor) then return false; end if;
    quiet:=sectalk_private.st_v6_quiet_for(p_actor,p_chat);
  else
    quiet:=sectalk_private.st_v6_quiet_for(p_actor,null);
  end if;
  return not quiet and sectalk_private.st_v6_notification_enabled(p_actor,category);
end
$$;

create function sectalk_private.st_v6_queue_web_push(
  p_actor uuid,p_kind text,p_room uuid default null,p_chat uuid default null,p_call uuid default null
)
returns void language sql set search_path='' as $$
  insert into sectalk_private.st_v6_push_jobs(subscription_id,kind,room_id,chat_id,call_id,expires_at)
  select s.id,p_kind,p_room,p_chat,p_call,
    case when p_call is null then now()+interval '5 minutes' else now()+interval '30 seconds' end
  from sectalk_private.st_v6_push_subscriptions s
  join auth.sessions a on a.id=s.session_id and a.user_id=s.recipient
  where s.recipient=p_actor and (a.not_after is null or a.not_after>now())
    and sectalk_private.st_v6_web_push_allowed(p_actor,p_kind,p_room,p_chat,p_call)
$$;

create function public.st_v6_claim_web_push()
returns table(job uuid,lease uuid,endpoint text,p256dh text,auth_secret text,ttl integer)
language plpgsql security definer set search_path='' as $$
begin
  delete from sectalk_private.st_v6_push_jobs q where q.expires_at<=now();
  return query
  with candidates as materialized (
    select q.id
    from sectalk_private.st_v6_push_jobs q
    where q.next_attempt_at<=now() and q.attempts<3
    order by q.next_attempt_at,q.id
    limit 25 for update of q skip locked
  ), claimed as (
    update sectalk_private.st_v6_push_jobs q
    set lease_id=gen_random_uuid(),next_attempt_at=now()+interval '45 seconds',attempts=q.attempts+1
    from candidates where q.id=candidates.id
    returning q.*
  )
  select q.id,q.lease_id,
    case when decision.allowed then s.endpoint end,
    case when decision.allowed then s.p256dh end,
    case when decision.allowed then s.auth_secret end,
    greatest(0,floor(extract(epoch from q.expires_at-now()))::integer)
  from claimed q
  join sectalk_private.st_v6_push_subscriptions s on s.id=q.subscription_id
  join auth.sessions a on a.id=s.session_id and a.user_id=s.recipient
  cross join lateral (select (a.not_after is null or a.not_after>now())
    and sectalk_private.st_v6_web_push_allowed(s.recipient,q.kind,q.room_id,q.chat_id,q.call_id) as allowed) decision;
end
$$;

create function public.st_v6_finish_web_push(p_job uuid,p_lease uuid,p_result text)
returns void language plpgsql security definer set search_path='' as $$
declare queued sectalk_private.st_v6_push_jobs;
begin
  select * into queued from sectalk_private.st_v6_push_jobs q where q.id=p_job and q.lease_id=p_lease for update;
  if not found then return; end if;
  if p_result='gone' then
    delete from sectalk_private.st_v6_push_subscriptions where id=queued.subscription_id;
  elsif p_result='retry' and queued.attempts<3 and queued.expires_at>now()+interval '15 seconds' then
    update sectalk_private.st_v6_push_jobs set next_attempt_at=now()+interval '15 seconds',lease_id=null where id=p_job;
  else
    delete from sectalk_private.st_v6_push_jobs where id=p_job;
  end if;
end
$$;

create function sectalk_private.st_v6_push_direct_alert()
returns trigger language plpgsql security definer set search_path='' as $$
declare recipient uuid;
begin
  if tg_table_name='st_calls' then
    if new.status='ringing' then
      perform sectalk_private.st_v6_queue_web_push(new.callee,'call.incoming',null,new.chat_id,new.id);
    end if;
  else
    select case when c.member_a=new.sender then c.member_b else c.member_a end into recipient
    from public.st_chats c where c.id=new.chat_id and new.sender in (c.member_a,c.member_b);
    if recipient is not null then
      perform sectalk_private.st_v6_queue_web_push(recipient,'dm.message',null,new.chat_id);
    end if;
  end if;
  return new;
end
$$;
create trigger st_v6_push_direct_alert after insert on public.st_messages
for each row execute function sectalk_private.st_v6_push_direct_alert();
create trigger st_v6_push_direct_alert after insert on public.st_calls
for each row execute function sectalk_private.st_v6_push_direct_alert();

create function sectalk_private.st_v6_push_task_notice()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_v6_queue_web_push(new.recipient,'task.'||new.kind,t.room_id,t.chat_id)
  from public.st_v6_tasks t where t.id=new.task_id and sectalk_private.st_v6_task_audience(t.room_id,t.chat_id,new.recipient);
  return new;
end
$$;
create trigger st_v6_push_task_notice after insert on public.st_v6_task_notices
for each row execute function sectalk_private.st_v6_push_task_notice();

revoke all on function sectalk_private.st_v6_web_push_allowed(uuid,text,uuid,uuid,uuid),
  sectalk_private.st_v6_queue_web_push(uuid,text,uuid,uuid,uuid),
  sectalk_private.st_v6_push_direct_alert(),sectalk_private.st_v6_push_task_notice() from public,anon,authenticated,service_role;
revoke all on function public.st_v6_push_subscription(uuid,uuid,text,text,text,text),
  public.st_v6_claim_web_push(),public.st_v6_finish_web_push(uuid,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_push_subscription(uuid,uuid,text,text,text,text),
  public.st_v6_claim_web_push(),public.st_v6_finish_web_push(uuid,uuid,text) to service_role;

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
  if alert.category<>'task' then
    perform sectalk_private.st_v6_queue_web_push(p_recipient,p_kind,p_room);
  end if;
  return true;
end
$$;



commit;
