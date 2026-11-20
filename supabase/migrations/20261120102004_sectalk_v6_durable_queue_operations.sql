begin;

alter table sectalk_private.st_v6_notification_delivery_events
  add column queue_position bigint generated always as identity;
create index st_v6_delivery_pending_key
  on sectalk_private.st_v6_notification_delivery_events(recipient,channel,queue_position) where state='pending';
create index st_v6_dead_letters_recent on sectalk_private.st_v6_notification_dead_letters(failed_at desc,id desc);

create table sectalk_private.st_v6_worker_acquisitions (
  channel text not null check(channel in ('web_push','email')),
  request_id uuid not null,
  acquired_at timestamptz not null default now(),
  primary key(channel,request_id)
);
create index st_v6_worker_acquisitions_retention on sectalk_private.st_v6_worker_acquisitions(acquired_at);
create table sectalk_private.st_v6_queue_operators (
  account_id uuid primary key references public.st_profiles on delete cascade
);
create table sectalk_private.st_v6_queue_replays (
  event_id uuid primary key references sectalk_private.st_v6_notification_delivery_events on delete cascade,
  dead_letter_id uuid not null,
  actor uuid not null,
  replayed_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v6_worker_acquisitions enable row level security;
alter table sectalk_private.st_v6_queue_operators enable row level security;
alter table sectalk_private.st_v6_queue_replays enable row level security;
revoke all on sectalk_private.st_v6_worker_acquisitions,sectalk_private.st_v6_queue_operators,
  sectalk_private.st_v6_queue_replays from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_acquire_worker_request(p_channel text,p_request uuid)
returns boolean language plpgsql set search_path='' as $$
begin
  if p_request is null then return false; end if;
  delete from sectalk_private.st_v6_worker_acquisitions where acquired_at<now()-interval '1 day';
  insert into sectalk_private.st_v6_worker_acquisitions(channel,request_id) values(p_channel,p_request)
  on conflict(channel,request_id) do nothing;
  return found;
end
$$;

create function public.st_v6_queue_operations_status()
returns text language sql stable security definer set search_path='' as $$
  select case when not exists(select 1 from sectalk_private.st_v6_queue_operators where account_id=auth.uid())
      or not coalesce(sectalk_private.st_v2_active(auth.uid()),false) or public.st_staff_status()='none' then 'none'
    when public.st_staff_status()='verified' and exists(
      select 1 from auth.sessions s
      join auth.mfa_factors f on f.id=s.factor_id and f.user_id=s.user_id
      join auth.mfa_amr_claims proof on proof.session_id=s.id
      where s.id::text=auth.jwt()->>'session_id' and s.user_id=auth.uid() and s.aal='aal2'
        and (s.not_after is null or s.not_after>now()) and f.status='verified' and f.factor_type='totp'
        and proof.authentication_method='totp' and proof.updated_at>now()-interval '10 minutes'
    ) then 'verified'
    else 'mfa' end
$$;

create function sectalk_private.st_v6_queue_replay_source_allowed(
  p_event sectalk_private.st_v6_notification_delivery_events
)
returns boolean language sql stable set search_path='' as $$
  select case
    when p_event.kind='dm.message' and split_part(p_event.event_key,':',1)='dm' then exists(
      select 1 from public.st_messages m where m.chat_id=p_event.chat_id and m.revoked_at is null
        and m.id=(substring(p_event.event_key from '^dm:([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$'))::uuid
        and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=p_event.recipient))
    when p_event.room_id is not null and split_part(p_event.event_key,':',1)='room' then exists(
      select 1 from public.st_v6_room_posts post where post.room_id=p_event.room_id and post.removed_at is null
        and post.id=(substring(p_event.event_key from '^room:[0-9a-f-]{36}:([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$'))::uuid
        and sectalk_private.open_pair(post.sender,p_event.recipient))
    when p_event.kind='call.incoming' then p_event.call_id is not null
    when p_event.kind like 'task.%' and split_part(p_event.event_key,':',1)='task' then exists(
      select 1 from public.st_v6_task_notices n join public.st_v6_tasks t on t.id=n.task_id
      where n.recipient=p_event.recipient and n.id::text=split_part(p_event.event_key,':',2)
        and p_event.kind='task.'||n.kind and t.room_id is not distinct from p_event.room_id
        and t.chat_id is not distinct from p_event.chat_id)
    when p_event.kind='security.account' and split_part(p_event.event_key,':',1)='account' then exists(
      select 1 from public.st_v5_account_notices n where n.user_id=p_event.recipient
        and n.id::text=split_part(p_event.event_key,':',2))
    else false end
$$;

create function sectalk_private.st_v6_queue_replay_eligible(
  p_dead sectalk_private.st_v6_notification_dead_letters
)
returns boolean language sql stable set search_path='' as $$
  select p_dead.failed_at>=now()-interval '7 days' and p_dead.reason in ('retry_exhausted','expired') and exists(
    select 1 from sectalk_private.st_v6_notification_delivery_events e
    left join sectalk_private.st_v6_push_jobs q on q.id=p_dead.job_id
    where e.id=coalesce(q.event_id,p_dead.email_event_id) and e.channel=p_dead.channel
      and e.state in ('fallback','discarded')
      and not exists(select 1 from sectalk_private.st_v6_queue_replays r where r.event_id=e.id)
      and not exists(select 1 from sectalk_private.st_v6_notification_delivery_events pending
        where (pending.recipient,pending.channel)=(e.recipient,e.channel) and pending.state='pending')
      and case e.channel when 'email' then
        e.window_end>now()-interval '1 day' and sectalk_private.st_v6_email_fallback_allowed(e)
        and exists(select 1 from sectalk_private.st_v6_notification_email p where p.recipient=e.recipient and p.delivery_id is null)
      else
        q.state='dead' and not exists(select 1 from sectalk_private.st_v6_push_jobs success
          where success.event_id=e.id and success.state='sent')
        and exists(select 1 from sectalk_private.st_v6_push_subscriptions s
          join auth.sessions session on session.id=s.session_id and session.user_id=s.recipient
          where s.id=q.subscription_id and s.recipient=e.recipient
            and (session.not_after is null or session.not_after>now()))
        and sectalk_private.st_v6_web_push_allowed(e.recipient,e.kind,e.room_id,e.chat_id,e.call_id)
        and sectalk_private.st_v6_queue_replay_source_allowed(e)
      end)
$$;

create function public.st_v6_queue_dead_letters()
returns table(id uuid,channel text,reason text,failed_at timestamptz,replayable boolean)
language plpgsql stable security definer set search_path='' as $$
begin
  if public.st_v6_queue_operations_status()<>'verified' then
    raise exception 'Fresh queue operator verification required' using errcode='42501';
  end if;
  return query
    select l.id,l.channel,l.reason,l.failed_at,sectalk_private.st_v6_queue_replay_eligible(l)
    from sectalk_private.st_v6_notification_dead_letters l
    where l.failed_at>=now()-interval '7 days' order by l.failed_at desc,l.id desc limit 100;
end
$$;

create function public.st_v6_replay_queue_dead_letter(p_id uuid)
returns void language plpgsql security definer set search_path='' as $$
declare
  dead sectalk_private.st_v6_notification_dead_letters;
  event sectalk_private.st_v6_notification_delivery_events;
  failed_job sectalk_private.st_v6_push_jobs;
  source_id uuid;
begin
  if public.st_v6_queue_operations_status()<>'verified' then
    raise exception 'Fresh queue operator verification required' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v6_queue_replay',15);
  select l.* into dead from sectalk_private.st_v6_notification_dead_letters l where l.id=p_id;
  if not found then raise exception 'Queue replay is unavailable'; end if;
  if dead.channel='email' then
    source_id:=dead.email_event_id;
    -- The email consumer also locks consent before its event.
    perform p.recipient from sectalk_private.st_v6_notification_email p where p.recipient=(
      select e.recipient from sectalk_private.st_v6_notification_delivery_events e where e.id=source_id
    ) for update;
  else
    select q.* into failed_job from sectalk_private.st_v6_push_jobs q where q.id=dead.job_id;
    source_id:=failed_job.event_id;
    -- Keep the same subscription → event lock order used by Web Push settlement.
    perform s.id from sectalk_private.st_v6_push_subscriptions s where s.id=failed_job.subscription_id for key share;
  end if;
  select e.* into event from sectalk_private.st_v6_notification_delivery_events e where e.id=source_id for update;
  if not found or not sectalk_private.st_v6_queue_replay_eligible(dead) then raise exception 'Queue replay is unavailable'; end if;
  insert into sectalk_private.st_v6_queue_replays(event_id,dead_letter_id,actor)
    values(event.id,dead.id,auth.uid());
  update sectalk_private.st_v6_notification_delivery_events set state='pending',completed_at=null,read_at=null
    where id=event.id;
  if dead.channel='email' then
    update sectalk_private.st_v6_notification_email set delivery_id=event.id,window_end=event.window_end,
      next_at=now(),attempts=0,lease_id=null where recipient=event.recipient;
  else
    insert into sectalk_private.st_v6_push_jobs(subscription_id,event_id,kind,room_id,chat_id,call_id,expires_at)
    values(failed_job.subscription_id,event.id,event.kind,event.room_id,event.chat_id,event.call_id,
      now()+case when event.call_id is null then interval '5 minutes' else interval '30 seconds' end);
  end if;
end
$$;

revoke all on function sectalk_private.st_v6_acquire_worker_request(text,uuid),
  sectalk_private.st_v6_queue_replay_source_allowed(sectalk_private.st_v6_notification_delivery_events),
  sectalk_private.st_v6_queue_replay_eligible(sectalk_private.st_v6_notification_dead_letters),
  public.st_v6_queue_operations_status(),public.st_v6_queue_dead_letters(),public.st_v6_replay_queue_dead_letter(uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_queue_operations_status(),public.st_v6_queue_dead_letters(),
  public.st_v6_replay_queue_dead_letter(uuid) to authenticated;

create function public.st_v6_claim_web_push(p_request uuid)
returns table(job uuid,lease uuid,endpoint text,p256dh text,auth_secret text,ttl integer,terminal text)
language plpgsql security definer set search_path='' as $$
begin
  if not sectalk_private.st_v6_acquire_worker_request('web_push',p_request) then return; end if;
  delete from sectalk_private.st_v6_notification_delivery_events e where e.completed_at<now()-interval '7 days';
  return query
  with candidates as materialized (
    select q.id from sectalk_private.st_v6_push_jobs q
    join sectalk_private.st_v6_notification_delivery_events e on e.id=q.event_id
    where q.state='pending' and q.next_attempt_at<=now()
      and not exists(select 1 from sectalk_private.st_v6_notification_delivery_events earlier
        where (earlier.recipient,earlier.channel)=(e.recipient,e.channel) and earlier.state='pending'
          and earlier.queue_position<e.queue_position)
      and not exists(select 1 from sectalk_private.st_v6_notification_delivery_events active
        join sectalk_private.st_v6_push_jobs work on work.event_id=active.id
        where (active.recipient,active.channel)=(e.recipient,e.channel)
          and active.state='pending' and active.id<>e.id and work.state='pending'
          and work.lease_id is not null and work.next_attempt_at>now())
    order by q.next_attempt_at,e.queue_position,q.id
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
    when exists(select 1 from sectalk_private.st_v6_queue_replays replay where replay.event_id=delivery.id)
      and not sectalk_private.st_v6_queue_replay_source_allowed(delivery) then 'discard'
    when q.expires_at<=now()+interval '1 second' then 'expired'
    when q.attempts>3 then 'exhausted'
    end as terminal) result;
end
$$;


create function public.st_v6_claim_notification_email(p_request uuid)
returns table(recipient uuid,lease uuid,email text,cadence text,unsubscribe_key uuid,mentions bigint,tasks bigint,calls bigint,delivery_id uuid)
language plpgsql security definer set search_path='' as $$
declare pref record; boundary timestamptz; activity_since timestamptz; counts record; event uuid;
begin
  if not sectalk_private.st_v6_acquire_worker_request('email',p_request) then return; end if;
  delete from sectalk_private.st_v6_notification_delivery_events e where e.channel='email'
    and e.completed_at<now()-interval '7 days';
  for pref in
    select p.*,u.email as current_email,u.email_confirmed_at,u.email_change
    from sectalk_private.st_v6_notification_email p join auth.users u on u.id=p.recipient
    where p.enabled and p.next_at<=now()
    order by p.next_at,p.recipient limit 20 for update of p skip locked
  loop
    if pref.email_confirmed_at is null or lower(pref.current_email) is distinct from pref.email_at_consent
      or coalesce(pref.email_change,'')<>'' or not sectalk_private.st_v2_active(pref.recipient) then
      update sectalk_private.st_v6_notification_email p set enabled=false,email_at_consent=null,
        lease_id=null,window_end=null,attempts=0 where p.recipient=pref.recipient;
      continue;
    end if;
    boundary:=coalesce(pref.window_end,now());
    event:=pref.delivery_id;
    activity_since:=coalesce((select e.window_start from sectalk_private.st_v6_notification_delivery_events e where e.id=event),
      pref.scanned_at);
    if event is not null and (boundary<=now()-interval '1 day' or pref.attempts>=3) then
      perform sectalk_private.st_v6_complete_email_window(pref.recipient,event,boundary,
        case when boundary<=now()-interval '1 day' then 'expired' else 'retry_exhausted' end);
      continue;
    end if;
    select * into counts from sectalk_private.st_v6_notification_email_counts(pref.recipient,pref.categories,activity_since,boundary);
    if counts.mentions+counts.tasks+counts.calls=0 then
      perform sectalk_private.st_v6_complete_email_window(pref.recipient,event,boundary,'discarded');
      continue;
    end if;
    if event is null then
      insert into sectalk_private.st_v6_notification_delivery_events
        (recipient,event_key,kind,channel,consent_version,window_start,window_end)
      values(pref.recipient,'email:'||pref.consent_version||':'||extract(epoch from boundary),'email.digest','email',
        pref.consent_version,pref.scanned_at,boundary)
      on conflict on constraint st_v6_notification_delivery_events_recipient_event_key_key do nothing returning id into event;
      if event is null then
        perform sectalk_private.st_v6_complete_email_window(pref.recipient,null,boundary,'discarded');
        continue;
      end if;
    end if;
    update sectalk_private.st_v6_notification_email p set next_at=now()+interval '45 seconds',
      window_end=boundary,lease_id=gen_random_uuid(),attempts=p.attempts+1,delivery_id=event
    where p.recipient=pref.recipient returning p.lease_id into lease;
    recipient:=pref.recipient;
    email:=pref.current_email;
    cadence:=pref.cadence;
    unsubscribe_key:=pref.unsubscribe_key;
    mentions:=counts.mentions;
    tasks:=counts.tasks;
    calls:=counts.calls;
    delivery_id:=event;
    return next;
  end loop;
end
$$;


create or replace function sectalk_private.st_v6_complete_email_window(
  p_recipient uuid,p_delivery uuid,p_boundary timestamptz,p_result text
)
returns void language plpgsql set search_path='' as $$
begin
  if p_result in ('provider_rejected','retry_exhausted','expired') then
    insert into sectalk_private.st_v6_notification_dead_letters(email_event_id,channel,reason)
      values(p_delivery,'email',p_result) on conflict(email_event_id) do nothing;
  end if;
  update sectalk_private.st_v6_notification_delivery_events e set
    state=case when p_result='sent' then 'sent'
      when p_result in ('provider_rejected','retry_exhausted','expired')
        and sectalk_private.st_v6_email_fallback_allowed(e) then 'fallback'
      else 'discarded' end,
    completed_at=clock_timestamp()
  where e.id=p_delivery and e.state='pending';
  update sectalk_private.st_v6_notification_email p set scanned_at=greatest(p.scanned_at,p_boundary),
    next_at=now()+sectalk_private.st_v6_email_cadence(p.cadence),window_end=null,
    lease_id=null,attempts=0,delivery_id=null
  where p.recipient=p_recipient;
end
$$;


create or replace function public.st_v6_claim_web_push()
returns table(job uuid,lease uuid,endpoint text,p256dh text,auth_secret text,ttl integer,terminal text)
language sql security definer set search_path=''
as $$ select * from public.st_v6_claim_web_push(gen_random_uuid()) $$;

create or replace function public.st_v6_claim_notification_email()
returns table(recipient uuid,lease uuid,email text,cadence text,unsubscribe_key uuid,mentions bigint,tasks bigint,calls bigint,delivery_id uuid)
language sql security definer set search_path=''
as $$ select * from public.st_v6_claim_notification_email(gen_random_uuid()) $$;

revoke all on function public.st_v6_claim_web_push(uuid),public.st_v6_claim_notification_email(uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_claim_web_push(uuid),public.st_v6_claim_notification_email(uuid) to service_role;

commit;
