begin;

-- A caller's authenticated server request can expedite only the push already
-- enqueued for its ringing call. Queue leases coordinate with the normal worker.
create function public.st_v6_claim_incoming_call_push(p_call uuid, p_actor uuid, p_session uuid)
returns table(job uuid, lease uuid, endpoint text, p256dh text, auth_secret text, ttl integer, terminal text)
language sql security definer set search_path='' as $$
  with active_call as materialized (
    select c.id, c.chat_id, c.expires_at
    from public.st_calls c
    join sectalk_private.st_v6_call_endpoints e on e.call_id=c.id and e.actor_id=c.caller
    join auth.sessions a on a.id=p_session and a.user_id=c.caller
    where c.id=p_call and c.caller=p_actor and e.auth_session=p_session::text
      and (a.not_after is null or a.not_after>now())
      and sectalk_private.st_v2_active(p_actor)
      and c.status='ringing' and c.expires_at>now()+interval '1 second'
  ), candidates as materialized (
    select q.id, least(q.expires_at, c.expires_at) as expires_at
    from active_call c
    join sectalk_private.st_v6_push_jobs q on q.call_id=c.id and q.chat_id=c.chat_id
    where q.kind='call.incoming' and q.state='pending' and q.next_attempt_at<=now()
    order by q.id
    limit 5
    for update of q skip locked
  ), claimed as (
    update sectalk_private.st_v6_push_jobs q
    set lease_id=gen_random_uuid(), next_attempt_at=now()+interval '45 seconds', attempts=q.attempts+1
    from candidates d where q.id=d.id
    returning q.*, d.expires_at as deadline
  )
  select q.id, q.lease_id,
    case when outcome.terminal is null then s.endpoint end,
    case when outcome.terminal is null then s.p256dh end,
    case when outcome.terminal is null then s.auth_secret end,
    greatest(0, floor(extract(epoch from q.deadline-now()))::integer),
    outcome.terminal
  from claimed q
  join sectalk_private.st_v6_notification_delivery_events e on e.id=q.event_id
  left join sectalk_private.st_v6_push_subscriptions s on s.id=q.subscription_id and s.recipient=e.recipient
  left join auth.sessions a on a.id=s.session_id and a.user_id=s.recipient
  cross join lateral (select case
    when a.id is null or a.not_after<=now() then 'discard'
    when not sectalk_private.st_v6_web_push_allowed(e.recipient,q.kind,q.room_id,q.chat_id,q.call_id) then 'discard'
    when q.deadline<=now()+interval '1 second' then 'expired'
    when q.attempts>3 then 'exhausted'
    end as terminal) outcome
$$;

revoke all on function public.st_v6_claim_incoming_call_push(uuid,uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_claim_incoming_call_push(uuid,uuid,uuid) to service_role;

commit;
