begin;

create index st_v6_pending_delivery_health on sectalk_private.st_v6_notification_delivery_events(channel,created_at)
  where state='pending';

create function public.st_v6_platform_queue_health()
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare
  result jsonb;
  cutoff timestamptz:=date_bin(interval '5 minutes',statement_timestamp(),'2000-01-01 00:00:00+00'::timestamptz);
begin
  if public.st_v6_queue_operations_status()<>'verified' then
    raise exception 'Fresh queue operator verification required' using errcode='42501';
  end if;
  with channels(channel) as (values ('web_push'::text),('email'::text)),
  backlog as (
    select channel,count(*) as depth,min(created_at) as oldest
    from sectalk_private.st_v6_notification_delivery_events
    where state='pending' group by channel
  ), recent_failures as (
    select channel,count(*) as dead_letters
    from sectalk_private.st_v6_notification_dead_letters
    where failed_at>=now()-interval '7 days' group by channel
  ), queues as (
    select jsonb_object_agg(c.channel,jsonb_build_object(
      'depth',coalesce(b.depth,0),'oldest_seconds',greatest(0,floor(extract(epoch from now()-b.oldest))),
      'dead_letters',coalesce(f.dead_letters,0)
    )) as channels
    from channels c left join backlog b using(channel) left join recent_failures f using(channel)
  ), counts as (
    select coalesce(sum(requests),0) as requests,
      coalesce(sum(requests-client_errors+throttled),0) as offered,
      coalesce(sum(server_errors+throttled),0) as failed,
      coalesce(sum(latency_histogram[1]+latency_histogram[2]+latency_histogram[3]+
        latency_histogram[4]+latency_histogram[5]),0) as fast
    from sectalk_private.st_v6_operation_rollups
    where bucket>=cutoff-interval '24 hours' and bucket<cutoff
  )
  select jsonb_build_object('through',cutoff,'queues',queues.channels,'slo',jsonb_build_object(
    'availability',jsonb_build_object('total',counts.offered,'good',counts.offered-counts.failed,'target',99.9),
    'handler_latency',jsonb_build_object('total',counts.requests,'good',counts.fast,'target',95,'threshold_ms',500)
  ))
  into result from queues cross join counts;
  return result;
end $$;

revoke all on function public.st_v6_platform_queue_health() from public,anon,authenticated,service_role;
grant execute on function public.st_v6_platform_queue_health() to authenticated;
notify pgrst,'reload schema';
commit;
