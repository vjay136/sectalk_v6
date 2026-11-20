begin;

alter table sectalk_private.st_v6_call_qos drop constraint st_v6_call_qos_check;
alter table sectalk_private.st_v6_call_qos add constraint st_v6_call_qos_check check (
    (metric = 'setup' and bucket in ('fast', 'moderate', 'slow', 'failed'))
    or (metric = 'relay' and bucket in ('relayed', 'non_relayed'))
    or (metric = 'recovery' and bucket in ('recovered', 'failed'))
    or
    (metric = 'join' and bucket in ('started', 'connected'))
    or (metric = 'ice_restart' and mode = 'direct' and bucket in ('not_requested', 'requested'))
    or (metric = 'mos' and bucket in ('below_2', '2_to_3', '3_to_4', '4_or_more'))
);

create or replace function public.st_v6_report_call_qos(
  p_mode text, p_resource uuid, p_device uuid, p_metric text, p_bucket text
) returns boolean language plpgsql security definer set search_path = '' as $$
declare
  actor uuid := auth.uid();
  utc_day date := (clock_timestamp() at time zone 'UTC')::date;
  key_bytes bytea;
  reporter bytea;
  event bytea;
begin
  if actor is null or p_resource is null or p_mode is null or p_metric is null or p_bucket is null or not (
    (p_metric = 'setup' and p_bucket in ('fast', 'moderate', 'slow', 'failed'))
    or (p_metric = 'relay' and p_bucket in ('relayed', 'non_relayed'))
    or (p_metric = 'recovery' and p_bucket in ('recovered', 'failed'))
    or
    (p_metric = 'join' and p_bucket in ('started', 'connected'))
    or (p_metric = 'ice_restart' and p_mode = 'direct' and p_bucket in ('not_requested', 'requested'))
    or (p_metric = 'mos' and p_bucket in ('below_2', '2_to_3', '3_to_4', '4_or_more'))
  ) then return false; end if;

  if p_mode = 'direct' then
    if p_metric = 'ice_restart' and not exists (
      select 1 from public.st_calls call where call.id = p_resource and call.caller = actor
    ) then return false; end if;
    if (not sectalk_private.call_access(p_resource, actor) and not exists (
      select 1 from public.st_calls call
      where call.id = p_resource and actor in (call.caller, call.callee)
        and call.status = 'ended' and call.end_reason is null
        and call.expires_at >= now() - interval '1 minute'
        and sectalk_private.open_pair(call.caller, call.callee)
    )) or exists (
      select 1 from sectalk_private.st_v6_call_endpoints e
      where e.call_id = p_resource and e.actor_id = actor and (
        e.device_id is distinct from p_device or e.auth_session is distinct from auth.jwt()->>'session_id'
      )
    ) then return false; end if;
  elsif p_mode = 'meeting' then
    if p_device is not null or not public.st_v3_media_access(p_resource) then return false; end if;
  else
    return false;
  end if;

  select secret into key_bytes from sectalk_private.st_v6_call_qos_key where singleton;
  reporter := extensions.hmac(convert_to('reporter:' || utc_day || ':' || actor, 'UTF8'), key_bytes, 'sha256');
  event := extensions.hmac(convert_to('event:' || utc_day || ':' || actor || ':' || p_mode || ':' || p_resource || ':' || p_metric, 'UTF8'),
    key_bytes, 'sha256');
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(encode(reporter, 'hex'), 0));
  if p_metric in ('join', 'ice_restart') then
    update sectalk_private.st_v6_call_qos set bucket = p_bucket
      where day = utc_day and event_key = event and (
        (metric = 'join' and bucket = 'started' and p_bucket = 'connected')
        or (metric = 'ice_restart' and bucket = 'not_requested' and p_bucket = 'requested')
      );
    if found then return true; end if;
  end if;
  if (select count(*) from sectalk_private.st_v6_call_qos where day = utc_day and reporter_key = reporter) >= 24 then
    return false;
  end if;
  insert into sectalk_private.st_v6_call_qos(day, event_key, reporter_key, mode, metric, bucket)
    values (utc_day, event, reporter, p_mode, p_metric, p_bucket) on conflict do nothing;
  return found;
end
$$;

create function sectalk_private.st_v6_call_quality_rates(p_window text, cutoff timestamptz)
returns jsonb language sql stable set search_path = '' as $$
  with eligible as (
    select day, mode, metric, reporter_key,
      bucket in ('connected', 'relayed', 'requested') as positive
    from sectalk_private.st_v6_call_qos
    where day >= (cutoff at time zone 'UTC')::date - (case p_window when '7d' then 7 when '30d' then 30 end)
      and day < (cutoff at time zone 'UTC')::date and metric in ('join', 'relay', 'ice_restart')
  ), daily as (
    select day, mode, metric, count(*) as measured, count(*) filter (where positive) as positive
    from eligible group by day, mode, metric
    having count(*) >= 10 and count(distinct reporter_key) >= 5
      and count(distinct reporter_key) filter (where positive) not between 1 and 4
      and count(distinct reporter_key) filter (where not positive) not between 1 and 4
  ), totals as (
    select mode, metric, sum((measured / 10) * 10) as measured,
      sum((positive / 10) * 10) as positive, sum(positive) * 10 / sum(measured) as rate
    from daily group by mode, metric
  )
  select coalesce(jsonb_object_agg(mode || ':' || metric, jsonb_build_object(
    'sampled', measured, 'positive', positive, 'percent', floor(rate) * 10
  )), '{}'::jsonb) from totals;
$$;
revoke all on function sectalk_private.st_v6_call_quality_rates(text, timestamptz) from public, anon, authenticated;

create or replace function public.st_v6_usage_metrics(p_window text,p_live boolean)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  cutoff timestamptz := date_trunc('minute',now(),'UTC');
begin
  if p_live is not true then return public.st_v6_usage_metrics(p_window); end if;
  perform sectalk_private.st_v6_touch_analytics_lease();
  return sectalk_private.st_v6_usage_metrics_at(p_window,cutoff)
    || jsonb_build_object('qos', sectalk_private.st_v6_call_qos_at(p_window,cutoff)
      || jsonb_build_object('rates', sectalk_private.st_v6_call_quality_rates(p_window,cutoff)));
end
$$;

commit;
