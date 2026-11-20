begin;

create table sectalk_private.st_v6_call_qos_key (
  singleton boolean primary key default true check (singleton),
  secret bytea not null default extensions.gen_random_bytes(32)
);
insert into sectalk_private.st_v6_call_qos_key default values;

create table sectalk_private.st_v6_call_qos (
  day date not null,
  event_key bytea not null,
  reporter_key bytea not null,
  mode text not null check (mode in ('direct', 'meeting')),
  metric text not null,
  bucket text not null,
  primary key (day, event_key),
  check (
    (metric = 'setup' and bucket in ('fast', 'moderate', 'slow', 'failed'))
    or (metric = 'relay' and bucket in ('relayed', 'non_relayed'))
    or (metric = 'recovery' and bucket in ('recovered', 'failed'))
  )
);
create index st_v6_call_qos_reporter_limit on sectalk_private.st_v6_call_qos (day, reporter_key);
alter table sectalk_private.st_v6_call_qos_key enable row level security;
alter table sectalk_private.st_v6_call_qos enable row level security;
revoke all on sectalk_private.st_v6_call_qos_key, sectalk_private.st_v6_call_qos from public, anon, authenticated;

create function public.st_v6_report_call_qos(
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
  ) then return false; end if;

  if p_mode = 'direct' then
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
  if (select count(*) from sectalk_private.st_v6_call_qos where day = utc_day and reporter_key = reporter) >= 24 then
    return false;
  end if;
  insert into sectalk_private.st_v6_call_qos(day, event_key, reporter_key, mode, metric, bucket)
    values (utc_day, event, reporter, p_mode, p_metric, p_bucket) on conflict do nothing;
  return found;
end
$$;
revoke all on function public.st_v6_report_call_qos(text, uuid, uuid, text, text) from public, anon, authenticated;
grant execute on function public.st_v6_report_call_qos(text, uuid, uuid, text, text) to authenticated;

create function sectalk_private.st_v6_call_qos_at(p_window text, cutoff timestamptz)
returns jsonb language sql stable set search_path = '' as $$
  with days as (
    select (cutoff at time zone 'UTC')::date as through,
      case p_window when '7d' then 7 when '30d' then 30 end as span
  ), daily as (
    select sample.day, sample.mode, sample.metric, sample.bucket, (count(*) / 10) * 10 as samples
    from sectalk_private.st_v6_call_qos sample cross join days
    where sample.day >= days.through - days.span and sample.day < days.through
    group by sample.day, sample.mode, sample.metric, sample.bucket
    having count(*) >= 10 and count(distinct sample.reporter_key) >= 5
  ), totals as (
    select mode, metric, bucket, sum(samples) as samples from daily group by mode, metric, bucket
  )
  select jsonb_build_object(
    'through', days.through,
    'metrics', coalesce((select jsonb_object_agg(mode || ':' || metric || ':' || bucket, samples) from totals), '{}'::jsonb)
  ) from days;
$$;
revoke all on function sectalk_private.st_v6_call_qos_at(text, timestamptz) from public, anon, authenticated;

create or replace function public.st_v6_usage_metrics(p_window text,p_live boolean)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  cutoff timestamptz := date_trunc('minute',now(),'UTC');
begin
  if p_live is not true then return public.st_v6_usage_metrics(p_window); end if;
  perform sectalk_private.st_v6_touch_analytics_lease();
  return sectalk_private.st_v6_usage_metrics_at(p_window,cutoff)
    || jsonb_build_object('qos',sectalk_private.st_v6_call_qos_at(p_window,cutoff));
end
$$;

select cron.schedule('sectalk-v6-prune-call-qos', '17 3 * * *',
  'delete from sectalk_private.st_v6_call_qos where day < (now() at time zone ''UTC'')::date - 35');

commit;
