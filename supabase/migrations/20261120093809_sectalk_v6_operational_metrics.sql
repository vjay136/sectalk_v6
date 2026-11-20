begin;

create table sectalk_private.st_v6_operation_rollups (
  bucket timestamptz not null,
  operation text not null check(operation in (
    'file_upload','file_publish','file_download_grant','file_download','call_ice','meeting_token',
    'billing_action','billing_webhook'
  )),
  requests bigint not null,
  client_errors bigint not null,
  server_errors bigint not null,
  throttled bigint not null,
  unavailable bigint not null,
  peak_in_flight integer not null,
  latency_histogram bigint[] not null check(cardinality(latency_histogram)=9),
  primary key(bucket,operation)
);
alter table sectalk_private.st_v6_operation_rollups enable row level security;
revoke all on sectalk_private.st_v6_operation_rollups from public,anon,authenticated,service_role;

create function public.st_v6_record_operational_metrics(p_samples jsonb)
returns void language plpgsql security definer set search_path='' as $$
declare current_bucket timestamptz := date_bin(interval '5 minutes',statement_timestamp(),'2000-01-01 00:00:00+00'::timestamptz);
begin
  if p_samples is null or jsonb_typeof(p_samples)<>'array' or octet_length(p_samples::text)>16384 then
    raise exception 'Invalid operational sample batch' using errcode='22023';
  end if;
  if jsonb_array_length(p_samples) not between 1 and 128 or exists(
    select 1 from jsonb_to_recordset(p_samples) as s(operation text,duration_ms integer,status integer,in_flight integer)
    where s.operation is null or s.operation not in (
      'file_upload','file_publish','file_download_grant','file_download','call_ice','meeting_token',
      'billing_action','billing_webhook'
    ) or (s.duration_ms between 0 and 60000) is not true or (s.status between 100 and 599) is not true
      or (s.in_flight between 1 and 10000) is not true
  ) then raise exception 'Invalid operational sample batch' using errcode='22023'; end if;

  insert into sectalk_private.st_v6_operation_rollups as previous(
    bucket,operation,requests,client_errors,server_errors,throttled,unavailable,peak_in_flight,latency_histogram
  )
  select current_bucket,s.operation,count(*),
    count(*) filter(where s.status between 400 and 499),count(*) filter(where s.status>=500),
    count(*) filter(where s.status=429),count(*) filter(where s.status=503),max(s.in_flight),
    array[
      count(*) filter(where s.duration_ms<=25),
      count(*) filter(where s.duration_ms>25 and s.duration_ms<=50),
      count(*) filter(where s.duration_ms>50 and s.duration_ms<=100),
      count(*) filter(where s.duration_ms>100 and s.duration_ms<=250),
      count(*) filter(where s.duration_ms>250 and s.duration_ms<=500),
      count(*) filter(where s.duration_ms>500 and s.duration_ms<=1000),
      count(*) filter(where s.duration_ms>1000 and s.duration_ms<=2500),
      count(*) filter(where s.duration_ms>2500 and s.duration_ms<=5000),
      count(*) filter(where s.duration_ms>5000)
    ]
  from jsonb_to_recordset(p_samples) as s(operation text,duration_ms integer,status integer,in_flight integer)
  group by s.operation order by s.operation
  on conflict(bucket,operation) do update set
    requests=previous.requests+excluded.requests,
    client_errors=previous.client_errors+excluded.client_errors,
    server_errors=previous.server_errors+excluded.server_errors,
    throttled=previous.throttled+excluded.throttled,
    unavailable=previous.unavailable+excluded.unavailable,
    peak_in_flight=greatest(previous.peak_in_flight,excluded.peak_in_flight),
    latency_histogram=array(select counts.prior+counts.incoming
      from unnest(previous.latency_histogram,excluded.latency_histogram)
        with ordinality as counts(prior,incoming,ordinal) order by counts.ordinal);
end
$$;

create function public.st_v6_operational_metrics(p_window text)
returns table(operation text,requests bigint,client_errors bigint,server_errors bigint,throttled bigint,
  unavailable bigint,peak_in_flight integer,p50_band integer,p95_band integer)
language plpgsql stable security definer set search_path='' as $$
declare
  span interval;
  current_bucket timestamptz := date_bin(interval '5 minutes',statement_timestamp(),'2000-01-01 00:00:00+00'::timestamptz);
begin
  if public.st_staff_status()<>'verified' or not sectalk_private.st_v2_active(auth.uid()) then
    raise exception 'Verified staff access required' using errcode='42501';
  end if;
  span:=case p_window when '1h' then interval '1 hour' when '24h' then interval '24 hours'
    when '7d' then interval '168 hours' end;
  if span is null then raise exception 'Choose 1 hour, 24 hours, or 7 days' using errcode='22023'; end if;

  return query
  with recent as materialized (
    select r.* from sectalk_private.st_v6_operation_rollups r
      where r.bucket>current_bucket-span and r.bucket<=current_bucket
  ), totals as (
    select r.operation,sum(r.requests)::bigint as requests,sum(r.client_errors)::bigint as client_errors,
      sum(r.server_errors)::bigint as server_errors,sum(r.throttled)::bigint as throttled,
      sum(r.unavailable)::bigint as unavailable,max(r.peak_in_flight) as peak
    from recent r group by r.operation
  ), bands as (
    select r.operation,h.band::integer as band,sum(h.samples) as samples
    from recent r cross join lateral unnest(r.latency_histogram) with ordinality h(samples,band)
    group by r.operation,h.band
  ), distribution as (
    select b.operation,b.band,sum(b.samples) over(partition by b.operation order by b.band) as cumulative
    from bands b
  )
  select t.operation,t.requests,t.client_errors,t.server_errors,t.throttled,t.unavailable,t.peak,
    min(d.band) filter(where d.cumulative>=ceil(t.requests*0.50)),
    min(d.band) filter(where d.cumulative>=ceil(t.requests*0.95))
  from totals t join distribution d on d.operation=t.operation
  group by t.operation,t.requests,t.client_errors,t.server_errors,t.throttled,t.unavailable,t.peak
  order by t.operation;
end
$$;

select cron.schedule('sectalk-v6-prune-operation-rollups','41 3 * * *',
  $job$delete from sectalk_private.st_v6_operation_rollups
    where bucket<now()-interval '168 hours'$job$);

revoke all on function public.st_v6_record_operational_metrics(jsonb),public.st_v6_operational_metrics(text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_record_operational_metrics(jsonb) to service_role;
grant execute on function public.st_v6_operational_metrics(text) to authenticated;

commit;
