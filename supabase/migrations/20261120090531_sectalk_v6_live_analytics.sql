begin;

create table sectalk_private.st_v6_analytics_viewers (
  user_id uuid primary key references sectalk_private.staff(user_id) on delete cascade,
  expires_at timestamptz not null,
  last_sent_at timestamptz
);
alter table sectalk_private.st_v6_analytics_viewers enable row level security;
revoke all on sectalk_private.st_v6_analytics_viewers from public,anon,authenticated;

create function public.st_v6_can_read_live_analytics()
returns boolean language sql stable security definer set search_path='' as $$
  select public.st_staff_status()='verified' and sectalk_private.st_v2_active(auth.uid())
$$;
revoke all on function public.st_v6_can_read_live_analytics() from public,anon,authenticated;
grant execute on function public.st_v6_can_read_live_analytics() to authenticated;

create policy st_v6_analytics_broadcast_read on realtime.messages for select to authenticated
  using (extension='broadcast'
    and (select public.st_v6_can_read_live_analytics())
    and (select realtime.topic())='st:analytics:'||(select auth.uid())::text
    and topic=(select realtime.topic()));

create policy st_v6_analytics_broadcast_scope on realtime.messages as restrictive for select to authenticated
  using ((coalesce((select realtime.topic()),'') not like 'st:analytics:%'
      and coalesce(topic,'') not like 'st:analytics:%')
    or (extension='broadcast' and (select public.st_v6_can_read_live_analytics())
      and (select realtime.topic())='st:analytics:'||(select auth.uid())::text
      and topic=(select realtime.topic())));

create policy st_v6_analytics_broadcast_anon on realtime.messages as restrictive for select to anon
  using (coalesce((select realtime.topic()),'') not like 'st:analytics:%'
    and coalesce(topic,'') not like 'st:analytics:%');

create policy st_v6_analytics_broadcast_server_only on realtime.messages as restrictive for insert to public
  with check (coalesce((select realtime.topic()),'') not like 'st:analytics:%'
    and coalesce(topic,'') not like 'st:analytics:%');

create function sectalk_private.st_v6_touch_analytics_lease()
returns void language plpgsql security definer set search_path='' as $$
begin
  if not public.st_v6_can_read_live_analytics() then
    raise exception 'Verified staff access required' using errcode='42501';
  end if;
  insert into sectalk_private.st_v6_analytics_viewers as viewers(user_id,expires_at)
    values(auth.uid(),now()+interval '3 minutes')
    on conflict(user_id) do update set expires_at=excluded.expires_at
      where viewers.expires_at<now()+interval '2 minutes';
end
$$;

create function sectalk_private.st_v6_publish_analytics_refresh()
returns void language plpgsql security definer set search_path='' as $$
declare
  recipient uuid;
  tick timestamptz := date_trunc('minute',now(),'UTC');
begin
  -- Fixed cadence avoids disclosing when particular activity occurred.
  for recipient in
    update sectalk_private.st_v6_analytics_viewers v set last_sent_at=tick
      where v.expires_at>now() and (v.last_sent_at is null or v.last_sent_at<tick)
        and sectalk_private.st_v2_active(v.user_id)
      returning v.user_id
  loop
    perform realtime.send('{}'::jsonb,'analytics_refresh','st:analytics:'||recipient::text,true);
  end loop;
end
$$;

revoke all on function sectalk_private.st_v6_touch_analytics_lease(),
  sectalk_private.st_v6_publish_analytics_refresh() from public,anon,authenticated;

create function sectalk_private.st_v6_delivery_latency_at(p_window text,cutoff timestamptz)
returns jsonb language plpgsql stable set search_path='' as $$
declare
  span interval;
  observed bigint;
  conversations bigint;
  latency double precision[];
begin
  span:=case p_window when '24h' then interval '24 hours' when '7d' then interval '168 hours'
    when '30d' then interval '720 hours' end;
  if span is null then raise exception 'Choose 24 hours, 7 days, or 30 days' using errcode='22023'; end if;
  select count(*),count(distinct m.chat_id),
    percentile_cont(array[0.50,0.95,0.99]::double precision[]) within group
      (order by extract(epoch from (m.delivered_at-m.created_at))*1000)
    into observed,conversations,latency
  from public.st_messages m where m.created_at>=cutoff-span and m.created_at<cutoff
    and m.delivered_at is not null and m.delivered_at>=m.created_at and m.delivered_at<cutoff;
  if observed<20 or conversations<5 then
    return jsonb_build_object('through',cutoff,'available',false);
  end if;
  return jsonb_build_object('through',cutoff,'available',true,
    'p50',round(latency[1])::bigint,'p95',round(latency[2])::bigint,'p99',round(latency[3])::bigint);
end $$;

create function sectalk_private.st_v6_usage_metrics_at(p_window text,cutoff timestamptz)
returns jsonb language plpgsql stable set search_path='' as $$
declare
  begins timestamptz;
  metrics jsonb;
begin
  begins:=case p_window when '7d' then cutoff-interval '168 hours' when '30d' then cutoff-interval '720 hours' end;
  if begins is null then raise exception 'Choose 7 days or 30 days' using errcode='22023'; end if;

  with events as materialized (
    select 'messages'::text as kind,m.sender as actor from public.st_messages m
      where m.created_at>=begins and m.created_at<cutoff
    union all select 'calls',c.caller from public.st_calls c where c.created_at>=begins and c.created_at<cutoff
    union all select 'meetings',m.host_id from public.st_v3_meetings m where m.created_at>=begins and m.created_at<cutoff
    union all select 'tasks',a.actor_id from public.st_v6_task_audit a
      where a.created_at>=begins and a.created_at<cutoff and a.action='status' and a.detail->>'to'='done'
  ), totals as (
    select e.kind,count(*) as volume,count(distinct e.actor) as people from events e group by e.kind
    union all select 'accounts',count(distinct e.actor),count(distinct e.actor) from events e
  )
  select coalesce(jsonb_object_agg(t.kind,(t.volume/10)*10) filter(where t.volume>=10 and t.people>=5),'{}'::jsonb)
    into metrics from totals t;
  return jsonb_build_object('through',cutoff,'metrics',metrics);
end $$;

revoke all on function sectalk_private.st_v6_delivery_latency_at(text,timestamptz),
  sectalk_private.st_v6_usage_metrics_at(text,timestamptz) from public,anon,authenticated;

create or replace function public.st_v6_delivery_latency(p_window text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
begin
  if not public.st_v6_can_read_live_analytics() then
    raise exception 'Verified staff access required' using errcode='42501';
  end if;
  return sectalk_private.st_v6_delivery_latency_at(p_window,date_trunc('hour',now(),'UTC'));
end
$$;

create or replace function public.st_v6_usage_metrics(p_window text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
begin
  if not public.st_v6_can_read_live_analytics() then
    raise exception 'Verified staff access required' using errcode='42501';
  end if;
  return sectalk_private.st_v6_usage_metrics_at(p_window,date_trunc('day',now(),'UTC'));
end
$$;

create function public.st_v6_delivery_latency(p_window text,p_live boolean)
returns jsonb language plpgsql security definer set search_path='' as $$
begin
  if p_live is not true then return public.st_v6_delivery_latency(p_window); end if;
  perform sectalk_private.st_v6_touch_analytics_lease();
  return sectalk_private.st_v6_delivery_latency_at(p_window,date_trunc('minute',now(),'UTC'));
end
$$;

create function public.st_v6_usage_metrics(p_window text,p_live boolean)
returns jsonb language plpgsql security definer set search_path='' as $$
begin
  if p_live is not true then return public.st_v6_usage_metrics(p_window); end if;
  perform sectalk_private.st_v6_touch_analytics_lease();
  return sectalk_private.st_v6_usage_metrics_at(p_window,date_trunc('minute',now(),'UTC'));
end
$$;

revoke all on function public.st_v6_delivery_latency(text,boolean),public.st_v6_usage_metrics(text,boolean)
  from public,anon,authenticated;
grant execute on function public.st_v6_delivery_latency(text,boolean),public.st_v6_usage_metrics(text,boolean)
  to authenticated;

select cron.schedule('sectalk-v6-publish-analytics-refresh','* * * * *',
  'select sectalk_private.st_v6_publish_analytics_refresh()');

commit;
