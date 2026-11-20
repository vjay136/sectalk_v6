begin;

create index st_v6_delivery_latency_interval on public.st_messages(created_at)
  include(delivered_at,chat_id) where delivered_at is not null;

create function public.st_v6_delivery_latency(p_window text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare
  cutoff timestamptz:=date_trunc('hour',now(),'UTC');
  span interval;
  observed bigint;
  conversations bigint;
  latency double precision[];
begin
  if public.st_staff_status()<>'verified' or not sectalk_private.st_v2_active(auth.uid())
    then raise exception 'Verified staff access required' using errcode='42501'; end if;
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

revoke all on function public.st_v6_delivery_latency(text) from public,anon,authenticated;
grant execute on function public.st_v6_delivery_latency(text) to authenticated;

commit;
