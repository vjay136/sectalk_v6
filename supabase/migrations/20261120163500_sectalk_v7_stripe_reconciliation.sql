begin;
create table sectalk_private.st_v7_stripe_receipts (
  id text primary key,
  fingerprint text not null,
  kind text not null,
  resource text not null,
  event_at timestamptz not null,
  observed_at timestamptz not null default clock_timestamp(),
  lease uuid,
  lease_until timestamptz,
  done boolean not null default false
);
create table sectalk_private.st_v7_stripe_reconcile (
  subscription text primary key,
  ready_at timestamptz not null,
  observed_at timestamptz not null,
  lease uuid not null,
  lease_until timestamptz not null
);
create index on sectalk_private.st_v7_stripe_receipts(event_at);
alter table sectalk_private.st_v7_stripe_receipts enable row level security;
alter table sectalk_private.st_v7_stripe_reconcile enable row level security;
revoke all on sectalk_private.st_v7_stripe_receipts,sectalk_private.st_v7_stripe_reconcile
  from public,anon,authenticated,service_role;

create function public.st_v7_stripe_claim(p_event text,p_hash text,p_kind text,p_resource text,p_event_at timestamptz)
returns jsonb language plpgsql security definer set search_path='' as $$
declare receipt sectalk_private.st_v7_stripe_receipts;
begin
  if p_event is null or p_event !~ '^evt_[a-zA-Z0-9_]{1,100}$'
    or p_hash is null or p_hash !~ '^[a-f0-9]{64}$' or p_kind is null
    or p_kind not in ('subscription','subscription_deleted','trial') or p_resource is null
    or p_resource !~ '^(sub|cs)_[a-zA-Z0-9_]{1,100}$'
    or p_event_at is null or p_event_at>now()+interval '5 minutes' or p_event_at<now()-interval '30 days' then
    return jsonb_build_object('state','invalid');
  end if;
  insert into sectalk_private.st_v7_stripe_receipts(id,fingerprint,kind,resource,event_at)
    values(p_event,p_hash,p_kind,p_resource,p_event_at) on conflict do nothing;
  select * into receipt from sectalk_private.st_v7_stripe_receipts where id=p_event for update;
  if (receipt.fingerprint,receipt.kind,receipt.resource,receipt.event_at)
    is distinct from (p_hash,p_kind,p_resource,p_event_at) then return jsonb_build_object('state','conflict'); end if;
  if receipt.done then return jsonb_build_object('state','done'); end if;
  if receipt.lease_until>clock_timestamp() then return jsonb_build_object('state','busy'); end if;
  update sectalk_private.st_v7_stripe_receipts set lease=gen_random_uuid(),lease_until=clock_timestamp()+interval '45 seconds',
    observed_at=clock_timestamp() where id=p_event returning * into receipt;
  return jsonb_build_object('state','claimed','lease',receipt.lease);
end $$;

create function sectalk_private.st_v7_sync_stripe_snapshot(event_key text, resource_key text, observed timestamptz, payload jsonb)
returns boolean language plpgsql security definer set search_path='' as $$
declare actor uuid:=(payload->>'user')::uuid; current_row public.st_v2_subscriptions;
begin
  if actor is null or payload->>'subscription' is distinct from resource_key
    or (payload->>'customer') !~ '^cus_[a-zA-Z0-9_]{1,100}$' or payload->>'customer' is null then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-v6-billing:'||actor::text,0));
  select * into current_row from public.st_v2_subscriptions where user_id=actor for update;
  if (current_row.customer_id is not null and current_row.customer_id is distinct from payload->>'customer')
    or (current_row.subscription_id is distinct from resource_key and payload->>'status'='canceled')
    or not exists(select 1 from auth.users where id=actor) then return false; end if;
  perform public.st_v6_sync_catalog_subscription(event_key,actor,payload->>'customer',resource_key,
    payload->>'price',payload->>'legacy_plan',payload->>'legacy_cadence',payload->>'status',
    (payload->>'period_end')::timestamptz,(payload->>'cancel')::boolean,observed,payload->>'currency',(payload->>'amount')::integer);
  return true;
end $$;

create function public.st_v7_stripe_finish(p_event text,p_lease uuid,p_outcome text,p_payload jsonb default null)
returns boolean language plpgsql security definer set search_path='' as $$
declare receipt sectalk_private.st_v7_stripe_receipts;
begin
  select * into receipt from sectalk_private.st_v7_stripe_receipts where id=p_event and lease=p_lease
    and lease_until>clock_timestamp() and not done for update;
  if not found or p_outcome is null or p_outcome not in ('retry','ignore','apply') then return false; end if;
  if p_outcome='apply' then
    if receipt.kind='trial' then
      perform public.st_v7_complete_trial_checkout((p_payload->>'reservation')::uuid,receipt.resource,receipt.event_at);
    else
      perform sectalk_private.st_v7_sync_stripe_snapshot(receipt.id,receipt.resource,receipt.observed_at,p_payload);
    end if;
  end if;
  update sectalk_private.st_v7_stripe_receipts set done=p_outcome<>'retry',lease=null,lease_until=null where id=p_event;
  return true;
end $$;

create function public.st_v7_stripe_reconcile_claim()
returns jsonb language plpgsql security definer set search_path='' as $$
declare item public.st_v2_subscriptions; run sectalk_private.st_v7_stripe_reconcile; results jsonb:='[]';
begin
  for item in select s.* from public.st_v2_subscriptions s
    left join sectalk_private.st_v7_stripe_reconcile r on r.subscription=s.subscription_id
    where s.subscription_id ~ '^sub_[a-zA-Z0-9]{1,100}$' and s.customer_id ~ '^cus_[a-zA-Z0-9]{1,100}$'
      and (r.subscription is null or r.ready_at<=clock_timestamp() and r.lease_until<=clock_timestamp())
    order by coalesce(r.ready_at,'-infinity'),s.user_id limit 8
    for update of s skip locked
  loop
    insert into sectalk_private.st_v7_stripe_reconcile as r(subscription,ready_at,observed_at,lease,lease_until)
      values(item.subscription_id,clock_timestamp(),clock_timestamp(),gen_random_uuid(),clock_timestamp()+interval '45 seconds')
    on conflict(subscription) do update set ready_at=excluded.ready_at,observed_at=excluded.observed_at,lease=excluded.lease,
      lease_until=excluded.lease_until where r.lease_until<=clock_timestamp() and r.ready_at<=clock_timestamp()
    returning * into run;
    if found then results:=results||jsonb_build_array(jsonb_build_object('id',item.subscription_id,'customer',item.customer_id,
      'user',item.user_id,'lease',run.lease)); end if;
  end loop;
  return results;
end $$;

create function public.st_v7_stripe_reconcile_finish(p_subscription text,p_lease uuid,p_payload jsonb default null)
returns boolean language plpgsql security definer set search_path='' as $$
declare run sectalk_private.st_v7_stripe_reconcile; item public.st_v2_subscriptions; accepted boolean:=false;
begin
  select * into run from sectalk_private.st_v7_stripe_reconcile where subscription=p_subscription and lease=p_lease
    and lease_until>clock_timestamp() for update;
  if not found then return false; end if;
  if p_payload is not null then
    select * into item from public.st_v2_subscriptions where subscription_id=p_subscription;
    if found and item.user_id::text=p_payload->>'user' and item.customer_id=p_payload->>'customer' then
      accepted:=sectalk_private.st_v7_sync_stripe_snapshot('reconcile:'||run.lease::text,p_subscription,run.observed_at,p_payload);
    end if;
  end if;
  update sectalk_private.st_v7_stripe_reconcile set lease_until='-infinity',
    ready_at=clock_timestamp()+case when accepted then interval '1 hour' else interval '5 minutes' end
    where subscription=p_subscription;
  return accepted;
end $$;

revoke all on function public.st_v7_stripe_claim(text,text,text,text,timestamptz),public.st_v7_stripe_finish(text,uuid,text,jsonb),
  public.st_v7_stripe_reconcile_claim(),public.st_v7_stripe_reconcile_finish(text,uuid,jsonb),
  sectalk_private.st_v7_sync_stripe_snapshot(text,text,timestamptz,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_stripe_claim(text,text,text,text,timestamptz),public.st_v7_stripe_finish(text,uuid,text,jsonb),
  public.st_v7_stripe_reconcile_claim(),public.st_v7_stripe_reconcile_finish(text,uuid,jsonb) to service_role;
select cron.schedule('sectalk-v7-stripe-receipt-cleanup','17 3 * * *',
  $job$delete from sectalk_private.st_v7_stripe_receipts where event_at<now()-interval '31 days';
  delete from sectalk_private.st_v7_stripe_reconcile r where r.ready_at<now()-interval '30 days'
    and not exists(select 1 from public.st_v2_subscriptions s where s.subscription_id=r.subscription);$job$);
commit;
