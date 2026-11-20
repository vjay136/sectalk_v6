begin;
create table sectalk_private.st_v8_razorpay_checkouts (
  id uuid primary key default gen_random_uuid(),
  account uuid not null references auth.users on delete cascade,
  plan text not null check(plan in ('basic','professional','business')),
  version integer not null,
  cadence text not null check(cadence in ('monthly','annual')),
  amount integer not null check(amount>0),
  provider_plan text not null check(provider_plan ~ '^plan_[A-Za-z0-9]{3,50}$'),
  provider_subscription text unique,
  url text,
  deadline timestamptz not null,
  billing_period_end timestamptz,
  paid_count integer not null default 0,
  observed_at bigint not null default 0,
  state text not null default 'reserving' check(state in ('reserving','open','active','closed')),
  created_at timestamptz not null default now()
);
create unique index on sectalk_private.st_v8_razorpay_checkouts(account) where state<>'closed';
create table sectalk_private.st_v8_razorpay_events (
  id text primary key,
  checkout uuid not null references sectalk_private.st_v8_razorpay_checkouts on delete cascade,
  body_hash text not null,
  payment text unique,
  received timestamptz not null default now()
);
alter table sectalk_private.st_v8_razorpay_checkouts enable row level security;
alter table sectalk_private.st_v8_razorpay_events enable row level security;
revoke all on sectalk_private.st_v8_razorpay_checkouts,sectalk_private.st_v8_razorpay_events from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_block_stripe_during_razorpay()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if exists(select 1 from sectalk_private.st_v8_razorpay_checkouts where account=new.user_id and
    (state in ('open','active') or (state='reserving' and deadline>now()))) then
    raise exception 'Another provider checkout is open' using errcode='23514';
  end if;
  return new;
end $$;
create trigger st_v8_block_stripe_during_razorpay before insert or update on sectalk_private.st_v2_checkout
for each row execute function sectalk_private.st_v8_block_stripe_during_razorpay();

create function public.st_v8_razorpay_checkout(p_actor uuid,p_action text,p_data jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare hold sectalk_private.st_v8_razorpay_checkouts; paid public.st_v2_subscriptions;
begin
  if not sectalk_private.st_v2_active(p_actor) then return null; end if;
  if p_action='status' then
    select * into hold from sectalk_private.st_v8_razorpay_checkouts where account=p_actor order by created_at desc limit 1;
    return jsonb_build_object('state',hold.state,'plan',hold.plan,'period_end',hold.billing_period_end);
  end if;
  perform pg_advisory_xact_lock(hashtextextended('coupon-checkout:'||p_actor::text,0));
  if p_action='reserve' then
    select * into paid from public.st_v2_subscriptions where user_id=p_actor;
    if (paid.subscription_id is not null and paid.subscription_id !~ '^rzp_sub_')
      or (paid.status in ('active','trialing','past_due') and paid.period_end>now())
      or exists(select 1 from sectalk_private.st_v2_checkout where user_id=p_actor)
      or exists(select 1 from sectalk_private.st_v7_coupon_holds where account=p_actor and state='held') then return null; end if;
    select * into hold from sectalk_private.st_v8_razorpay_checkouts where account=p_actor and state<>'closed' for update;
    if hold.state='open' and hold.deadline<=clock_timestamp() then
      return jsonb_build_object('probe',hold.provider_subscription,'id',hold.id,'provider_plan',hold.provider_plan);
    end if;
    if hold.state in ('open','reserving') and hold.deadline>clock_timestamp() then
      if hold.state='open' and (hold.plan,hold.version,hold.cadence,hold.provider_plan)=
        (p_data->>'plan',(p_data->>'version')::integer,p_data->>'cadence',p_data->>'provider_plan') then
        return jsonb_build_object('url',hold.url);
      end if;
      return null;
    end if;
    if hold.state='active' then return null; end if;
    if not exists(select 1 from sectalk_private.st_v6_plan_prices p join sectalk_private.st_v6_active_plans() v
      on (v.plan,v.version)=(p.plan,p.version) where v.visible and p.currency='INR'
      and (p.plan,p.version,p.cadence,p.amount)=(p_data->>'plan',(p_data->>'version')::integer,
        p_data->>'cadence',(p_data->>'amount')::integer)) then return null; end if;
    update sectalk_private.st_v8_razorpay_checkouts set state='closed' where id=hold.id;
    insert into sectalk_private.st_v8_razorpay_checkouts(account,plan,version,cadence,amount,provider_plan,deadline)
      values(p_actor,p_data->>'plan',(p_data->>'version')::integer,p_data->>'cadence',
      (p_data->>'amount')::integer,p_data->>'provider_plan',date_trunc('second',clock_timestamp()+interval '30 minutes'))
      returning * into hold;
    return jsonb_build_object('id',hold.id,'deadline',extract(epoch from hold.deadline)::bigint);
  elsif p_action='attach' then
    if p_data->>'subscription' is null or p_data->>'subscription' !~ '^sub_[A-Za-z0-9]{3,50}$' or
      p_data->>'url' is null or p_data->>'url' !~ '^https://rzp\.io/rzp/[A-Za-z0-9]{3,80}$' then return null; end if;
    update sectalk_private.st_v8_razorpay_checkouts set state='open',provider_subscription=p_data->>'subscription',url=p_data->>'url'
      where id=(p_data->>'id')::uuid and account=p_actor and state='reserving' and deadline>clock_timestamp();
    return to_jsonb(found);
  elsif p_action='expire' then
    update sectalk_private.st_v8_razorpay_checkouts set state='closed',url=null
      where id=(p_data->>'id')::uuid and account=p_actor and state='open'
      and provider_subscription=p_data->>'subscription' and deadline<=clock_timestamp();
    return to_jsonb(found);
  end if;
  return null;
end $$;

create function public.st_v8_razorpay_sync(p_action text,p_data jsonb)
returns jsonb language plpgsql security definer set search_path='' as $$
declare hold sectalk_private.st_v8_razorpay_checkouts; source text; note_time bigint; window_end timestamptz;
declare current_row public.st_v2_subscriptions; receipt sectalk_private.st_v8_razorpay_events;
begin
  select * into hold from sectalk_private.st_v8_razorpay_checkouts where provider_subscription=p_data->>'subscription';
  if not found then return null; end if;
  if p_action='scope' then return jsonb_build_object('id',hold.id,'provider_plan',hold.provider_plan,'amount',hold.amount,
    'state',hold.state,'cadence',hold.cadence); end if;
  if p_action<>'event' then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended('coupon-checkout:'||hold.account::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-v6-billing:'||hold.account::text,0));
  select * into hold from sectalk_private.st_v8_razorpay_checkouts where id=hold.id for update;
  select * into receipt from sectalk_private.st_v8_razorpay_events where id=p_data->>'event';
  if found then return to_jsonb(receipt.body_hash=p_data->>'hash'); end if;
  note_time:=(p_data->>'observed')::bigint;
  if hold.state='closed' or note_time<hold.observed_at then return 'true'::jsonb; end if;
  if p_data->>'kind'='closed' then
    if (p_data->>'count')::integer>hold.paid_count then return 'true'::jsonb; end if;
    update sectalk_private.st_v8_razorpay_checkouts set state='closed',url=null,observed_at=note_time where id=hold.id;
  elsif p_data->>'kind'='paid' then
    window_end:=to_timestamp((p_data->>'end')::bigint);
    if (p_data->>'count')::integer<=hold.paid_count then return 'true'::jsonb; end if;
    if window_end<=now() or (hold.billing_period_end is not null and window_end<=hold.billing_period_end) then return 'true'::jsonb; end if;
    if p_data->>'payment' is null or exists(select 1 from sectalk_private.st_v8_razorpay_events where payment=p_data->>'payment')
      then return 'true'::jsonb; end if;
    source:='rzp_'||hold.provider_subscription;
    select * into current_row from public.st_v2_subscriptions where user_id=hold.account for update;
    if found and current_row.subscription_id is distinct from source
      and (current_row.subscription_id !~ '^rzp_sub_' or current_row.period_end>now()) then return null; end if;
    insert into public.st_v2_subscriptions as s(user_id,plan,status,subscription_id,period_end,catalog_version,
      billing_currency,billing_cadence,billing_amount,synced_at)
      values(hold.account,hold.plan,'active',source,window_end,hold.version,'INR',hold.cadence,hold.amount,clock_timestamp())
      on conflict(user_id) do update set plan=excluded.plan,status='active',subscription_id=excluded.subscription_id,
      period_end=excluded.period_end,catalog_version=excluded.catalog_version,billing_currency='INR',
      billing_cadence=excluded.billing_cadence,billing_amount=excluded.billing_amount,synced_at=excluded.synced_at;
    update sectalk_private.st_v8_razorpay_checkouts set state='active',observed_at=note_time,
      paid_count=(p_data->>'count')::integer,billing_period_end=window_end,url=null where id=hold.id;
  else return null;
  end if;
  insert into sectalk_private.st_v8_razorpay_events(id,checkout,body_hash,payment)
    values(p_data->>'event',hold.id,p_data->>'hash',p_data->>'payment');
  return 'true'::jsonb;
end $$;
revoke all on function sectalk_private.st_v8_block_stripe_during_razorpay(),public.st_v8_razorpay_checkout(uuid,text,jsonb),
  public.st_v8_razorpay_sync(text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_razorpay_checkout(uuid,text,jsonb),public.st_v8_razorpay_sync(text,jsonb) to service_role;
commit;
