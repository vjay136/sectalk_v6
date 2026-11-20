begin;

create table sectalk_private.st_v6_plan_versions (
  plan text not null check (plan in ('free','basic','professional','business','enterprise')),
  version integer not null check (version > 0),
  title text not null check (char_length(btrim(title)) between 1 and 50),
  description text not null check (char_length(btrim(description)) between 1 and 240),
  visible boolean not null,
  active_from timestamptz not null,
  primary key (plan,version)
);

create table sectalk_private.st_v6_plan_prices (
  plan text not null,
  version integer not null,
  cadence text not null check (cadence in ('monthly','annual')),
  currency text not null check (currency in ('USD','EUR','GBP','INR','CAD','AUD','JPY')),
  amount integer not null check (amount between 1 and 100000000),
  provider_price text not null unique check (provider_price ~ '^price_[A-Za-z0-9_]{3,96}$'),
  primary key (plan,version,cadence,currency),
  foreign key (plan,version) references sectalk_private.st_v6_plan_versions,
  check (plan in ('basic','professional','business'))
);

insert into sectalk_private.st_v6_plan_versions values
  ('free',1,'Free','Direct chat, one-to-one calls, and team collaboration',true,'-infinity'),
  ('basic',1,'Basic','More space for families and small teams',false,'-infinity'),
  ('professional',1,'Pro','Higher limits for growing teams',true,'-infinity'),
  ('business',1,'Team','Workspace capacity for larger teams',true,'-infinity'),
  ('enterprise',1,'Enterprise','Contract-based limits and onboarding',true,'-infinity');

alter table sectalk_private.st_v6_plan_versions enable row level security;
alter table sectalk_private.st_v6_plan_prices enable row level security;
revoke all on sectalk_private.st_v6_plan_versions,sectalk_private.st_v6_plan_prices from public,anon,authenticated,service_role;

alter table public.st_v2_subscriptions add column catalog_version integer not null default 1,
  add column billing_currency text check (billing_currency ~ '^[A-Z]{3}$'),
  add column billing_cadence text check (billing_cadence in ('monthly','annual')),
  add column billing_amount integer check (billing_amount > 0),
  add foreign key (plan,catalog_version) references sectalk_private.st_v6_plan_versions;

create function sectalk_private.st_v6_active_plans()
returns setof sectalk_private.st_v6_plan_versions
language sql stable set search_path='' as $$
  select distinct on (plan) *
  from sectalk_private.st_v6_plan_versions
  where active_from <= now()
  order by plan,version desc
$$;

create function public.st_v6_plan_catalog()
returns table(plan text,version integer,title text,description text,prices jsonb)
language sql stable security definer set search_path='' as $$
  select v.plan,v.version,v.title,v.description,coalesce((
    select jsonb_agg(jsonb_build_object('cadence',p.cadence,'currency',p.currency,'amount',p.amount)
      order by p.currency,p.cadence)
    from sectalk_private.st_v6_plan_prices p where (p.plan,p.version)=(v.plan,v.version)
  ),'[]'::jsonb)
  from sectalk_private.st_v6_active_plans() v
  where v.visible
  order by array_position(array['free','basic','professional','business','enterprise'],v.plan)
$$;

create function public.st_v6_publish_plan(p_plan text,p_title text,p_description text,p_visible boolean,
  p_active_from timestamptz,p_prices jsonb)
returns integer language plpgsql security definer set search_path='' as $$
declare next_version integer; latest_activation timestamptz;
begin
  if p_plan is null or p_plan not in ('free','basic','professional','business','enterprise')
    or p_active_from is null or not isfinite(p_active_from) or jsonb_typeof(p_prices) is distinct from 'array'
    or jsonb_array_length(p_prices)>14
    or (p_visible and p_plan in ('basic','professional','business') and jsonb_array_length(p_prices)=0) then
    raise exception using errcode='22023',message='Invalid plan revision';
  end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-v6-plan:'||p_plan,0));
  select version+1,active_from into next_version,latest_activation
    from sectalk_private.st_v6_plan_versions where plan=p_plan order by version desc limit 1;
  if p_active_from<=latest_activation then
    raise exception using errcode='22023',message='A revision must follow the preceding activation';
  end if;
  insert into sectalk_private.st_v6_plan_versions values
    (p_plan,next_version,btrim(p_title),btrim(p_description),p_visible,p_active_from);
  insert into sectalk_private.st_v6_plan_prices
    select p_plan,next_version,p.cadence,p.currency,p.amount,p.provider_price
    from jsonb_to_recordset(p_prices) as p(cadence text,currency text,amount integer,provider_price text);
  return next_version;
end $$;

create function public.st_v6_checkout_plan_price(p_plan text,p_cadence text,p_currency text,p_version integer,p_legacy_price text)
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('id',coalesce(p.provider_price,p_legacy_price),'amount',p.amount)
  from sectalk_private.st_v6_active_plans() v
  left join sectalk_private.st_v6_plan_prices p on (p.plan,p.version)=(v.plan,v.version)
    and p.cadence=p_cadence and p.currency=p_currency
  where v.visible and v.plan=p_plan and v.version=p_version
    and (p.provider_price is not null or (v.version=1 and p_currency='USD' and p_legacy_price is not null))
$$;

create function public.st_v6_my_plan_title()
returns text language sql stable security definer set search_path='' as $$
  select v.title from public.st_v2_subscriptions s
    join sectalk_private.st_v6_plan_versions v on (v.plan,v.version)=(s.plan,s.catalog_version)
  where s.user_id=(select auth.uid())
$$;

create function public.st_v6_sync_catalog_subscription(
  p_event text,p_user uuid,p_customer text,p_subscription text,p_provider_price text,
  p_legacy_plan text,p_legacy_cadence text,p_status text,p_end timestamptz,
  p_cancel boolean,p_synced timestamptz,p_currency text,p_amount integer
) returns void language plpgsql security definer set search_path='' as $$
declare price sectalk_private.st_v6_plan_prices; current_subscription public.st_v2_subscriptions;
begin
  select * into price from sectalk_private.st_v6_plan_prices where provider_price=p_provider_price;
  if not found then
    if p_legacy_plan is null or p_legacy_plan not in ('basic','professional','business')
      or p_legacy_cadence is null or p_legacy_cadence not in ('monthly','annual') then
      raise exception using errcode='22023',message='Unsupported provider price';
    end if;
    price.plan:=p_legacy_plan;
    price.version:=1;
    price.cadence:=p_legacy_cadence;
    price.currency:=p_currency;
    price.amount:=p_amount;
  elsif (price.currency,price.amount) is distinct from (p_currency,p_amount) then
    raise exception using errcode='22023',message='Provider price terms differ from the catalog';
  end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-v6-billing:'||p_user::text,0));
  if exists(select 1 from sectalk_private.st_v2_billing_events where event_id=p_event) then return; end if;
  select * into current_subscription from public.st_v2_subscriptions where user_id=p_user for update;
  if current_subscription.plan is distinct from price.plan and current_subscription.catalog_version>1
    and current_subscription.synced_at<=p_synced and (current_subscription.subscription_id=p_subscription
      or current_subscription.status in ('canceled','incomplete_expired','unpaid','paused')) then
    update public.st_v2_subscriptions set catalog_version=1 where user_id=p_user;
  end if;
  perform public.st_v2_sync_billing(p_event,p_user,p_customer,p_subscription,price.plan,
    p_status,p_end,p_cancel,p_synced);
  update public.st_v2_subscriptions set catalog_version=price.version,billing_currency=price.currency,
    billing_cadence=price.cadence,billing_amount=price.amount
  where user_id=p_user and plan=price.plan and subscription_id=p_subscription and synced_at=p_synced;
end $$;

revoke all on function sectalk_private.st_v6_active_plans() from public,anon,authenticated,service_role;
revoke all on function public.st_v6_plan_catalog() from public;
grant execute on function public.st_v6_plan_catalog() to anon,authenticated;
revoke all on function public.st_v6_my_plan_title() from public,anon;
grant execute on function public.st_v6_my_plan_title() to authenticated;
revoke all on function public.st_v6_publish_plan(text,text,text,boolean,timestamptz,jsonb),
  public.st_v6_checkout_plan_price(text,text,text,integer,text),
  public.st_v6_sync_catalog_subscription(text,uuid,text,text,text,text,text,text,timestamptz,boolean,timestamptz,text,integer)
  from public,anon,authenticated;
grant execute on function public.st_v6_publish_plan(text,text,text,boolean,timestamptz,jsonb),
  public.st_v6_checkout_plan_price(text,text,text,integer,text),
  public.st_v6_sync_catalog_subscription(text,uuid,text,text,text,text,text,text,timestamptz,boolean,timestamptz,text,integer)
  to service_role;

notify pgrst,'reload schema';
commit;
