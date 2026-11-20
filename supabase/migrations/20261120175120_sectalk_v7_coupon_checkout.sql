begin;
create table sectalk_private.st_v7_coupon_operators (
  account uuid primary key references sectalk_private.staff(user_id) on delete cascade
);
create table sectalk_private.st_v7_coupon_campaigns (
  code text primary key check(code ~ '^[A-Z0-9-]{4,40}$'),
  revision integer not null check(revision>0)
);
create table sectalk_private.st_v7_coupon_versions (
  code text not null references sectalk_private.st_v7_coupon_campaigns,
  revision integer not null,
  enabled boolean not null,
  coupon text not null check(coupon ~ '^[A-Za-z0-9_-]{2,96}$'),
  percent_bps integer check(percent_bps between 1 and 10000),
  amount_off integer check(amount_off between 1 and 100000000),
  plans text[] not null check(cardinality(plans) between 1 and 3 and plans <@ array['basic','professional','business']),
  currencies text[] not null check(cardinality(currencies) between 1 and 7 and currencies <@ array['USD','EUR','GBP','INR','CAD','AUD','JPY']),
  duration text not null check(duration in ('once','repeating','forever')),
  months integer,
  starts_at timestamptz not null,
  ends_at timestamptz not null,
  max_redemptions integer not null check(max_redemptions between 1 and 100000),
  actor uuid not null,
  authored_at timestamptz not null default statement_timestamp(),
  primary key(code,revision),
  check(num_nonnulls(percent_bps,amount_off)=1 and (amount_off is null or cardinality(currencies)=1)),
  check((duration='repeating' and months is not null and months between 1 and 36) or (duration<>'repeating' and months is null)),
  check(isfinite(starts_at) and isfinite(ends_at) and starts_at<ends_at)
);
create index on sectalk_private.st_v7_coupon_versions(coupon);
create table sectalk_private.st_v7_coupon_holds (
  id uuid primary key,
  account uuid not null,
  code text not null,
  revision integer not null,
  price text not null check(price ~ '^price_[A-Za-z0-9_]{1,100}$'),
  currency text not null check(currency ~ '^[A-Z]{3}$'),
  expires_at timestamptz not null,
  provider_session text unique,
  state text not null default 'held' check(state in ('held','redeemed','expired')),
  settled_at timestamptz,
  probe_at timestamptz not null default clock_timestamp(),
  foreign key(code,revision) references sectalk_private.st_v7_coupon_versions
);
create index on sectalk_private.st_v7_coupon_holds(code,state,account);
create index on sectalk_private.st_v7_coupon_holds(probe_at) where state='held' and provider_session is not null;
alter table sectalk_private.st_v7_coupon_operators enable row level security;
alter table sectalk_private.st_v7_coupon_campaigns enable row level security;
alter table sectalk_private.st_v7_coupon_versions enable row level security;
alter table sectalk_private.st_v7_coupon_holds enable row level security;
revoke all on sectalk_private.st_v7_coupon_operators,sectalk_private.st_v7_coupon_campaigns,
  sectalk_private.st_v7_coupon_versions,sectalk_private.st_v7_coupon_holds from public,anon,authenticated,service_role;

create function public.st_v7_publish_coupon(p_code text,p_revision integer,p_terms jsonb)
returns integer language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); terms sectalk_private.st_v7_coupon_versions; prior integer;
begin
  if not coalesce(sectalk_private.st_v7_admin_fresh(),false) or not exists(
    select 1 from sectalk_private.st_v7_coupon_operators o where o.account=actor
      and sectalk_private.st_v2_active(o.account)) then
    raise exception 'Fresh coupon operator proof required' using errcode='42501'; end if;
  if p_code is null or p_code !~ '^[A-Z0-9-]{4,40}$' or p_revision is null or p_revision<0
    or jsonb_typeof(p_terms) is distinct from 'object' or pg_column_size(p_terms)>4096 then
    raise exception 'Invalid campaign version' using errcode='22023'; end if;
  perform sectalk_private.limit_action('v7_publish_coupon',20);
  terms:=jsonb_populate_record(null::sectalk_private.st_v7_coupon_versions,p_terms);
  perform pg_advisory_xact_lock(hashtextextended('coupon-provider:'||terms.coupon,0));
  if exists(select 1 from sectalk_private.st_v7_coupon_versions v where v.coupon=terms.coupon and v.code<>p_code)
    then raise exception 'Provider coupon belongs to another campaign' using errcode='PT409'; end if;
  perform pg_advisory_xact_lock(hashtextextended('coupon-code:'||p_code,0));
  select c.revision into prior from sectalk_private.st_v7_coupon_campaigns c where c.code=p_code for update;
  if coalesce(prior,0)<>p_revision then raise exception 'Campaign version changed' using errcode='PT409'; end if;
  insert into sectalk_private.st_v7_coupon_campaigns(code,revision) values(p_code,p_revision+1)
    on conflict(code) do update set revision=excluded.revision;
  insert into sectalk_private.st_v7_coupon_versions(code,revision,enabled,coupon,percent_bps,amount_off,plans,currencies,
    duration,months,starts_at,ends_at,max_redemptions,actor)
  values(p_code,p_revision+1,terms.enabled,terms.coupon,terms.percent_bps,terms.amount_off,terms.plans,terms.currencies,
    terms.duration,terms.months,terms.starts_at,terms.ends_at,terms.max_redemptions,actor);
  return p_revision+1;
end $$;

create function public.st_v7_quote_coupon(p_code text,p_plan text,p_currency text)
returns jsonb language sql stable security definer set search_path='' as $$
  select to_jsonb(v)-'actor'-'authored_at' from sectalk_private.st_v7_coupon_campaigns c
  join sectalk_private.st_v7_coupon_versions v on (v.code,v.revision)=(c.code,c.revision)
  where c.code=p_code and v.enabled and p_plan=any(v.plans) and p_currency=any(v.currencies)
    and v.starts_at<=now() and v.ends_at>now()+interval '31 minutes'
$$;

create function public.st_v7_reserve_coupon_checkout(p_account uuid,p_price text,p_code text,p_revision integer,
  p_plan text,p_currency text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare active sectalk_private.st_v2_checkout; hold sectalk_private.st_v7_coupon_holds;
  campaign sectalk_private.st_v7_coupon_versions; base jsonb; deadline timestamptz;
begin
  if p_account is null or p_price is null or p_price !~ '^price_[A-Za-z0-9_]{1,100}$' then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended('coupon-checkout:'||p_account::text,0));
  select * into active from sectalk_private.st_v2_checkout where user_id=p_account and expires>clock_timestamp() for update;
  if active.id is not null then
    select * into hold from sectalk_private.st_v7_coupon_holds where id=active.id;
    if active.price is distinct from p_price or hold.code is distinct from p_code
      or (p_code is not null and (hold.revision is distinct from p_revision or hold.state<>'held'
         or hold.currency is distinct from p_currency)) then return null; end if;
  end if;
  if active.id is null and exists(select 1 from sectalk_private.st_v7_coupon_holds h where h.account=p_account and h.state='held')
    then return null; end if;
  if p_code is null then return public.st_v2_reserve_checkout(p_account,p_price); end if;
  perform pg_advisory_xact_lock(hashtextextended('coupon-code:'||p_code,0));
  select v.* into campaign from sectalk_private.st_v7_coupon_campaigns c
    join sectalk_private.st_v7_coupon_versions v on (v.code,v.revision)=(c.code,c.revision)
    where c.code=p_code and c.revision=p_revision and v.enabled and p_plan=any(v.plans) and p_currency=any(v.currencies)
      and v.starts_at<=clock_timestamp() and v.ends_at>clock_timestamp()+interval '31 minutes';
  if not found then return null; end if;
  if hold.id is not null then
    return jsonb_build_object('id',hold.id,'expires_epoch',floor(extract(epoch from hold.expires_at)),
      'coupon',campaign.coupon,'session',hold.provider_session);
  end if;
  if exists(select 1 from sectalk_private.st_v7_coupon_holds h where h.code=p_code and h.account=p_account and h.state in ('held','redeemed'))
    or (select count(*) from sectalk_private.st_v7_coupon_holds h where h.code=p_code and h.state in ('held','redeemed'))>=campaign.max_redemptions
    then return null; end if;
  base:=public.st_v2_reserve_checkout(p_account,p_price);
  if base is null then return null; end if;
  deadline:=date_trunc('second',least(to_timestamp((base->>'expires_epoch')::double precision),campaign.ends_at));
  insert into sectalk_private.st_v7_coupon_holds(id,account,code,revision,price,currency,expires_at)
    values((base->>'id')::uuid,p_account,p_code,p_revision,p_price,p_currency,deadline);
  update sectalk_private.st_v2_checkout set expires=deadline where user_id=p_account and id=(base->>'id')::uuid;
  return base||jsonb_build_object('expires_epoch',extract(epoch from deadline),'coupon',campaign.coupon);
end $$;

create function public.st_v7_attach_coupon_checkout(p_hold uuid,p_account uuid,p_session text)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  if p_session is null or p_session !~ '^cs_[A-Za-z0-9_]{1,100}$' then return false; end if;
  update sectalk_private.st_v7_coupon_holds h set provider_session=p_session
    where id=p_hold and account=p_account and state='held' and (provider_session is null or provider_session=p_session);
  return found;
end $$;

create function sectalk_private.st_v7_settle_coupon_checkout(p_session text,p_payload jsonb)
returns boolean language plpgsql security definer set search_path='' as $$
declare hold sectalk_private.st_v7_coupon_holds; terms sectalk_private.st_v7_coupon_versions; next text:=p_payload->>'state';
begin
  if next is null or next not in ('redeemed','expired') or p_session is null or p_session !~ '^cs_[A-Za-z0-9_]{1,100}$' then return false; end if;
  select * into hold from sectalk_private.st_v7_coupon_holds h where h.id=(p_payload->>'hold')::uuid for update;
  if not found or hold.account::text is distinct from p_payload->>'account'
    or hold.currency is distinct from p_payload->>'currency' or hold.price is distinct from p_payload->>'price'
    or extract(epoch from hold.expires_at) is distinct from (p_payload->>'expires')::numeric
    or (hold.provider_session is not null and hold.provider_session<>p_session) then return false; end if;
  select * into terms from sectalk_private.st_v7_coupon_versions v where (v.code,v.revision)=(hold.code,hold.revision);
  if terms.coupon is distinct from p_payload->>'coupon' then return false; end if;
  if hold.state<>'held' then return hold.state=next and hold.provider_session=p_session; end if;
  update sectalk_private.st_v7_coupon_holds set state=next,provider_session=p_session,settled_at=clock_timestamp() where id=hold.id;
  if next='expired' then
    delete from sectalk_private.st_v2_checkout where user_id=hold.account and id=hold.id;
  end if;
  return true;
end $$;

create function public.st_v7_coupon_probe_claim()
returns jsonb language sql security definer set search_path='' as $$
  with due as (
    select id from sectalk_private.st_v7_coupon_holds where state='held' and provider_session is not null
      and expires_at<=clock_timestamp() and probe_at<=clock_timestamp()
    order by probe_at,id limit 4 for update skip locked
  ), claimed as (
    update sectalk_private.st_v7_coupon_holds h set probe_at=clock_timestamp()+interval '10 minutes'
    from due where h.id=due.id returning h.id,h.provider_session
  ) select coalesce(jsonb_agg(to_jsonb(claimed)),'[]') from claimed
$$;

create function public.st_v7_coupon_probe_finish(p_session text,p_payload jsonb)
returns boolean language sql security definer set search_path='' as $$
  select sectalk_private.st_v7_settle_coupon_checkout(p_session,p_payload)
$$;

revoke all on function public.st_v7_publish_coupon(text,integer,jsonb),public.st_v7_quote_coupon(text,text,text),
  public.st_v7_reserve_coupon_checkout(uuid,text,text,integer,text,text),public.st_v7_attach_coupon_checkout(uuid,uuid,text),
  sectalk_private.st_v7_settle_coupon_checkout(text,jsonb),public.st_v7_coupon_probe_claim(),
  public.st_v7_coupon_probe_finish(text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_publish_coupon(text,integer,jsonb) to authenticated;
grant execute on function public.st_v7_quote_coupon(text,text,text),public.st_v7_reserve_coupon_checkout(uuid,text,text,integer,text,text),
  public.st_v7_attach_coupon_checkout(uuid,uuid,text),public.st_v7_coupon_probe_claim(),public.st_v7_coupon_probe_finish(text,jsonb) to service_role;
create or replace function public.st_v7_stripe_claim(p_event text,p_hash text,p_kind text,p_resource text,p_event_at timestamptz)
returns jsonb language plpgsql security definer set search_path='' as $$
declare receipt sectalk_private.st_v7_stripe_receipts;
begin
  if p_event is null or p_event !~ '^evt_[a-zA-Z0-9_]{1,100}$'
    or p_hash is null or p_hash !~ '^[a-f0-9]{64}$' or p_kind is null
    or p_kind not in ('subscription','subscription_deleted','trial','invoice_renewal','coupon_checkout') or p_resource is null
    or p_resource !~ '^(sub|cs|in)_[a-zA-Z0-9_]{1,100}$'
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
create or replace function public.st_v7_stripe_finish(p_event text,p_lease uuid,p_outcome text,p_payload jsonb default null)
returns boolean language plpgsql security definer set search_path='' as $$
declare receipt sectalk_private.st_v7_stripe_receipts;
begin
  select * into receipt from sectalk_private.st_v7_stripe_receipts where id=p_event and lease=p_lease
    and lease_until>clock_timestamp() and not done for update;
  if not found or p_outcome is null or p_outcome not in ('retry','ignore','apply') then return false; end if;
  if p_outcome='apply' then
    if receipt.kind='trial' then
      perform public.st_v7_complete_trial_checkout((p_payload->>'reservation')::uuid,receipt.resource,receipt.event_at);
    elsif receipt.kind='coupon_checkout' then
      perform sectalk_private.st_v7_settle_coupon_checkout(receipt.resource,p_payload);
    elsif receipt.kind='invoice_renewal' then
      if jsonb_typeof(p_payload->'provider_subscription')='object' and
        sectalk_private.st_v7_renewal_binding(p_payload->>'customer',p_payload->>'subscription')::text
          = p_payload->'provider_subscription'->>'user' then
        perform sectalk_private.st_v7_sync_stripe_snapshot('renewal:'||receipt.id,p_payload->>'subscription',
          receipt.observed_at,p_payload->'provider_subscription');
      end if;
      perform sectalk_private.st_v7_apply_renewal(receipt.resource,receipt.event_at,receipt.observed_at,p_payload,
        (p_payload->>'new_failure')::boolean is true);
    else
      perform sectalk_private.st_v7_sync_stripe_snapshot(receipt.id,receipt.resource,receipt.observed_at,p_payload);
    end if;
  end if;
  update sectalk_private.st_v7_stripe_receipts set done=p_outcome<>'retry',lease=null,lease_until=null where id=p_event;
  return true;
end $$;
commit;
