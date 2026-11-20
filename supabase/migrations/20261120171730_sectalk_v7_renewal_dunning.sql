begin;
create table sectalk_private.st_v7_renewal_policy (
  singleton boolean primary key default true check(singleton),
  grace_hours integer not null check(grace_hours between 24 and 336)
);
insert into sectalk_private.st_v7_renewal_policy(grace_hours) values(72);
create table sectalk_private.st_v7_renewal_cases (
  invoice text primary key check(invoice ~ '^in_[a-zA-Z0-9_]{1,100}$'),
  recipient uuid not null references auth.users on delete cascade,
  customer text not null,
  subscription text not null,
  stage text not null check(stage in ('open','paid','closed')),
  attempt integer not null check(attempt between 1 and 100),
  first_failed_at timestamptz not null,
  grace_until timestamptz not null,
  retry_at timestamptz,
  observed_at timestamptz not null,
  probe_at timestamptz not null default clock_timestamp()
);
create index on sectalk_private.st_v7_renewal_cases(recipient,subscription,grace_until) where stage='open';
create index on sectalk_private.st_v7_renewal_cases(probe_at,invoice) where stage='open';
create table sectalk_private.st_v7_renewal_mail (
  id uuid primary key default gen_random_uuid(),
  invoice text not null references sectalk_private.st_v7_renewal_cases on delete cascade,
  attempt integer not null,
  state text not null default 'queued' check(state in ('queued','sent','closed','failed')),
  attempts integer not null default 0 check(attempts between 0 and 4),
  ready_at timestamptz not null default clock_timestamp(),
  lease uuid,
  lease_until timestamptz,
  unique(invoice,attempt)
);
create index on sectalk_private.st_v7_renewal_mail(ready_at) where state='queued';
alter table sectalk_private.st_v7_renewal_policy enable row level security;
alter table sectalk_private.st_v7_renewal_cases enable row level security;
alter table sectalk_private.st_v7_renewal_mail enable row level security;
revoke all on sectalk_private.st_v7_renewal_policy,sectalk_private.st_v7_renewal_cases,sectalk_private.st_v7_renewal_mail
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_renewal_binding(p_customer text,p_subscription text)
returns uuid language sql stable security definer set search_path='' as $$
  select s.user_id from public.st_v2_subscriptions s where s.customer_id=p_customer and s.subscription_id=p_subscription
    and s.status not in ('canceled','incomplete_expired','unpaid','paused')
$$;

create function sectalk_private.st_v7_apply_renewal(p_invoice text,p_failed_at timestamptz,p_observed timestamptz,p_payload jsonb,p_create boolean)
returns boolean language plpgsql security definer set search_path='' as $$
declare
  customer_key text:=p_payload->>'customer';
  subscription_key text:=p_payload->>'subscription';
  next_stage text:=p_payload->>'stage';
  next_attempt integer:=(p_payload->>'attempt')::integer;
  next_retry timestamptz:=(p_payload->>'retry_at')::timestamptz;
  recipient_id uuid;
  entry sectalk_private.st_v7_renewal_cases;
  hours integer;
begin
  if p_invoice is null or p_invoice !~ '^in_[a-zA-Z0-9_]{1,100}$'
    or next_stage is null or next_stage not in ('open','paid','closed') or p_observed is null then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-renewal:'||p_invoice,0));
  select * into entry from sectalk_private.st_v7_renewal_cases where invoice=p_invoice for update;
  recipient_id:=sectalk_private.st_v7_renewal_binding(customer_key,subscription_key);
  if recipient_id is null then return false; end if;
  if entry.invoice is not null and (entry.customer,entry.subscription,entry.recipient)
    is distinct from (customer_key,subscription_key,recipient_id) then return false; end if;
  if next_stage<>'open' then
    update sectalk_private.st_v7_renewal_cases set stage=next_stage,retry_at=null,observed_at=greatest(observed_at,p_observed)
      where invoice=p_invoice and stage<>'paid' and (next_stage='paid' or observed_at<=p_observed);
    if found then update sectalk_private.st_v7_renewal_mail set state='closed',lease=null,lease_until=null
      where invoice=p_invoice and state='queued'; end if;
    return true;
  end if;
  if entry.stage in ('closed','paid') then return true; end if;
  if p_create and p_failed_at>=p_observed-interval '30 days' and p_failed_at<entry.first_failed_at then
    update sectalk_private.st_v7_renewal_cases c set first_failed_at=p_failed_at,
      grace_until=p_failed_at+(c.grace_until-c.first_failed_at)
      where c.invoice=p_invoice returning * into entry;
  end if;
  if next_attempt is null or next_attempt not between 1 and 100 then return false; end if;
  if next_retry is not null and (not isfinite(next_retry) or next_retry>p_observed+interval '45 days') then next_retry:=null; end if;
  if entry.invoice is null then
    if not p_create or p_failed_at is null or p_failed_at>p_observed+interval '5 minutes'
      or p_failed_at<p_observed-interval '30 days' then return false; end if;
    select grace_hours into hours from sectalk_private.st_v7_renewal_policy where singleton;
    insert into sectalk_private.st_v7_renewal_cases(invoice,recipient,customer,subscription,stage,attempt,first_failed_at,grace_until,retry_at,observed_at)
      values(p_invoice,recipient_id,customer_key,subscription_key,'open',next_attempt,p_failed_at,
        p_failed_at+make_interval(hours=>hours),next_retry,p_observed) returning * into entry;
  elsif p_observed>=entry.observed_at and next_attempt>=entry.attempt then
    update sectalk_private.st_v7_renewal_cases set attempt=next_attempt,retry_at=next_retry,observed_at=p_observed
      where invoice=p_invoice returning * into entry;
  end if;
  if entry.attempt=next_attempt and next_attempt<=6 and entry.grace_until>clock_timestamp() then
    update sectalk_private.st_v7_renewal_mail set state='closed',lease=null,lease_until=null
      where invoice=p_invoice and attempt<next_attempt and state='queued';
    insert into sectalk_private.st_v7_renewal_mail(invoice,attempt) values(p_invoice,next_attempt) on conflict do nothing;
  end if;
  return true;
end $$;

create function sectalk_private.st_v7_renewal_closed_subscription()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  update sectalk_private.st_v7_renewal_cases c set stage='closed',retry_at=null
  where c.recipient=new.user_id and c.stage='open' and (c.subscription is distinct from new.subscription_id
    or c.customer is distinct from new.customer_id or new.status in ('canceled','incomplete_expired','unpaid','paused'));
  update sectalk_private.st_v7_renewal_mail m set state='closed',lease=null,lease_until=null
  from sectalk_private.st_v7_renewal_cases c where c.invoice=m.invoice and c.recipient=new.user_id
    and c.stage='closed' and m.state='queued';
  return new;
end $$;
create trigger st_v7_close_renewal_after_subscription after update of status,subscription_id,customer_id on public.st_v2_subscriptions
for each row execute function sectalk_private.st_v7_renewal_closed_subscription();

create function sectalk_private.st_v7_renewal_grace(p_user uuid,p_subscription text,p_period timestamptz)
returns timestamptz language sql stable security definer set search_path='' as $$
  select coalesce((select min(c.grace_until) from sectalk_private.st_v7_renewal_cases c
    where c.recipient=p_user and c.subscription=p_subscription and c.stage='open'),
    p_period+make_interval(hours=>(select grace_hours from sectalk_private.st_v7_renewal_policy where singleton)))
$$;

create function public.st_v7_renewal_status()
returns jsonb language sql stable security definer set search_path='' as $$
  select coalesce((select jsonb_build_object('state',case when c.grace_until>now() then 'grace' else 'expired' end,
      'grace_until',c.grace_until,'retry_at',case when c.retry_at>now() then c.retry_at end,'attempt',c.attempt)
    from sectalk_private.st_v7_renewal_cases c join public.st_v2_subscriptions s
      on s.user_id=c.recipient and s.subscription_id=c.subscription and s.customer_id=c.customer
    where c.recipient=auth.uid() and c.stage='open' order by c.grace_until,c.invoice limit 1),
    (select jsonb_build_object('state',case when g.deadline>now() then 'grace' else 'expired' end,'grace_until',g.deadline)
     from public.st_v2_subscriptions s
     cross join lateral (select sectalk_private.st_v7_renewal_grace(s.user_id,s.subscription_id,s.period_end) deadline) g
     where s.user_id=auth.uid() and s.status='past_due' and g.deadline is not null),'{"state":"clear"}')
  where auth.uid() is not null and public.st_v7_current_session_valid()
$$;

create function public.st_v7_renewal_mail_claim()
returns jsonb language sql security definer set search_path='' as $$
  with due as (
    select m.id from sectalk_private.st_v7_renewal_mail m join sectalk_private.st_v7_renewal_cases c on c.invoice=m.invoice
    join auth.users u on u.id=c.recipient
    where m.state='queued' and m.attempts<4 and m.ready_at<=clock_timestamp()
      and (m.lease_until is null or m.lease_until<=clock_timestamp()) and c.stage='open' and c.grace_until>clock_timestamp()
      and u.email_confirmed_at is not null and u.email is not null and coalesce(u.email_change,'')=''
      and sectalk_private.st_v2_active(c.recipient)
    order by m.ready_at,m.id limit 6 for update of m skip locked
  ), leased as (
    update sectalk_private.st_v7_renewal_mail m set attempts=attempts+1,lease=gen_random_uuid(),
      lease_until=clock_timestamp()+interval '45 seconds'
    from due where due.id=m.id returning m.id,m.lease
  ) select coalesce(jsonb_agg(to_jsonb(leased)),'[]') from leased
$$;

create function public.st_v7_renewal_mail_confirm(p_id uuid,p_lease uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('email',u.email,'grace_until',c.grace_until,'retry_at',case when c.retry_at>now() then c.retry_at end)
  from sectalk_private.st_v7_renewal_mail m join sectalk_private.st_v7_renewal_cases c on c.invoice=m.invoice
  join auth.users u on u.id=c.recipient where m.id=p_id and m.lease=p_lease and m.state='queued'
    and m.lease_until>clock_timestamp() and c.stage='open' and c.grace_until>clock_timestamp()
    and u.email_confirmed_at is not null and u.email is not null and coalesce(u.email_change,'')=''
    and sectalk_private.st_v2_active(c.recipient)
    and sectalk_private.st_v7_renewal_binding(c.customer,c.subscription)=c.recipient
$$;

create function public.st_v7_renewal_mail_finish(p_id uuid,p_lease uuid,p_outcome text)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  if p_outcome is null or p_outcome not in ('sent','retry','failed','closed') then return false; end if;
  update sectalk_private.st_v7_renewal_mail m set state=case
    when p_outcome='retry' then case when attempts>=4 then 'failed' else 'queued' end else p_outcome end,
    ready_at=clock_timestamp()+make_interval(secs=>30*power(2,attempts)::integer),lease=null,lease_until=null
  where id=p_id and lease=p_lease and lease_until>clock_timestamp() and state='queued';
  return found;
end $$;

create function public.st_v7_renewal_probe_claim()
returns jsonb language sql security definer set search_path='' as $$
  with due as (
    select invoice from sectalk_private.st_v7_renewal_cases c where c.stage='open' and c.probe_at<=clock_timestamp()
      and c.first_failed_at>clock_timestamp()-interval '45 days' order by c.probe_at,c.invoice limit 6 for update skip locked
  ), leased as (
    update sectalk_private.st_v7_renewal_cases c set probe_at=clock_timestamp()+interval '10 minutes'
      from due where due.invoice=c.invoice returning c.invoice,c.customer,c.subscription,c.probe_at
  ) select coalesce(jsonb_agg(to_jsonb(leased)),'[]') from leased
$$;

create function public.st_v7_renewal_probe_finish(p_invoice text,p_probe_at timestamptz,p_payload jsonb)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  if not exists(select 1 from sectalk_private.st_v7_renewal_cases c where c.invoice=p_invoice and c.probe_at=p_probe_at
    and c.stage='open') then return false; end if;
  if jsonb_typeof(p_payload->'provider_subscription')='object' and
    sectalk_private.st_v7_renewal_binding(p_payload->>'customer',p_payload->>'subscription')::text
      = p_payload->'provider_subscription'->>'user' then
    perform sectalk_private.st_v7_sync_stripe_snapshot('renewal-probe:'||p_invoice||':'||extract(epoch from p_probe_at)::text,
      p_payload->>'subscription',p_probe_at-interval '10 minutes',p_payload->'provider_subscription');
  end if;
  return sectalk_private.st_v7_apply_renewal(p_invoice,null,p_probe_at-interval '10 minutes',p_payload,false);
end $$;

revoke all on function sectalk_private.st_v7_renewal_binding(text,text),sectalk_private.st_v7_apply_renewal(text,timestamptz,timestamptz,jsonb,boolean),
  sectalk_private.st_v7_renewal_closed_subscription(),sectalk_private.st_v7_renewal_grace(uuid,text,timestamptz),
  public.st_v7_renewal_status(),public.st_v7_renewal_mail_claim(),public.st_v7_renewal_mail_confirm(uuid,uuid),
  public.st_v7_renewal_mail_finish(uuid,uuid,text),public.st_v7_renewal_probe_claim(),public.st_v7_renewal_probe_finish(text,timestamptz,jsonb)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_renewal_status() to authenticated;
grant execute on function public.st_v7_renewal_mail_claim(),public.st_v7_renewal_mail_confirm(uuid,uuid),
  public.st_v7_renewal_mail_finish(uuid,uuid,text),public.st_v7_renewal_probe_claim(),public.st_v7_renewal_probe_finish(text,timestamptz,jsonb) to service_role;
select cron.schedule('sectalk-v7-renewal-mail-expiry','*/15 * * * *',
  $job$update sectalk_private.st_v7_renewal_mail m set state=case when m.attempts=4 then 'failed' else 'closed' end,
    lease=null,lease_until=null from sectalk_private.st_v7_renewal_cases c
    where c.invoice=m.invoice and m.state='queued' and coalesce(m.lease_until,'-infinity')<=clock_timestamp()
      and (c.grace_until<=clock_timestamp() or c.stage<>'open' or m.attempts=4);$job$);
create or replace function public.st_v7_stripe_claim(p_event text,p_hash text,p_kind text,p_resource text,p_event_at timestamptz)
returns jsonb language plpgsql security definer set search_path='' as $$
declare receipt sectalk_private.st_v7_stripe_receipts;
begin
  if p_event is null or p_event !~ '^evt_[a-zA-Z0-9_]{1,100}$'
    or p_hash is null or p_hash !~ '^[a-f0-9]{64}$' or p_kind is null
    or p_kind not in ('subscription','subscription_deleted','trial','invoice_renewal') or p_resource is null
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
create or replace function sectalk_private.st_v7_account_entitlements(p_actor uuid)
returns sectalk_private.st_v7_plan_entitlements language sql stable security definer set search_path='' as $$
  select e.* from sectalk_private.st_v7_plan_entitlements e where (e.plan,e.version)=(
    select coalesce(s.plan,'free'),coalesce(s.catalog_version,f.version)
    from sectalk_private.st_v6_active_plans() f
    left join public.st_v2_subscriptions s on s.user_id=p_actor and (
      (s.status in ('active','trialing') and s.period_end>now()) or
      (s.status='past_due' and sectalk_private.st_v7_renewal_grace(s.user_id,s.subscription_id,s.period_end)>now()))
    where f.plan='free'
  );
$$;
commit;
