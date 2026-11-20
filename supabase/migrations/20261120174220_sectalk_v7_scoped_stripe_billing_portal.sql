begin;
create table sectalk_private.st_v7_billing_portal_audit (
  id uuid primary key default gen_random_uuid(),
  account uuid not null references auth.users on delete cascade,
  purpose text not null check(purpose in ('overview','payment_method','plan','invoices','tax_ids','cancel','reactivate')),
  created_at timestamptz not null default clock_timestamp()
);
create index on sectalk_private.st_v7_billing_portal_audit(account,created_at desc);
alter table sectalk_private.st_v7_billing_portal_audit enable row level security;
revoke all on sectalk_private.st_v7_billing_portal_audit from public,anon,authenticated,service_role;

create function public.st_v7_billing_portal_scope(p_purpose text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); binding public.st_v2_subscriptions;
begin
  if actor is null or public.st_v7_sensitive_action_status('billing') is distinct from 'verified' then
    raise exception 'Fresh account proof required' using errcode='42501'; end if;
  if p_purpose is null or p_purpose not in ('overview','payment_method','plan','invoices','tax_ids','cancel','reactivate') then
    raise exception 'Portal action unavailable' using errcode='22023'; end if;
  perform sectalk_private.limit_action('v7_billing_portal',15);
  select * into binding from public.st_v2_subscriptions s where s.user_id=actor
    and s.customer_id ~ '^cus_[A-Za-z0-9_]{1,100}$' and s.subscription_id ~ '^sub_[A-Za-z0-9_]{1,100}$';
  if not found then return null; end if;
  return jsonb_build_object('customer',binding.customer_id,'subscription',binding.subscription_id);
end $$;

create function public.st_v7_billing_portal_prices(p_prices text[])
returns text[] language sql stable security definer set search_path='' as $$
  select coalesce(array_agg(p.provider_price order by p.provider_price),'{}')
  from sectalk_private.st_v6_plan_prices p join sectalk_private.st_v6_active_plans() active
    on (active.plan,active.version)=(p.plan,p.version)
  where active.visible and cardinality(p_prices) between 1 and 100 and p.provider_price=any(p_prices)
$$;

create function public.st_v7_billing_portal_record(p_actor uuid,p_customer text,p_subscription text,p_purpose text)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  if p_purpose is null or p_purpose not in ('overview','payment_method','plan','invoices','tax_ids','cancel','reactivate') then return false; end if;
  perform 1 from public.st_v2_subscriptions s where s.user_id=p_actor and
    (s.customer_id,s.subscription_id)=(p_customer,p_subscription) and sectalk_private.st_v2_active(p_actor) for share;
  if not found then return false; end if;
  insert into sectalk_private.st_v7_billing_portal_audit(account,purpose) values(p_actor,p_purpose);
  return true;
end $$;
revoke all on function public.st_v7_billing_portal_scope(text),public.st_v7_billing_portal_prices(text[]),
  public.st_v7_billing_portal_record(uuid,text,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_billing_portal_scope(text) to authenticated;
grant execute on function public.st_v7_billing_portal_prices(text[]),
  public.st_v7_billing_portal_record(uuid,text,text,text) to service_role;
commit;
