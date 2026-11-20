begin;
create table sectalk_private.st_v7_stripe_invoice_numbers (
  live boolean not null,
  invoice text not null check(invoice ~ '^in_[a-zA-Z0-9_]{1,100}$'),
  number text not null check(number ~ '^[A-Z0-9][A-Z0-9-]{0,31}-[0-9]{1,12}$'),
  customer text not null check(customer ~ '^cus_[a-zA-Z0-9_]{1,100}$'),
  subscription text not null check(subscription ~ '^sub_[a-zA-Z0-9_]{1,100}$'),
  issued_at timestamptz not null,
  recorded_at timestamptz not null default clock_timestamp(),
  primary key(live,invoice),
  unique(live,number)
);
alter table sectalk_private.st_v7_stripe_invoice_numbers enable row level security;
revoke all on sectalk_private.st_v7_stripe_invoice_numbers from public,anon,authenticated,service_role;

create function public.st_v7_pin_stripe_invoice(p_live boolean,p_invoice text,p_number text,p_customer text,
  p_subscription text,p_issued_at timestamptz)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  if p_issued_at is null or not isfinite(p_issued_at) or p_issued_at>statement_timestamp()+interval '5 minutes' then return false; end if;
  insert into sectalk_private.st_v7_stripe_invoice_numbers(live,invoice,number,customer,subscription,issued_at)
    values(p_live,p_invoice,p_number,p_customer,p_subscription,p_issued_at) on conflict do nothing;
  return exists(select 1 from sectalk_private.st_v7_stripe_invoice_numbers r where (r.live,r.invoice)=(p_live,p_invoice)
    and (r.number,r.customer,r.subscription,r.issued_at)=(p_number,p_customer,p_subscription,p_issued_at));
end $$;
revoke all on function public.st_v7_pin_stripe_invoice(boolean,text,text,text,text,timestamptz) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_pin_stripe_invoice(boolean,text,text,text,text,timestamptz) to service_role;
commit;
