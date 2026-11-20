begin;
create table sectalk_private.st_v8_invoice_adjustments (
  id uuid primary key default gen_random_uuid(),
  workspace uuid not null,
  actor uuid not null,
  customer text not null,
  subscription text not null,
  invoice text not null,
  currency text not null check(currency ~ '^[A-Z]{3}$'),
  amount integer not null check(amount between 1 and 100000000),
  kind text not null check(kind in ('refund','credit','adjustment')),
  reason text not null check(reason in ('duplicate','order_change','product_unsatisfactory','fraudulent')),
  state text not null default 'quoted' check(state in ('quoted','running','rejected','issued','void','refund_pending','refund_failed','refunded')),
  note text unique,
  refund text unique,
  created_at timestamptz not null default now(),
  changed_at timestamptz not null default now(),
  lease uuid,
  lease_until timestamptz
);
create unique index on sectalk_private.st_v8_invoice_adjustments(invoice) where state='running';
create index on sectalk_private.st_v8_invoice_adjustments(workspace,created_at desc);
alter table sectalk_private.st_v8_invoice_adjustments enable row level security;
revoke all on sectalk_private.st_v8_invoice_adjustments from public,anon,authenticated,service_role;

create table sectalk_private.st_v8_invoice_adjustment_events (
  id bigint generated always as identity primary key,
  adjustment uuid not null references sectalk_private.st_v8_invoice_adjustments on delete cascade,
  previous text not null,
  current text not null,
  recorded_at timestamptz not null default now()
);
create index on sectalk_private.st_v8_invoice_adjustment_events(adjustment,id);
alter table sectalk_private.st_v8_invoice_adjustment_events enable row level security;
revoke all on sectalk_private.st_v8_invoice_adjustment_events from public,anon,authenticated,service_role;
create function sectalk_private.st_v8_audit_invoice_adjustment()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  insert into sectalk_private.st_v8_invoice_adjustment_events(adjustment,previous,current)
    values(new.id,old.state,new.state);
  return new;
end $$;
revoke all on function sectalk_private.st_v8_audit_invoice_adjustment() from public,anon,authenticated,service_role;
create trigger st_v8_invoice_adjustment_audit after update of state on sectalk_private.st_v8_invoice_adjustments
for each row when(old.state is distinct from new.state) execute function sectalk_private.st_v8_audit_invoice_adjustment();

create function public.st_v8_invoice_adjustment_scope(p_workspace uuid)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false) or
    not coalesce(sectalk_private.st_v7_billing_admin_allowed(p_workspace,auth.uid()),false) or
    public.st_v7_sensitive_action_status('billing') is distinct from 'verified' then
    raise exception 'Delegated billing administrator and fresh proof required' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v8_invoice_adjustment',24);
  return true;
end $$;

create function public.st_v8_invoice_adjustment_command(p_workspace uuid,p_actor uuid,p_action text,p_id uuid default null,p_data jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare payer text; source text; job sectalk_private.st_v8_invoice_adjustments;
begin
  select s.customer_id into payer from public.st_v2_workspaces w join public.st_v2_subscriptions s on s.user_id=w.owner
    where w.id=p_workspace and sectalk_private.st_v7_billing_admin_allowed(w.id,p_actor) for no key update of w;
  if not found or payer is null then return null; end if;
  select subscription into source from (
    select subscription,0 as priority,null::timestamptz as ended from sectalk_private.st_v8_workspace_seats
      where workspace=p_workspace and customer=payer
    union all
    select subscription,1,finished_at from sectalk_private.st_v8_workspace_seat_closures where workspace=p_workspace and customer=payer
  ) s where subscription is not null order by priority,ended desc nulls first limit 1;
  if p_action='scope' then
    return jsonb_build_object('customer',payer,'subscription',source,'history',coalesce((
      select jsonb_agg(to_jsonb(x)) from (
        select id,kind,reason,currency,amount,state,created_at,actor=p_actor as owned from sectalk_private.st_v8_invoice_adjustments
        where workspace=p_workspace and customer=payer and state<>'quoted' order by created_at desc limit 25
      ) x),'[]'::jsonb));
  elsif p_action='quote' then
    if source is null or source is distinct from p_data->>'subscription' or p_data->>'invoice' !~ '^in_[A-Za-z0-9_]{3,96}$'
      or p_data->>'invoice' is null then return null; end if;
    insert into sectalk_private.st_v8_invoice_adjustments(workspace,actor,customer,subscription,invoice,currency,amount,kind,reason)
      values(p_workspace,p_actor,payer,source,p_data->>'invoice',p_data->>'currency',(p_data->>'amount')::integer,p_data->>'kind',p_data->>'reason')
      returning * into job;
    return jsonb_build_object('id',job.id);
  end if;
  select * into job from sectalk_private.st_v8_invoice_adjustments
    where id=p_id and workspace=p_workspace and actor=p_actor and customer=payer;
  if not found then return null; end if;
  if p_action='inspect' then return to_jsonb(job); end if;
  if p_action='reject' and job.state='running' and job.lease::text=p_data->>'lease' then
    update sectalk_private.st_v8_invoice_adjustments set state='rejected',changed_at=now(),lease=null,lease_until=null where id=job.id;
    return 'true'::jsonb;
  elsif p_action='claim' then
    if job.state not in ('quoted','running') then return jsonb_build_object('state',job.state); end if;
    if (job.state='quoted' and job.created_at<now()-interval '10 minutes') or
      (job.state='running' and (job.lease_until>now() or job.created_at<now()-interval '22 hours')) or exists (
        select 1 from sectalk_private.st_v8_invoice_adjustments where invoice=job.invoice and state='running' and id<>job.id
      ) then return null; end if;
    update sectalk_private.st_v8_invoice_adjustments set state='running',changed_at=now(),
      lease=gen_random_uuid(),lease_until=now()+interval '2 minutes' where id=job.id returning lease into job.lease;
    return jsonb_build_object('lease',job.lease,'retry',job.state='running');
  end if;
  return null;
end $$;

create function public.st_v8_invoice_adjustment_sync(p_action text,p_data jsonb)
returns jsonb language plpgsql security definer set search_path='' as $$
declare job sectalk_private.st_v8_invoice_adjustments;
begin
  if p_action='note' then
    select * into job from sectalk_private.st_v8_invoice_adjustments where id=(p_data->>'id')::uuid for update;
    if not found or job.state in ('quoted','rejected') or job.customer is distinct from p_data->>'customer'
      or job.invoice is distinct from p_data->>'invoice' or job.currency is distinct from p_data->>'currency'
      or job.amount is distinct from (p_data->>'amount')::integer or job.reason is distinct from p_data->>'reason'
      or p_data->>'state' not in ('issued','void','refund_pending','refund_failed','refunded')
      or (job.kind='adjustment' and ((p_data->>'pre')::integer is distinct from job.amount or (p_data->>'post')::integer is distinct from 0))
      or (job.kind in ('credit','refund') and ((p_data->>'pre')::integer is distinct from 0 or (p_data->>'post')::integer is distinct from job.amount))
      or (job.kind='refund' and p_data->>'refund' is null)
      or (job.kind='credit' and p_data->>'balance' is null)
      or (job.kind<>'refund' and p_data->>'refund' is not null)
      or (job.note is not null and job.note is distinct from p_data->>'note') then return 'false'::jsonb; end if;
    update sectalk_private.st_v8_invoice_adjustments set state=p_data->>'state',note=p_data->>'note',
      refund=p_data->>'refund',lease=null,lease_until=null,changed_at=now()
      where id=job.id and (state,note,refund) is distinct from (p_data->>'state',p_data->>'note',p_data->>'refund');
    return 'true'::jsonb;
  elsif p_action='refund_note' then
    return (select to_jsonb(note) from sectalk_private.st_v8_invoice_adjustments where refund=p_data->>'refund');
  end if;
  return 'false'::jsonb;
end $$;
revoke all on function public.st_v8_invoice_adjustment_scope(uuid),public.st_v8_invoice_adjustment_command(uuid,uuid,text,uuid,jsonb),
  public.st_v8_invoice_adjustment_sync(text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_invoice_adjustment_scope(uuid) to authenticated;
grant execute on function public.st_v8_invoice_adjustment_command(uuid,uuid,text,uuid,jsonb),public.st_v8_invoice_adjustment_sync(text,jsonb) to service_role;
commit;
