begin;
create table sectalk_private.st_v7_plan_changes (
  id uuid primary key default gen_random_uuid(),
  account uuid not null references auth.users on delete cascade,
  customer text not null,
  subscription text not null,
  command jsonb not null,
  state text not null default 'quoted' check(state in ('quoted','running','done','superseded')),
  expires timestamptz not null default now()+interval '10 minutes',
  lease_until timestamptz,
  lease_token uuid,
  result jsonb,
  created_at timestamptz not null default now()
);
create unique index st_v7_plan_changes_one_running on sectalk_private.st_v7_plan_changes(account) where state='running';
create index on sectalk_private.st_v7_plan_changes(account,created_at desc);
alter table sectalk_private.st_v7_plan_changes enable row level security;
revoke all on sectalk_private.st_v7_plan_changes from public,anon,authenticated,service_role;

create function public.st_v7_plan_change_command(
  p_actor uuid,p_customer text,p_subscription text,p_action text,p_id uuid default null,p_data jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare change sectalk_private.st_v7_plan_changes;
begin
  perform 1 from public.st_v2_subscriptions where user_id=p_actor and customer_id=p_customer
    and subscription_id=p_subscription and sectalk_private.st_v2_active(p_actor) for update;
  if not found then return null; end if;
  if p_action='current_price' then
    return to_jsonb(exists(select 1 from public.st_v2_subscriptions s
      join sectalk_private.st_v6_plan_prices p on (p.plan,p.version,p.cadence,p.currency,p.amount)=
        (s.plan,s.catalog_version,s.billing_cadence,s.billing_currency,s.billing_amount)
      where s.user_id=p_actor and p.provider_price=p_data->>'price'));
  elsif p_action='status' then
    select * into change from sectalk_private.st_v7_plan_changes where account=p_actor and subscription=p_subscription
      and (state='running' or (state='done' and result->>'state' in ('scheduled','aborted')))
      order by (state='running') desc, created_at desc limit 1;
    if change.state='running' then return jsonb_build_object('pending',change.id,'command',change.command); end if;
    return change.result;
  elsif p_action='quote' then
    if exists(select 1 from sectalk_private.st_v7_plan_changes where account=p_actor and state='running') then
      return null;
    end if;
    update sectalk_private.st_v7_plan_changes set state='superseded' where account=p_actor and state='quoted';
    insert into sectalk_private.st_v7_plan_changes(account,customer,subscription,command)
      values(p_actor,p_customer,p_subscription,p_data) returning * into change;
    return jsonb_build_object('id',change.id);
  end if;
  select * into change from sectalk_private.st_v7_plan_changes where id=p_id and account=p_actor
    and customer=p_customer and subscription=p_subscription;
  if not found then return null; end if;
  if p_action='claim' then
    if change.state='done' then return jsonb_build_object('result',change.result); end if;
    if change.state='superseded' or (change.state='quoted' and change.expires<=now())
      or (change.state='running' and (change.lease_until>now() or change.expires+interval '22 hours'<=now())) then return null; end if;
    update sectalk_private.st_v7_plan_changes set state='running',lease_until=now()+interval '3 minutes',
      lease_token=gen_random_uuid() where id=p_id returning lease_token into change.lease_token;
    return jsonb_build_object('command',change.command,'retry',change.state='running','lease',change.lease_token);
  elsif p_action='finish' and change.state='running' and change.lease_token::text=p_data->>'lease' then
    update sectalk_private.st_v7_plan_changes set state='done',result=p_data->'result',lease_until=null,lease_token=null where id=p_id;
    return p_data->'result';
  end if;
  return null;
end $$;
revoke all on function public.st_v7_plan_change_command(uuid,text,text,text,uuid,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_plan_change_command(uuid,text,text,text,uuid,jsonb) to service_role;
commit;
