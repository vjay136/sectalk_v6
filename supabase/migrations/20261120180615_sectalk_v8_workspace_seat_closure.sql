begin;
create table sectalk_private.st_v8_workspace_seat_closures (
  subscription text primary key,
  workspace uuid not null,
  customer text not null,
  lease uuid,
  retry_at timestamptz not null default now(),
  finished_at timestamptz
);
create index on sectalk_private.st_v8_workspace_seat_closures(retry_at) where finished_at is null;
alter table sectalk_private.st_v8_workspace_seat_closures enable row level security;
revoke all on sectalk_private.st_v8_workspace_seat_closures from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_queue_deleted_workspace_seats()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if old.subscription is not null then
    insert into sectalk_private.st_v8_workspace_seat_closures(subscription,workspace,customer)
      values(old.subscription,old.workspace,old.customer) on conflict do nothing;
  end if;
  return old;
end $$;
create trigger st_v8_queue_deleted_workspace_seats before delete on sectalk_private.st_v8_workspace_seats
for each row execute function sectalk_private.st_v8_queue_deleted_workspace_seats();

create function sectalk_private.st_v8_queue_base_seat_closures()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if tg_op='UPDATE' then
    if new.status not in ('canceled','incomplete_expired') and
      (new.subscription_id,new.customer_id) is not distinct from (old.subscription_id,old.customer_id) then return new; end if;
  end if;
  insert into sectalk_private.st_v8_workspace_seat_closures(subscription,workspace,customer)
    select s.subscription,s.workspace,s.customer from sectalk_private.st_v8_workspace_seats s
    join public.st_v2_workspaces w on w.id=s.workspace
    where w.owner=old.user_id and s.customer=old.customer_id and s.subscription is not null on conflict do nothing;
  if tg_op='DELETE' then return old; end if;
  return new;
end $$;
create trigger st_v8_queue_base_seat_closures after update of status,subscription_id,customer_id or delete on public.st_v2_subscriptions
for each row execute function sectalk_private.st_v8_queue_base_seat_closures();

create or replace function public.st_v8_workspace_seat_renew(p_workspace uuid,p_customer text,p_subscription text,p_quantity integer,p_until bigint,p_active boolean)
returns boolean language plpgsql security definer set search_path='' as $$
declare owner_id uuid;
begin
  select owner into owner_id from public.st_v2_workspaces where id=p_workspace for update;
  if owner_id is null or not exists(
    select 1 from public.st_v2_subscriptions where user_id=owner_id and
      status not in ('canceled','incomplete_expired') and customer_id=p_customer
  ) then
    insert into sectalk_private.st_v8_workspace_seat_closures(subscription,workspace,customer)
      values(p_subscription,p_workspace,p_customer) on conflict do nothing;
    return true;
  end if;
  if p_until<=0 then return true; end if;
  update sectalk_private.st_v8_workspace_seats set current_until=case when p_active then to_timestamp(p_until) else now() end
    where workspace=p_workspace and customer=p_customer and subscription=p_subscription and quantity=p_quantity
    and not exists(select 1 from sectalk_private.st_v8_workspace_seat_closures where subscription=p_subscription);
  return found;
end $$;

create function public.st_v8_workspace_seat_closures(p_subscription text default null,p_lease uuid default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare jobs jsonb;
begin
  if p_subscription is null and p_lease is null then
    with batch as (
      select subscription from sectalk_private.st_v8_workspace_seat_closures
      where finished_at is null and retry_at<=now() order by retry_at limit 8 for update skip locked
    ), leased as (
      update sectalk_private.st_v8_workspace_seat_closures c set lease=gen_random_uuid(),retry_at=now()+interval '5 minutes'
      from batch b where b.subscription=c.subscription returning c.subscription,c.workspace,c.customer,c.lease
    ) select coalesce(jsonb_agg(to_jsonb(leased)),'[]'::jsonb) into jobs from leased;
    return jobs;
  end if;
  perform 1 from public.st_v2_workspaces w where w.id=(
    select workspace from sectalk_private.st_v8_workspace_seat_closures where subscription=p_subscription
  ) for update;
  update sectalk_private.st_v8_workspace_seat_closures set finished_at=now(),lease=null
    where subscription=p_subscription and lease=p_lease and finished_at is null;
  if not found then return 'false'::jsonb; end if;
  delete from sectalk_private.st_v8_workspace_seats where subscription=p_subscription;
  return 'true'::jsonb;
end $$;
revoke all on function sectalk_private.st_v8_queue_deleted_workspace_seats(),sectalk_private.st_v8_queue_base_seat_closures(),
  public.st_v8_workspace_seat_closures(text,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_seat_closures(text,uuid) to service_role;
commit;
