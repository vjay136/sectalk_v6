begin;
create table sectalk_private.st_v8_workspace_seats (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  customer text not null,
  subscription text unique,
  quantity integer check(quantity between 1 and 10000),
  current_until timestamptz,
  check((subscription is null)=(quantity is null))
);
create table sectalk_private.st_v8_workspace_seat_changes (
  id uuid primary key default gen_random_uuid(),
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  actor uuid references auth.users on delete set null,
  customer text not null,
  price text not null,
  quantity integer not null check(quantity between 1 and 10000),
  intent text not null check(intent in ('manual','true_up')),
  created_at timestamptz not null default now(),
  lease_until timestamptz not null default now()+interval '2 minutes',
  lease_token uuid not null default gen_random_uuid(),
  finished_at timestamptz,
  outcome text check(outcome in ('settled','rejected'))
);
create unique index on sectalk_private.st_v8_workspace_seat_changes(workspace) where finished_at is null;
create index on sectalk_private.st_v8_workspace_seat_changes(workspace,created_at desc);
alter table sectalk_private.st_v8_workspace_seats enable row level security;
alter table sectalk_private.st_v8_workspace_seat_changes enable row level security;
revoke all on sectalk_private.st_v8_workspace_seats,sectalk_private.st_v8_workspace_seat_changes from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_workspace_seat_entitlement()
returns trigger language plpgsql security definer set search_path='' as $$
declare allocation sectalk_private.st_v8_workspace_seats; pending integer; limit_size integer;
begin
  perform 1 from public.st_v2_workspaces where id=new.workspace_id for update;
  select * into allocation from sectalk_private.st_v8_workspace_seats where workspace=new.workspace_id;
  if exists(select 1 from public.st_v2_members m where (m.workspace_id,m.user_id)=(new.workspace_id,new.user_id)) then return new; end if;
  select quantity into pending from sectalk_private.st_v8_workspace_seat_changes where workspace=new.workspace_id and finished_at is null;
  if allocation.quantity is null and pending is null then return new; end if;
  limit_size:=least(allocation.quantity,coalesce(pending,allocation.quantity),
    coalesce((sectalk_private.st_v7_workspace_entitlements(new.workspace_id)).seat_limit,0));
  if (allocation.quantity is not null and coalesce(allocation.current_until<=clock_timestamp(),true))
    or (select count(*) from public.st_v2_members where workspace_id=new.workspace_id)>=limit_size then
    raise exception 'Workspace seat capacity requires billing administrator approval' using errcode='23514';
  end if;
  return new;
end $$;
create trigger st_v8_workspace_seat_entitlement before insert or update of workspace_id on public.st_v2_members
for each row execute function sectalk_private.st_v8_workspace_seat_entitlement();

create function public.st_v8_workspace_seat_scope(p_workspace uuid)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false) or
    public.st_v7_sensitive_action_status('billing') is distinct from 'verified' or
    not (coalesce(sectalk_private.st_v7_billing_admin_allowed(p_workspace,auth.uid()),false) or
    sectalk_private.st_v2_role(p_workspace,auth.uid()) is not distinct from 'owner') then
    raise exception 'Fresh workspace billing approval required' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v8_workspace_seat',24);
  return true;
end $$;

create function public.st_v8_workspace_seat_command(p_workspace uuid,p_actor uuid,p_action text,p_data jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare owner_id uuid; binding public.st_v2_subscriptions; allocation sectalk_private.st_v8_workspace_seats;
declare job sectalk_private.st_v8_workspace_seat_changes; occupied integer; awaiting integer; cap integer; requested integer;
begin
  select owner into owner_id from public.st_v2_workspaces where id=p_workspace for update;
  if not found or not (p_actor=owner_id and sectalk_private.st_v2_role(p_workspace,p_actor) is not distinct from 'owner'
      or sectalk_private.st_v7_billing_admin_allowed(p_workspace,p_actor))
    or not sectalk_private.st_v2_active(p_actor) then return null; end if;
  select * into binding from public.st_v2_subscriptions where user_id=owner_id;
  if not found or binding.status is distinct from 'active' or binding.period_end<=now()
    or binding.customer_id is null or binding.subscription_id is null then return jsonb_build_object('linked',false); end if;
  select * into allocation from sectalk_private.st_v8_workspace_seats where workspace=p_workspace;
  if found and allocation.customer is distinct from binding.customer_id then return null; end if;
  select * into job from sectalk_private.st_v8_workspace_seat_changes where workspace=p_workspace and finished_at is null;
  select count(*) into occupied from public.st_v2_members where workspace_id=p_workspace;
  cap:=coalesce((sectalk_private.st_v7_workspace_entitlements(p_workspace)).seat_limit,0);
  if p_action='status' then
    select count(*) into awaiting from (
      select coalesce(lower(u.email),i.invitee::text) as recipient from public.st_v2_invites i
      join auth.users u on u.id=i.invitee
      where i.workspace_id=p_workspace and i.status='pending'
      and sectalk_private.st_v2_role(p_workspace,i.created_by) in ('owner','admin')
      and not exists(select 1 from public.st_v2_members m where (m.workspace_id,m.user_id)=(p_workspace,i.invitee))
      union
      select i.email from sectalk_private.st_v6_workspace_link_invites i
      where i.workspace_id=p_workspace and i.consumed_at is null and i.expires_at>now()
      and sectalk_private.st_v2_role(p_workspace,i.issued_by) in ('owner','admin')
      and sectalk_private.st_v6_link_domain_allowed(p_workspace,i.email)
      and not exists(select 1 from public.st_v2_members m join auth.users u on u.id=m.user_id
        where m.workspace_id=p_workspace and lower(u.email)=i.email)
    ) recipients;
    return jsonb_build_object('linked',true,'owner',owner_id,'customer',binding.customer_id,'base',binding.subscription_id,
      'currency',binding.billing_currency,'cadence',binding.billing_cadence,'subscription',allocation.subscription,
      'quantity',allocation.quantity,'until',allocation.current_until,'occupied',occupied,'cap',cap,
      'awaiting',awaiting,'pending',job.quantity,'intent',job.intent);
  elsif p_action='claim' then
    requested:=(p_data->>'quantity')::integer;
    if requested is null or requested<greatest(occupied,1) or requested>cap
      or p_data->>'price' !~ '^price_[A-Za-z0-9_]{3,96}$' or p_data->>'intent' not in ('manual','true_up')
      or p_data->>'intent' is null or p_data->>'price' is null then return null; end if;
    if job.id is not null then
      if job.lease_until>now() or job.created_at<now()-interval '23 hours'
        or (job.quantity,job.intent,job.price) is distinct from (requested,p_data->>'intent',p_data->>'price') then return null; end if;
      update sectalk_private.st_v8_workspace_seat_changes set lease_until=now()+interval '2 minutes',lease_token=gen_random_uuid()
        where id=job.id returning * into job;
    else
      insert into sectalk_private.st_v8_workspace_seat_changes(workspace,actor,customer,price,quantity,intent)
        values(p_workspace,p_actor,binding.customer_id,p_data->>'price',requested,p_data->>'intent') returning * into job;
    end if;
    return jsonb_build_object('id',job.id,'lease',job.lease_token);
  elsif p_action='finish' and job.id::text=p_data->>'id' and job.lease_token::text=p_data->>'lease' then
    if p_data->>'result'='settled' then
      if p_data->>'subscription' !~ '^sub_[A-Za-z0-9_]{3,96}$' or p_data->>'subscription' is null
        or (allocation.subscription is not null and allocation.subscription is distinct from p_data->>'subscription') then return null; end if;
      insert into sectalk_private.st_v8_workspace_seats values(p_workspace,binding.customer_id,p_data->>'subscription',
        job.quantity,to_timestamp((p_data->>'until')::bigint))
      on conflict(workspace) do update set quantity=excluded.quantity,current_until=excluded.current_until;
    elsif p_data->>'result' is distinct from 'rejected' then return null; end if;
    update sectalk_private.st_v8_workspace_seat_changes set finished_at=now(),outcome=p_data->>'result' where id=job.id;
    return 'true'::jsonb;
  end if;
  return null;
end $$;
create function public.st_v8_workspace_seat_renew(p_workspace uuid,p_customer text,p_subscription text,p_quantity integer,p_until bigint,p_active boolean)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  perform 1 from public.st_v2_workspaces where id=p_workspace for update;
  update sectalk_private.st_v8_workspace_seats set current_until=case when p_active then to_timestamp(p_until) else now() end
    where workspace=p_workspace and customer=p_customer and subscription=p_subscription and quantity=p_quantity;
  return found;
end $$;
revoke all on function sectalk_private.st_v8_workspace_seat_entitlement(),public.st_v8_workspace_seat_scope(uuid),
  public.st_v8_workspace_seat_command(uuid,uuid,text,jsonb),
  public.st_v8_workspace_seat_renew(uuid,text,text,integer,bigint,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_seat_scope(uuid) to authenticated;
grant execute on function public.st_v8_workspace_seat_command(uuid,uuid,text,jsonb) to service_role;
grant execute on function public.st_v8_workspace_seat_renew(uuid,text,text,integer,bigint,boolean) to service_role;
commit;
