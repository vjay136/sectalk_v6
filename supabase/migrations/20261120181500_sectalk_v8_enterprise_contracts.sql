begin;

create table sectalk_private.st_v8_enterprise_billing_operators (
  workspace uuid not null references public.st_v2_workspaces(id) on delete cascade,
  actor uuid not null references auth.users(id) on delete cascade,
  primary key (workspace,actor)
);

create table sectalk_private.st_v8_enterprise_orders (
  id uuid primary key,
  workspace uuid not null references public.st_v2_workspaces(id) on delete restrict,
  reference text not null check(char_length(reference) between 3 and 80),
  currency text not null check(currency in ('USD','EUR','GBP','INR','CAD','AUD','JPY')),
  committed_seats integer not null check(committed_seats between 1 and 100000),
  annual_total integer not null check(annual_total between 1 and 1000000000),
  starts_on date not null,
  ends_on date not null,
  expires_on date not null,
  terms text not null check(char_length(terms) between 12 and 1500),
  quoted_by uuid not null,
  accepted_by uuid,
  po text check(char_length(po) between 1 and 100),
  invoice_number text unique,
  due_on date,
  payment_reference text check(char_length(payment_reference) between 3 and 100),
  state text not null default 'quoted' check(state in ('quoted','accepted','invoiced','paid','withdrawn')),
  created_at timestamptz not null default statement_timestamp(),
  unique(workspace,reference),
  check(ends_on>starts_on),
  check(expires_on<=starts_on),
  check(state not in ('accepted','invoiced','paid') or (accepted_by is not null and accepted_by<>quoted_by and po is not null)),
  check(state not in ('invoiced','paid') or (invoice_number is not null and due_on is not null)),
  check(state<>'paid' or payment_reference is not null)
);
create index on sectalk_private.st_v8_enterprise_orders(workspace,created_at desc,id);

create table sectalk_private.st_v8_enterprise_order_events (
  id bigint generated always as identity primary key,
  order_id uuid not null references sectalk_private.st_v8_enterprise_orders(id) on delete restrict,
  workspace uuid not null,
  actor uuid not null,
  action text not null check(action in ('quote','accept','invoice','paid','withdraw')),
  note text check(char_length(note) between 3 and 300),
  happened_at timestamptz not null default statement_timestamp()
);

alter table sectalk_private.st_v8_enterprise_billing_operators enable row level security;
alter table sectalk_private.st_v8_enterprise_orders enable row level security;
alter table sectalk_private.st_v8_enterprise_order_events enable row level security;
revoke all on sectalk_private.st_v8_enterprise_billing_operators,sectalk_private.st_v8_enterprise_orders,
  sectalk_private.st_v8_enterprise_order_events from public,anon,authenticated,service_role;
create trigger st_v8_enterprise_audit_immutable before update or delete on sectalk_private.st_v8_enterprise_order_events
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

create function sectalk_private.st_v8_enterprise_billing_roles(p_workspace uuid)
returns text[] language sql stable security definer set search_path='' as $$
  select case when not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    then array[]::text[] else array_remove(array[
    case when exists(select 1 from public.st_v2_workspaces w where w.id=p_workspace and w.owner=auth.uid()
      and sectalk_private.st_v2_role(p_workspace,auth.uid())='owner') then 'owner' end,
    case when sectalk_private.st_v7_billing_admin_allowed(p_workspace,auth.uid()) then 'billing' end,
    case when exists(select 1 from sectalk_private.st_v8_enterprise_billing_operators
      where workspace=p_workspace and actor=auth.uid()) then 'commercial' end
  ],null) end;
$$;

create function public.st_v8_enterprise_billing_workspaces()
returns table(id uuid,name text) language sql stable security definer set search_path='' as $$
  select w.id,w.name from sectalk_private.st_v8_enterprise_billing_operators g
    join public.st_v2_workspaces w on w.id=g.workspace
  where g.actor=auth.uid() and sectalk_private.st_v7_billing_admin_session()
  order by w.name,w.id limit 100;
$$;

create function public.st_v8_enterprise_billing_view(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare roles text[]:=sectalk_private.st_v8_enterprise_billing_roles(p_workspace); enterprise boolean;
begin
  if cardinality(roles)=0 then raise exception 'Enterprise billing access unavailable' using errcode='42501'; end if;
  enterprise:=coalesce((sectalk_private.st_v7_workspace_entitlements(p_workspace)).plan='enterprise',false);
  if public.st_v7_sensitive_action_status('billing') is distinct from 'verified' then
    return jsonb_build_object('access','mfa','eligible',enterprise);
  end if;
  return jsonb_build_object('access','verified','eligible',enterprise,'roles',roles,'orders',
    coalesce((select jsonb_agg(to_jsonb(q)-'quoted_by'-'accepted_by'-'workspace'-'payment_reference') from (
      select o.* from sectalk_private.st_v8_enterprise_orders o where o.workspace=p_workspace
      order by o.created_at desc,o.id limit 100
    ) q),'[]'::jsonb));
end $$;

create function public.st_v8_enterprise_billing_command(p_workspace uuid,p_order uuid,p_action text,p_data jsonb)
returns void language plpgsql security definer set search_path='' as $$
declare roles text[]; who uuid:=auth.uid(); prior sectalk_private.st_v8_enterprise_orders;
  today date:=(now() at time zone 'UTC')::date; start_date date; end_date date; expiration date; due_date date;
  order_reference text; order_currency text; order_seats integer; total integer; order_terms text; note text;
begin
  if p_workspace is null or p_order is null or p_action is null or p_data is null or jsonb_typeof(p_data)<>'object'
    or octet_length(p_data::text)>10000 then raise exception 'Invalid enterprise order' using errcode='22023'; end if;
  roles:=sectalk_private.st_v8_enterprise_billing_roles(p_workspace);
  if cardinality(roles)=0 or public.st_v7_sensitive_action_status('billing') is distinct from 'verified' then
    raise exception 'Fresh billing verification required' using errcode='42501'; end if;
  perform 1 from public.st_v2_workspaces w where w.id=p_workspace for no key update;
  roles:=sectalk_private.st_v8_enterprise_billing_roles(p_workspace);
  perform sectalk_private.limit_action('v8_enterprise_billing',20);
  select * into prior from sectalk_private.st_v8_enterprise_orders o where (o.workspace,o.id)=(p_workspace,p_order)
    for update;

  if p_action='quote' and 'commercial'=any(roles) then
    if (sectalk_private.st_v7_workspace_entitlements(p_workspace)).plan is distinct from 'enterprise' then
      raise exception 'An existing Enterprise entitlement is required' using errcode='42501'; end if;
    begin
      start_date:=(p_data->>'starts')::date; expiration:=(p_data->>'expires')::date;
      end_date:=(start_date+interval '1 year')::date;
      order_reference:=nullif(btrim(p_data->>'reference'),''); order_currency:=p_data->>'currency';
      order_seats:=(p_data->>'seats')::integer; total:=(p_data->>'total')::integer; order_terms:=btrim(p_data->>'terms');
    exception when data_exception then raise exception 'Enter valid annual pricing and dates' using errcode='22023'; end;
    if start_date is null or expiration is null or not isfinite(start_date) or not isfinite(expiration)
      or start_date not between today and today+366 or expiration not between today and start_date
      or order_reference is null or order_currency is null or order_seats is null or total is null or order_terms is null then
      raise exception 'Enter complete annual pricing and dates' using errcode='22023'; end if;
    if prior.id is not null then
      if (prior.quoted_by,prior.reference,prior.currency,prior.committed_seats,prior.annual_total,prior.starts_on,prior.expires_on,prior.terms)
        is not distinct from (who,order_reference,order_currency,order_seats,total,start_date,expiration,order_terms) then return; end if;
      raise exception 'Order identifier already used' using errcode='22023';
    end if;
    insert into sectalk_private.st_v8_enterprise_orders(id,workspace,reference,currency,committed_seats,annual_total,
      starts_on,ends_on,expires_on,terms,quoted_by)
      values(p_order,p_workspace,order_reference,order_currency,order_seats,total,start_date,end_date,expiration,order_terms,who);
  elsif p_action='accept' and 'owner'=any(roles) and prior.quoted_by<>who then
    note:=nullif(btrim(p_data->>'po'),'');
    if note is null or char_length(note)>100 then raise exception 'Purchase order reference is required' using errcode='22023'; end if;
    if prior.accepted_by=who and prior.po=note and prior.state in ('accepted','invoiced','paid') then return; end if;
    if prior.state<>'quoted' or prior.expires_on<today then raise exception 'Quote is unavailable' using errcode='42501'; end if;
    if exists(select 1 from sectalk_private.st_v8_enterprise_orders o where o.workspace=p_workspace and o.id<>prior.id
      and o.state in ('accepted','invoiced','paid') and o.starts_on<prior.ends_on and prior.starts_on<o.ends_on) then
      raise exception 'A commitment already covers these dates' using errcode='22023'; end if;
    update sectalk_private.st_v8_enterprise_orders set state='accepted',accepted_by=who,po=note where id=prior.id;
    note:=null;
  elsif p_action='invoice' and 'commercial'=any(roles) and prior.accepted_by<>who then
    begin due_date:=(p_data->>'due')::date;
    exception when data_exception then raise exception 'Enter a valid invoice due date' using errcode='22023'; end;
    if prior.state in ('invoiced','paid') and due_date=prior.due_on then return; end if;
    if prior.state<>'accepted' or due_date is null or due_date not between today and today+120 then
      raise exception 'An accepted order and valid due date are required' using errcode='22023'; end if;
    update sectalk_private.st_v8_enterprise_orders set state='invoiced',due_on=due_date,
      invoice_number='ENT-'||upper(replace(id::text,'-','')) where id=prior.id;
  elsif p_action='paid' and 'commercial'=any(roles) and prior.accepted_by<>who then
    note:=btrim(p_data->>'payment');
    if prior.state='paid' and prior.payment_reference=note then return; end if;
    if prior.state<>'invoiced' or note is null or char_length(note) not between 3 and 100 then
      raise exception 'An issued invoice and payment reference are required' using errcode='22023'; end if;
    update sectalk_private.st_v8_enterprise_orders set state='paid',payment_reference=note where id=prior.id;
    note:=null;
  elsif p_action='withdraw' and 'commercial'=any(roles) then
    note:=btrim(p_data->>'reason');
    if prior.state='withdrawn' then return; end if;
    if prior.state is distinct from 'quoted' or note is null or char_length(note) not between 12 and 300 then
      raise exception 'An open quote and withdrawal reason are required' using errcode='22023'; end if;
    update sectalk_private.st_v8_enterprise_orders set state='withdrawn' where id=prior.id;
  else
    raise exception 'Enterprise order unavailable' using errcode='42501';
  end if;
  insert into sectalk_private.st_v8_enterprise_order_events(order_id,workspace,actor,action,note)
    values(p_order,p_workspace,who,p_action,note);
end $$;

revoke all on function sectalk_private.st_v8_enterprise_billing_roles(uuid),public.st_v8_enterprise_billing_workspaces(),
  public.st_v8_enterprise_billing_view(uuid),public.st_v8_enterprise_billing_command(uuid,uuid,text,jsonb)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_enterprise_billing_workspaces(),public.st_v8_enterprise_billing_view(uuid),
  public.st_v8_enterprise_billing_command(uuid,uuid,text,jsonb) to authenticated;
notify pgrst,'reload schema';
commit;
