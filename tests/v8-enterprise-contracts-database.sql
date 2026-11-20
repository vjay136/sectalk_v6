begin;

insert into auth.users(id,email,email_confirmed_at) values
  ('b8140000-0000-4000-8000-000000000001','contract-owner@example.invalid',now()),
  ('b8140000-0000-4000-8000-000000000002','contract-commercial@example.invalid',now()),
  ('b8140000-0000-4000-8000-000000000003','contract-stale@example.invalid',now());
insert into public.st_profiles(id,handle,name) values
  ('b8140000-0000-4000-8000-000000000001','contract_fixture_owner','Enterprise fixture owner'),
  ('b8140000-0000-4000-8000-000000000002','contract_commercial','Enterprise fixture commercial operator'),
  ('b8140000-0000-4000-8000-000000000003','contract_fixture_stale','Enterprise stale-session operator');
insert into auth.sessions(id,user_id,aal)
select ('b8140000-0000-4000-8000-00000000001'||i)::uuid,('b8140000-0000-4000-8000-00000000000'||i)::uuid,'aal1'
from generate_series(1,3) as i;
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
select gen_random_uuid(),('b8140000-0000-4000-8000-00000000001'||i)::uuid,'password',now(),
  case when i=3 then now()-interval '20 minutes' else now() end from generate_series(1,3) i;
insert into public.st_v2_subscriptions(user_id,plan,catalog_version,status,period_end)
  values('b8140000-0000-4000-8000-000000000001','enterprise',1,'active',now()+interval '90 days');
insert into public.st_v2_workspaces(id,name,owner) values
  ('b8140000-0000-4000-8000-000000000021','Enterprise rollback tenant','b8140000-0000-4000-8000-000000000001'),
  ('b8140000-0000-4000-8000-000000000022','Free rollback tenant','b8140000-0000-4000-8000-000000000003');
insert into public.st_v2_members(workspace_id,user_id,role) values
  ('b8140000-0000-4000-8000-000000000021','b8140000-0000-4000-8000-000000000001','owner'),
  ('b8140000-0000-4000-8000-000000000022','b8140000-0000-4000-8000-000000000003','owner');
insert into sectalk_private.st_v8_enterprise_billing_operators(workspace,actor) values
  ('b8140000-0000-4000-8000-000000000021','b8140000-0000-4000-8000-000000000002'),
  ('b8140000-0000-4000-8000-000000000021','b8140000-0000-4000-8000-000000000003'),
  ('b8140000-0000-4000-8000-000000000022','b8140000-0000-4000-8000-000000000002');

create function pg_temp.contract_actor(i integer) returns void
language sql set search_path='' as $$
  select set_config('request.jwt.claims',jsonb_build_object('sub','b8140000-0000-4000-8000-00000000000'||i,
    'role','authenticated','aal','aal1','session_id','b8140000-0000-4000-8000-00000000001'||i)::text,true);
$$;

do $$
declare workspace uuid:='b8140000-0000-4000-8000-000000000021'; free_space uuid:='b8140000-0000-4000-8000-000000000022';
  first_order uuid:=gen_random_uuid(); second_order uuid:=gen_random_uuid();
  today date:=(now() at time zone 'UTC')::date;
  terms jsonb:=jsonb_build_object('reference','Contract fixture 1','total',150000,'seats',25,'currency','JPY',
    'starts',today+5,'expires',today+3,'terms','Synthetic negotiated enterprise amount.');
begin
  if has_table_privilege('authenticated','sectalk_private.st_v8_enterprise_orders','select')
    or has_function_privilege('anon','public.st_v8_enterprise_billing_view(uuid)','execute') then
    raise exception 'Ledger is directly exposed'; end if;
  set local role authenticated;
  perform pg_temp.contract_actor(3);
  if public.st_v8_enterprise_billing_view(workspace)->>'access'<>'mfa' then raise exception 'Stale proof returned ledger'; end if;
  begin
    perform public.st_v8_enterprise_billing_command(workspace,first_order,'quote',terms);
    raise exception 'Stale proof allowed commercial mutation';
  exception when insufficient_privilege then null; end;
  perform pg_temp.contract_actor(2);
  begin
    perform public.st_v8_enterprise_billing_command(free_space,first_order,'quote',terms);
    raise exception 'Unentitled workspace got a quote';
  exception when insufficient_privilege then null; end;
  perform public.st_v8_enterprise_billing_command(workspace,first_order,'quote',terms);
  perform public.st_v8_enterprise_billing_command(workspace,first_order,'quote',terms);
  begin
    perform public.st_v8_enterprise_billing_command(workspace,first_order,'quote',terms||'{"total":999}'::jsonb);
    raise exception 'Quoted price changed on retry';
  exception when invalid_parameter_value then null; end;
  perform public.st_v8_enterprise_billing_command(workspace,second_order,'quote',terms||'{"reference":"Contract fixture 2"}'::jsonb);
  perform pg_temp.contract_actor(1);
  perform public.st_v8_enterprise_billing_command(workspace,first_order,'accept','{"po":"LOCAL-TEST"}');
  begin
    perform public.st_v8_enterprise_billing_command(workspace,second_order,'accept','{"po":"LOCAL-OVERLAP"}');
    raise exception 'Overlapping annual contract accepted';
  exception when invalid_parameter_value then null; end;
  perform pg_temp.contract_actor(2);
  perform public.st_v8_enterprise_billing_command(workspace,first_order,'invoice',jsonb_build_object('due',today+30));
  perform public.st_v8_enterprise_billing_command(workspace,first_order,'paid','{"payment":"LOCAL-PAID"}');
  reset role;
  if (select count(*) from sectalk_private.st_v8_enterprise_order_events where order_id=first_order)<>4 then
    raise exception 'Order action retry produced a duplicate audit record'; end if;
  begin
    delete from sectalk_private.st_v8_enterprise_order_events where order_id=first_order;
    raise exception 'Audit deletion permitted';
  exception when insufficient_privilege then null; end;
end $$;

select 'passed: isolated enterprise ledger, live proof, entitlement, price immutability, overlap, event integrity' as result;
rollback;
