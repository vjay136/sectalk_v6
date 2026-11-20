begin;

insert into auth.users(id,email) values
 ('d60b0090-79ef-4cc1-a22c-000000000001','catalog-fixture-one@example.invalid'),
 ('d60b0090-79ef-4cc1-a22c-000000000002','catalog-fixture-two@example.invalid');

do $$
declare
  subscriber uuid:='d60b0090-79ef-4cc1-a22c-000000000001';
  outsider uuid:='d60b0090-79ef-4cc1-a22c-000000000002';
  revision integer;
  price jsonb;
  legacy jsonb;
begin
  set local role anon;
  if (select count(*) from public.st_v6_plan_catalog())<>4
    or has_function_privilege(current_user,'public.st_v6_publish_plan(text,text,text,boolean,timestamptz,jsonb)','execute')
    or has_function_privilege(current_user,'public.st_v6_checkout_plan_price(text,text,text,integer,text)','execute') then
    raise exception 'Incorrect public catalog access';
  end if;
  reset role;
  set local role service_role;
  legacy:=public.st_v6_checkout_plan_price('professional','monthly','USD',1,'price_legacy_a1');
  if legacy->>'id' is distinct from 'price_legacy_a1'
    or public.st_v6_checkout_plan_price('basic','monthly','USD',1,'price_legacy_a1') is not null then
    raise exception 'Legacy visibility policy failed';
  end if;

  revision:=public.st_v6_publish_plan('professional','Pro terms fixture','Revision with fixed offers',true,
    now()-interval '2 days',
    '[{"cadence":"monthly","currency":"EUR","amount":900,"provider_price":"price_fixture_pro_eur_v2"},
      {"cadence":"annual","currency":"JPY","amount":9000,"provider_price":"price_fixture_pro_jpy_v2"}]');
  if revision<>2 then raise exception 'Expected initial paid revision'; end if;
  perform public.st_v6_sync_catalog_subscription(
    'catalog_fixture_event_1',subscriber,'cus_catalog_fixture','sub_catalog_fixture','price_fixture_pro_eur_v2',
    null,null,'active',now()+interval '30 days',false,now()-interval '1 day','EUR',900);
  perform public.st_v6_publish_plan('professional','Pro updated terms fixture','Revised monthly prices',true,
    now()-interval '1 hour',
    '[{"cadence":"monthly","currency":"EUR","amount":1100,"provider_price":"price_fixture_pro_eur_v3"},
      {"cadence":"monthly","currency":"USD","amount":1200,"provider_price":"price_fixture_pro_usd_v3"}]');
  perform public.st_v6_publish_plan('professional','Future terms fixture','Offers activate at launch',true,
    now()+interval '1 day',
    '[{"cadence":"monthly","currency":"EUR","amount":1500,"provider_price":"price_fixture_pro_eur_v4"}]');

  price:=public.st_v6_checkout_plan_price('professional','monthly','EUR',3,'price_legacy_a1');
  if price->>'id' is distinct from 'price_fixture_pro_eur_v3' or (price->>'amount')::int is distinct from 1100
    or public.st_v6_checkout_plan_price('professional','monthly','EUR',2,null) is not null
    or public.st_v6_checkout_plan_price('professional','monthly','EUR',4,null) is not null
    or public.st_v6_checkout_plan_price('professional','annual','USD',3,'price_legacy_a1') is not null then
    raise exception 'Only selected currently offered terms may be used for checkout';
  end if;
  begin
    perform public.st_v6_sync_catalog_subscription(
      'catalog_fixture_bad_terms',subscriber,'cus_catalog_fixture','sub_catalog_fixture','price_fixture_pro_eur_v2',
      null,null,'active',now()+interval '30 days',false,now(),'EUR',999);
    raise exception 'Mismatched terms accepted';
  exception when invalid_parameter_value then null; end;
  perform public.st_v6_sync_catalog_subscription(
    'catalog_fixture_event_2',subscriber,'cus_catalog_fixture','sub_catalog_fixture','price_fixture_pro_eur_v2',
    null,null,'active',now()+interval '60 days',false,now(),'EUR',900);
  perform public.st_v6_sync_catalog_subscription(
    'catalog_fixture_event_2',subscriber,'cus_catalog_fixture','sub_catalog_fixture','price_fixture_pro_eur_v3',
    null,null,'active',now()+interval '60 days',false,now(),'EUR',1100);
  perform public.st_v6_sync_catalog_subscription(
    'catalog_fixture_outdated',subscriber,'cus_catalog_fixture','sub_catalog_fixture','price_fixture_pro_eur_v3',
    null,null,'active',now()+interval '60 days',false,now()-interval '2 hours','EUR',1100);
  reset role;

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',subscriber::text,true);
  if public.st_v6_my_plan_title() is distinct from 'Pro terms fixture'
    or (select (catalog_version,billing_currency,billing_amount) from public.st_v2_subscriptions where user_id=subscriber)
      is distinct from row(2,'EUR'::text,900) then
    raise exception 'Renewal did not preserve prior subscription pricing';
  end if;
  perform set_config('request.jwt.claim.sub',outsider::text,true);
  if public.st_v6_my_plan_title() is not null or exists(select from public.st_v2_subscriptions where user_id=subscriber)
    or has_function_privilege(current_user,'public.st_v6_publish_plan(text,text,text,boolean,timestamptz,jsonb)','execute') then
    raise exception 'Foreign subscription terms or service mutations were exposed';
  end if;
  reset role;
  set local role anon;
  if (select version from public.st_v6_plan_catalog() where plan='professional') is distinct from 3
    or (select prices::text like '%price_fixture%' from public.st_v6_plan_catalog() where plan='professional') then
    raise exception 'Catalog leaked provider IDs or showed the wrong public revision';
  end if;
end $$;

select 'passed: scheduled catalog, exact currencies, scoped billing terms and grandfathered renewal' as result;
rollback;
