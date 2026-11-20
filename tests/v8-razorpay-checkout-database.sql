\set ON_ERROR_STOP on
begin;

do $$
declare actor uuid:=gen_random_uuid(); other uuid:=gen_random_uuid(); reservation jsonb; version integer:=2100000000;
declare terms jsonb; charge jsonb; settled jsonb; contradictory jsonb;
begin
  if has_function_privilege('authenticated','public.st_v8_razorpay_checkout(uuid,text,jsonb)','execute')
    or has_function_privilege('authenticated','public.st_v8_razorpay_sync(text,jsonb)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v8_razorpay_checkouts','select') then
    raise exception 'Client roles can access the provider ledger';
  end if;
  insert into auth.users(id,email,created_at,updated_at) values
    (actor,actor::text||'@example.invalid',now(),now()),
    (other,other::text||'@example.invalid',now(),now());
  insert into sectalk_private.st_v6_plan_versions(plan,version,title,description,visible,active_from)
    values('professional',version,'Pro','Rollback Razorpay offer',true,now()-interval '1 minute');
  insert into sectalk_private.st_v6_plan_prices(plan,version,cadence,currency,amount,provider_price)
    values('professional',version,'monthly','INR',10000,'price_RazorpaySQL');
  terms:=jsonb_build_object('plan','professional','version',version,'cadence','monthly','amount',10000,'provider_plan','plan_Fixture');
  perform public.st_v2_reserve_checkout(other,'price_RazorpaySQL');
  if public.st_v8_razorpay_checkout(other,'reserve',terms) is not null then
    raise exception 'Stripe reservation was not respected by Razorpay';
  end if;
  if public.st_v8_razorpay_checkout(actor,'reserve',terms||'{"amount":1}') is not null then
    raise exception 'Razorpay reserved non-catalog amount';
  end if;
  reservation:=public.st_v8_razorpay_checkout(actor,'reserve',terms);
  if reservation->>'id' is null then raise exception 'Could not reserve Razorpay'; end if;
  begin
    perform public.st_v2_reserve_checkout(actor,'price_RazorpaySQL');
    raise exception 'Razorpay reservation was not respected by Stripe';
  exception when check_violation then null;
  end;
  if public.st_v8_razorpay_checkout(actor,'attach',jsonb_build_object('id',reservation->>'id',
    'subscription','sub_RazorSQL','url','https://example.invalid/checkout')) is not null then
    raise exception 'An unapproved hosted checkout destination was attached';
  end if;
  if public.st_v8_razorpay_checkout(actor,'attach',jsonb_build_object('id',reservation->>'id',
    'subscription','sub_RazorSQL','url','https://rzp.io/rzp/ExampleSQL')) is distinct from 'true'::jsonb then
    raise exception 'Could not attach Razorpay checkout';
  end if;
  charge:=jsonb_build_object('subscription','sub_RazorSQL','hash','fixture','event','evt_fixture',
    'observed',extract(epoch from now())::bigint,'kind','paid','payment','pay_RazorSQL','count',1,
    'end',extract(epoch from now()+interval '30 days')::bigint);
  settled:=public.st_v8_razorpay_sync('event',charge);
  contradictory:=public.st_v8_razorpay_sync('event',charge||'{"hash":"different"}');
  if settled is distinct from 'true'::jsonb or contradictory is distinct from 'false'::jsonb or
    (select subscription_id from public.st_v2_subscriptions where user_id=actor) is distinct from 'rzp_sub_RazorSQL' then
    raise exception 'Canonical signed receipt binding failed (settled %, contradictory %)',settled,contradictory;
  end if;
end $$;
rollback;
