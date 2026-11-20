begin;
insert into auth.users(id,email,email_confirmed_at) values
 ('b1040000-0000-4000-8000-000000000001','coupon-operator@example.invalid',now()),
 ('b1040000-0000-4000-8000-000000000002','coupon-a@example.invalid',now()),
 ('b1040000-0000-4000-8000-000000000003','coupon-b@example.invalid',now());
insert into public.st_profiles(id,handle,name) values
 ('b1040000-0000-4000-8000-000000000001','coupon_operator','Coupon operator'),
 ('b1040000-0000-4000-8000-000000000002','coupon_fixture_a','Coupon A'),
 ('b1040000-0000-4000-8000-000000000003','coupon_fixture_b','Coupon B');
insert into sectalk_private.staff(user_id) values('b1040000-0000-4000-8000-000000000001');
insert into sectalk_private.st_v7_coupon_operators values('b1040000-0000-4000-8000-000000000001');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
 ('b1040000-0000-4000-8000-000000000011','b1040000-0000-4000-8000-000000000001','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
 ('b1040000-0000-4000-8000-000000000021','b1040000-0000-4000-8000-000000000001','aal2','b1040000-0000-4000-8000-000000000011');
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
 ('b1040000-0000-4000-8000-000000000031','b1040000-0000-4000-8000-000000000021','totp',now(),now()-interval '10 minutes');

do $$
declare
  operator constant uuid:='b1040000-0000-4000-8000-000000000001';
  first constant uuid:='b1040000-0000-4000-8000-000000000002';
  second constant uuid:='b1040000-0000-4000-8000-000000000003';
  terms constant jsonb:=jsonb_build_object('enabled',true,'coupon','coupon_sql_fixture','percent_bps',1500,
    'duration','repeating','months',3,'plans',array['business'],'currencies',array['USD'],
    'max_redemptions',1,'starts_at',now()-interval '1 hour','ends_at',now()+interval '2 hours');
  lease jsonb;
  completion jsonb;
begin
  perform set_config('request.jwt.claims',jsonb_build_object('sub',operator,'role','authenticated','aal','aal2',
    'session_id','b1040000-0000-4000-8000-000000000021')::text,true);
  set local role authenticated;
  begin
    perform public.st_v7_publish_coupon('FIXTURE-B104',0,terms);
    raise exception 'Stale TOTP could publish a campaign';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_reserve_coupon_checkout(first,'price_Fixture','FIXTURE-B104',1,'business','USD');
    raise exception 'Public role could reserve transactions directly';
  exception when insufficient_privilege then null; end;
  reset role;
  update auth.mfa_amr_claims set updated_at=now() where id='b1040000-0000-4000-8000-000000000031';
  set local role authenticated;
  if public.st_v7_publish_coupon('FIXTURE-B104',0,terms)<>1 then raise exception 'Campaign not published'; end if;
  begin
    perform public.st_v7_publish_coupon('FIXTURE-B104',0,terms);
    raise exception 'Out-of-date publisher overwrote the campaign';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  set local role service_role;
  if public.st_v7_quote_coupon('FIXTURE-B104','professional','USD') is not null
    or public.st_v7_quote_coupon('FIXTURE-B104','business','GBP') is not null
    or public.st_v7_quote_coupon('FIXTURE-B104','business','USD')->>'months'<>'3' then
    raise exception 'Plan, currency, or duration wrong'; end if;
  lease:=public.st_v7_reserve_coupon_checkout(first,'price_Fixture','FIXTURE-B104',1,'business','USD');
  if lease is null or public.st_v7_reserve_coupon_checkout(first,'price_Fixture',null,null,'business','USD') is not null
    or public.st_v7_reserve_coupon_checkout(second,'price_Fixture','FIXTURE-B104',1,'business','USD') is not null then
    raise exception 'Reservation identity, stacking, or capacity failed'; end if;
  if not public.st_v7_attach_coupon_checkout((lease->>'id')::uuid,first,'cs_test_first_coupon') then
    raise exception 'Checkout attach failed'; end if;
  completion:=jsonb_build_object('hold',lease->>'id','account',first,'price','price_Fixture','currency','USD',
    'coupon','coupon_sql_fixture','expires',lease->>'expires_epoch','state','expired');
  if public.st_v7_coupon_probe_finish('cs_test_interloper',completion)
    or not public.st_v7_coupon_probe_finish('cs_test_first_coupon',completion) then
    raise exception 'Wrong session was accepted or genuine expiry was denied'; end if;
  lease:=public.st_v7_reserve_coupon_checkout(second,'price_Fixture','FIXTURE-B104',1,'business','USD');
  if lease is null then raise exception 'Authoritative expiry did not release capacity'; end if;
  completion:=completion||jsonb_build_object('hold',lease->>'id','account',second,'expires',lease->>'expires_epoch','state','redeemed');
  if not public.st_v7_coupon_probe_finish('cs_test_second_coupon',completion)
    or not public.st_v7_coupon_probe_finish('cs_test_second_coupon',completion)
    or public.st_v7_coupon_probe_finish('cs_test_second_coupon',completion||'{"state":"expired"}')
    or public.st_v7_reserve_coupon_checkout(first,'price_Fixture','FIXTURE-B104',1,'business','USD') is not null then
    raise exception 'Redemption replay, terminal state or lifetime cap failed'; end if;
  reset role;
end $$;
rollback;
