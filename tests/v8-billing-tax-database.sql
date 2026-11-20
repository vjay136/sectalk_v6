\set ON_ERROR_STOP on
begin;
do $$
declare actor uuid:=gen_random_uuid(); other uuid:=gen_random_uuid(); profile jsonb; quote jsonb; reserve jsonb; data jsonb;
begin
  if has_function_privilege('authenticated','public.st_v8_tax_checkout(uuid,text,jsonb)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v8_tax_profiles','select')
    or has_table_privilege('anon','sectalk_private.st_v8_tax_checkout_quotes','select') then
    raise exception 'Tax profile or quote exposed to a browser role';
  end if;
  insert into auth.users(id,email,created_at,updated_at) values
    (actor,actor::text||'@example.invalid',now(),now()),(other,other::text||'@example.invalid',now(),now());
  profile:=public.st_v8_tax_checkout(actor,'save','{"country":"IN","taxId":"Fixture"}');
  quote:=public.st_v8_tax_checkout(actor,'quote',jsonb_build_object('revision',profile->>'revision',
    'price','price_TaxQA','estimate',jsonb_build_object('total',11800)));
  data:=jsonb_build_object('id',quote->>'id','price','price_TaxQA');
  if quote->>'id' is null or public.st_v8_tax_checkout(other,'validate',data) is not null
    or public.st_v8_tax_checkout(actor,'validate',data||'{"price":"price_Different"}') is not null then
    raise exception 'Quote anchor was not enforced';
  end if;
  reserve:=public.st_v2_reserve_checkout(actor,'price_TaxQA');
  if public.st_v8_tax_checkout(actor,'attach',data||jsonb_build_object('checkout',reserve->>'id')) is null then
    raise exception 'Could not bind quote to active checkout';
  end if;
  perform public.st_v8_tax_checkout(actor,'save','{"country":"US","taxId":""}');
  if public.st_v8_tax_checkout(actor,'validate',data) is not null then raise exception 'A stale tax profile could be reused'; end if;
end $$;
rollback;
