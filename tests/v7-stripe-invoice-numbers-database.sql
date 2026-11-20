begin;
do $$
declare stamp constant timestamptz:=date_trunc('second',now());
begin
  set local role authenticated;
  begin
    perform public.st_v7_pin_stripe_invoice(false,'in_fixture','QA-0001','cus_QA','sub_QA',stamp);
    raise exception 'Authenticated account could pin invoice number';
  exception when insufficient_privilege then null; end;
  reset role;
  set local role service_role;
  if not public.st_v7_pin_stripe_invoice(false,'in_fixture','QA-0001','cus_QA','sub_QA',stamp)
    or not public.st_v7_pin_stripe_invoice(false,'in_fixture','QA-0001','cus_QA','sub_QA',stamp)
    or public.st_v7_pin_stripe_invoice(false,'in_fixture','QA-0002','cus_QA','sub_QA',stamp)
    or public.st_v7_pin_stripe_invoice(false,'in_second','QA-0001','cus_QA','sub_QA',stamp)
    or public.st_v7_pin_stripe_invoice(false,'in_fixture','QA-0001','cus_QA','sub_Foreign',stamp)
    or public.st_v7_pin_stripe_invoice(false,'in_fixture','QA-0001','cus_QA','sub_QA',stamp-interval '1 hour')
    or not public.st_v7_pin_stripe_invoice(true,'in_fixture','QA-0001','cus_QA','sub_QA',stamp) then
    raise exception 'Provider invoice numbering, binding or environment failed';
  end if;
  reset role;
end $$;
rollback;
