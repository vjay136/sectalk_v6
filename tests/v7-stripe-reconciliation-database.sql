begin;
do $$
declare
  event_id constant text:='evt_qa_lease_billing12';
  resource constant text:='sub_QABilling12';
  signed_at constant timestamptz:=date_trunc('second',now());
  claim jsonb;
  first_lease uuid;
  second_lease uuid;
begin
  set local role anon;
  begin
    perform public.st_v7_stripe_claim(event_id,repeat('1',64),'subscription',resource,signed_at);
    raise exception 'Anonymous claim accepted';
  exception when insufficient_privilege then null; end;
  reset role;
  set local role authenticated;
  begin
    perform public.st_v7_stripe_reconcile_claim();
    raise exception 'Account could acquire a payment reconciliation lease';
  exception when insufficient_privilege then null; end;
  reset role;
  set local role service_role;
  claim:=public.st_v7_stripe_claim(event_id,repeat('1',64),'subscription',resource,signed_at);
  first_lease:=(claim->>'lease')::uuid;
  if claim->>'state'<>'claimed' or first_lease is null then raise exception 'Missing initial receipt lease'; end if;
  if public.st_v7_stripe_claim(event_id,repeat('1',64),'subscription',resource,signed_at)->>'state'<>'busy'
    or public.st_v7_stripe_claim(event_id,repeat('2',64),'subscription',resource,signed_at)->>'state'<>'conflict'
    or public.st_v7_stripe_claim('evt_qa_old_billing12',repeat('1',64),'subscription',resource,signed_at-interval '31 days')->>'state'<>'invalid'
    then raise exception 'Receipt validation or exclusive lease failed'; end if;
  reset role;
  update sectalk_private.st_v7_stripe_receipts set lease_until=clock_timestamp()-interval '1 second' where id=event_id;
  set local role service_role;
  if public.st_v7_stripe_finish(event_id,first_lease,'ignore') then raise exception 'Expired lease accepted'; end if;
  claim:=public.st_v7_stripe_claim(event_id,repeat('1',64),'subscription',resource,signed_at);
  second_lease:=(claim->>'lease')::uuid;
  if second_lease is null or second_lease=first_lease then raise exception 'Expired receipt not recovered'; end if;
  if not public.st_v7_stripe_finish(event_id,second_lease,'retry') then raise exception 'Receipt cannot release for retry'; end if;
  claim:=public.st_v7_stripe_claim(event_id,repeat('1',64),'subscription',resource,signed_at);
  second_lease:=(claim->>'lease')::uuid;
  if second_lease is null or not public.st_v7_stripe_finish(event_id,second_lease,'ignore')
    or public.st_v7_stripe_finish(event_id,second_lease,'apply','{}')
    or public.st_v7_stripe_claim(event_id,repeat('1',64),'subscription',resource,signed_at)->>'state'<>'done' then
    raise exception 'Finished receipt allowed replay';
  end if;
  reset role;
end $$;
rollback;
