begin;
insert into auth.users(id,email,email_confirmed_at) values
 ('b1070000-0000-4000-8000-000000000001','renewal-sql@example.invalid',now());
insert into public.st_profiles(id,handle,name) values
 ('b1070000-0000-4000-8000-000000000001','renewal_sql','Renewal SQL');
select public.st_v2_sync_billing('evt_fixture_renewal_sql','b1070000-0000-4000-8000-000000000001','cus_FixtureRenewal',
  'sub_FixtureRenewal','business','past_due',now()-interval '1 hour',false,now());
update sectalk_private.st_v7_renewal_policy set grace_hours=48 where singleton;

do $$
declare invoice_key constant text:='in_RenewalSQL';
  actor constant uuid:='b1070000-0000-4000-8000-000000000001';
  observed constant timestamptz:=statement_timestamp();
  failed constant timestamptz:=observed-interval '1 hour';
  attempt1 constant jsonb:=jsonb_build_object('customer','cus_FixtureRenewal','subscription','sub_FixtureRenewal',
     'stage','open','attempt',1,'retry_at',observed+interval '12 hours','new_failure',true);
  attempt2 constant jsonb:=attempt1||jsonb_build_object('attempt',2);
  paid constant jsonb:=attempt1||jsonb_build_object('stage','paid');
  message_id uuid;
  claimed jsonb;
  lease uuid;
begin
  set local role authenticated;
  begin
    perform public.st_v7_renewal_mail_claim();
    raise exception 'Account obtained renewal worker lease';
  exception when insufficient_privilege then null; end;
  reset role;
  if not sectalk_private.st_v7_apply_renewal(invoice_key,failed,observed,attempt1,true)
    or not sectalk_private.st_v7_apply_renewal(invoice_key,failed,observed,attempt1,true) then raise exception 'Renewal apply failed'; end if;
  if sectalk_private.st_v7_renewal_grace(actor,'sub_FixtureRenewal',null)<>failed+interval '48 hours' then
    raise exception 'The configured grace period was not applied'; end if;
  if sectalk_private.st_v7_apply_renewal('in_Foreign',failed,observed,attempt1||'{"customer":"cus_Foreign"}',true) then
    raise exception 'Foreign billing case accepted'; end if;
  select id into message_id from sectalk_private.st_v7_renewal_mail where invoice=invoice_key and attempt=1;
  update sectalk_private.st_v7_renewal_mail set ready_at='-infinity' where id=message_id;
  set local role service_role;
  select entry into claimed from jsonb_array_elements(public.st_v7_renewal_mail_claim()) entry where (entry->>'id')::uuid=message_id;
  lease:=(claimed->>'lease')::uuid;
  if lease is null or public.st_v7_renewal_mail_confirm(message_id,lease)->>'email'<>'renewal-sql@example.invalid'
    or not public.st_v7_renewal_mail_finish(message_id,lease,'retry') then raise exception 'Renewal mail retry failed'; end if;
  reset role;
  if (select attempts from sectalk_private.st_v7_renewal_mail where id=message_id)<>1 then raise exception 'Expected one SMTP try'; end if;
  perform sectalk_private.st_v7_apply_renewal(invoice_key,failed+interval '5 minutes',observed,attempt2,true);
  if sectalk_private.st_v7_renewal_grace(actor,'sub_FixtureRenewal',null)<>failed+interval '48 hours' then
    raise exception 'Retry extended grace'; end if;
  perform sectalk_private.st_v7_apply_renewal(invoice_key,failed-interval '5 minutes',observed,attempt1,true);
  if sectalk_private.st_v7_renewal_grace(actor,'sub_FixtureRenewal',null)<>failed+interval '47 hours 55 minutes' then
    raise exception 'Delayed first failure did not reconcile earlier deadline'; end if;
  if (sectalk_private.st_v7_account_entitlements(actor)).plan<>'business' then
    raise exception 'Past due plan did not retain configured grace'; end if;
  update sectalk_private.st_v7_renewal_cases set grace_until=observed-interval '1 minute' where invoice=invoice_key;
  if (sectalk_private.st_v7_account_entitlements(actor)).plan<>'free' then
    raise exception 'Past due plan remained active past configured grace'; end if;
  perform sectalk_private.st_v7_apply_renewal(invoice_key,null,observed,paid,false);
  perform sectalk_private.st_v7_apply_renewal(invoice_key,failed,observed,attempt2,true);
  if (select stage from sectalk_private.st_v7_renewal_cases c where c.invoice=invoice_key)<>'paid'
    or exists(select 1 from sectalk_private.st_v7_renewal_mail m where m.invoice=invoice_key and m.state='queued') then
    raise exception 'Paid renewal reopened or retained unsent mail'; end if;
  perform sectalk_private.st_v7_apply_renewal('in_CanceledSQL',failed,observed,attempt1,true);
  update public.st_v2_subscriptions set status='canceled' where user_id=actor;
  if (select stage from sectalk_private.st_v7_renewal_cases where invoice='in_CanceledSQL')<>'closed'
    or (sectalk_private.st_v7_account_entitlements(actor)).plan<>'free' then
    raise exception 'Canceled subscription kept grace or queued renewal'; end if;
end $$;
rollback;
