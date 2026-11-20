\set ON_ERROR_STOP on
begin;

do $$
declare owner_id uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid(); other uuid:=gen_random_uuid();
declare tenant uuid:=gen_random_uuid(); first_id uuid; second_id uuid; approval jsonb;
declare details jsonb:='{"subscription":"sub_SeatAdjustSQL","invoice":"in_AdjustmentSQL","currency":"USD","amount":300,"kind":"refund","reason":"duplicate"}';
begin
  if has_function_privilege('authenticated','public.st_v8_invoice_adjustment_command(uuid,uuid,text,uuid,jsonb)','execute')
    or has_function_privilege('authenticated','public.st_v8_invoice_adjustment_sync(text,jsonb)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v8_invoice_adjustments','select') then
    raise exception 'Adjustment ledger is client accessible';
  end if;
  insert into auth.users(id,email,created_at,updated_at) values
    (owner_id,owner_id::text||'@example.invalid',now(),now()),
    (actor,actor::text||'@example.invalid',now(),now()),(other,other::text||'@example.invalid',now(),now());
  insert into public.st_profiles(id,handle,name) values
    (owner_id,'adown_'||substr(owner_id::text,1,8),'Fixture owner'),
    (actor,'adact_'||substr(actor::text,1,8),'Fixture actor'),
    (other,'adoth_'||substr(other::text,1,8),'Other fixture actor');
  insert into public.st_v2_workspaces(id,name,owner) values(tenant,'Adjustment fixture',owner_id);
  insert into public.st_v2_members(workspace_id,user_id,role) values
    (tenant,owner_id,'owner'),(tenant,actor,'member'),(tenant,other,'admin');
  insert into sectalk_private.st_v7_billing_admins(workspace,account,assigned_by) values(tenant,actor,owner_id);
  insert into public.st_v2_subscriptions(user_id,customer_id,subscription_id,plan,status,period_end)
    values(owner_id,'cus_AdjustSQL','sub_BaseAdjustSQL','business','active',now()+interval '1 month');
  insert into sectalk_private.st_v8_workspace_seats(workspace,customer,subscription,quantity,current_until)
    values(tenant,'cus_AdjustSQL','sub_SeatAdjustSQL',3,now()+interval '1 month');
  if public.st_v8_invoice_adjustment_command(tenant,other,'scope') is not null
    or public.st_v8_invoice_adjustment_command(tenant,owner_id,'scope') is not null then
    raise exception 'Owner or ordinary admin bypassed explicit billing grant';
  end if;
  first_id:=(public.st_v8_invoice_adjustment_command(tenant,actor,'quote',null,details)->>'id')::uuid;
  second_id:=(public.st_v8_invoice_adjustment_command(tenant,actor,'quote',null,details)->>'id')::uuid;
  approval:=public.st_v8_invoice_adjustment_command(tenant,actor,'claim',first_id);
  if approval->>'lease' is null or public.st_v8_invoice_adjustment_command(tenant,actor,'claim',second_id) is not null then
    raise exception 'Multiple concurrent adjustment leases on the same invoice';
  end if;
  if public.st_v8_invoice_adjustment_sync('note',jsonb_build_object('id',first_id,'state','issued',
    'customer','cus_AdjustSQL','invoice','in_AdjustmentSQL','currency','USD','amount',300,'reason','duplicate',
    'note','cn_SQLFixture','pre',300,'post',0)) is distinct from 'false'::jsonb then
    raise exception 'A provider event changed the approved payout rail';
  end if;
  if public.st_v8_invoice_adjustment_sync('note',jsonb_build_object('id',first_id,'state','refunded',
    'customer','cus_AdjustSQL','invoice','in_AdjustmentSQL','currency','USD','amount',300,'reason','duplicate',
    'note','cn_SQLFixture','refund','re_SQLFixture','pre',0,'post',300)) is distinct from 'true'::jsonb then
    raise exception 'Authentic provider snapshot did not reconcile';
  end if;
  if public.st_v8_invoice_adjustment_command(tenant,actor,'claim',first_id)->>'state' is distinct from 'refunded' then
    raise exception 'Confirmed operation replay attempted another provider write';
  end if;
  if (select string_agg(previous||':'||current,',' order by id) from sectalk_private.st_v8_invoice_adjustment_events
    where adjustment=first_id) is distinct from 'quoted:running,running:refunded' then
    raise exception 'Financial transitions were omitted or duplicated in the private audit';
  end if;
end $$;

rollback;
