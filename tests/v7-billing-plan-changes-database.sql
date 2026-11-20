\set ON_ERROR_STOP on
begin;

do $$
declare actor uuid:=gen_random_uuid(); stranger uuid:=gen_random_uuid(); quote uuid; result jsonb; first_lease text;
begin
  if has_function_privilege('authenticated','public.st_v7_plan_change_command(uuid,text,text,text,uuid,jsonb)','execute')
    or has_function_privilege('anon','public.st_v7_plan_change_command(uuid,text,text,text,uuid,jsonb)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v7_plan_changes','select') then
    raise exception 'Client roles can access the private change ledger';
  end if;
  insert into auth.users(id,email,created_at,updated_at) values
    (actor,actor::text||'@example.invalid',now(),now()),
    (stranger,stranger::text||'@example.invalid',now(),now());
  insert into public.st_v2_subscriptions(user_id,customer_id,subscription_id,plan,status,period_end) values
    (actor,'cus_PlanFixture','sub_PlanFixture','business','active',now()+interval '1 month'),
    (stranger,'cus_PlanOther','sub_PlanOther','business','active',now()+interval '1 month');
  quote:=(public.st_v7_plan_change_command(actor,'cus_PlanFixture','sub_PlanFixture','quote',null,'{"kind":"schedule"}')->>'id')::uuid;
  if quote is null or public.st_v7_plan_change_command(stranger,'cus_PlanOther','sub_PlanOther','claim',quote) is not null then
    raise exception 'Quote issued incorrectly or accessible to another billing account';
  end if;
  result:=public.st_v7_plan_change_command(actor,'cus_PlanFixture','sub_PlanFixture','claim',quote);
  first_lease:=result->>'lease';
  if result->>'retry' is distinct from 'false' then raise exception 'First claim failed'; end if;
  if public.st_v7_plan_change_command(actor,'cus_PlanFixture','sub_PlanFixture','claim',quote) is not null
    or public.st_v7_plan_change_command(actor,'cus_PlanFixture','sub_PlanFixture','quote',null,'{"kind":"upgrade"}') is not null then
    raise exception 'Running lease permitted a duplicate mutation';
  end if;
  update sectalk_private.st_v7_plan_changes set lease_until=now()-interval '1 second' where id=quote;
  result:=public.st_v7_plan_change_command(actor,'cus_PlanFixture','sub_PlanFixture','claim',quote);
  if result->>'retry' is distinct from 'true' or result->'command'->>'kind' is distinct from 'schedule' then
    raise exception 'Expired lease did not retry the original operation';
  end if;
  if public.st_v7_plan_change_command(actor,'cus_PlanFixture','sub_PlanFixture','finish',quote,
    jsonb_build_object('lease',first_lease,'result','{"state":"aborted"}'::jsonb)) is not null then
    raise exception 'A stale worker could finish a reacquired operation';
  end if;
  perform public.st_v7_plan_change_command(actor,'cus_PlanFixture','sub_PlanFixture','finish',quote,
    jsonb_build_object('lease',result->>'lease','result','{"state":"scheduled","schedule":{"id":"sub_sched_QA"}}'::jsonb));
  if public.st_v7_plan_change_command(actor,'cus_PlanFixture','sub_PlanFixture','claim',quote)->'result'->>'state' is distinct from 'scheduled' then
    raise exception 'Successful replay did not return the original result';
  end if;
end $$;
rollback;
