\set ON_ERROR_STOP on
begin;
do $$
declare owner_id uuid:=gen_random_uuid(); outsider uuid:=gen_random_uuid(); tenant uuid:=gen_random_uuid(); job jsonb;
begin
  if has_function_privilege('authenticated','public.st_v8_workspace_seat_command(uuid,uuid,text,jsonb)','execute')
    or has_function_privilege('authenticated','public.st_v8_workspace_seat_closures(text,uuid)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v8_workspace_seats','select') then
    raise exception 'Client roles can bypass billing middleware or see provider bindings';
  end if;
  insert into auth.users(id,email,created_at,updated_at) values
    (owner_id,owner_id::text||'@example.invalid',now(),now()),
    (outsider,outsider::text||'@example.invalid',now(),now());
  insert into public.st_profiles(id,handle,name) values
    (owner_id,'wsowner_'||substr(owner_id::text,1,8),'Seat fixture owner'),
    (outsider,'wsout_'||substr(outsider::text,1,8),'Seat fixture outsider');
  insert into public.st_v2_workspaces(id,name,owner) values(tenant,'Seat guard fixture',owner_id);
  insert into public.st_v2_members(workspace_id,user_id,role) values(tenant,owner_id,'owner');
  insert into public.st_v2_subscriptions(user_id,customer_id,subscription_id,plan,status,period_end)
    values(owner_id,'cus_SeatSQL','sub_BaseSQL','business','active',now()+interval '1 month');
  insert into sectalk_private.st_v8_workspace_seats(workspace,customer,subscription,quantity,current_until)
    values(tenant,'cus_SeatSQL','sub_AddonSQL',1,now()+interval '1 month');
  begin
    insert into public.st_v2_members(workspace_id,user_id) values(tenant,outsider);
    raise exception 'Native membership insert bypassed the paid allocation';
  exception when check_violation then null;
  end;
  if public.st_v8_workspace_seat_command(tenant,outsider,'status') is not null then
    raise exception 'Unrelated operator queried the workspace seat scope';
  end if;
  update public.st_v2_subscriptions set status='canceled' where user_id=owner_id;
  if not exists(select 1 from sectalk_private.st_v8_workspace_seat_closures where subscription='sub_AddonSQL' and workspace=tenant) then
    raise exception 'Terminal base subscription left the workspace add-on recurring';
  end if;
  update sectalk_private.st_v8_workspace_seat_closures set retry_at='-infinity' where subscription='sub_AddonSQL';
  select value into job from jsonb_array_elements(public.st_v8_workspace_seat_closures())
    where value->>'subscription'='sub_AddonSQL';
  if job is null or public.st_v8_workspace_seat_closures('sub_AddonSQL',gen_random_uuid()) is distinct from 'false'::jsonb
    or public.st_v8_workspace_seat_closures('sub_AddonSQL',(job->>'lease')::uuid) is distinct from 'true'::jsonb then
    raise exception 'Closure lease ownership failed';
  end if;
end $$;
rollback;
