begin;

insert into auth.users(id,email) values
  ('65888990-1de4-433a-8541-000000000001','entitlement-old@example.invalid'),
  ('65888990-1de4-433a-8541-000000000002','entitlement-new@example.invalid'),
  ('65888990-1de4-433a-8541-000000000003','entitlement-free@example.invalid');
insert into public.st_profiles(id,handle,name)
  select id, 'entitlement_'||right(id::text,2),'Entitlement fixture'
  from auth.users where id::text like '65888990-1de4-433a-8541-%';

do $$
declare
  grandfathered uuid:='65888990-1de4-433a-8541-000000000001';
  current_subscriber uuid:='65888990-1de4-433a-8541-000000000002';
  free_user uuid:='65888990-1de4-433a-8541-000000000003';
  old_workspace uuid;
  current_workspace uuid;
  public_offer record;
  snapshot jsonb;
begin
  set local role service_role;
  perform public.st_v6_sync_catalog_subscription('entitlements-old',grandfathered,'cus_ent_old','sub_ent_old',
    'price_ent_old','business','monthly','active',now()+interval '30 days',false,now(),'USD',null);
  if public.st_v7_publish_plan_entitlements('business','Business revision','Revised service',true,now()-interval '1 hour',
    '[{"cadence":"monthly","currency":"USD","amount":9900,"provider_price":"price_ent_new"}]',
    1,1,2,16384,32768,false,false,false)<>2 then raise exception 'Expected revision two'; end if;
  perform public.st_v6_sync_catalog_subscription('entitlements-new',current_subscriber,'cus_ent_new','sub_ent_new',
    'price_ent_new',null,null,'active',now()+interval '30 days',false,now(),'USD',9900);
  perform public.st_v7_publish_plan_entitlements('business','Future business','Scheduled service',true,now()+interval '1 day',
    '[{"cadence":"monthly","currency":"USD","amount":10900,"provider_price":"price_ent_future"}]',
    8,10,12,16384,32768,true,true,true);
  begin
    perform public.st_v7_publish_plan_entitlements('business','Broken limits','Should roll back',true,now()+interval '2 days',
      '[{"cadence":"monthly","currency":"USD","amount":11900,"provider_price":"price_ent_bad"}]',
      0,1,2,16384,32768,false,false,false);
    raise exception 'Invalid quota unexpectedly published';
  exception when check_violation then null; end;
  reset role;
  if exists(select from sectalk_private.st_v6_plan_versions where plan='business' and version>3) then
    raise exception 'Invalid terms left a partially published revision';
  end if;

  set local role anon;
  select * into public_offer from public.st_v7_public_plan_entitlements() where plan='business';
  if public_offer.version is distinct from 2 or public_offer.entitlements->>'version' is distinct from '2'
    or public_offer.entitlements->>'seat_limit' is distinct from '1'
    or (public_offer.prices->0->>'amount')::integer is distinct from 9900
    or public_offer.prices::text like '%price_ent%' then raise exception 'Public offer mixed revisions or exposed provider details'; end if;
  if has_function_privilege(current_user,'public.st_v7_my_entitlements()','execute') then
    raise exception 'Anonymous access to account entitlements';
  end if;
  reset role;

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',grandfathered::text,true);
  snapshot:=public.st_v7_my_entitlements();
  if snapshot->>'version' is distinct from '1' or snapshot->>'integration_api' is distinct from 'true' then
    raise exception 'Existing subscriber lost purchased terms';
  end if;
  old_workspace:=public.st_v2_create_workspace('Entitlement legacy workspace');
  perform set_config('request.jwt.claim.sub',current_subscriber::text,true);
  snapshot:=public.st_v7_my_entitlements();
  if snapshot->>'version' is distinct from '2' or snapshot->>'file_bytes' is distinct from '16384' then
    raise exception 'New subscriber did not receive revision two';
  end if;
  current_workspace:=public.st_v2_create_workspace('Entitlement current workspace');
  begin
    perform public.st_v2_create_workspace('Workspace beyond allowance');
    raise exception using errcode='XX000',message='Workspace cap failed';
  exception when raise_exception then
    if sqlerrm not like '%workspace limit%' then raise; end if;
  end;
  perform public.st_v2_invite(current_workspace,'entitlement_03');
  perform set_config('request.jwt.claim.sub',free_user::text,true);
  if (public.st_v7_my_entitlements()->>'plan') is distinct from 'free' then raise exception 'Incorrect free entitlement'; end if;
  begin
    perform public.st_v2_reply_invite((select id from public.st_v2_invites where workspace_id=current_workspace),true);
    raise exception using errcode='XX000',message='Seat cap failed';
  exception when raise_exception then
    if sqlerrm not like '%member limit%' then raise; end if;
  end;
  reset role;

  if not sectalk_private.st_v6_workspace_feature_entitled('integration_api',old_workspace)
    or sectalk_private.st_v6_workspace_feature_entitled('integration_api',current_workspace)
    or sectalk_private.st_v6_workspace_feature_entitled('task_creation',current_workspace)
    or sectalk_private.st_v6_workspace_feature_entitled('recurring_meetings',current_workspace)
    or (select max_file_bytes from sectalk_private.st_v6_attachment_entitlement(current_subscriber)) is distinct from 16384 then
    raise exception 'A policy consumer bypassed the purchased revision';
  end if;
  update public.st_v2_subscriptions set status='past_due',period_end=now()-interval '4 days' where user_id=grandfathered;
  if (sectalk_private.st_v7_account_entitlements(grandfathered)).plan is distinct from 'free'
    or sectalk_private.st_v6_workspace_feature_entitled('integration_api',old_workspace) then
    raise exception 'An expired purchased entitlement remained active';
  end if;
end $$;

select 'passed: atomic public offers, pinned paid terms, current access gates and immediate expiry fallback' as result;
rollback;
