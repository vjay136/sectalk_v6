begin;

insert into auth.users(id,email) values
 ('63aff930-fd67-4d15-9900-000000000001','trial-team@example.invalid'),
 ('63aff930-fd67-4d15-9900-000000000002','trial-pro@example.invalid'),
 ('63aff930-fd67-4d15-9900-000000000003','trial-other@example.invalid');
insert into public.st_profiles(id,handle,name)
  select id,'trial_'||right(id::text,2),'Trial fixture' from auth.users where id::text like '63aff930-fd67-4d15-9900-%';

do $$
declare owner_team uuid:='63aff930-fd67-4d15-9900-000000000001';
declare owner_pro uuid:='63aff930-fd67-4d15-9900-000000000002';
declare outsider uuid:='63aff930-fd67-4d15-9900-000000000003';
declare team_workspace uuid;
declare pro_workspace uuid;
declare team_session uuid:=gen_random_uuid();
declare pro_session uuid:=gen_random_uuid();
declare pending jsonb;
declare active jsonb;
declare reservation uuid;
begin
  insert into auth.sessions(id,user_id,aal) values(team_session,owner_team,'aal1'),(pro_session,owner_pro,'aal1');
  set local role authenticated;
  perform set_config('request.jwt.claim.sub',owner_team::text,true);
  team_workspace:=public.st_v2_create_workspace('Trial Team workspace');
  perform set_config('request.jwt.claim.sub',owner_pro::text,true);
  pro_workspace:=public.st_v2_create_workspace('Trial Pro workspace');
  if public.st_v7_workspace_trial_status(pro_workspace)->>'state' is distinct from 'eligible' then
    raise exception 'New workspace should be eligible';
  end if;
  begin
    perform public.st_v7_workspace_trial_status(team_workspace);
    raise exception 'Foreign trial details exposed';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_start_workspace_trial_for_session(pro_workspace,owner_pro,pro_session,'professional',false);
    raise exception 'Untrusted start RPC succeeded';
  exception when insufficient_privilege then null; end;
  reset role;

  set local role service_role;
  begin
    perform public.st_v8_start_workspace_trial_for_session(pro_workspace,outsider,pro_session,'professional',false);
    raise exception 'Foreign trusted actor bypassed owner gate';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_start_workspace_trial_for_session(pro_workspace,owner_pro,team_session,'professional',false);
    raise exception 'A session from another owner authorized the trial';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_start_workspace_trial(pro_workspace,owner_pro,'professional',false);
    raise exception 'The legacy service endpoint bypassed the session gate';
  exception when insufficient_privilege then null; end;
  active:=public.st_v8_start_workspace_trial_for_session(team_workspace,owner_team,team_session,'business',false);
  if active->>'state' is distinct from 'active' or (active->>'expires_at')::timestamptz is distinct from now()+interval '336 hours'
    or public.st_v8_start_workspace_trial_for_session(team_workspace,owner_team,team_session,'business',false) is distinct from active then
    raise exception 'No-card trial did not start for 14 days and safely replay';
  end if;
  begin
    perform public.st_v8_start_workspace_trial_for_session(team_workspace,owner_team,team_session,'professional',false);
    raise exception 'A second trial was granted';
  exception when sqlstate 'PT409' then null; end;

  pending:=public.st_v8_start_workspace_trial_for_session(pro_workspace,owner_pro,pro_session,'professional',true);
  reservation:=(pending->>'reservation')::uuid;
  if reservation is null or pending->>'state' is distinct from 'pending'
    or public.st_v8_start_workspace_trial_for_session(pro_workspace,owner_pro,pro_session,'professional',true)->>'reservation' is distinct from reservation::text then
    raise exception 'Card-required trial did not reserve a stable checkout';
  end if;
  reset role;
  if (sectalk_private.st_v7_workspace_entitlements(pro_workspace)).plan is distinct from 'free'
    or (sectalk_private.st_v7_workspace_entitlements(team_workspace)).seat_limit is distinct from 100
    or (sectalk_private.st_v7_account_entitlements(owner_team)).plan is distinct from 'free'
    or not sectalk_private.st_v6_workspace_feature_entitled('integration_api',team_workspace) then
    raise exception 'Trial entitlement activated early or escaped its workspace';
  end if;
  set local role service_role;
  if not public.st_v7_attach_trial_checkout(reservation,'cs_test_fixture123')
    or public.st_v7_attach_trial_checkout(reservation,'cs_test_wrong123')
    or public.st_v7_complete_trial_checkout(reservation,'cs_test_wrong123',now())
    or public.st_v7_complete_trial_checkout(reservation,'cs_test_fixture123',now()-interval '1 day')
    or not public.st_v7_complete_trial_checkout(reservation,'cs_test_fixture123',now())
    or not public.st_v7_complete_trial_checkout(reservation,'cs_test_fixture123',now()) then
    raise exception 'Trusted checkout binding, timestamp, or idempotence failed';
  end if;
  reset role;
  if (sectalk_private.st_v7_workspace_entitlements(pro_workspace)).plan is distinct from 'professional'
    or (select count(*) from public.st_v2_workspace_audit where event='billing.trial_started' and workspace_id in(team_workspace,pro_workspace))<>2 then
    raise exception 'Completed card verification did not produce a single activation';
  end if;
  update sectalk_private.st_v7_workspace_trials set started_at=now()-interval '337 hours',expires_at=now()-interval '1 hour'
    where workspace_id=team_workspace;
  if (sectalk_private.st_v7_workspace_entitlements(team_workspace)).plan is distinct from 'free' then
    raise exception 'Trial did not expire automatically';
  end if;
  set local role authenticated;
  perform set_config('request.jwt.claim.sub',owner_team::text,true);
  if public.st_v7_workspace_trial_status(team_workspace)->>'state' is distinct from 'used' then
    raise exception 'Used trial history was lost';
  end if;
  reset role;
  set local role service_role;
  begin
    perform public.st_v8_start_workspace_trial_for_session(team_workspace,owner_team,team_session,'business',false);
    raise exception 'Expired trial was granted a second time';
  exception when sqlstate 'PT409' then null; end;
end $$;

select 'passed: isolated no-card and verified-card trial activation, one trial, repeat safety and exact expiry' as result;
rollback;
