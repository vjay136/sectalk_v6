begin;
insert into auth.users(id,email,email_confirmed_at) values
  ('aa231300-0000-4000-8000-000000000001','siem-owner@example.invalid',now()),
  ('aa231300-0000-4000-8000-000000000002','siem-other@example.invalid',now());
insert into public.st_profiles(id,handle,name) values
  ('aa231300-0000-4000-8000-000000000001','siem_qa_owner','SIEM owner'),
  ('aa231300-0000-4000-8000-000000000002','siem_qa_other','SIEM other');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
 ('aa231300-0000-4000-8000-000000000011','aa231300-0000-4000-8000-000000000001','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
 ('aa231300-0000-4000-8000-000000000021','aa231300-0000-4000-8000-000000000001','aal2','aa231300-0000-4000-8000-000000000011');
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
 ('aa231300-0000-4000-8000-000000000031','aa231300-0000-4000-8000-000000000021','totp',now(),now());
select public.st_v2_sync_billing('evt_siem_fixture','aa231300-0000-4000-8000-000000000001','cus_siem_fixture',
  'sub_siem_fixture','enterprise','active',now()+interval '1 day',false,now());
insert into public.st_v2_workspaces(id,name,owner) values
  ('aa231300-0000-4000-8000-000000000041','Synthetic SIEM workspace','aa231300-0000-4000-8000-000000000001'),
  ('aa231300-0000-4000-8000-000000000042','Other SIEM workspace','aa231300-0000-4000-8000-000000000002');
insert into public.st_v2_members(workspace_id,user_id,role) values
  ('aa231300-0000-4000-8000-000000000041','aa231300-0000-4000-8000-000000000001','owner'),
  ('aa231300-0000-4000-8000-000000000042','aa231300-0000-4000-8000-000000000002','owner');
insert into public.st_v2_workspace_audit(workspace_id,actor,event,target,created_at)
select workspace,actor,event,actor,date_trunc('hour',now(),'UTC')-interval '30 mins' from (values
  ('aa231300-0000-4000-8000-000000000041'::uuid,'aa231300-0000-4000-8000-000000000001'::uuid,'member.suspend'),
  ('aa231300-0000-4000-8000-000000000041','aa231300-0000-4000-8000-000000000001','private_ignored_event'),
  ('aa231300-0000-4000-8000-000000000042','aa231300-0000-4000-8000-000000000002','member.admin')) e(workspace,actor,event);

do $$
declare
  workspace constant uuid:='aa231300-0000-4000-8000-000000000041';
  other_workspace constant uuid:='aa231300-0000-4000-8000-000000000042';
  actor constant uuid:='aa231300-0000-4000-8000-000000000001';
  actor_session constant uuid:='aa231300-0000-4000-8000-000000000021';
  period constant timestamptz:=date_trunc('hour',now(),'UTC')-interval '1 hour';
  batch_id uuid;
  payload jsonb;
  lease1 uuid;
  lease2 uuid;
begin
  perform set_config('request.jwt.claims',jsonb_build_object('sub',actor,'role','authenticated','session_id',actor_session,'aal','aal2')::text,true);
  set local role authenticated;
  begin
    perform public.st_v7_siem_batch(other_workspace,period,'download');
    raise exception 'Cross-tenant export succeeded';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_siem_claim(workspace,'webhook');
    raise exception 'User could claim SIEM delivery';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_siem_batch(workspace,period+interval '1 hour','download');
    raise exception 'Open hour was accepted';
  exception when invalid_parameter_value then null; end;
  batch_id:=public.st_v7_siem_batch(workspace,period,'webhook');
  if public.st_v7_siem_batch(workspace,period,'webhook')<>batch_id then raise exception 'Batch dedupe failed'; end if;
  payload:=public.st_v7_siem_batch_read(workspace,batch_id);
  if payload->'counts'<>'{"member_suspended":1}' or payload ? 'actor' or payload ? 'target'
    or payload::text like '%private_ignored_event%' then raise exception 'Unexpected export payload %',payload; end if;
  reset role;
  update auth.mfa_amr_claims set updated_at=now()-interval '15 mins' where auth.mfa_amr_claims.session_id=actor_session;
  set local role authenticated;
  begin
    perform public.st_v7_siem_batch_read(workspace,batch_id);
    raise exception 'Stale MFA read succeeded';
  exception when insufficient_privilege then null; end;
  reset role;
  set local role service_role;
  lease1:=(public.st_v7_siem_claim(workspace,'webhook')->>'lease')::uuid;
  if lease1 is null or public.st_v7_siem_claim(workspace,'webhook') is not null then raise exception 'Lease not exclusive'; end if;
  if not public.st_v7_siem_finish(batch_id,'webhook',lease1,'retry') then raise exception 'Retry was not saved'; end if;
  if public.st_v7_siem_claim(workspace,'webhook') is not null then raise exception 'Backoff absent'; end if;
  reset role;
  update sectalk_private.st_v7_siem_deliveries set ready_at=now()-interval '1 sec' where sectalk_private.st_v7_siem_deliveries.batch=batch_id;
  set local role service_role;
  lease2:=(public.st_v7_siem_claim(workspace,'webhook')->>'lease')::uuid;
  if lease2 is null or lease2=lease1 or public.st_v7_siem_finish(batch_id,'webhook',lease1,'sent')
    or not public.st_v7_siem_finish(batch_id,'webhook',lease2,'sent')
    or public.st_v7_siem_claim(workspace,'webhook') is not null then raise exception 'Lease replay discharged'; end if;
  reset role;
end $$;
rollback;
