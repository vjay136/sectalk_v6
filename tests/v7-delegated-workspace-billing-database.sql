begin;
insert into auth.users(id,email,email_confirmed_at) values
 ('ad120000-0000-4000-8000-000000000001','billing-grant-owner@example.invalid',now()),
 ('ad120000-0000-4000-8000-000000000002','billing-grant-admin@example.invalid',now()),
 ('ad120000-0000-4000-8000-000000000003','billing-grant-other@example.invalid',now());
insert into public.st_profiles(id,handle,name) values
 ('ad120000-0000-4000-8000-000000000001','billing_grant_owner','Grant owner'),
 ('ad120000-0000-4000-8000-000000000002','billing_grant_admin','Grant admin'),
 ('ad120000-0000-4000-8000-000000000003','billing_grant_other','Grant other');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
 ('ad120000-0000-4000-8000-000000000031','ad120000-0000-4000-8000-000000000001','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
 ('ad120000-0000-4000-8000-000000000021','ad120000-0000-4000-8000-000000000001','aal2','ad120000-0000-4000-8000-000000000031'),
 ('ad120000-0000-4000-8000-000000000022','ad120000-0000-4000-8000-000000000002','aal1',null);
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
 ('ad120000-0000-4000-8000-000000000041','ad120000-0000-4000-8000-000000000021','totp',now(),now()-interval '10 minutes');
insert into public.st_v2_workspaces(id,name,owner) values
 ('ad120000-0000-4000-8000-000000000011','Billing trial','ad120000-0000-4000-8000-000000000001'),
 ('ad120000-0000-4000-8000-000000000012','Other company','ad120000-0000-4000-8000-000000000003');
insert into public.st_v2_members(workspace_id,user_id,role) values
 ('ad120000-0000-4000-8000-000000000011','ad120000-0000-4000-8000-000000000001','owner'),
 ('ad120000-0000-4000-8000-000000000011','ad120000-0000-4000-8000-000000000002','admin'),
 ('ad120000-0000-4000-8000-000000000012','ad120000-0000-4000-8000-000000000003','owner');
insert into sectalk_private.st_v7_workspace_trials(workspace_id,requested_by,plan,version,started_at,expires_at)
select 'ad120000-0000-4000-8000-000000000011','ad120000-0000-4000-8000-000000000001',e.plan,e.version,
  now(),now()+interval '336 hours'
from sectalk_private.st_v7_plan_entitlements e where e.plan='professional' order by e.version limit 1;

do $$
declare
  owner_id constant uuid:='ad120000-0000-4000-8000-000000000001';
  delegate constant uuid:='ad120000-0000-4000-8000-000000000002';
  tenant constant uuid:='ad120000-0000-4000-8000-000000000011';
  foreign_tenant constant uuid:='ad120000-0000-4000-8000-000000000012';
  proof constant text:=jsonb_build_object('sub',owner_id,'role','authenticated','aal','aal2',
    'session_id','ad120000-0000-4000-8000-000000000021')::text;
  ordinary constant text:=jsonb_build_object('sub',delegate,'role','authenticated','aal','aal1',
    'session_id','ad120000-0000-4000-8000-000000000022')::text;
  summary jsonb;
begin
  perform set_config('request.jwt.claims',ordinary,true);
  set local role authenticated;
  if public.st_v7_billing_admin_view()<>'[]' then raise exception 'Ordinary workspace admin listed billing'; end if;
  begin
    perform public.st_v7_billing_admin_manage(tenant,delegate,true);
    raise exception 'Ordinary workspace admin granted access';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_billing_admin_provider_scope(tenant,delegate);
    raise exception 'Account can obtain raw provider scope';
  exception when insufficient_privilege then null; end;
  reset role;
  perform set_config('request.jwt.claims',proof,true);
  set local role authenticated;
  if public.st_v7_billing_admin_manage(tenant,delegate,true)->>'access'<>'mfa' then
    raise exception 'Stale TOTP granted billing access'; end if;
  begin
    perform public.st_v7_billing_admin_view(tenant);
    raise exception 'Owner obtained delegated billing data without a grant';
  exception when insufficient_privilege then null; end;
  reset role;
  update auth.mfa_amr_claims set updated_at=now() where id='ad120000-0000-4000-8000-000000000041';
  set local role authenticated;
  if public.st_v7_billing_admin_manage(tenant,delegate,true)->>'access'<>'verified' then
    raise exception 'Verified owner grant failed'; end if;
  begin
    perform public.st_v7_billing_admin_manage(tenant,owner_id,true);
    raise exception 'Owner could self-assign';
  exception when invalid_parameter_value then null; end;
  perform set_config('request.jwt.claims',ordinary,true);
  summary:=public.st_v7_billing_admin_view(tenant);
  if summary->>'plan'<>'professional' or summary->>'seat_limit'<>'30' or summary->>'seats'<>'2' then
    raise exception 'Trial plan or seat selection incorrect: %',summary; end if;
  begin
    perform public.st_v7_billing_admin_view(foreign_tenant);
    raise exception 'Foreign billing allowed';
  exception when insufficient_privilege then null; end;
  reset role;
  update public.st_v2_members set suspended_at=now() where workspace_id=tenant and user_id=delegate;
  set local role authenticated;
  begin
    perform public.st_v7_billing_admin_view(tenant);
    raise exception 'Suspended billing administrator retained access';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',proof,true);
  perform public.st_v7_billing_admin_manage(tenant,delegate,false);
  reset role;
  if exists(select 1 from sectalk_private.st_v7_billing_admins where workspace=tenant)
    or (select count(*) from public.st_v2_workspace_audit where workspace_id=tenant
       and event in ('billing.access_granted','billing.access_revoked'))<>2 then
    raise exception 'Billing assignment or audit did not settle atomically'; end if;
end $$;
rollback;
