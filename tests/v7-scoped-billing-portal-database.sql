begin;
insert into auth.users(id,email,email_confirmed_at) values
 ('b1130000-0000-4000-8000-000000000001','portal-proof-owner@example.invalid',now()),
 ('b1130000-0000-4000-8000-000000000002','portal-proof-none@example.invalid',now());
insert into public.st_profiles(id,handle,name) values
 ('b1130000-0000-4000-8000-000000000001','portal_proof_owner','Portal owner'),
 ('b1130000-0000-4000-8000-000000000002','portal_proof_none','Unlinked user');
insert into auth.sessions(id,user_id,aal) values
 ('b1130000-0000-4000-8000-000000000011','b1130000-0000-4000-8000-000000000001','aal1'),
 ('b1130000-0000-4000-8000-000000000012','b1130000-0000-4000-8000-000000000002','aal1');
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
 ('b1130000-0000-4000-8000-000000000021','b1130000-0000-4000-8000-000000000011','password',now(),now()-interval '10 minutes'),
 ('b1130000-0000-4000-8000-000000000022','b1130000-0000-4000-8000-000000000012','password',now(),now());
select public.st_v2_sync_billing('evt_fixture_safe_portal','b1130000-0000-4000-8000-000000000001','cus_ProofPortal',
 'sub_ProofPortal','business','active',now()+interval '30 days',false,now());

do $$
declare owner_id constant uuid:='b1130000-0000-4000-8000-000000000001';
  other_id constant uuid:='b1130000-0000-4000-8000-000000000002';
  owner_claims constant text:=jsonb_build_object('sub',owner_id,'role','authenticated','aal','aal1',
    'session_id','b1130000-0000-4000-8000-000000000011')::text;
  other_claims constant text:=jsonb_build_object('sub',other_id,'role','authenticated','aal','aal1',
    'session_id','b1130000-0000-4000-8000-000000000012')::text;
begin
  perform set_config('request.jwt.claims',owner_claims,true);
  set local role authenticated;
  begin
    perform public.st_v7_billing_portal_scope('overview');
    raise exception 'Stale proof unexpectedly established an account billing scope';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_billing_portal_record(owner_id,'cus_ProofPortal','sub_ProofPortal','overview');
    raise exception 'Authenticated caller inserted an issuance audit';
  exception when insufficient_privilege then null; end;
  reset role;
  update auth.mfa_amr_claims set updated_at=now() where id='b1130000-0000-4000-8000-000000000021';
  set local role authenticated;
  if public.st_v7_billing_portal_scope('payment_method') is distinct from '{"customer":"cus_ProofPortal","subscription":"sub_ProofPortal"}'::jsonb then
    raise exception 'Current owner scope unavailable'; end if;
  perform set_config('request.jwt.claims',other_claims,true);
  if public.st_v7_billing_portal_scope('overview') is not null then raise exception 'Unlinked owner inherited billing scope'; end if;
  reset role;
  set local role service_role;
  if public.st_v7_billing_portal_record(owner_id,'cus_Foreign','sub_ProofPortal','overview')
    or public.st_v7_billing_portal_record(other_id,'cus_ProofPortal','sub_ProofPortal','overview')
    or not public.st_v7_billing_portal_record(owner_id,'cus_ProofPortal','sub_ProofPortal','reactivate') then
    raise exception 'Portal scope or audit authorization failed'; end if;
  reset role;
  if (select count(*) from sectalk_private.st_v7_billing_portal_audit a where a.account=owner_id and purpose='reactivate')<>1 then
    raise exception 'Successful issuance was not audited'; end if;
end $$;
rollback;
