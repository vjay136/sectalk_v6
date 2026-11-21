begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; w uuid; other_workspace uuid; request_id uuid:=gen_random_uuid(); case_id uuid; hold_id uuid:=gen_random_uuid();
  rejected_change uuid; settled_change uuid; pending_change uuid; leased_change uuid; command jsonb; original jsonb;
  copy jsonb; selected_plan jsonb; receipt jsonb; status jsonb; initial_billing integer; before_billing jsonb;
  fake_customer text:='cus_disposable_'||replace(gen_random_uuid()::text,'-','');
  fake_base text:='sub_disposable_'||replace(gen_random_uuid()::text,'-','');
  fake_price text:='price_disposable_exact'; original_lease uuid;
begin
  foreach actor in array array[owner_id,reviewer_id] loop
    session_id:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email,email_confirmed_at) values(actor,actor||'@example.invalid',now());
    insert into public.st_profiles(id,handle,name) values(actor,'batch_'||left(actor::text,8),'Disposable batch actor');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',session_id,'aal','aal2'));
  end loop;
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end,customer_id,subscription_id)
    values(owner_id,'enterprise','active',now()+interval '1 day',fake_customer,fake_base);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  other_workspace:=public.st_v2_create_workspace('Disposable seat reference control');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  w:=public.st_v2_create_workspace('Disposable rejected seat-change source');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(w,reviewer_id);
  set local role authenticated;
  perform public.st_v7_billing_admin_manage(w,reviewer_id,true);
  reset role;
  set local role service_role;
  command:=public.st_v8_workspace_seat_command(w,owner_id,'claim',jsonb_build_object('quantity',3,'intent','manual','price',fake_price));
  rejected_change:=(command->>'id')::uuid; original_lease:=(command->>'lease')::uuid;
  if public.st_v8_workspace_seat_command(w,owner_id,'finish',command||'{"result":"rejected"}'::jsonb) is distinct from 'true'::jsonb
    then raise exception 'Native rejected billing fixture did not finish'; end if;
  command:=public.st_v8_workspace_seat_command(w,owner_id,'claim',jsonb_build_object('quantity',4,'intent','manual','price',fake_price));
  leased_change:=(command->>'id')::uuid;
  if public.st_v8_workspace_seat_command(w,owner_id,'finish',command||'{"result":"rejected"}'::jsonb) is distinct from 'true'::jsonb
    then raise exception 'Native currently leased control failed'; end if;
  command:=public.st_v8_workspace_seat_command(w,owner_id,'claim',jsonb_build_object('quantity',4,'intent','manual','price',fake_price));
  settled_change:=(command->>'id')::uuid;
  if public.st_v8_workspace_seat_command(w,owner_id,'finish',command||jsonb_build_object('result','settled',
      'subscription',fake_base||'_seat','until',extract(epoch from now()+interval '1 day')::bigint)) is distinct from 'true'::jsonb
    then raise exception 'Native settled billing fixture did not finish'; end if;
  command:=public.st_v8_workspace_seat_command(w,owner_id,'claim',jsonb_build_object('quantity',5,'intent','manual','price',fake_price));
  pending_change:=(command->>'id')::uuid;
  before_billing:=public.st_v8_workspace_seat_command(w,owner_id,'status',null);
  if before_billing->>'quantity' is distinct from '4' or before_billing->>'pending' is distinct from '5'
    then raise exception 'Native allocation or pending jobs were not prepared'; end if;
  reset role;
  update sectalk_private.st_v8_workspace_seat_changes j set
    created_at=now()-interval '10 minutes',finished_at=now()-interval '9 minutes',lease_until=now()-interval '8 minutes'
    where j.id=rejected_change;
  select to_jsonb(j)-'lease_token' into strict original from sectalk_private.st_v8_workspace_seat_changes j where j.id=rejected_change;
  set local role authenticated;
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Review rejected seat change history.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  case_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(case_id,w,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  status:=public.st_v8_offboarding_rejected_seat_change_status(w);
  if jsonb_array_length(status->'changes')<>1 or status#>>'{changes,0,id}'<>rejected_change::text
    then raise exception 'Live lease, pending or settled control listed as eligible'; end if;
  begin
    perform public.st_v8_offboarding_rejected_seat_change(w,rejected_change,'capture',w::text);
    raise exception 'Captured a rejection before exact metadata copy';
  exception when sqlstate 'PT409' then null; end;
  copy:=public.st_v8_offboarding_rejected_seat_change(w,rejected_change,'copy',w::text);
  if copy->>'sha256' is distinct from encode(sha256(convert_to(copy->>'json','UTF8')),'hex')
    or (copy->>'json')::jsonb#>>'{change,id}' is distinct from rejected_change::text
    or (copy->>'json')::jsonb#>>'{change,outcome}' is distinct from 'rejected'
    or copy::text like '%'||fake_customer||'%' or copy::text like '%'||fake_price||'%' or copy::text like '%'||original_lease::text||'%'
    then raise exception 'The redacted copy omitted facts or exposed provider and lease identifiers'; end if;
  selected_plan:=public.st_v8_offboarding_rejected_seat_change(w,rejected_change,'capture',w::text);
  begin
    perform public.st_v8_offboarding_rejected_seat_change(w,rejected_change,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner retired the change without independent approval';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_rejected_seat_change(w,rejected_change,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  reset role;
  delete from sectalk_private.st_v7_billing_admins a where (a.workspace,a.account)=(w,reviewer_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_rejected_seat_change(w,rejected_change,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'A stale billing delegation remained valid after review';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into sectalk_private.st_v7_billing_admins(workspace,account,assigned_by) values(w,reviewer_id,owner_id);
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,w,owner_id,'Preserve the disposable seat billing history.',owner_id);
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_rejected_seat_change(w,rejected_change,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Retired seat change despite active preservation hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release the disposable evidence hold.' where h.id=hold_id;
  set local role authenticated;
  initial_billing:=(public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,categories,billing}')::integer;
  receipt:=public.st_v8_offboarding_rejected_seat_change(w,rejected_change,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  if receipt->>'deletedAt' is null or receipt is distinct from
    public.st_v8_offboarding_rejected_seat_change(w,rejected_change,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256')
    or (public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,categories,billing}')::integer<>initial_billing-1
    then raise exception 'Retirement receipt or billing root count did not match'; end if;
  reset role;
  set local role service_role;
  if public.st_v8_workspace_seat_command(w,owner_id,'status',null) is distinct from before_billing
    then raise exception 'Retirement modified the pending job, active subscription or seat allocation'; end if;
  reset role;
  begin
    insert into sectalk_private.st_v8_workspace_seat_changes(id,workspace,actor,customer,price,quantity,intent)
      values(rejected_change,other_workspace,reviewer_id,fake_customer,fake_price,1,'manual');
    raise exception 'The original seat change idempotency identifier was reused';
  exception when sqlstate 'PT409' then
    if sqlerrm<>'This seat change identifier is permanently retired' then raise; end if;
  end;
  if exists(select 1 from sectalk_private.st_v8_workspace_seat_changes j where j.id=rejected_change)
    or (select count(*) from sectalk_private.st_v8_workspace_seat_changes j where j.id in (pending_change,settled_change,leased_change))<>3
    or not exists(select 1 from sectalk_private.st_v8_offboarding_retired_rejected_seat_change c where
      (c.plan,c.change_id,c.custody,c.copy_sha256)=((selected_plan->>'plan')::uuid,rejected_change,original,copy->>'sha256'))
    then raise exception 'Private rejected evidence or other native source jobs are missing'; end if;
end $$;

select 'passed: exact rejected seat change custody, redacted copy, active allocation and sources retained, hold/billing delegation and job ID reuse denied';
rollback;