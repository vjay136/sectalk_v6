begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; w uuid; request_id uuid:=gen_random_uuid(); case_id uuid; hold_id uuid:=gen_random_uuid();
  withdrawn_quote uuid:=gen_random_uuid(); accepted_quote uuid:=gen_random_uuid(); open_quote uuid:=gen_random_uuid(); item uuid;
  copy jsonb; selected_plan jsonb; receipt jsonb; status jsonb; initial_restrict integer;
  today date:=(now() at time zone 'UTC')::date;
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
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values(owner_id,'enterprise','active',now()+interval '1 day');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  w:=public.st_v2_create_workspace('Disposable withdrawn quote custody source');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(w,reviewer_id);
  insert into sectalk_private.st_v8_enterprise_billing_operators values(w,reviewer_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  foreach item in array array[withdrawn_quote,accepted_quote,open_quote] loop
    perform public.st_v8_enterprise_billing_command(w,item,'quote',jsonb_build_object(
      'reference','Disposable reference '||left(item::text,8),'currency','USD','seats',3,'total',1000,
      'starts',today+1,'expires',today,'terms','Synthetic approved quote terms are preserved.'));
  end loop;
  perform public.st_v8_enterprise_billing_command(w,withdrawn_quote,'withdraw',
    jsonb_build_object('reason','Synthetic quote withdrawn before purchase acceptance.'));
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_enterprise_billing_command(w,accepted_quote,'accept',jsonb_build_object('po','Synthetic accepted purchase order'));
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Review exact retained commercial evidence.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  case_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(case_id,w,owner_id,'downloaded');
  begin
    update sectalk_private.st_v8_enterprise_orders o set live_workspace=null where o.id=withdrawn_quote;
    raise exception 'Native foreign-key link detached without approved custody';
  exception when sqlstate 'PT409' then null; end;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  initial_restrict:=(public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,deleteActions,restrict}')::integer;
  if initial_restrict<>3 then raise exception 'Original quote and active order references ceased protecting the workspace'; end if;
  status:=public.st_v8_offboarding_withdrawn_quote_status(w);
  if jsonb_array_length(status->'orders')<>1 or status#>>'{orders,0,id}'<>withdrawn_quote::text then
    raise exception 'Accepted or open commercial records were listed for disposition'; end if;
  begin
    perform public.st_v8_offboarding_withdrawn_quote(w,withdrawn_quote,'capture',w::text);
    raise exception 'Captured before exact copy';
  exception when sqlstate 'PT409' then null; end;
  copy:=public.st_v8_offboarding_withdrawn_quote(w,withdrawn_quote,'copy',w::text);
  if copy->>'sha256' is distinct from encode(sha256(convert_to(copy->>'json','UTF8')),'hex')
    or (copy->>'json')::jsonb#>>'{order,id}' is distinct from withdrawn_quote::text
    or (copy->>'json')::jsonb#>>'{order,state}' is distinct from 'withdrawn'
    or (copy->>'json')::jsonb#>>'{billingEvents,0,action}' is distinct from 'quote'
    or (copy->>'json')::jsonb#>>'{billingEvents,1,action}' is distinct from 'withdraw'
    then raise exception 'Copy did not match exact withdrawn quote and immutable event history'; end if;
  selected_plan:=public.st_v8_offboarding_withdrawn_quote(w,withdrawn_quote,'capture',w::text);
  begin
    perform public.st_v8_offboarding_withdrawn_quote(w,withdrawn_quote,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner self approved the quote';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_offboarding_withdrawn_quote(w,withdrawn_quote,'detach',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Detached before independent approval';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  status:=public.st_v8_offboarding_withdrawn_quote_status(w);
  if jsonb_array_length(status->'orders')<>0 or not exists(select 1 from jsonb_array_elements(status->'plans') q
    where q->>'plan'=selected_plan->>'plan' and q->>'order'=withdrawn_quote::text and q->>'copySha256'=copy->>'sha256') then
    raise exception 'Wrong reviewer visibility or copy identity'; end if;
  reset role;
  delete from sectalk_private.st_v8_enterprise_billing_operators x where (x.workspace,x.actor)=(w,reviewer_id);
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_withdrawn_quote(w,withdrawn_quote,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Revoked commercial reviewer approved retained billing evidence';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into sectalk_private.st_v8_enterprise_billing_operators values(w,reviewer_id);
  set local role authenticated;
  perform public.st_v8_offboarding_withdrawn_quote(w,withdrawn_quote,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  reset role;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,w,owner_id,'Keep disposable commercial evidence during a hold.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_withdrawn_quote(w,withdrawn_quote,'detach',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Detached quote under active preservation hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release disposable commercial evidence hold.' where h.id=hold_id;
  set local role authenticated;
  receipt:=public.st_v8_offboarding_withdrawn_quote(w,withdrawn_quote,'detach',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  if receipt->>'detachedAt' is null or receipt is distinct from
    public.st_v8_offboarding_withdrawn_quote(w,withdrawn_quote,'detach',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256')
    or (public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,deleteActions,restrict}')::integer<>initial_restrict-1
    then raise exception 'No exact retained custody or restrictive root reference was reduced'; end if;
  status:=public.st_v8_enterprise_billing_view(w);
  if not exists(select 1 from jsonb_array_elements(status->'orders') q where q->>'id'=withdrawn_quote::text
    and q->>'state'='withdrawn' and not (q ? 'live_workspace'))
    then raise exception 'Existing authorized billing view lost the native historical quote or exposed an internal link'; end if;
  reset role;
  begin
    update sectalk_private.st_v8_enterprise_orders o set terms='A synthetic unauthorized change' where o.id=withdrawn_quote;
    raise exception 'Edited original retained terms';
  exception when sqlstate 'PT409' then null; end;
  begin
    insert into sectalk_private.st_v8_enterprise_order_events(order_id,workspace,actor,action)
      values(withdrawn_quote,w,reviewer_id,'quote');
    raise exception 'Appended a new commercial event after custody';
  exception when sqlstate 'PT409' then null; end;
  if not exists(select 1 from sectalk_private.st_v8_enterprise_orders o where (o.id,o.workspace)=(withdrawn_quote,w)
      and o.live_workspace is null and o.terms='Synthetic approved quote terms are preserved.')
    or (select count(*) from sectalk_private.st_v8_enterprise_order_events e where (e.order_id,e.workspace)=(withdrawn_quote,w))<>2
    or (select count(*) from sectalk_private.st_v8_enterprise_orders o where o.live_workspace=w and o.id in (accepted_quote,open_quote))<>2
    or not exists(select 1 from sectalk_private.st_v8_offboarding_retired_withdrawn_quote q where
      (q.plan,q.order_id,q.custody,q.sha256)=((selected_plan->>'plan')::uuid,withdrawn_quote,(copy->>'json')::jsonb,copy->>'sha256'))
    then raise exception 'Native order, events, or protected attached contracts were altered'; end if;
  update public.st_v2_workspaces x set created_at=created_at+interval '1 second' where x.id=w;
  set local role authenticated;
  status:=public.st_v8_enterprise_billing_view(w);
  if exists(select 1 from jsonb_array_elements(status->'orders') q where q->>'id'=withdrawn_quote::text)
    then raise exception 'Historical retained quote was shown to a different workspace generation'; end if;
  reset role;
end $$;

select 'passed: exact withdrawn quote detachment, native events retained, open/accepted constraints, revoked reviewer, holds, immutable custody and generation isolation';
rollback;