begin;

do $$
declare
  operator_id uuid:=gen_random_uuid();
  reviewer_id uuid:=gen_random_uuid();
  owner_id uuid:=gen_random_uuid();
  other_id uuid:=gen_random_uuid();
  actor_id uuid;
  operator_session uuid:=gen_random_uuid();
  reviewer_session uuid:=gen_random_uuid();
  owner_session uuid:=gen_random_uuid();
  sibling_session uuid:=gen_random_uuid();
  factor_id uuid;
  fixture_device uuid:=gen_random_uuid();
  sibling_id uuid:=gen_random_uuid();
  foreign_id uuid:=gen_random_uuid();
  result jsonb;
  operator_claim text;
begin
  foreach actor_id in array array[operator_id,reviewer_id,owner_id,other_id] loop
    insert into auth.users(id,email,email_confirmed_at,encrypted_password) values(actor_id,actor_id||'@example.invalid',now(),'fixture');
    insert into auth.identities(provider_id,user_id,identity_data,provider)
      values(actor_id::text,actor_id,jsonb_build_object('sub',actor_id),'email');
    insert into public.st_profiles(id,handle,name) values(actor_id,'adm03_'||left(actor_id::text,8),'Device operator fixture');
  end loop;
  foreach actor_id in array array[operator_id,reviewer_id] loop
    factor_id:=gen_random_uuid();
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor_id,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id)
      values(case when actor_id=operator_id then operator_session else reviewer_session end,actor_id,'aal2',factor_id);
  end loop;
  insert into auth.sessions(id,user_id,aal) values(owner_session,owner_id,'aal1'),(sibling_session,owner_id,'aal1');
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    select gen_random_uuid(),f.sid,f.method,now(),now()
    from (values(operator_session,'totp'),(reviewer_session,'totp'),(sibling_session,'password')) f(sid,method);
  insert into sectalk_private.st_v7_account_operators values(operator_id,'operator'),(reviewer_id,'reviewer');
  insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature)
    values(fixture_device,owner_id,'trusted',repeat('a',87),repeat('b',87),repeat('c',86)),
      (sibling_id,owner_id,'known',repeat('d',87),repeat('e',87),repeat('f',86)),
      (foreign_id,other_id,'known',repeat('g',87),repeat('h',87),repeat('i',86));
  insert into sectalk_private.st_v7_device_trust_audit(device_id,state,source) values(fixture_device,'trusted','owner');
  insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id)
    values(owner_session,owner_id,fixture_device),(sibling_session,owner_id,sibling_id);
  if has_function_privilege('anon','public.st_v7_operator_device_inventory(uuid)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v7_operator_device_audit','select')
    or has_function_privilege('authenticated','sectalk_private.st_v7_queue_device_command(uuid,uuid,text,uuid,text)','execute') then
    raise exception 'Private inventory or audit was exposed';
  end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',reviewer_id,'role','authenticated',
    'session_id',reviewer_session,'aal','aal2')::text,true);
  set local role authenticated;
  begin
    perform public.st_v7_operator_device_inventory(owner_id);
    raise exception 'An account reviewer read an operator-only inventory';
  exception when insufficient_privilege then null; end;
  reset role;
  operator_claim:=jsonb_build_object('sub',operator_id,'role','authenticated','session_id',operator_session,'aal','aal2')::text;
  perform set_config('request.jwt.claims',operator_claim,true);
  set local role authenticated;
  if (select count(*) from public.st_v7_operator_device_inventory(owner_id))<>2
    or exists(select 1 from public.st_v7_operator_device_inventory(owner_id) d where d.id=foreign_id) then
    raise exception 'Operator device inventory was not owner-scoped';
  end if;
  if public.st_v7_operator_device_action(owner_id,foreign_id,'wipe','ADM03 case wrong owner')
    or public.st_v7_operator_device_action(owner_id,sibling_id,'mark_managed','ADM03 case untrusted target') then
    raise exception 'Operator bypassed device ownership or established trust';
  end if;
  if not public.st_v7_operator_device_action(owner_id,fixture_device,'mark_managed','ADM03 case trusted device')
    then raise exception 'Operator could not flag an already trusted device'; end if;
  reset role;
  if not public.st_v7_mark_device_managed(owner_id,fixture_device,true,'Provider management proof') then
    raise exception 'Management provider could not take responsibility'; end if;
  set local role authenticated;
  if public.st_v7_operator_device_action(owner_id,fixture_device,'clear_managed','ADM03 case provider safeguard')
    then raise exception 'Operator cleared provider management'; end if;
  if not public.st_v7_operator_device_action(owner_id,fixture_device,'wipe','ADM03 case operator wipe')
    then raise exception 'An eligible operator could not request the wipe'; end if;
  reset role;
  if exists(select 1 from auth.sessions where id=owner_session)
    or not exists(select 1 from auth.sessions where id=sibling_session)
    or not exists(select 1 from sectalk_private.st_v7_account_admin_audit a where a.target=owner_id and a.request_id=owner_session
      and a.action='session_revoked') then raise exception 'Device-issued logout escaped its binding or missed audit'; end if;

  insert into sectalk_private.staff(user_id) values(owner_id);
  result:=public.st_v7_claim_device_command(owner_id,fixture_device,gen_random_uuid(),statement_timestamp());
  if result->'command'<>'null'::jsonb or (result->>'wiped')::boolean or (result->>'locked')::boolean
    or not exists(select 1 from sectalk_private.st_v7_device_commands c where c.device_id=fixture_device and c.state='cancelled') then
    raise exception 'An undelivered operator wipe survived a protected role change';
  end if;
  set local role authenticated;
  begin
    perform public.st_v7_operator_device_inventory(owner_id);
    raise exception 'An operator read a protected staff inventory';
  exception when insufficient_privilege then null; end;
  reset role;
  delete from sectalk_private.staff where user_id=owner_id;
  set local role authenticated;
  if not public.st_v7_operator_device_action(owner_id,sibling_id,'block_device','ADM03 case permanent block') then
    raise exception 'Operator could not block an existing registered device';
  end if;
  reset role;
  if exists(select 1 from auth.sessions where id=sibling_session)
    or not exists(select 1 from sectalk_private.st_v7_devices d where d.id=sibling_id and d.state='blocked' and d.wiped_at is null)
    or public.st_v7_mark_device_managed(owner_id,sibling_id,true,'Provider cannot restore blocked identity') then
    raise exception 'Permanent device block failed to isolate keys and cease access';
  end if;
  update auth.mfa_amr_claims set updated_at=now()-interval '6 minutes' where session_id=operator_session;
  set local role authenticated;
  begin
    perform public.st_v7_operator_device_action(owner_id,sibling_id,'wipe','ADM03 case stale verification');
    raise exception 'An expired TOTP authorized a device command';
  exception when insufficient_privilege then null; end;
  reset role;
  if (select count(*) from sectalk_private.st_v7_operator_device_audit a where a.owner=owner_id and a.device=fixture_device)<>2
    then raise exception 'Operator actions lost durable audit'; end if;
end $$;

select 'passed: scoped inventory, trust/provider precedence, native revocation, permanent block, pending wipe protection and fresh TOTP' as result;
rollback;
