begin;

do $$
declare
  operator_id uuid:=gen_random_uuid();
  account_id uuid:=gen_random_uuid();
  operator_factor uuid:=gen_random_uuid();
  operator_session uuid:=gen_random_uuid();
  target_session uuid:=gen_random_uuid();
  workspace_id uuid;
  webhook_id uuid:=gen_random_uuid();
  job_id uuid:=gen_random_uuid();
  webhook_lease uuid:=gen_random_uuid();
  rule_domain uuid;
  rule_hash uuid;
  rule_ip uuid;
  test_domain text:='qa-'||left(gen_random_uuid()::text,8)||'.example.invalid';
  test_hash text:=encode(sha256(convert_to(gen_random_uuid()::text,'UTF8')),'hex');
  case_reason text:='QA-405 synthetic abuse indicator';
begin
  insert into auth.users(id,email) values(operator_id,operator_id||'@example.invalid'),(account_id,account_id||'@example.invalid');
  insert into public.st_profiles(id,handle,name) values
    (operator_id,'qa_'||left(operator_id::text,8),'Global policy operator'),
    (account_id,'qa_'||left(account_id::text,8),'Global policy member');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values(operator_id,'business','active',now()+interval '1 day');
  insert into sectalk_private.st_v7_abuse_blocklist_operators values(operator_id);
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(operator_factor,operator_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id,ip) values
    (operator_session,operator_id,'aal2',operator_factor,'198.51.100.22'),
    (target_session,account_id,'aal1',null,'192.0.2.21');
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),operator_session,'totp',now(),now());
  if has_function_privilege('anon','public.st_v7_add_abuse_block(text,text,text,integer)','execute')
    or has_function_privilege('authenticated','public.st_v7_upload_digest_blocked(text)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v7_abuse_blocks','select')
    or has_function_privilege('service_role','sectalk_private.st_v7_publish_hashed_file(uuid,uuid,text,text)','execute')
    or has_function_privilege('service_role','sectalk_private.st_v6_workspace_file_command(uuid,uuid,text,uuid,text,integer,text)','execute')
  then raise exception 'PLT-04 rule data or original bypass RPCs were exposed'; end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',account_id,'role','authenticated',
    'session_id',target_session,'aal','aal1')::text,true);
  set local role authenticated;
  if public.st_v7_abuse_blocklist_access()<>'none' then raise exception 'Member obtained operator access'; end if;
  begin
    perform public.st_v7_add_abuse_block('domain',test_domain,case_reason,7);
    raise exception 'Member wrote a global indicator';
  exception when insufficient_privilege then null; end;
  reset role;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',operator_id,'role','authenticated',
    'session_id',operator_session,'aal','aal1')::text,true);
  set local role authenticated;
  if public.st_v7_abuse_blocklist_access()<>'mfa' then raise exception 'AAL1 obtained verified operator access'; end if;
  begin
    perform public.st_v7_abuse_blocks();
    raise exception 'An unverified operator read indicators';
  exception when insufficient_privilege then null; end;
  reset role;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',operator_id,'role','authenticated',
    'session_id',operator_session,'aal','aal2')::text,true);
  set local role authenticated;
  workspace_id:=public.st_v2_create_workspace('Abuse blocklist verification');
  reset role;

  insert into sectalk_private.st_v6_webhooks(id,workspace_id,owner,label,destination,wrapped_key,topics)
    values(webhook_id,workspace_id,operator_id,'Controlled domain test','https://svc.'||test_domain||'/receiver',
      repeat('A',80),array['room.created']);
  insert into sectalk_private.st_v6_webhook_jobs(id,endpoint_id,event_id,payload,lease,lease_expires)
    values(job_id,webhook_id,gen_random_uuid(),'{}',webhook_lease,now()+interval '2 minutes');
  if not public.st_v6_webhook_lease_active(job_id,webhook_lease)
    or not sectalk_private.st_v6_link_domain_allowed(workspace_id,'staff@svc.'||test_domain) then
    raise exception 'Known benign fixtures failed before an indicator existed';
  end if;

  set local role authenticated;
  rule_domain:=public.st_v7_add_abuse_block('domain',upper(test_domain)||'.',case_reason,7);
  rule_hash:=public.st_v7_add_abuse_block('sha256',upper(test_hash),case_reason,7);
  rule_ip:=public.st_v7_add_abuse_block('cidr','192.0.2.0/24',case_reason,7);
  perform public.st_v7_add_abuse_block('cidr','2001:db8:40::/48',case_reason,7);
  if (select count(*) from public.st_v7_abuse_blocks('cidr','active'))<2 then raise exception 'CIDR filters omitted active rules'; end if;
  begin
    perform public.st_v7_add_abuse_block('domain',test_domain,case_reason,7);
    raise exception 'Duplicate live rule inserted';
  exception when sqlstate 'PT409' then null; end;
  begin
    perform public.st_v7_add_abuse_block('cidr','198.51.100.0/24',case_reason,7);
    raise exception 'Operator could block the current session network';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_v7_add_abuse_block('cidr','0.0.0.0/0',case_reason,7);
    raise exception 'Unbounded IPv4 block accepted';
  exception when invalid_parameter_value then null; end;
  reset role;

  if public.st_v6_webhook_lease_active(job_id,webhook_lease)
    or sectalk_private.st_v6_link_domain_allowed(workspace_id,'staff@svc.'||test_domain)
    or not sectalk_private.st_v7_domain_blocked(test_domain)
    or sectalk_private.st_v7_domain_blocked('notsuffix-'||test_domain)
    or sectalk_private.st_v7_domain_blocked(test_domain||'.other.invalid') then
    raise exception 'Domain block did not cover webhook leases and invite domains with a DNS boundary';
  end if;
  begin
    insert into sectalk_private.st_v6_webhooks(id,workspace_id,owner,label,destination,wrapped_key,topics)
      values(gen_random_uuid(),workspace_id,operator_id,'Blocked','https://api.'||test_domain||'/',
        repeat('B',80),array['room.created']);
    raise exception 'A blocked webhook host was registered';
  exception when invalid_parameter_value then null; end;
  if not public.st_v7_upload_digest_blocked(test_hash) then raise exception 'Verified digest lookups ignored a rule'; end if;
  begin
    perform public.st_v7_publish_hashed_file(gen_random_uuid(),account_id,'',test_hash);
    raise exception 'Direct publication ignored a blocked digest';
  exception when sqlstate 'PT422' then null; end;
  begin
    perform public.st_v6_workspace_file_command(workspace_id,operator_id,'reserve',gen_random_uuid(),'qa.txt',10,test_hash);
    raise exception 'Workspace file reservation ignored a blocked digest';
  exception when sqlstate 'PT422' then null; end;
  begin
    update auth.sessions set refreshed_at=now() where id=target_session;
    raise exception 'A matched native session refreshed';
  exception when insufficient_privilege then null; end;
  begin
    insert into auth.sessions(id,user_id,ip) values(gen_random_uuid(),account_id,'::ffff:192.0.2.22');
    raise exception 'IPv4-mapped address bypassed the block';
  exception when insufficient_privilege then null; end;
  begin
    insert into auth.sessions(id,user_id,ip) values(gen_random_uuid(),account_id,'2001:db8:40::5');
    raise exception 'IPv6 address bypassed the block';
  exception when insufficient_privilege then null; end;
  insert into auth.sessions(id,user_id,ip) values(gen_random_uuid(),account_id,'198.51.100.24');

  update auth.mfa_amr_claims set updated_at=now()-interval '6 minutes' where session_id=operator_session;
  set local role authenticated;
  begin
    perform public.st_v7_revoke_abuse_block(rule_ip,'QA-406 stale operator factor');
    raise exception 'Expired TOTP released a rule';
  exception when insufficient_privilege then null; end;
  reset role;
  update auth.mfa_amr_claims set updated_at=now() where session_id=operator_session;
  set local role authenticated;
  if not public.st_v7_revoke_abuse_block(rule_ip,'QA-406 network remediation complete')
    or not public.st_v7_revoke_abuse_block(rule_domain,'QA-406 domain remediation complete')
    or not public.st_v7_revoke_abuse_block(rule_hash,'QA-406 content verification complete') then
    raise exception 'An operator could not release an active block';
  end if;
  if not exists(select 1 from public.st_v7_abuse_blocks('sha256','closed') r where r.id=rule_hash
    and r.revoked_by=operator_id and r.revocation_reason='QA-406 content verification complete') then
    raise exception 'Releasing the block lost audit history';
  end if;
  reset role;
  insert into auth.sessions(id,user_id,ip) values(gen_random_uuid(),account_id,'192.0.2.23');
  if not public.st_v6_webhook_lease_active(job_id,webhook_lease)
    or not sectalk_private.st_v6_link_domain_allowed(workspace_id,'staff@svc.'||test_domain)
    or public.st_v7_upload_digest_blocked(test_hash) then
    raise exception 'Released blocks remained effective';
  end if;
  update sectalk_private.st_v7_abuse_blocks set created_at=now()-interval '2 days',expires_at=now()-interval '1 day'
    where kind='cidr' and value='2001:db8:40::/48' and created_by=operator_id;
  insert into auth.sessions(id,user_id,ip) values(gen_random_uuid(),account_id,'2001:db8:40::5');
end $$;

select 'passed: provisioned fresh TOTP, deny rules, pre-existing webhook leases, CIDR auth, release, expiry and durable audit' as result;
rollback;
