begin;

do $$
declare
  owner_id uuid:=gen_random_uuid();
  outsider uuid:=gen_random_uuid();
  owner_session uuid:=gen_random_uuid();
  other_session uuid:=gen_random_uuid();
  owner_device uuid:=gen_random_uuid();
  workspace uuid:=gen_random_uuid();
  foreign_workspace uuid:=gen_random_uuid();
  identifier text:=encode(extensions.gen_random_bytes(32),'hex');
  owner_bucket bytea;
  device_bucket bytea;
  tenant_bucket bytea;
  tenant_balance numeric;
  ip_bucket bytea;
begin
  insert into auth.users(id,email) select id,id||'@example.invalid' from unnest(array[owner_id,outsider]) id;
  insert into public.st_profiles(id,handle,name) select id,'ratelimit_'||left(id::text,8),'Rate fixture'
    from unnest(array[owner_id,outsider]) id;
  insert into public.st_v2_workspaces(id,name,owner) values(workspace,'Rate limit QA',owner_id);
  insert into public.st_v2_workspaces(id,name,owner) values(foreign_workspace,'Separate rate limit QA',outsider);
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,owner_id,'owner');
  insert into public.st_v2_members(workspace_id,user_id,role) values(foreign_workspace,outsider,'owner');
  insert into auth.sessions(id,user_id,aal,created_at,ip) values
    (owner_session,owner_id,'aal1',now(),'192.0.2.71'),(other_session,outsider,'aal1',now(),'198.51.100.5');
  insert into sectalk_private.st_v7_devices(id,owner,signing_key,agreement_key,bundle_signature)
    values(owner_device,owner_id,repeat('A',87),repeat('B',87),repeat('C',86));
  insert into sectalk_private.st_v7_device_sessions values(owner_session,owner_id,owner_device);
  owner_bucket:=sectalk_private.st_v7_rate_bucket('account',owner_id::text);
  device_bucket:=sectalk_private.st_v7_rate_bucket('device',owner_device::text);
  tenant_bucket:=sectalk_private.st_v7_rate_bucket('tenant',workspace::text);
  ip_bucket:=sectalk_private.st_v7_rate_bucket('network',sectalk_private.st_v7_login_network('192.0.2.71')::text);
  if has_table_privilege('authenticated','sectalk_private.st_v7_rate_buckets','select')
    or has_function_privilege('authenticated','public.st_v7_admit_password_request(text,inet)','execute')
    or has_function_privilege('anon','public.st_v7_admit_file_request(text,text,uuid)','execute') then
    raise exception 'Rate identities or counters escaped their ACL'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'role','authenticated',
    'session_id',owner_session,'aal','aal1')::text,true);
  set local role authenticated;
  if public.st_v7_admit_file_request('file_write','workspace',workspace)<>0 then raise exception 'First request denied'; end if;
  reset role;
  if (select count(*) from sectalk_private.st_v7_rate_buckets
    where action='file_write' and bucket in (owner_bucket,device_bucket,tenant_bucket,ip_bucket))<>4 then
    raise exception 'A native quota dimension was missed'; end if;
  select b.tokens into tenant_balance from sectalk_private.st_v7_rate_buckets b
    where b.bucket=tenant_bucket and b.action='file_write';
  perform set_config('request.jwt.claims',jsonb_build_object('sub',outsider,'role','authenticated',
    'session_id',other_session,'aal','aal1')::text,true);
  set local role authenticated;
  if public.st_v7_admit_file_request('file_write','workspace',workspace)<>0 then raise exception 'Foreign preflight denied unexpectedly'; end if;
  if public.st_v7_admit_file_request('file_write','workspace',foreign_workspace)<>0 then
    raise exception 'Own tenant did not retain its separate budget'; end if;
  reset role;
  if (select b.tokens from sectalk_private.st_v7_rate_buckets b where b.bucket=tenant_bucket and b.action='file_write')<>tenant_balance then
    raise exception 'Foreign actor charged a tenant budget'; end if;
  if not exists(select 1 from sectalk_private.st_v7_rate_buckets b where b.action='file_write' and b.dimension='tenant'
    and b.bucket=sectalk_private.st_v7_rate_bucket('tenant',foreign_workspace::text)) then
    raise exception 'A separate authorized workspace did not receive its own bucket'; end if;

  insert into sectalk_private.st_v7_session_scores(session_id,user_id,score,signals,provider)
    values(owner_session,owner_id,40,array['asn_reputation'],'matched');
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'role','authenticated',
    'session_id',owner_session,'aal','aal1')::text,true);
  set local role authenticated;
  if public.st_v7_admit_file_request('file_write','workspace',workspace)<>0 then raise exception 'Elevated risk denied entirely'; end if;
  reset role;
  if (select tokens from sectalk_private.st_v7_rate_buckets where action='file_write' and bucket=device_bucket)>7
    or (select tokens from sectalk_private.st_v7_rate_buckets where action='file_write' and bucket=owner_bucket)>11 then
    raise exception 'Elevated risk did not tighten only device and account capacity'; end if;
  update sectalk_private.st_v7_rate_buckets set tokens=0,measured_at=clock_timestamp()+interval '1 second'
    where action='file_write' and bucket=device_bucket;
  select b.tokens into tenant_balance from sectalk_private.st_v7_rate_buckets b where b.bucket=tenant_bucket and b.action='file_write';
  set local role authenticated;
  if public.st_v7_admit_file_request('file_write','workspace',workspace)<=0 then raise exception 'Exhausted device was admitted'; end if;
  reset role;
  if (select b.tokens from sectalk_private.st_v7_rate_buckets b where b.bucket=tenant_bucket and b.action='file_write')<>tenant_balance then
    raise exception 'Denied request consumed granted quota on another scope'; end if;
  update sectalk_private.st_v7_rate_buckets set measured_at=clock_timestamp()-interval '30 seconds'
    where action='file_write' and bucket=device_bucket;
  set local role authenticated;
  if public.st_v7_admit_file_request('file_write','workspace',workspace)<>0 then raise exception 'Bucket did not refill'; end if;
  reset role;

  set local role service_role;
  perform public.st_v7_record_password_failure(identifier) from generate_series(1,4);
  for idx in 1..4 loop
    if public.st_v7_admit_password_request(identifier,'203.0.113.212')<>0 then raise exception 'Risk-adjusted quota too low'; end if;
  end loop;
  if public.st_v7_admit_password_request(identifier,'203.0.113.220')<1 then raise exception 'Adaptive password budget failed'; end if;
  reset role;
  ip_bucket:=sectalk_private.st_v7_rate_bucket('network',sectalk_private.st_v7_login_network('198.18.101.9')::text);
  insert into sectalk_private.st_v7_rate_buckets(action,dimension,bucket,tokens,measured_at)
    values('password','network',ip_bucket,0,clock_timestamp()+interval '10 seconds')
    on conflict(action,dimension,bucket) do update set tokens=excluded.tokens,measured_at=excluded.measured_at;
  set local role service_role;
  if public.st_v7_admit_password_request(encode(extensions.gen_random_bytes(32),'hex'),'198.18.101.44')<1
    or public.st_v7_admit_password_request(encode(extensions.gen_random_bytes(32),'hex'),'198.18.102.44')<>0 then
    raise exception 'Trusted network budgets did not separate adjacent subnets'; end if;
end $$;

rollback;
