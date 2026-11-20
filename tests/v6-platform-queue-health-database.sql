begin;

insert into auth.users(id,email) values
 ('86af0000-0000-4000-8000-000000000001','queue-health@example.invalid'),
 ('86af0000-0000-4000-8000-000000000002','queue-health-other@example.invalid');
insert into public.st_profiles(id,handle,name) values
 ('86af0000-0000-4000-8000-000000000001','queue_health_fixture','Queue operator'),
 ('86af0000-0000-4000-8000-000000000002','queue_health_peer','Queue peer');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
 ('86af0000-0000-4000-8000-000000000011','86af0000-0000-4000-8000-000000000001','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
 ('86af0000-0000-4000-8000-000000000021','86af0000-0000-4000-8000-000000000001','aal2','86af0000-0000-4000-8000-000000000011');
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
 ('86af0000-0000-4000-8000-000000000031','86af0000-0000-4000-8000-000000000021','totp',now(),now());
insert into sectalk_private.staff(user_id) values('86af0000-0000-4000-8000-000000000001');
insert into sectalk_private.st_v6_queue_operators(account_id) values('86af0000-0000-4000-8000-000000000001');

do $$
declare
  operator_id constant uuid:='86af0000-0000-4000-8000-000000000001';
  peer constant uuid:='86af0000-0000-4000-8000-000000000002';
  claims constant text:=jsonb_build_object('sub',operator_id,'session_id','86af0000-0000-4000-8000-000000000021','aal','aal2')::text;
  cutoff constant timestamptz:=date_bin(interval '5 minutes',statement_timestamp(),'2000-01-01 00:00:00+00'::timestamptz);
  state jsonb;
  original_push bigint;
begin
  if has_function_privilege('anon','public.st_v6_platform_queue_health()','execute') then
    raise exception 'Anonymous account could request telemetry';
  end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',peer,'aal','aal1')::text,true);
  begin
    perform public.st_v6_platform_queue_health();
    raise exception 'Non-operator saw platform queue health';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims,true);
  state:=public.st_v6_platform_queue_health();
  original_push:=(state#>>'{queues,web_push,depth}')::bigint;
  insert into sectalk_private.st_v6_notification_delivery_events(recipient,event_key,kind,state,created_at)
  values(peer,'queue-health-pending-fixture','dm.message','pending',now()-interval '13 minutes');

  delete from sectalk_private.st_v6_operation_rollups where bucket>=cutoff-interval '24 hours';
  state:=public.st_v6_platform_queue_health();
  if (state#>>'{slo,availability,total}')::int is distinct from 0 then raise exception 'Empty windows must have zero samples'; end if;
  insert into sectalk_private.st_v6_operation_rollups values
    (cutoff-interval '5 minutes','call_ice',100,9,3,1,2,5,array[40,10,10,10,10,20,0,0,0]::bigint[]),
    (cutoff,'call_ice',100,0,0,0,0,1,array[100,0,0,0,0,0,0,0,0]::bigint[]);
  state:=public.st_v6_platform_queue_health();
  if state#>'{slo,availability}' is distinct from '{"total":92,"good":88,"target":99.9}'::jsonb
    or state#>'{slo,handler_latency}' is distinct from '{"total":100,"good":80,"target":95,"threshold_ms":500}'::jsonb
    or (state#>>'{queues,web_push,depth}')::bigint is distinct from original_push+1
    or (state#>>'{queues,web_push,oldest_seconds}')::int<780
    or state::text like '%queue-health-pending-fixture%' then
    raise exception 'Expected completed-window service measurements and private channel depth';
  end if;
  update auth.mfa_amr_claims set updated_at=now()-interval '11 minutes' where id='86af0000-0000-4000-8000-000000000031';
  begin
    perform public.st_v6_platform_queue_health();
    raise exception 'Stale MFA could view queue health';
  exception when insufficient_privilege then null; end;
end $$;

select 'passed: queue depth, private aggregate data, objective calculations, completed windows and fresh MFA' as result;
rollback;
