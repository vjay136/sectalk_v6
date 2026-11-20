\set ON_ERROR_STOP on
begin;

insert into auth.users(id,email,aud,role)
select format('6a000001-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  format('live-analytics-%s@example.invalid',n),'authenticated','authenticated' from generate_series(1,6) n;
insert into public.st_profiles(id,handle,name)
select id,'liveanalytics_'||split_part(split_part(email,'@',1),'-',3),'Live analytics fixture'
  from auth.users where email like 'live-analytics-%@example.invalid';
insert into sectalk_private.staff(user_id) values
  ('6a000001-0000-4000-8000-000000000001'),('6a000001-0000-4000-8000-000000000002');
insert into sectalk_private.st_v6_analytics_viewers(user_id,expires_at)
  values('6a000001-0000-4000-8000-000000000002',now()-interval '1 second');

insert into public.st_chats(id,member_a,member_b,requester,status)
select format('6a000001-0001-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  '6a000001-0000-4000-8000-000000000001',format('6a000001-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  '6a000001-0000-4000-8000-000000000001','accepted' from generate_series(2,6) n;

-- Isolate delivery receipts from preceding browser fixtures in this rollback-only transaction.
update public.st_messages set delivered_at=null where delivered_at is not null;
insert into public.st_messages(id,chat_id,sender,body,created_at,delivered_at)
select gen_random_uuid(),format('6a000001-0001-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  format('6a000001-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  'Private live analytics fixture',date_trunc('minute',now(),'UTC')-interval '10 seconds',
  date_trunc('minute',now(),'UTC')-interval '8.75 seconds'
from generate_series(2,6) n cross join generate_series(1,4);

set local role authenticated;
do $$
declare
  staffer constant uuid := '6a000001-0000-4000-8000-000000000001';
  other_staff constant uuid := '6a000001-0000-4000-8000-000000000002';
  non_staff constant uuid := '6a000001-0000-4000-8000-000000000003';
  live jsonb;
begin
  perform set_config('request.jwt.claims',jsonb_build_object('sub',staffer,'aal','aal1')::text,true);
  begin
    perform public.st_v6_delivery_latency('24h',true);
    raise exception 'Staff without MFA could fetch live delivery metrics';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',non_staff,'aal','aal2')::text,true);
  begin
    perform public.st_v6_usage_metrics('7d',true);
    raise exception 'Non-staff member could fetch live usage metrics';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',staffer,'aal','aal2')::text,true);
  live:=public.st_v6_usage_metrics('7d',true);
  if (live->>'through')::timestamptz<>date_trunc('minute',now(),'UTC')
    or (public.st_v6_usage_metrics('7d')->>'through')::timestamptz<>date_trunc('day',now(),'UTC')
    or (public.st_v6_delivery_latency('24h')->>'through')::timestamptz<>date_trunc('hour',now(),'UTC')
  then raise exception 'Live and fixed reporting cutoffs regressed'; end if;
  if public.st_v6_delivery_latency('24h',true)-'through'
       is distinct from '{"available":true,"p50":1250,"p95":1250,"p99":1250}'::jsonb then
    raise exception 'Live delivery did not include the completed minute and exact eligible cohort';
  end if;
  begin
    perform public.st_v6_usage_metrics('1m',true);
    raise exception 'An unapproved live time window was accepted';
  exception when invalid_parameter_value then null; end;
  if public.st_v6_can_read_live_analytics() is not true then
    raise exception 'MFA staff could not subscribe';
  end if;

  perform set_config('realtime.topic','st:analytics:'||other_staff::text,true);
  begin
    insert into realtime.messages(topic,extension,event,payload,private)
      values('st:analytics:'||other_staff,'broadcast','analytics_refresh','{}',true);
    raise exception 'Client could publish an analytics event';
  exception when insufficient_privilege then null; end;
end
$$;
reset role;

update public.st_messages set delivered_at=null
  where chat_id='6a000001-0001-4000-8000-000000000006';
set local role authenticated;
do $$
begin
  if public.st_v6_delivery_latency('24h',true)-'through' is distinct from '{"available":false}'::jsonb then
    raise exception 'Live delivery disclosed an undersized cohort';
  end if;
end
$$;
reset role;

-- Publish twice to exercise the per-recipient dedupe in the same minute.
select sectalk_private.st_v6_publish_analytics_refresh();
select sectalk_private.st_v6_publish_analytics_refresh();
do $$
begin
  if (select count(*) from realtime.messages
    where topic='st:analytics:6a000001-0000-4000-8000-000000000001' and event='analytics_refresh')<>1
    or not exists(select 1 from realtime.messages
      where topic='st:analytics:6a000001-0000-4000-8000-000000000001' and event='analytics_refresh'
        and private and payload-'id'='{}'::jsonb)
    or exists(select 1 from realtime.messages
      where topic='st:analytics:6a000001-0000-4000-8000-000000000002' and event='analytics_refresh')
    then raise exception 'Live analytics leaked event data or published outside its viewer lease/cadence'; end if;
end
$$;

set local role authenticated;
do $$
declare
  staffer constant uuid := '6a000001-0000-4000-8000-000000000001';
  other_staff constant uuid := '6a000001-0000-4000-8000-000000000002';
  own_topic constant text := 'st:analytics:'||staffer;
begin
  perform set_config('realtime.topic',own_topic,true);
  if not exists(select 1 from realtime.messages where topic=own_topic and event='analytics_refresh') then
    raise exception 'Authorized recipient could not read its notification';
  end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',other_staff,'aal','aal2')::text,true);
  if exists(select 1 from realtime.messages where topic=own_topic and event='analytics_refresh') then
    raise exception 'Another MFA staffer read the recipient notification';
  end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',staffer,'aal','aal1')::text,true);
  if exists(select 1 from realtime.messages where topic=own_topic and event='analytics_refresh') then
    raise exception 'Staff AAL1 could read the recipient notification';
  end if;
end
$$;
reset role;
select 'passed: private analytics recipient, MFA, cutoff compatibility, empty hint, deduplication and expiry' as result;
rollback;
