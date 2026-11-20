begin;
insert into auth.users(id,email)
select ('67310dbe-30f2-4048-9804-'||lpad(n::text,12,'0'))::uuid,
  'workspace-analytics-'||n||'@example.invalid' from generate_series(1,6) n;
insert into public.st_profiles(id,name,handle)
select ('67310dbe-30f2-4048-9804-'||lpad(n::text,12,'0'))::uuid,
  'Analytics fixture '||n,'analytics_ws_'||n from generate_series(1,6) n;
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
  ('67310dbe-30f2-4048-9804-000000000011','67310dbe-30f2-4048-9804-000000000001','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
  ('67310dbe-30f2-4048-9804-000000000021','67310dbe-30f2-4048-9804-000000000001','aal2','67310dbe-30f2-4048-9804-000000000011');

do $$
declare
  owner_id uuid:='67310dbe-30f2-4048-9804-000000000001';
  outsider_id uuid:='67310dbe-30f2-4048-9804-000000000006';
  owner_claims text:=json_build_object('sub',owner_id,'role','authenticated','aal','aal2',
    'session_id','67310dbe-30f2-4048-9804-000000000021')::text;
  workspace uuid;
  foreign_workspace uuid;
  shared_room uuid:=gen_random_uuid();
  protected_room uuid:=gen_random_uuid();
  meeting uuid:=gen_random_uuid();
  result jsonb;
  cutoff timestamptz:=date_trunc('day',now(),'UTC');
begin
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claims,true);
  workspace:=public.st_v2_create_workspace('Analytics fixture');
  perform public.st_v6_room_create(shared_room,workspace,'Shared analytics','public','blank');
  perform public.st_v6_room_create(protected_room,workspace,'Confidential analytics','private','blank');
  perform public.st_v6_start_instant_meeting(meeting,workspace,'Sampled workspace meeting',30);
  if public.st_v6_report_call_qos('meeting',meeting,null,'join','started') is not true
    or public.st_v6_report_call_qos('meeting',meeting,null,'join','connected') is not true
  then raise exception 'Workspace meeting did not record the normal join samples'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',outsider_id,'role','authenticated')::text,true);
  foreign_workspace:=public.st_v2_create_workspace('Foreign analytics fixture');
  begin
    perform public.st_v6_workspace_analytics(workspace);
    raise exception 'An unrelated workspace owner read metrics';
  exception when insufficient_privilege then null; end;
  reset role;
  if (select count(*) from sectalk_private.st_v6_call_qos
    where workspace_id=workspace and metric='join' and bucket='connected')<>1
  then raise exception 'The app join sample was not scoped or monotonic'; end if;
  insert into public.st_v2_members(workspace_id,user_id)
  select workspace,('67310dbe-30f2-4048-9804-'||lpad(n::text,12,'0'))::uuid from generate_series(2,5) n;
  insert into public.st_v6_room_posts(room_id,id,sender,body,kind,created_at)
  select r,gen_random_uuid(),('67310dbe-30f2-4048-9804-'||lpad(n::text,12,'0'))::uuid,
    'Synthetic scope fixture','message',cutoff-interval '1 day'
  from generate_series(1,5) n cross join unnest(array[shared_room,protected_room]) r;
  insert into sectalk_private.st_v6_call_qos(day,event_key,reporter_key,mode,metric,bucket,workspace_id)
  select (cutoff at time zone 'UTC')::date-1,sha256(convert_to(n::text||w::text||k,'UTF8')),
    sha256(convert_to((n%5)::text||w::text,'UTF8')),'meeting',k,
    case when k='join' then (case when n<=5 then 'connected' else 'started' end)
      else (case when n<=3 then 'relayed' else 'non_relayed' end) end,w
  from generate_series(1,10) n cross join unnest(array[workspace,foreign_workspace]) w
  cross join unnest(array['join','relay']) k;
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claims,true);
  result:=public.st_v6_workspace_analytics(workspace);
  if result->'shared_activity'<>jsonb_build_object('posts',5,'contributors',5)
    or result->'meeting_quality'<>'{"join":{"samples":10,"percent":50}}'::jsonb
    or result->'security_posture'->>'protected_rooms'<>'1'
    or result::text like '%Analytics fixture%' or result::text like '%'||owner_id::text||'%'
  then raise exception 'Scoped activity, quality or posture failed privacy and cohort assertions'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  begin
    perform public.st_v6_workspace_analytics(workspace);
    raise exception 'An unverified owner accessed analytics';
  exception when insufficient_privilege then null; end;
end $$;
select 'passed: workspace-scoped measured QoS, projected counts, suppression and genuine MFA' as result;
rollback;
