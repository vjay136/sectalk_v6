begin;

insert into auth.users(id,email)
select ('61820000-1c93-48e4-b600-00000000000'||n)::uuid,'channel-review-'||n||'@example.invalid' from generate_series(1,5) n;
insert into public.st_profiles(id,handle,name)
select ('61820000-1c93-48e4-b600-00000000000'||n)::uuid,'channelreview_'||n,'Channel review QA' from generate_series(1,5) n;
insert into sectalk_private.staff values('61820000-1c93-48e4-b600-000000000001');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
select ('61821000-1c93-48e4-b600-00000000000'||n)::uuid,('61820000-1c93-48e4-b600-00000000000'||n)::uuid,
  'totp','verified',now(),now() from generate_series(1,5) n;
insert into auth.sessions(id,user_id,aal,factor_id)
select ('61822000-1c93-48e4-b600-00000000000'||n)::uuid,('61820000-1c93-48e4-b600-00000000000'||n)::uuid,
  'aal2',('61821000-1c93-48e4-b600-00000000000'||n)::uuid from generate_series(1,5) n;

create function pg_temp.channel_report_actor(n integer,assurance text default 'aal2') returns void language sql as $$
 select set_config('request.jwt.claims',jsonb_build_object('sub','61820000-1c93-48e4-b600-00000000000'||n,
   'aal',assurance,'session_id','61822000-1c93-48e4-b600-00000000000'||n)::text,true)::text::void
$$;

do $$
declare workspace uuid;
declare channel uuid;
declare post_id uuid:=gen_random_uuid();
declare severe_id uuid:=gen_random_uuid();
declare first_report uuid;
declare severe_report uuid;
declare readout jsonb;
begin
  set local role authenticated;
  perform pg_temp.channel_report_actor(2);
  workspace:=public.st_v2_create_workspace('Channel review QA');
  channel:=public.st_v2_create_channel(workspace,'channel-review');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values
    (workspace,'61820000-1c93-48e4-b600-000000000003','member'),
    (workspace,'61820000-1c93-48e4-b600-000000000004','member');
  insert into public.st_v2_posts(id,channel_id,sender,body) values
    (post_id,channel,'61820000-1c93-48e4-b600-000000000004','Flagged fixture revision'),
    (severe_id,channel,'61820000-1c93-48e4-b600-000000000004','Severe fixture revision');
  set local role authenticated;
  perform pg_temp.channel_report_actor(3);
  begin
    perform public.st_v7_submit_channel_report(channel,post_id,'spam','',false,true);
    raise exception 'Report without explicit consent was accepted';
  exception when invalid_parameter_value then null; end;
  first_report:=public.st_v7_submit_channel_report(channel,post_id,'spam','Private reporter note',true,true);
  if public.st_v7_submit_channel_report(channel,post_id,'other','Replayed request',true,false) is distinct from first_report then
    raise exception 'Same channel report duplicated';
  end if;
  severe_report:=public.st_v7_submit_channel_report(channel,severe_id,'sexual_content','High severity',true,true);
  perform pg_temp.channel_report_actor(5);
  begin
    perform public.st_v7_submit_channel_report(channel,post_id,'spam','',true,true);
    raise exception 'An outsider could report channel content';
  exception when insufficient_privilege then null; end;
  if public.st_v7_my_channel_reports() <> '[]'::jsonb then raise exception 'Report timeline leaked'; end if;
  perform pg_temp.channel_report_actor(2);
  if public.st_v7_channel_report_queue('workspace') <> '[]'::jsonb then raise exception 'Unreferred case leaked'; end if;
  perform pg_temp.channel_report_actor(1,'aal1');
  begin
    perform public.st_v7_channel_report_queue('platform');
    raise exception 'Missing AAL2 was accepted';
  exception when insufficient_privilege then null; end;
  perform pg_temp.channel_report_actor(1);
  readout:=public.st_v7_channel_report_queue('platform');
  if not exists(select 1 from jsonb_array_elements(readout) r where r->>'id'=first_report::text
      and r->>'evidence'='Flagged fixture revision' and r->>'details'='Private reporter note') then
    raise exception 'Authorized exact evidence unavailable';
  end if;
  begin
    perform public.st_v7_review_channel_report(severe_report,'platform','handoff','Bad severe handoff');
    raise exception 'Severe case was referred to the workspace';
  exception when insufficient_privilege then null; end;
  perform public.st_v7_review_channel_report(first_report,'platform','handoff','Consented low severity review');
  perform pg_temp.channel_report_actor(2);
  readout:=public.st_v7_channel_report_queue('workspace');
  if not exists(select 1 from jsonb_array_elements(readout) r where r->>'id'=first_report::text
      and r->>'evidence'='Flagged fixture revision' and r->>'details'='') then
    raise exception 'Scoped workspace review or private reporter note protection failed';
  end if;
  perform public.st_v7_review_channel_report(first_report,'workspace','resolved','Private reviewer decision');
  perform pg_temp.channel_report_actor(3);
  readout:=public.st_v7_my_channel_reports();
  if not exists(select 1 from jsonb_array_elements(readout) r where r->>'id'=first_report::text
      and r->>'state'='resolved' and jsonb_array_length(r->'timeline')=2 and not (r ? 'details'))
    or readout::text like '%Private reviewer decision%' then raise exception 'Reporter state showed the wrong action or private reviewer notes'; end if;
  reset role;
  if (select count(*) from sectalk_private.st_v7_channel_report_actions where report_id=first_report)<>2 then
    raise exception 'Expected two audited actions';
  end if;
end $$;

select 'passed: consent, channel membership, exact evidence, MFA handoff and private report timelines' as result;
rollback;
