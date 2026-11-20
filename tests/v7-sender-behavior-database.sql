begin;

do $$
declare
  sender uuid:=gen_random_uuid();
  recipient uuid:=gen_random_uuid();
  reviewer uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid();
  staff_session uuid:=gen_random_uuid();
  sender_session uuid:=gen_random_uuid();
  peer_session uuid:=gen_random_uuid();
  sender_device uuid:=gen_random_uuid();
  peer_device uuid:=gen_random_uuid();
  alias_key text:=repeat('M',87);
  conversation uuid;
  report_id uuid;
  old_report uuid;
  aggregate jsonb;
  proof_id uuid;
  same_actor uuid;
  extra uuid;
  i integer;
begin
  insert into auth.users(id,email,created_at) values
    (sender,'behavior-sender@example.invalid',now()),(recipient,'behavior-recipient@example.invalid',now()),
    (reviewer,'behavior-reviewer@example.invalid',now());
  insert into public.st_profiles(id,handle,name) values
    (sender,'behavior_fixture_sender','Behavior sender'),(recipient,'behavior_fixture_peer','Behavior recipient'),
    (reviewer,'behavior_fixture_staff','Behavior reviewer');
  insert into sectalk_private.staff(user_id) values(reviewer);
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,reviewer,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(staff_session,reviewer,'aal2',factor),
    (sender_session,sender,'aal1',null),(peer_session,recipient,'aal1',null);
  insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature) values
    (sender_device,sender,'trusted',repeat('A',87),repeat('B',87),repeat('C',86)),
    (peer_device,recipient,'known',repeat('D',87),repeat('E',87),repeat('F',86));
  insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id) values
    (sender_session,sender,sender_device),(peer_session,recipient,peer_device);
  insert into public.st_chats(member_a,member_b,requester,status)
    values(least(sender,recipient),greatest(sender,recipient),sender,'accepted') returning id into conversation;
  insert into public.st_messages(id,chat_id,sender,body)
    select gen_random_uuid(),conversation,sender,'Synthetic aggregate fixture' from generate_series(1,14);
  for i in 1..5 loop
    extra:=gen_random_uuid();
    insert into auth.users(id,email) values(extra,'behavior-extra-'||i||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(extra,'behavior_extra_'||i,'Behavior invite fixture');
    insert into public.st_chats(member_a,member_b,requester,status)
      values(least(sender,extra),greatest(sender,extra),sender,'pending');
  end loop;
  insert into public.st_reports(reporter,subject,chat_id,category,details) values
    (recipient,sender,conversation,'threat','Synthetic reviewed case') returning id into report_id;
  insert into public.st_reports(reporter,subject,chat_id,category,details) values
    (recipient,sender,conversation,'other','Older synthetic case') returning id into old_report;
  insert into sectalk_private.audit(actor,report_id,action,created_at,note) values
    (reviewer,report_id,'warn',now()-interval '1 day','Recent fixture'),
    (reviewer,old_report,'restrict',now()-interval '20 days','Decayed fixture');

  if has_table_privilege('authenticated','sectalk_private.st_v7_behavior_counts','select')
    or has_table_privilege('authenticated','sectalk_private.st_v7_browser_link','select')
    or has_function_privilege('authenticated','public.st_v7_finish_browser_reputation_link(uuid,uuid,uuid)','execute')
    or exists(select 1 from pg_trigger where tgrelid='sectalk_private.st_group_messages'::regclass and tgname like 'st_v7_count_%') then
    raise exception 'Message telemetry or browser linkage crosses an unauthorized boundary';
  end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',sender,'aal','aal1','session_id',sender_session)::text,true);
  set local role authenticated;
  proof_id:=(public.st_v7_manage_browser_reputation_link('begin',alias_key)->>'challenge')::uuid;
  if proof_id is null then raise exception 'Approved device could not get an alias challenge'; end if;
  begin
    perform public.st_v7_case_sender_behavior(report_id);
    raise exception 'An ordinary account could view case behavior';
  exception when insufficient_privilege then null; end;
  reset role;
  if public.st_v7_finish_browser_reputation_link(proof_id,recipient,peer_session) or
    not public.st_v7_finish_browser_reputation_link(proof_id,sender,sender_session) or
    public.st_v7_finish_browser_reputation_link(proof_id,sender,sender_session) then
    raise exception 'Challenge was cross-session, invalid, or replayable';
  end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',recipient,'aal','aal1','session_id',peer_session)::text,true);
  set local role authenticated;
  if public.st_v7_manage_browser_reputation_link('begin',alias_key) is not null then
    raise exception 'Known-only device was able to establish a link';
  end if;
  reset role;
  update sectalk_private.st_v7_devices set state='trusted' where id=peer_device;
  set local role authenticated;
  proof_id:=(public.st_v7_manage_browser_reputation_link('begin',alias_key)->>'challenge')::uuid;
  reset role;
  if not public.st_v7_finish_browser_reputation_link(proof_id,recipient,peer_session) then
    raise exception 'Second approved fixture link failed';
  end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',reviewer,'aal','aal2','session_id',staff_session)::text,true);
  set local role authenticated;
  aggregate:=public.st_v7_case_sender_behavior(report_id);
  if aggregate is null or aggregate->>'sharedApprovedBrowser'<>'true'
    or (aggregate->>'peakMinuteSend')::integer<12 or (aggregate->>'peakHourInvites')::integer<>5
    or (aggregate->>'reviewedFlagWeight')::integer<>12 or (aggregate->>'score')::integer<>47
    or (select array_agg(k order by k) from jsonb_object_keys(aggregate) k) <>
      array['peakHourInvites','peakMinuteSend','reviewedFlagWeight','score','sharedApprovedBrowser'] then
    raise exception 'Advisory weights or restricted output are wrong: %',aggregate;
  end if;
  reset role;
  insert into sectalk_private.audit(actor,report_id,action,created_at,note) values
    (reviewer,old_report,'restore',now(),'Corrected fixture');
  perform set_config('request.jwt.claims',jsonb_build_object('sub',recipient,'aal','aal1','session_id',peer_session)::text,true);
  set local role authenticated;
  perform public.st_v7_manage_browser_reputation_link('forget');
  reset role;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',reviewer,'aal','aal2','session_id',staff_session)::text,true);
  set local role authenticated;
  aggregate:=public.st_v7_case_sender_behavior(report_id);
  if aggregate->>'sharedApprovedBrowser'<>'false' or aggregate->>'reviewedFlagWeight'<>'8' then
    raise exception 'Withdrawing linkage or restoring a reviewed finding left stale behavior';
  end if;
  reset role;
  if exists(select 1 from sectalk_private.suspensions where user_id=sender) then raise exception 'Advisory applied punishment'; end if;
end
$$;

select 'passed: live managed rate counters, consented one-use browser links, MFA-only aggregates and reviewed flag decay' as result;
rollback;
