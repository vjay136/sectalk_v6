begin;
do $$
declare
  proposer uuid:=gen_random_uuid();
  reviewer uuid:=gen_random_uuid();
  outsider uuid:=gen_random_uuid();
  reported uuid:=gen_random_uuid();
  reporter uuid:=gen_random_uuid();
  actor_id uuid;
  session_key uuid;
  subject_session uuid:=gen_random_uuid();
  subject_other_session uuid:=gen_random_uuid();
  factor_key uuid;
  request_ids uuid[]:='{}';
  negative_response uuid;
  exact_url_response uuid;
  group_response uuid;
  room_response uuid;
  room_report uuid:=gen_random_uuid();
  room_post uuid:=gen_random_uuid();
  group_key uuid:=gen_random_uuid();
  group_message uuid:=gen_random_uuid();
  other_group_message uuid:=gen_random_uuid();
  group_case uuid;
  unconsented_group_case uuid;
  reporter_session uuid:=gen_random_uuid();
  reporter_device uuid:=gen_random_uuid();
  group_feed jsonb;
  reporter_claims text;
  action_names text[]:=array['quarantine_file','quarantine_message','revoke_device','force_logout','suspend_user','block_domain','lock_room'];
  action_name text;
  action_index integer;
  source_chat uuid:=gen_random_uuid();
  report_key uuid:=gen_random_uuid();
  unconsented_report uuid:=gen_random_uuid();
  message_key uuid:=gen_random_uuid();
  file_key uuid:=gen_random_uuid();
  first_room uuid:=gen_random_uuid();
  unrelated_room uuid:=gen_random_uuid();
  workspace_key uuid:=gen_random_uuid();
  unrelated_space uuid:=gen_random_uuid();
  device_key uuid:=gen_random_uuid();
  domain_name text:='soc-'||left(gen_random_uuid()::text,8)||'.example.invalid';
  claims jsonb:='{}';
  note text:='Verified the scoped synthetic response';
  exact_url text:='https://clean.example.invalid/folder/Specific';
begin
  foreach actor_id in array array[proposer,reviewer,outsider,reported,reporter] loop
    insert into auth.users(id,email,encrypted_password,email_confirmed_at)
      values(actor_id,actor_id||'@example.invalid','qa-local-only',now());
    insert into public.st_profiles(id,handle,name)
      values(actor_id,'socqa_'||left(actor_id::text,8),'SOC response QA');
    insert into auth.identities(provider_id,user_id,identity_data,provider)
      values(actor_id::text,actor_id,jsonb_build_object('sub',actor_id,'email',actor_id||'@example.invalid'),'email');
    if actor_id in (proposer,reviewer,outsider) then
      session_key:=gen_random_uuid();
      factor_key:=gen_random_uuid();
      insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
        values(factor_key,actor_id,'totp','verified',now(),now());
      insert into auth.sessions(id,user_id,aal,factor_id) values(session_key,actor_id,'aal2',factor_key);
      insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
        values(gen_random_uuid(),session_key,'totp',now(),now());
      claims:=claims||jsonb_build_object(actor_id::text,jsonb_build_object(
        'sub',actor_id,'role','authenticated','session_id',session_key,'aal','aal2'));
    end if;
  end loop;
  insert into auth.sessions(id,user_id,aal) values
    (subject_session,reported,'aal1'),(subject_other_session,reported,'aal1');
  insert into sectalk_private.staff values(proposer),(reviewer),(outsider);
  insert into sectalk_private.st_v7_account_operators values(proposer,'operator'),(reviewer,'operator');
  insert into sectalk_private.st_v7_abuse_blocklist_operators values(proposer),(reviewer);
  insert into public.st_v2_workspaces(id,name,owner) values(workspace_key,'SOC workspace QA',proposer),(unrelated_space,'Other SOC workspace',outsider);
  insert into public.st_v2_members(workspace_id,user_id,role)
    values(workspace_key,proposer,'owner'),(workspace_key,reviewer,'admin'),(unrelated_space,outsider,'owner') on conflict do nothing;
  insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator)
    values(first_room,workspace_key,'Scoped room','private','blank',proposer),
      (unrelated_room,unrelated_space,'Other room','private','blank',outsider);
  insert into public.st_v6_room_members(room_id,user_id,role)
    values(first_room,proposer,'owner'),(first_room,reviewer,'moderator'),(unrelated_room,outsider,'owner');
  insert into public.st_chats(id,member_a,member_b,requester,status)
    values(source_chat,least(reported,reporter),greatest(reported,reporter),reporter,'accepted');
  insert into public.st_messages(id,chat_id,sender,body) values(message_key,source_chat,reported,'Benign consented fixture');
  insert into public.st_reports(id,reporter,subject,chat_id,message_id,category,details,evidence)
    values(report_key,reporter,reported,source_chat,message_key,'other','Review fixture','Benign consented fixture'),
      (unconsented_report,reporter,reported,source_chat,message_key,'other','Unconsented fixture',null);
  insert into public.st_v5_files(id,chat_id,uploader,filename,size_bytes,message_id)
    values(file_key,source_chat,reported,'fixture.txt',32,message_key);
  insert into sectalk_private.st_v5_attachment_reports(report_id,file_id) values(report_key,file_key);
  insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature)
    values(device_key,reported,'trusted',repeat('A',87),repeat('B',87),repeat('C',86));
  insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id) values(subject_session,reported,device_key);

  foreach action_name in array action_names loop
    insert into sectalk_private.st_v7_soc_response_grants(actor,action,workspace,role) values
      (proposer,action_name,case when action_name='lock_room' then workspace_key end,'requester'),
      (reviewer,action_name,case when action_name='lock_room' then workspace_key end,'approver');
  end loop;
  insert into sectalk_private.st_v7_soc_response_grants(actor,action,workspace,role) values
    (proposer,'quarantine_message',null,'approver'),(outsider,'lock_room',unrelated_space,'approver');
  if has_table_privilege('authenticated','sectalk_private.st_v7_soc_responses','select')
    or has_table_privilege('service_role','sectalk_private.st_v7_soc_responses','update')
    or has_function_privilege('anon','public.st_v7_decide_soc_response(uuid,boolean,text)','execute') then
    raise exception 'A direct response action or audit path was exposed'; end if;

  perform set_config('request.jwt.claims',(claims->proposer::text||'{"aal":"aal1"}')::text,true);
  set local role authenticated;
  if public.st_v7_soc_response_catalog()<>'[]'::jsonb then raise exception 'AAL1 listed response roles'; end if;
  reset role;
  perform set_config('request.jwt.claims',(claims->proposer::text)::text,true);
  set local role authenticated;
  foreach action_name in array array['quarantine_message','quarantine_file'] loop
    begin
      perform public.st_v7_request_soc_response(action_name,null,unconsented_report,null,null,note);
      raise exception 'Unconsented object was actionable';
    exception when insufficient_privilege then null; end;
  end loop;
  begin
    perform public.st_v7_request_soc_response('lock_room',workspace_key,null,unrelated_room,null,note);
    raise exception 'Cross-tenant room matched';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_request_soc_response('block_domain',null,null,null,'https://example.invalid/page',note);
    raise exception 'An unrecognized URL action was accepted';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_v7_request_soc_response('block_domain',null,null,null,domain_name,'short');
    raise exception 'Request omitted the required reason';
  exception when invalid_parameter_value then null; end;
  negative_response:=public.st_v7_request_soc_response('block_domain',null,null,null,'negative-'||domain_name,note);
  for action_index in 1..cardinality(action_names) loop
    action_name:=action_names[action_index];
    request_ids:=array_append(request_ids,public.st_v7_request_soc_response(action_name,
      case when action_name='lock_room' then workspace_key end,
      case when action_name not in ('block_domain','lock_room') then report_key end,
      case when action_name='revoke_device' then device_key when action_name='lock_room' then first_room end,
      case when action_name='block_domain' then upper(domain_name)||'.' end,note));
  end loop;
  begin
    perform public.st_v7_decide_soc_response(request_ids[2],true,note);
    raise exception 'Proposer approved own action';
  exception when insufficient_privilege then null; end;
  reset role;

  if exists(select 1 from public.st_v5_files where id=file_key and deleted_at is not null)
    or exists(select 1 from public.st_messages where id=message_key and revoked_at is not null)
    or exists(select 1 from public.st_v6_rooms where id=first_room and locked) then
    raise exception 'Request mutated a target before approval'; end if;
  perform set_config('request.jwt.claims',(claims->outsider::text)::text,true);
  set local role authenticated;
  if public.st_v7_soc_response_queue()<>'[]'::jsonb then raise exception 'Other tenant saw the queue'; end if;
  begin
    perform public.st_v7_decide_soc_response(request_ids[7],true,note);
    raise exception 'Cross-tenant approval accepted';
  exception when insufficient_privilege then null; end;
  reset role;
  perform set_config('request.jwt.claims',(claims->reviewer::text)::text,true);
  set local role authenticated;
  for action_index in 1..cardinality(request_ids) loop
    if public.st_v7_decide_soc_response(request_ids[action_index],true,note)<>'executed' then
      raise exception 'Expected an action effect'; end if;
    if action_index=3 then
      reset role;
      if exists(select 1 from auth.sessions where id=subject_session)
        or not exists(select 1 from auth.sessions where id=subject_other_session) then
        raise exception 'Device action affected the wrong native sessions'; end if;
      set local role authenticated;
    end if;
  end loop;
  if public.st_v7_decide_soc_response(request_ids[7],true,note)<>'executed' then raise exception 'Retry did not resolve idempotently'; end if;
  reset role;
  delete from sectalk_private.st_v7_soc_response_grants
    where actor=proposer and action='block_domain' and role='requester';
  set local role authenticated;
  begin
    perform public.st_v7_decide_soc_response(negative_response,true,note);
    raise exception 'The revoked requester retained action authority';
  exception when sqlstate 'PT409' then null; end;
  if public.st_v7_decide_soc_response(negative_response,false,note)<>'rejected' then raise exception 'Rejection was not recorded'; end if;
  reset role;
  if (select count(*) from sectalk_private.st_v7_soc_responses r where r.id=any(request_ids)
        and r.decision='executed' and r.decider=reviewer and r.requester=proposer and r.decision_reason=note)<>7
    or not exists(select 1 from public.st_v5_files where id=file_key and deleted_at is not null and purged_at is null)
    or not sectalk_private.st_v6_attachment_retention_held(file_key)
    or not exists(select 1 from public.st_messages where id=message_key and revoked_at is not null)
    or not exists(select 1 from public.st_reports where id=report_key and evidence='Benign consented fixture')
    or not exists(select 1 from sectalk_private.st_v7_devices where id=device_key and state='blocked')
    or exists(select 1 from auth.sessions where id in (subject_session,subject_other_session))
    or not exists(select 1 from sectalk_private.st_v7_account_admin_audit where target=reported and action='force_logout')
    or not exists(select 1 from sectalk_private.suspensions where user_id=reported and until_at>now())
    or not sectalk_private.st_v7_domain_blocked(domain_name)
    or sectalk_private.st_v7_domain_blocked('negative-'||domain_name)
    or not exists(select 1 from public.st_v6_rooms where id=first_room and locked)
    or exists(select 1 from public.st_v6_rooms where id=unrelated_room and locked)
    or (select count(*) from public.st_v6_room_audit where room_id=first_room and action='room.lock')<>1 then
    raise exception 'A required effect, evidence hold, or audit invariant failed'; end if;
  begin
    update sectalk_private.st_v7_soc_responses set decision_reason='Changed after the decision' where id=request_ids[1];
    raise exception 'Response decision audit could be rewritten';
  exception when insufficient_privilege then null; end;

  insert into auth.sessions(id,user_id,aal) values(reporter_session,reporter,'aal1');
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),reporter_session,'password',now(),now());
  insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature)
    values(reporter_device,reporter,'trusted',repeat('D',87),repeat('E',87),repeat('F',86));
  insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id) values(reporter_session,reporter,reporter_device);
  insert into sectalk_private.st_group_chats(id,owner,name,epoch,member_cap)
    values(group_key,reporter,'Group quarantine fixture',1,4);
  insert into sectalk_private.st_group_members(group_id,actor) values(group_key,reported),(group_key,reporter);
  insert into sectalk_private.st_group_envelopes(group_id,epoch,device,sealed,ephemeral)
    values(group_key,1,reporter_device,repeat('A',80),repeat('B',87));
  insert into sectalk_private.st_group_messages(group_id,id,epoch,actor,device,signing,payload,signature)
    select group_key,m,1,reported,device_key,repeat('K',87),repeat('T',48),repeat('P',86)
    from unnest(array[group_message,other_group_message]) m;
  reporter_claims:=jsonb_build_object('sub',reporter,'role','authenticated','session_id',reporter_session,'aal','aal1')::text;
  perform set_config('request.jwt.claims',reporter_claims,true);
  set local role authenticated;
  group_case:=public.st_report_group_message(group_key,group_message,'other',true,'Reporter supplied benign evidence');
  unconsented_group_case:=public.st_report_group_message(group_key,other_group_message,'other',false);
  reset role;

  insert into public.st_v6_room_posts(room_id,id,sender,body,kind)
    values(first_room,room_post,reported,'Benign room review fixture','message');
  insert into sectalk_private.st_v6_room_reports(id,workspace_id,room_id,post_id,reporter,subject,category,details,
      share_with_workspace,status,handed_off_at)
    values(room_report,workspace_key,first_room,room_post,reporter,reported,'other','Room fixture',true,'reviewing',now());
  insert into sectalk_private.st_v6_room_report_stages(report_id,stage,assignee,assigned_at,acknowledge_by,action_by,acknowledged_at)
    values(room_report,3,proposer,now(),now()+interval '1 hour',now()+interval '1 day',now());
  insert into sectalk_private.st_v7_soc_response_grants(actor,action,workspace,role) values
    (proposer,'block_url',null,'requester'),(reviewer,'block_url',null,'approver'),
    (proposer,'quarantine_room_post',workspace_key,'requester'),(reviewer,'quarantine_room_post',workspace_key,'approver');

  perform set_config('request.jwt.claims',(claims->proposer::text)::text,true);
  set local role authenticated;
  exact_url_response:=public.st_v7_request_soc_response('block_url',null,null,null,
    'HTTPS://Clean.Example.Invalid/folder/%53pecific?discard=this#context',note);
  begin
    perform public.st_v7_request_soc_response('quarantine_message',null,unconsented_group_case,null,null,note);
    raise exception 'Group report without shared text could quarantine';
  exception when insufficient_privilege then null; end;
  group_response:=public.st_v7_request_soc_response('quarantine_message',null,group_case,null,null,note);
  room_response:=public.st_v7_request_soc_response('quarantine_room_post',workspace_key,room_report,null,null,note);
  reset role;
  perform set_config('request.jwt.claims',(claims->reviewer::text)::text,true);
  set local role authenticated;
  if not public.st_v7_link_policy_allows(exact_url) then raise exception 'Unapproved URL request was applied'; end if;
  if public.st_v8_link_safety_summary(exact_url) is distinct from '{"allowed":true,"recordedRisk":false}'::jsonb then
    raise exception 'Pending URL request was projected as recorded risk'; end if;
  if public.st_v7_decide_soc_response(exact_url_response,true,note)<>'executed'
    or public.st_v7_decide_soc_response(group_response,true,note)<>'executed'
    or public.st_v7_decide_soc_response(room_response,true,note)<>'executed' then
    raise exception 'Scope extension failed to execute'; end if;
  if public.st_v7_link_policy_allows(exact_url)
    or public.st_v7_link_policy_allows(exact_url||'?alternate=1')
    or not public.st_v7_link_policy_allows(exact_url||'/neighbor')
    or not public.st_v7_link_policy_allows(replace(exact_url,'Specific','specific'))
    or not public.st_v7_link_policy_allows(replace(exact_url,'https:','http:')) then
    raise exception 'URL exact scope diverged or suppressed neighboring URLs'; end if;
  if public.st_v8_link_safety_summary(exact_url||'?discard=this') is distinct from '{"allowed":false,"recordedRisk":true}'::jsonb
    or public.st_v8_link_safety_summary(replace(exact_url,'/Specific','/%53pecific')) is distinct from '{"allowed":false,"recordedRisk":true}'::jsonb
    or public.st_v8_link_safety_summary(exact_url||'/neighbor') is distinct from '{"allowed":true,"recordedRisk":false}'::jsonb
    or public.st_v8_link_safety_summary(replace(exact_url,'Specific','specific')) is distinct from '{"allowed":true,"recordedRisk":false}'::jsonb
    or public.st_v8_link_safety_summary(replace(exact_url,'https:','http:')) is distinct from '{"allowed":true,"recordedRisk":false}'::jsonb
    or public.st_v8_link_safety_summary('file:///fixture') is not null then
    raise exception 'Recorded URL safety projection did not respect its exact normalized address'; end if;
  if public.st_v7_read_room_quarantine_evidence(room_report) is distinct from 'Benign room review fixture' then
    raise exception 'Authorized room reviewer lost consented evidence'; end if;
  reset role;

  if not exists(select 1 from public.st_v6_room_posts where room_id=first_room and id=room_post and body='Message removed')
    or not exists(select 1 from public.st_reports where id=group_case and evidence='Reporter supplied benign evidence')
    or not exists(select 1 from sectalk_private.st_group_messages where group_id=group_key and id=group_message and payload=repeat('T',48)) then
    raise exception 'Room tombstone or encrypted retained evidence changed'; end if;
  perform set_config('request.jwt.claims',(claims->outsider::text)::text,true);
  set local role authenticated;
  if public.st_v7_read_room_quarantine_evidence(room_report) is not null then
    raise exception 'Foreign reviewer obtained retained room evidence'; end if;
  if public.st_v8_link_safety_summary(exact_url) is distinct from '{"allowed":false,"recordedRisk":true}'::jsonb then
    raise exception 'An active signed-in account cannot check a global recorded URL risk'; end if;
  reset role;
  if has_function_privilege('anon','public.st_v8_link_safety_summary(text)','execute')
    or has_function_privilege('service_role','public.st_v8_link_safety_summary(text)','execute') then
    raise exception 'Recorded URL risks exposed outside the signed-in projection'; end if;
  update sectalk_private.st_v7_soc_url_blocks set expires_at=now()-interval '1 second' where url_key=exact_url;

  perform set_config('request.jwt.claims',reporter_claims,true);
  set local role authenticated;
  if public.st_v8_link_safety_summary(exact_url) is distinct from '{"allowed":true,"recordedRisk":false}'::jsonb then
    raise exception 'Expired block was projected as active URL risk'; end if;
  group_feed:=public.st_group_chat('read',group_key);
  if not exists(select 1 from jsonb_array_elements(group_feed->'messages') m where m->>'id'=group_message::text
      and m->>'quarantined'='true' and not (m?'payload' or m?'signature' or m?'signing'))
    or not exists(select 1 from jsonb_array_elements(group_feed->'messages') m where m->>'id'=other_group_message::text and m?'payload')
    or exists(select 1 from jsonb_array_elements(public.st_group_search_metadata(group_key)->'messages') m where m->>'id'=group_message::text) then
    raise exception 'Group-authorized feed or encrypted search leaked the quarantined envelope'; end if;
  reset role;
end $$;
rollback;
