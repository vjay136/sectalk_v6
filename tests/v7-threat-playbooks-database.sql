begin;
do $$
declare
  first_reviewer uuid:=gen_random_uuid();
  second_reviewer uuid:=gen_random_uuid();
  third_reviewer uuid:=gen_random_uuid();
  person uuid;
  session_key uuid;
  factor_key uuid;
  native_claims jsonb:='{}';
  item_a uuid;
  item_b uuid;
  item_c uuid;
  item_hidden uuid;
  source_id uuid:=gen_random_uuid();
  playbook_key uuid;
  run_a uuid;
  run_b uuid;
  run_c uuid;
  plan jsonb;
  note text:='Reviewed the scoped signal manually';
begin
  foreach person in array array[first_reviewer,second_reviewer,third_reviewer] loop
    session_key:=gen_random_uuid();
    factor_key:=gen_random_uuid();
    insert into auth.users(id,email) values(person,person||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(person,'play_'||left(person::text,8),'Playbook QA');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor_key,person,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_key,person,'aal2',factor_key);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_key,'totp',now(),now());
    native_claims:=native_claims||jsonb_build_object(person::text,jsonb_build_object(
      'sub',person,'role','authenticated','session_id',session_key,'aal','aal2'));
  end loop;

  insert into sectalk_private.st_v7_threat_reviewers(user_id,signal_type) values
    (first_reviewer,'detection'),(second_reviewer,'detection'),(third_reviewer,'attachment_inspection');
  insert into sectalk_private.st_v7_playbook_grants(reviewer,signal_type,capability) values
    (first_reviewer,'detection','author'),(first_reviewer,'detection','approver'),
    (second_reviewer,'detection','approver'),(third_reviewer,'attachment_inspection','approver');
  perform sectalk_private.st_v7_enqueue_threat('detection',source_id||':a','medium','supported','{}',now());
  perform sectalk_private.st_v7_enqueue_threat('detection',source_id||':b','medium','supported','{}',now());
  perform sectalk_private.st_v7_enqueue_threat('detection',source_id||':c','medium','supported','{}',now());
  perform sectalk_private.st_v7_enqueue_threat('attachment_inspection',source_id||':d','high','heuristic','{}',now());
  select id into strict item_a from sectalk_private.st_v7_threat_items where source_key=source_id||':a';
  select id into strict item_b from sectalk_private.st_v7_threat_items where source_key=source_id||':b';
  select id into strict item_c from sectalk_private.st_v7_threat_items where source_key=source_id||':c';
  select id into strict item_hidden from sectalk_private.st_v7_threat_items where source_key=source_id||':d';

  if has_table_privilege('authenticated','sectalk_private.st_v7_playbook_effects','select')
    or has_table_privilege('service_role','sectalk_private.st_v7_playbook_runs','update')
    or has_function_privilege('anon','public.st_v7_decide_playbook(uuid,boolean,text)','execute') then
    raise exception 'Direct workflow authority was exposed'; end if;

  perform set_config('request.jwt.claims',(native_claims->first_reviewer::text||'{"aal":"aal1"}')::text,true);
  set local role authenticated;
  if jsonb_array_length(public.st_v7_playbook_catalog()->'grants')<>0 then raise exception 'AAL1 inherited playbook access'; end if;
  reset role;
  perform set_config('request.jwt.claims',(native_claims->first_reviewer::text)::text,true);
  set local role authenticated;
  begin
    perform public.st_v7_save_playbook(null,0,'detection','Invalid QA','medium',array['send_webhook']);
    raise exception 'Unsupported action accepted';
  exception when invalid_parameter_value then null; end;
  playbook_key:=public.st_v7_save_playbook(null,0,'detection','Bounded QA','medium',
    array['mark_reviewing','verify_signal','document_findings']);
  plan:=public.st_v7_simulate_playbook(playbook_key,1,item_a,1,false);
  if plan->>'matches'<>'true' or plan->>'run' is not null then raise exception 'Simulation wrote a workflow'; end if;
  begin
    perform public.st_v7_simulate_playbook(playbook_key,1,item_hidden,1,true);
    raise exception 'Cross-scope simulation accepted';
  exception when insufficient_privilege then null; end;
  run_a:=(public.st_v7_simulate_playbook(playbook_key,1,item_a,1,true)->>'run')::uuid;
  run_b:=(public.st_v7_simulate_playbook(playbook_key,1,item_b,1,true)->>'run')::uuid;
  run_c:=(public.st_v7_simulate_playbook(playbook_key,1,item_c,1,true)->>'run')::uuid;
  begin
    perform public.st_v7_simulate_playbook(playbook_key,1,item_a,1,true);
    raise exception 'Duplicate request accepted';
  exception when sqlstate 'PT409' then null; end;
  begin
    perform public.st_v7_decide_playbook(run_a,true,note);
    raise exception 'Self approval accepted';
  exception when insufficient_privilege then null; end;
  perform public.st_v7_save_playbook(playbook_key,1,'detection','Bounded QA v2','high',array['verify_signal']);
  if (public.st_v7_simulate_playbook(playbook_key,2,item_b,1,false)->>'matches')::boolean then
    raise exception 'Nonmatching severity accepted'; end if;
  perform public.st_v7_apply_threat_triage(jsonb_build_array(jsonb_build_object('id',item_b,'revision',1)),'dismissed',note);
  reset role;

  if exists(select 1 from sectalk_private.st_v7_playbook_effects f where f.run in (run_a,run_b,run_c)) then
    raise exception 'Effect executed without consent'; end if;
  perform set_config('request.jwt.claims',(native_claims->third_reviewer::text)::text,true);
  set local role authenticated;
  if public.st_v7_playbook_runs(item_a)<>'[]'::jsonb then raise exception 'Cross-scope run was disclosed'; end if;
  begin
    perform public.st_v7_decide_playbook(run_a,true,note);
    raise exception 'Cross-scope approval accepted';
  exception when insufficient_privilege then null; end;
  reset role;
  perform set_config('request.jwt.claims',(native_claims->second_reviewer::text)::text,true);
  set local role authenticated;
  if public.st_v7_decide_playbook(run_a,true,note)<>'executed'
    or public.st_v7_decide_playbook(run_a,true,note)<>'executed' then raise exception 'Approval retry was not idempotent'; end if;
  if not public.st_v7_complete_playbook_step(run_a,'verify_signal')
    or not public.st_v7_complete_playbook_step(run_a,'verify_signal') then
    raise exception 'Checklist completion retry was not idempotent'; end if;
  begin
    perform public.st_v7_decide_playbook(run_b,true,note);
    raise exception 'Stale signal approval accepted';
  exception when sqlstate 'PT409' then null; end;
  if public.st_v7_decide_playbook(run_b,false,note)<>'rejected' then raise exception 'Stale rejection failed'; end if;
  reset role;

  if (select count(*) from sectalk_private.st_v7_playbook_effects f where f.run=run_a and f.actor=second_reviewer)<>3
    or (select count(*) from sectalk_private.st_v7_playbook_checklist_status c where c.run=run_a)<>1
    or exists(select 1 from sectalk_private.st_v7_playbook_effects f where f.run in (run_b,run_c))
    or not exists(select 1 from sectalk_private.st_v7_threat_triage_audit a where a.item_id=item_a
      and a.action='reviewing' and a.actor=second_reviewer and a.revision=2 and a.reason=note) then
    raise exception 'Audited effect set differed from the approved immutable version'; end if;
  begin
    update sectalk_private.st_v7_playbook_runs set reason='Replace the written decision' where id=run_a;
    raise exception 'Resolved decision was mutable';
  exception when insufficient_privilege then null; end;
  delete from sectalk_private.st_v7_playbook_grants where reviewer=first_reviewer and capability='author';
  set local role authenticated;
  begin
    perform public.st_v7_decide_playbook(run_c,true,note);
    raise exception 'Revoked author request executed';
  exception when sqlstate 'PT409' then null; end;
  reset role;
end $$;
rollback;
