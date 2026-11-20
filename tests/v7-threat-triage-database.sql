begin;

do $$
declare
  reviewer_id uuid:=gen_random_uuid();
  reviewer_session uuid:=gen_random_uuid();
  factor_id uuid:=gen_random_uuid();
  detection_key uuid:=gen_random_uuid();
  malware_key uuid:=gen_random_uuid();
  detection_item uuid;
  malware_item uuid;
  selection jsonb;
  note text:='Reviewed synthetic operational signals';
begin
  insert into auth.users(id,email) values(reviewer_id,reviewer_id||'@example.invalid');
  insert into public.st_profiles(id,handle,name)
    values(reviewer_id,'triage_'||left(reviewer_id::text,8),'Threat review QA');
  insert into sectalk_private.staff(user_id) values(reviewer_id);
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor_id,reviewer_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(reviewer_session,reviewer_id,'aal2',factor_id);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),reviewer_session,'totp',now(),now());
  if has_function_privilege('anon','public.st_v7_threat_triage_access()','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v7_threat_items','select')
    or has_table_privilege('service_role','sectalk_private.st_v7_threat_triage_audit','update')
    or has_function_privilege('authenticated','sectalk_private.st_v7_enqueue_threat(text,text,text,text,jsonb,timestamptz)','execute') then
    raise exception 'Private threat producer, queue or audit exposed';
  end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',reviewer_id,'role','authenticated',
    'session_id',reviewer_session,'aal','aal2')::text,true);
  set local role authenticated;
  if public.st_v7_threat_triage_access()->>'status'<>'none' then raise exception 'Staff inherited reviewer access'; end if;
  reset role;
  insert into sectalk_private.st_v7_threat_reviewers(user_id,signal_type) values(reviewer_id,'detection');
  perform set_config('request.jwt.claims',jsonb_build_object('sub',reviewer_id,'role','authenticated',
    'session_id',reviewer_session,'aal','aal1')::text,true);
  set local role authenticated;
  if public.st_v7_threat_triage_access()->>'status'<>'mfa' then raise exception 'AAL1 reviewer did not require TOTP'; end if;
  begin
    perform public.st_v7_threat_queue();
    raise exception 'AAL1 reviewer could read the queue';
  exception when insufficient_privilege then null; end;
  reset role;

  perform sectalk_private.st_v7_enqueue_threat('detection',detection_key::text,'medium','supported','{}',now());
  perform sectalk_private.st_v7_enqueue_threat('detection',detection_key::text,'medium','supported','{}',now());
  perform sectalk_private.st_v7_enqueue_attachment_threat(jsonb_populate_record(null::sectalk_private.st_v6_attachment_scans,
    jsonb_build_object('file_id',malware_key,'state','malware','scanned_at',now())));
  select q.id into strict detection_item from sectalk_private.st_v7_threat_items q where q.source_key=detection_key::text;
  select q.id into strict malware_item from sectalk_private.st_v7_threat_items q where q.source_key=malware_key::text;
  perform sectalk_private.st_v7_enqueue_threat('detection',gen_random_uuid()::text,'low','supported','{}',now()+interval '1 second')
    from generate_series(1,42);
  selection:=jsonb_build_array(jsonb_build_object('id',detection_item,'revision',1));

  perform set_config('request.jwt.claims',jsonb_build_object('sub',reviewer_id,'role','authenticated',
    'session_id',reviewer_session,'aal','aal2')::text,true);
  set local role authenticated;
  if (select count(*) from public.st_v7_threat_queue())<>41
    or not exists(select 1 from public.st_v7_threat_queue('open','detection','medium','supported') q where q.id=detection_item)
    or exists(select 1 from public.st_v7_threat_queue('all','malware'))
    or exists(select 1 from public.st_v7_threat_triage_history(malware_item))
    or (select count(*) from public.st_v7_threat_triage_history(detection_item))<>1 then
    raise exception 'Queue filtering, scope, or deduplication failed';
  end if;
  begin
    perform public.st_v7_apply_threat_triage(selection||jsonb_build_array(jsonb_build_object('id',malware_item,'revision',1)),
      'reviewing',note);
    raise exception 'Mixed-scope decision accepted';
  exception when insufficient_privilege then null; end;
  if (select count(*) from public.st_v7_threat_triage_history(detection_item))<>1 then raise exception 'Mixed decision partially audited'; end if;
  begin
    perform public.st_v7_apply_threat_triage(selection||selection,'reviewing',note);
    raise exception 'Duplicate selection accepted';
  exception when invalid_parameter_value then null; end;
  if public.st_v7_apply_threat_triage(selection,'confirmed',note)<>1 then raise exception 'Confirmation failed'; end if;
  begin
    perform public.st_v7_apply_threat_triage(selection,'dismissed',note);
    raise exception 'Stale decision accepted';
  exception when sqlstate 'PT409' then null; end;
  if public.st_v7_apply_threat_triage(jsonb_build_array(jsonb_build_object('id',detection_item,'revision',2)),'reopened',note)<>1 then
    raise exception 'Reopening failed';
  end if;
  reset role;
  begin
    delete from sectalk_private.st_v7_threat_triage_audit a where a.item_id=detection_item;
    raise exception 'Immutable audit deletion succeeded';
  exception when insufficient_privilege then null; end;
  if not exists(select 1 from sectalk_private.st_v7_threat_triage_audit a where a.item_id=detection_item
    and a.action='reopened' and a.previous_state='confirmed' and a.state='open' and a.actor=reviewer_id and a.reason=note) then
    raise exception 'Reopening audit missing';
  end if;
end $$;

rollback;
