begin;

do $$
declare
  actor uuid; platform_id uuid:=gen_random_uuid(); owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid();
  reporter_id uuid:=gen_random_uuid(); subject_id uuid:=gen_random_uuid(); outsider_id uuid:=gen_random_uuid();
  session_id uuid; factor_id uuid; claims jsonb:='{}'; space uuid; room_id uuid:=gen_random_uuid();
  managed_room uuid:=gen_random_uuid(); post_id uuid:=gen_random_uuid(); managed_post uuid:=gen_random_uuid();
  report_id uuid; managed_report uuid:=gen_random_uuid(); response_id uuid; events jsonb;
  note constant text:='Private operator-only rationale for disposable validation.';
begin
  foreach actor in array array[platform_id,owner_id,reviewer_id,reporter_id,subject_id,outsider_id] loop
    session_id:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'st_tl_'||left(actor::text,8),'Private timeline actor');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor_id,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',session_id,'aal','aal2'));
  end loop;
  insert into sectalk_private.staff values(platform_id);
  insert into sectalk_private.st_v6_case_on_call(user_id,tier,starts_at,ends_at)
    select platform_id,tier,now(),now()+interval '1 hour' from generate_series(1,3) tier;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  space:=public.st_v2_create_workspace('Disposable room timeline');
  perform public.st_v6_room_create(room_id,space,'Disposable standard room','public','blank');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(space,reporter_id,'member'),(space,subject_id,'member'),(space,reviewer_id,'admin');
  insert into public.st_v6_room_members(room_id,user_id,role) values(room_id,reporter_id,'member'),(room_id,subject_id,'member'),(room_id,reviewer_id,'moderator');
  insert into sectalk_private.st_v7_soc_response_grants(actor,action,workspace,role) values
    (owner_id,'quarantine_room_post',space,'requester'),(reviewer_id,'quarantine_room_post',space,'approver');
  insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator,encryption_mode)
    values(managed_room,space,'Disposable managed room','public','blank',owner_id,'managed');
  insert into sectalk_private.st_v6_room_reports(id,workspace_id,room_id,post_id,reporter,subject,category,details,share_with_workspace)
    values(managed_report,space,managed_room,managed_post,reporter_id,subject_id,'threat','Private managed notes',false);
  insert into sectalk_private.st_v8_managed_room_evidence(report,room,post,workspace,sender,key_version,revision,body,nonce,tag,wrapped_dek)
    values(managed_report,managed_room,managed_post,space,subject_id,1,repeat('a',64),'EXCLUDED_ENVELOPE','nonce','tag',repeat('b',80));
  insert into sectalk_private.st_v8_managed_room_evidence_reads(report,actor,revision) values(managed_report,platform_id,repeat('a',64));

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>subject_id::text,true);
  perform public.st_v6_room_post(room_id,post_id,'Private standard report message');
  perform set_config('request.jwt.claims',claims->>reporter_id::text,true);
  report_id:=public.st_v6_submit_room_report(room_id,post_id,'spam','Reporter private note',true);
  if (select array_agg(t.action) from public.st_v8_my_room_report_timeline(report_id) t) is distinct from array['submitted']::text[]
    then raise exception 'Initial timeline missing'; end if;

  perform set_config('request.jwt.claims',claims->>platform_id::text,true);
  perform public.st_v6_review_room_report(report_id,'platform','route',note,0::smallint);
  perform public.st_v6_review_room_report(report_id,'platform','acknowledge',note,1::smallint);
  perform public.st_v6_review_room_report(report_id,'platform','route',note,1::smallint);
  perform public.st_v6_review_room_report(report_id,'platform','acknowledge',note,2::smallint);
  perform public.st_v6_review_room_report(report_id,'platform','route',note,2::smallint);
  perform public.st_v6_review_room_report(managed_report,'platform','reviewing',note,0::smallint);
  perform public.st_v6_review_room_report(managed_report,'platform','dismissed',note,0::smallint);
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v6_review_room_report(report_id,'workspace','acknowledge',note,3::smallint);
  response_id:=public.st_v7_request_soc_response('quarantine_room_post',space,report_id,null,null,note);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v7_decide_soc_response(response_id,true,note);
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v6_review_room_report(report_id,'workspace','route',note,3::smallint);
  perform set_config('request.jwt.claims',claims->>platform_id::text,true);
  perform public.st_v6_review_room_report(report_id,'platform','acknowledge',note,4::smallint);
  perform public.st_v6_review_room_report(report_id,'platform','resolved',note,4::smallint);

  foreach actor in array array[platform_id,owner_id,reviewer_id,subject_id,outsider_id] loop
    perform set_config('request.jwt.claims',claims->>actor::text,true);
    if exists(select 1 from public.st_v8_my_room_report_timeline(report_id))
      or exists(select 1 from public.st_v8_my_room_report_timeline(managed_report)) then raise exception 'Timeline leaked to another actor'; end if;
  end loop;
  perform set_config('request.jwt.claims',claims->>reporter_id::text,true);
  select jsonb_agg(to_jsonb(t)) into events from public.st_v8_my_room_report_timeline(report_id) t;
  if (select array_agg(x->>'action') from jsonb_array_elements(events) x) is distinct from
    array['submitted','reviewing','handoff','quarantined','returned_to_platform','resolved']::text[]
    or (select array_agg(x->>'scope') from jsonb_array_elements(events) x) is distinct from
    array[null,'platform','workspace','workspace','platform','platform']::text[]
    or exists(select 1 from jsonb_array_elements(events) x where x-ARRAY['action','at','scope']<>'{}'::jsonb) then
    raise exception 'Unexpected shared timeline: %',events; end if;
  select jsonb_agg(to_jsonb(t)) into events from public.st_v8_my_room_report_timeline(managed_report) t;
  if (select array_agg(x->>'action') from jsonb_array_elements(events) x) is distinct from array['submitted','reviewing','dismissed']::text[]
    or events::text like '%EXCLUDED_ENVELOPE%' or events::text like '%Private%' then raise exception 'Managed room timeline: %',events; end if;
  reset role;
  delete from auth.sessions n where n.user_id=reporter_id;
  set local role authenticated;
  if exists(select 1 from public.st_v8_my_room_report_timeline(report_id)) then raise exception 'Ended session retained access'; end if;
  reset role;
  if has_function_privilege('anon','public.st_v8_my_room_report_timeline(uuid)','EXECUTE')
    or has_function_privilege('service_role','public.st_v8_my_room_report_timeline(uuid)','EXECUTE') then raise exception 'Unwanted timeline grant'; end if;
end $$;

select 'passed: reporter-only standard and managed room progress, actual scoped response and no internal audit leakage';
rollback;
