begin;

do $$
<<fixture>>
declare
  staff_id uuid:=gen_random_uuid(); reporter_id uuid:=gen_random_uuid(); subject_id uuid:=gen_random_uuid(); outsider uuid:=gen_random_uuid();
  actor uuid; session_id uuid; factor_id uuid; claims jsonb:='{}'; chat uuid; post uuid:=gen_random_uuid();
  report_id uuid; group_case uuid:=gen_random_uuid(); events jsonb;
  hidden constant text:='PRIVATE_ONLY operator reason and restricted moderation information.';
  shared constant text:='We reviewed your report and closed this case.';
begin
  foreach actor in array array[staff_id,reporter_id,subject_id,outsider] loop
    session_id:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'rs_'||left(actor::text,8),'Disposable resolution participant');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor_id,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',session_id,'aal','aal2'));
  end loop;
  insert into sectalk_private.staff values(staff_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reporter_id::text,true);
  chat:=public.st_request('rs_'||left(subject_id::text,8));
  perform set_config('request.jwt.claims',claims->>subject_id::text,true);
  perform public.st_respond(chat,true);
  perform public.st_send(chat,post,'PRIVATE_ONLY reported evidence');
  perform set_config('request.jwt.claims',claims->>reporter_id::text,true);
  report_id:=public.st_v5_report(chat,post,'scam','PRIVATE_ONLY reporter notes',false);
  reset role;
  insert into public.st_reports(id,reporter,subject,group_chat_id,group_message_id,category,details)
    values(group_case,reporter_id,subject_id,gen_random_uuid(),gen_random_uuid(),'scam',hidden);
  insert into sectalk_private.staff values(subject_id);

  set local role authenticated;
  foreach actor in array array[reporter_id,subject_id,outsider] loop
    perform set_config('request.jwt.claims',claims->>actor::text,true);
    begin
      perform public.st_v8_resolve_direct_report(report_id,'resolved',hidden,shared);
      raise exception 'An unauthorized participant could resolve the report';
    exception when insufficient_privilege then null; end;
  end loop;
  perform set_config('request.jwt.claims',claims->>staff_id::text,true);
  if public.st_v5_case(report_id)->>'report_scope' is distinct from 'direct'
    or public.st_v5_case(group_case)->>'report_scope' is distinct from 'group' then raise exception 'Staff case type missing'; end if;
  begin
    perform public.st_v8_resolve_direct_report(report_id,'resolved',hidden,E' \n ');
    raise exception 'Accepted an empty reporter summary';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_v8_resolve_direct_report(group_case,'resolved',hidden,shared);
    raise exception 'Accepted a summary for an encrypted-group case';
  exception when insufficient_privilege then null; end;
  perform public.st_v5_moderate(report_id,'reviewing',hidden);
  perform public.st_v8_resolve_direct_report(report_id,'resolved',hidden,shared);
  begin
    perform public.st_v8_resolve_direct_report(report_id,'dismissed',hidden,'Conflicting terminal summary');
    raise exception 'Accepted a conflicting terminal decision';
  exception when sqlstate 'PT409' then null; end;
  perform public.st_v5_moderate(group_case,'dismissed',hidden);

  foreach actor in array array[staff_id,subject_id,outsider] loop
    perform set_config('request.jwt.claims',claims->>actor::text,true);
    if exists(select 1 from public.st_v8_my_message_report_timeline(report_id)) then raise exception 'Timeline exposed to non-reporter'; end if;
  end loop;
  perform set_config('request.jwt.claims',claims->>reporter_id::text,true);
  select jsonb_agg(to_jsonb(t)) into events from public.st_v8_my_message_report_timeline(report_id) t;
  if (select array_agg(x->>'action') from jsonb_array_elements(events) x) is distinct from array['resolved','reviewing','submitted']::text[]
    or (select array_agg(x->>'summary') from jsonb_array_elements(events) x) is distinct from array[shared,null,null]::text[]
    or exists(select 1 from jsonb_array_elements(events) x where x-ARRAY['action','at','summary']<>'{}'::jsonb)
    or events::text like '%PRIVATE_ONLY%' then raise exception 'Unexpected reporter direct timeline %',events; end if;
  select jsonb_agg(to_jsonb(t)) into events from public.st_v8_my_message_report_timeline(group_case) t;
  if (select array_agg(x->>'action') from jsonb_array_elements(events) x) is distinct from array['dismissed','submitted']::text[]
    or exists(select 1 from jsonb_array_elements(events) x where x->>'summary' is not null)
    or events::text like '%PRIVATE_ONLY%' then raise exception 'Unexpected legacy encrypted-group timeline %',events; end if;
  reset role;
  if not exists(select 1 from sectalk_private.st_v8_direct_report_resolution_summaries d join sectalk_private.audit a on a.id=d.decision
    where d.report=fixture.report_id and d.summary=shared and a.actor=staff_id and a.action='resolved' and a.note=hidden)
    or has_table_privilege('authenticated','sectalk_private.st_v8_direct_report_resolution_summaries','SELECT')
    or has_function_privilege('anon','public.st_v8_my_message_report_timeline(uuid)','EXECUTE') then raise exception 'Invalid audit separation or privilege'; end if;
end $$;

select 'passed: direct terminal decision and reporter-only summary, private audit and legacy group timeline preserved';
rollback;
