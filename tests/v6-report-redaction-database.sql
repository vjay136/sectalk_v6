begin;
insert into auth.users(id,email) values
  ('99800000-0000-4000-8000-000000000001','redaction-author@example.invalid'),
  ('99800000-0000-4000-8000-000000000002','redaction-reporter@example.invalid'),
  ('99800000-0000-4000-8000-000000000003','redaction-moderator@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('99800000-0000-4000-8000-000000000001','redaction_author','Redaction Author'),
  ('99800000-0000-4000-8000-000000000002','redaction_reporter','Redaction Reporter'),
  ('99800000-0000-4000-8000-000000000003','redaction_moderator','Redaction Moderator');
insert into sectalk_private.staff values('99800000-0000-4000-8000-000000000003');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
  ('99800000-0001-4000-8000-000000000003','99800000-0000-4000-8000-000000000003','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
  ('99800000-0002-4000-8000-000000000003','99800000-0000-4000-8000-000000000003','aal2','99800000-0001-4000-8000-000000000003');

do $$
declare
  writer constant uuid:='99800000-0000-4000-8000-000000000001';
  recipient constant uuid:='99800000-0000-4000-8000-000000000002';
  staff constant uuid:='99800000-0000-4000-8000-000000000003';
  session constant uuid:='99800000-0002-4000-8000-000000000003';
  chat uuid;
  shared_id uuid:=gen_random_uuid();
  changed_id uuid:=gen_random_uuid();
  target_case uuid;
  changed_report uuid;
begin
  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',writer,'role','authenticated')::text,true);
  chat:=public.st_request('redaction_reporter');
  perform set_config('request.jwt.claims',json_build_object('sub',recipient,'role','authenticated')::text,true);
  perform public.st_respond(chat,true);
  perform set_config('request.jwt.claims',json_build_object('sub',writer,'role','authenticated')::text,true);
  perform public.st_send(chat,shared_id,'Shared report evidence');
  perform public.st_send(chat,changed_id,'Original reported text');
  perform set_config('request.jwt.claims',json_build_object('sub',recipient,'role','authenticated')::text,true);
  target_case:=public.st_v5_report(chat,shared_id,'harassment','Review this fixture');
  changed_report:=public.st_v5_report(chat,changed_id,'harassment','Review the edited fixture');
  begin
    perform public.st_v6_case_redact(target_case,'Ordinary account request');
    raise exception 'An ordinary user redacted a peer message';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',writer,'role','authenticated')::text,true);
  perform public.st_v2_edit_message(changed_id,'Different live revision');

  perform set_config('request.jwt.claims',json_build_object('sub',staff,'role','authenticated','aal','aal2','session_id',gen_random_uuid())::text,true);
  begin
    perform public.st_v6_case_redact(target_case,'Unverified session request');
    raise exception 'A stale staff session redacted evidence';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',staff,'role','authenticated','aal','aal2','session_id',session)::text,true);
  if (public.st_v5_case(target_case)->>'message_redaction_available') is distinct from 'true'
    or (public.st_v5_case(changed_report)->>'message_redaction_available') is distinct from 'false'
  then raise exception 'Wrong redaction eligibility'; end if;
  begin
    perform public.st_v6_case_redact(changed_report,'Do not redact an unshared revision');
    raise exception 'Changed message was removed without a new report' using errcode='P0100';
  exception when raise_exception then null; end;
  perform public.st_v6_case_redact(target_case,'Verified case moderation');
  perform public.st_v6_case_redact(target_case,'Verified case moderation');
  if public.st_v5_case(target_case)->>'evidence'<>'Shared report evidence'
    or public.st_v5_case(target_case)->>'message_redaction_available'<>'false'
  then raise exception 'Case evidence or finalized state was lost'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',recipient,'role','authenticated')::text,true);
  if not exists(select 1 from public.st_messages m where m.id=shared_id and m.body='Message removed' and m.revoked_at is not null)
    or (select count(*) from public.st_v5_report_timeline(target_case) where action='redacted')<>1
    or exists(select 1 from public.st_v6_search('Shared report evidence','direct',null))
  then raise exception 'Tombstone, search, or reporter history did not honor redaction'; end if;
  reset role;
  if (select count(*) from sectalk_private.audit a where a.report_id=target_case and a.action='redacted')<>1
  then raise exception 'Redaction retry produced an incorrect audit record'; end if;
end $$;
select 'passed: case-bound redaction, native MFA, scope limits, tombstone, retained evidence and audited retry' as result;
rollback;
