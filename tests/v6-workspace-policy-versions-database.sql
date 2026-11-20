begin;
insert into auth.users(id,email) values
 ('d5bc3b26-df75-4eb4-a2d1-4a244fd00001','versions-owner@example.invalid'),
 ('d5bc3b26-df75-4eb4-a2d1-4a244fd00002','versions-other@example.invalid');
insert into public.st_profiles(id,handle,name) values
 ('d5bc3b26-df75-4eb4-a2d1-4a244fd00001','versions_test_owner','Versions owner'),
 ('d5bc3b26-df75-4eb4-a2d1-4a244fd00002','versions_test_other','Versions outsider');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
 ('d5bc3b26-df75-4eb4-a2d1-4a244fd00011','d5bc3b26-df75-4eb4-a2d1-4a244fd00001','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
 ('d5bc3b26-df75-4eb4-a2d1-4a244fd00021','d5bc3b26-df75-4eb4-a2d1-4a244fd00001','aal2','d5bc3b26-df75-4eb4-a2d1-4a244fd00011');

do $$
declare
  workspace uuid;
  room uuid:=gen_random_uuid();
  outcome jsonb;
begin
  set local role authenticated;
  perform set_config('request.jwt.claims',
    '{"sub":"d5bc3b26-df75-4eb4-a2d1-4a244fd00001","role":"authenticated","aal":"aal2","session_id":"d5bc3b26-df75-4eb4-a2d1-4a244fd00021"}',true);
  workspace:=public.st_v2_create_workspace('Policy version fixture');
  perform public.st_v6_room_create(room,workspace,'Archived policy fixture','public','blank');
  perform public.st_v6_room_settings(room,'archive');
  perform public.st_v6_room_retirement(room,'schedule');
  reset role;
  update sectalk_private.st_v6_room_retirements set requested_at=now()-interval '10 days' where room_id=room;
  set local role authenticated;
  outcome:=public.st_v6_change_workspace_policy(workspace,'retention','preview','{"days":7}',0);
  if outcome->>'queued'<>'1' or outcome->>'eligible_under_proposal'<>'1'
    or public.st_v6_room_retention_policy(workspace)<>30
  then raise exception 'Dry run changed live policy or misreported eligibility'; end if;
  outcome:=public.st_v6_change_workspace_policy(workspace,'retention','apply','{"days":7}',0);
  if outcome->>'version'<>'1' or public.st_v6_room_retention_policy(workspace)<>7
  then raise exception 'Policy application did not enforce new retention'; end if;
  outcome:=public.st_v6_change_workspace_policy(workspace,'retention','apply','{"days":7}',1);
  if outcome->>'version'<>'1' then raise exception 'Unchanged policy produced a duplicate version'; end if;
  perform public.st_v6_room_retention_policy(workspace,14);
  begin
    perform public.st_v6_change_workspace_policy(workspace,'retention','rollback',null,1,0);
    raise exception 'Rollback overwrote a newer policy';
  exception when serialization_failure then null; end;
  outcome:=public.st_v6_change_workspace_policy(workspace,'retention','rollback',null,2,0);
  if outcome->>'version'<>'3' or jsonb_array_length(outcome->'entries')<>4
    or public.st_v6_room_retention_policy(workspace)<>30
  then raise exception 'Rollback did not restore baseline as a new version'; end if;
  outcome:=public.st_v6_change_workspace_policy(workspace,'notifications','preview','{"categories":["mention"],"quiet_minutes":20}',0);
  if outcome->'new_mandatory'<>'["mention"]'::jsonb
    or public.st_v6_workspace_notification_settings(workspace)->'mandatory_categories'<>'[]'::jsonb
  then raise exception 'Notification dry run changed delivery policy'; end if;
  outcome:=public.st_v6_change_workspace_policy(workspace,'notifications','apply','{"categories":["mention"],"quiet_minutes":20}',0);
  if outcome->>'version'<>'1' or public.st_v6_workspace_notification_settings(workspace)->>'max_quiet_minutes'<>'20'
  then raise exception 'Versioned change did not reach the existing delivery policy'; end if;
  perform public.st_v6_change_workspace_policy(workspace,'notifications','rollback',null,1,0);
  if public.st_v6_workspace_notification_settings(workspace)->'mandatory_categories'<>'[]'::jsonb
  then raise exception 'Notification rollback failed'; end if;
  perform set_config('request.jwt.claims','{"sub":"d5bc3b26-df75-4eb4-a2d1-4a244fd00002","role":"authenticated"}',true);
  begin
    perform public.st_v6_workspace_policy_versions(workspace,'retention');
    raise exception 'An unrelated user read policy history';
  exception when insufficient_privilege then null; end;
end $$;
select 'passed: scoped policy preview, application, stale update denial and versioned rollback' as result;
rollback;
