begin;
do $$
declare owner uuid:=gen_random_uuid(); other uuid:=gen_random_uuid(); clean uuid:=gen_random_uuid();
  owner_session uuid:=gen_random_uuid(); other_session uuid:=gen_random_uuid(); clean_session uuid:=gen_random_uuid();
  chat uuid; workspace uuid; hold uuid:=gen_random_uuid(); result jsonb;
begin
  insert into auth.users(id,email) values(owner,'settings-owner@example.invalid'),(other,'settings-other@example.invalid'),
    (clean,'settings-delete@example.invalid');
  insert into public.st_profiles(id,handle,name) values(owner,'p_settings_owner','Settings owner'),
    (other,'p_settings_other','Settings other'),(clean,'p_settings_delete','Settings delete');
  insert into auth.sessions(id,user_id,aal) values(owner_session,owner,'aal1'),(other_session,other,'aal1'),(clean_session,clean,'aal1');
  insert into public.st_chats(member_a,member_b,requester,status)
    values(least(owner,other),greatest(owner,other),owner,'accepted') returning id into chat;
  insert into public.st_messages(id,chat_id,sender,body,expires_at) values
    (gen_random_uuid(),chat,owner,'Personal owner export text',null),
    (gen_random_uuid(),chat,other,'Peer text must not be exported',null),
    (gen_random_uuid(),chat,owner,'Disappearing message excluded',now()+interval '1 minute');
  insert into public.st_v2_workspaces(name,owner) values('Synthetic hold workspace',owner) returning id into workspace;
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,owner,'owner');
  insert into public.st_v6_saved_searches(user_id,query,kind)
    values(owner,'my own saved search','direct'),(other,'another account saved search','direct');
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold,workspace,clean,'Synthetic preservation test',owner);
  if has_function_privilege('anon','public.st_v7_personal_data_export(uuid,timestamptz,uuid)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v7_user_appearance','select') then
    raise exception 'Personal settings are exposed outside the account';
  end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner,'session_id',owner_session,'aal','aal1')::text,true);
  set local role authenticated;
  result:=public.st_v7_user_appearance(owner,'high-contrast',true);
  if result<>jsonb_build_object('theme','high-contrast','reduceMotion',true) then raise exception 'Appearance did not persist'; end if;
  begin
    perform public.st_v7_user_appearance(owner,'invalid',false);
    raise exception 'Invalid theme accepted';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_v8_personal_data_export(owner);
    raise exception 'Unverified session exported account data';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'password',now(),now()),(gen_random_uuid(),clean_session,'password',now(),now());

  set local role authenticated;
  result:=public.st_v8_personal_data_export(owner);
  if result#>>'{profile,handle}'<>'p_settings_owner' or jsonb_array_length(result->'authoredMessages')<>1
    or result#>>'{authoredMessages,0,body}'<>'Personal owner export text'
    or result#>>'{appearance,theme}'<>'high-contrast'
    or jsonb_array_length(result#>'{personalSettings,savedSearches}')<>1
    or result#>>'{personalSettings,savedSearches,0,query}'<>'my own saved search'
    or result#>>'{personalSettings,currentWorkspaces,0,id}'<>workspace::text then
      raise exception 'Self export lost scope or leaked private data'; end if;
  begin
    perform public.st_v7_personal_deletion(owner,'request','WRONG');
    raise exception 'Deletion happened without explicit confirmation';
  exception when invalid_parameter_value then null; end;
  if public.st_v7_personal_deletion(owner,'request','DELETE ACCOUNT')->>'status'<>'needs_review' then
    raise exception 'Account with retained conversation did not enter review';
  end if;
  if not (public.st_v8_personal_deletion_status(owner)->'blockers' ? 'workspace_owner') then
    raise exception 'Ownership blocker was missing from the owner status'; end if;
  if public.st_v7_personal_deletion(owner,'cancel')->>'status'<>'none' then raise exception 'Request could not be retracted'; end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',other,'session_id',other_session,'aal','aal1')::text,true);
  begin
    perform public.st_v7_user_appearance(owner);
    raise exception 'Appearance exposed across accounts';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_personal_deletion_status(owner);
    raise exception 'Deletion status exposed across accounts';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',clean,'session_id',clean_session,'aal','aal1')::text,true);
  begin
    perform public.st_v7_personal_deletion(clean,'retry','DELETE ACCOUNT');
    raise exception 'Retry accepted without an existing request';
  exception when invalid_parameter_value then null; end;
  result:=public.st_v7_personal_deletion(clean,'request','DELETE ACCOUNT');
  if result->>'status'<>'needs_review' or public.st_v7_personal_deletion(clean,'retry','DELETE ACCOUNT')<>result then
    raise exception 'Active hold did not preserve the original pending request';
  end if;
  if public.st_v8_personal_deletion_status(clean)->'blockers'<>'["retained_content"]'::jsonb then
    raise exception 'Retained content summary disclosed or misplaced a blocker'; end if;
  reset role;
  update sectalk_private.st_v6_workspace_holds set released_at=now(),released_by=owner,release_reason='Synthetic authorized release' where id=hold;
  set local role authenticated;
  if public.st_v7_personal_deletion(clean,'retry','DELETE ACCOUNT')->>'status'<>'deleted' then
    raise exception 'Eligible unused account was not deleted';
  end if;
  reset role;
  if exists(select 1 from auth.users where id=clean) or exists(select 1 from auth.sessions where user_id=clean)
    or not exists(select 1 from auth.users where id=owner) then raise exception 'Account deletion scope was incorrect'; end if;
end
$$;
select 'passed: isolated appearance, fresh credentials, scoped JSON export, dependent request/cancel, hold release retry and actual eligible-account deletion' as result;
rollback;
