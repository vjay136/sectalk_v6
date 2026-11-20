begin;
do $$
declare manager uuid:=gen_random_uuid(); student uuid:=gen_random_uuid(); classmate uuid:=gen_random_uuid(); outsider uuid:=gen_random_uuid();
  manager_session uuid:=gen_random_uuid(); student_session uuid:=gen_random_uuid(); outsider_session uuid:=gen_random_uuid();
  workspace uuid; link uuid; pending_chat uuid; accepted_chat uuid; result jsonb;
  manager_jwt text:=jsonb_build_object('sub',manager,'session_id',manager_session,'role','authenticated','aal','aal1')::text;
  student_jwt text:=jsonb_build_object('sub',student,'session_id',student_session,'role','authenticated','aal','aal1')::text;
  outsider_jwt text:=jsonb_build_object('sub',outsider,'session_id',outsider_session,'role','authenticated','aal','aal1')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (manager,'managed-manager@example.invalid',now()),(student,'managed-student@example.invalid',now()),
    (classmate,'managed-classmate@example.invalid',now()),(outsider,'managed-outsider@example.invalid',now());
  insert into public.st_profiles(id,handle,name) values
    (manager,'managed_manager','Manager'),(student,'managed_student','Student'),
    (classmate,'managed_classmate','Classmate'),(outsider,'managed_outsider','Outsider');
  insert into auth.sessions(id,user_id,aal) values(manager_session,manager,'aal1'),(student_session,student,'aal1'),
    (outsider_session,outsider,'aal1');
  insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature)
    values(gen_random_uuid(),student,'trusted',repeat('A',87),repeat('B',87),repeat('C',86));
  insert into public.st_chats(member_a,member_b,requester,status) values
    (least(student,outsider),greatest(student,outsider),student,'accepted') returning id into accepted_chat;
  insert into public.st_chats(member_a,member_b,requester) values
    (least(manager,student),greatest(manager,student),manager) returning id into pending_chat;
  if has_table_privilege('authenticated','sectalk_private.st_v7_managed_accounts','select') or
    has_function_privilege('anon','public.st_v7_managed_account(uuid,text,uuid,uuid,boolean)','execute') then
    raise exception 'Managed relationship storage exposed';
  end if;

  set local role authenticated;
  perform set_config('request.jwt.claims',manager_jwt,true);
  workspace:=public.st_v6_create_typed_workspace(gen_random_uuid(),'School oversight','school');
  begin
    perform public.st_v7_managed_account(workspace,'offer',student);
    raise exception 'Stale supervisor offered oversight';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,student,'member'),(workspace,classmate,'member');
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
    (gen_random_uuid(),manager_session,'password',now(),now()),(gen_random_uuid(),student_session,'password',now(),now());
  set local role authenticated;
  result:=public.st_v7_managed_account(workspace,'offer',student);
  link:=(result#>>'{relationships,0,id}')::uuid;
  if result#>>'{relationships,0,verifiedDevices}' is not null then raise exception 'Device count leaked before consent'; end if;
  begin
    perform public.st_v7_managed_account(workspace,'accept',p_link=>link);
    raise exception 'Supervisor consented for participant';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',student_jwt,true);
  result:=public.st_v7_managed_account(workspace,'accept',p_link=>link);
  if result->>'kind'<>'school' or result#>>'{relationships,0,state}'<>'active'
    or result#>>'{relationships,0,verifiedDevices}'<>'1' or result::text like '%AAAAAAAAAA%' then
    raise exception 'Consent or scoped device summary failed';
  end if;
  perform public.st_respond(pending_chat,true);
  if public.st_request('managed_classmate') is null then raise exception 'Classmate request blocked'; end if;
  if public.st_request('managed_outsider') is distinct from accepted_chat then raise exception 'Existing connection was removed'; end if;
  perform public.st_send(accepted_chat,gen_random_uuid(),'Private fixture text');
  perform set_config('request.jwt.claims',manager_jwt,true);
  if exists(select 1 from public.st_messages where chat_id=accepted_chat) then raise exception 'Oversight exposed private content'; end if;
  perform set_config('request.jwt.claims',outsider_jwt,true);
  begin
    perform public.st_v7_managed_account(workspace);
    raise exception 'Outsider read oversight';
  exception when insufficient_privilege then null; end;
  reset role;
  update public.st_v2_members set suspended_at=clock_timestamp() where workspace_id=workspace and user_id=student;
  update public.st_v2_members set suspended_at=null where workspace_id=workspace and user_id=student;
  set local role authenticated;
  perform set_config('request.jwt.claims',manager_jwt,true);
  result:=public.st_v7_managed_account(workspace);
  if result#>>'{relationships,0,state}'<>'ended' or result#>>'{relationships,0,verifiedDevices}' is not null then
    raise exception 'Membership restoration reactivated oversight or retained device disclosure';
  end if;
end
$$;
select 'passed: school identity scope, two-party fresh consent, device minimization, accepted chat privacy and durable roster revocation' as result;
rollback;
