begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid(); factor uuid:=gen_random_uuid();
  owner_session uuid:=gen_random_uuid(); sso_session uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid();
  workspace uuid; room uuid:=gen_random_uuid(); task uuid; event uuid; direct_chat uuid;
  room_task uuid:=gen_random_uuid(); direct_task uuid:=gen_random_uuid(); checklist uuid:=gen_random_uuid();
  provider text:='custom:planner-sso-rollback'; domain text:='planner-sso.example.invalid';
  member_handle text:='planner_'||left(replace(actor::text,'-',''),12);
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  pass_claim text:=jsonb_build_object('sub',actor,'session_id',password_session,'role','authenticated')::text;
  sso_claim text:=jsonb_build_object('sub',actor,'session_id',sso_session,'role','authenticated')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'owner@planner-sso.example.invalid',now()),
    (actor,'member@planner-sso.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values(owner_id,'owner_'||left(replace(owner_id::text,'-',''),12),'Planner owner'),
    (actor,member_handle,'Planner member');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),
    (sso_session,actor,'aal1',null),(password_session,actor,'aal1',null);
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Fixture OIDC','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  workspace:=public.st_v2_create_workspace('Workspace planning SSO fixture');
  if public.st_v8_workspace_planner_policy(workspace,true)->>'access' is distinct from 'mfa' then
    raise exception 'Owner enabled planning SSO without fresh native TOTP'; end if;
  reset role;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(workspace,domain,now());
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,actor,'member');
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(workspace,'save',domain,'oidc',true);
  if public.st_v8_workspace_planner_policy(workspace,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'Planning SSO enabled without an observed provider receipt'; end if;
  task:=public.st_v2_add_item(workspace,'task','Planner receipt sentinel','Board details',now()+interval '1 hour');
  event:=public.st_v2_add_item(workspace,'event','A workspace event','Event details',now()+interval '1 hour');
  perform public.st_v4_task_change(task,'assign',actor);
  perform public.st_v4_task_change(task,'checklist.add',null,checklist,'Review plan');
  perform public.st_v6_room_create(room,workspace,'Private planning room','private','project');
  perform public.st_v6_task_create(room_task,room,null,'Room planning sentinel');
  direct_chat:=public.st_request(member_handle);
  reset role;
  insert into public.st_v6_room_members(room_id,user_id,role) values(room,actor,'member');
  set local role authenticated;
  perform set_config('request.jwt.claims',pass_claim,true);
  perform public.st_respond(direct_chat,true);
  perform public.st_v6_task_create(direct_task,null,direct_chat,'Direct task unaffected');
  if public.st_v8_workspace_planner_requires_sso(workspace)
    or not exists(select 1 from public.st_v2_items where id=task)
    or not exists(select 1 from public.st_v6_tasks where id=room_task) then
    raise exception 'Planning SSO changed an unprotected workspace'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(sso_session,workspace,actor,'oidc',provider);

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_planner_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not enable planning SSO'; end if;
  perform set_config('request.jwt.claims',pass_claim,true);
  if not public.st_v8_workspace_planner_requires_sso(workspace)
    or not exists(select 1 from public.st_v2_members where workspace_id=workspace and user_id=actor)
    or exists(select 1 from public.st_v2_items where id in (task,event))
    or exists(select 1 from public.st_v4_task_assignments where task_id=task)
    or exists(select 1 from public.st_v4_checklist where id=checklist)
    or exists(select 1 from public.st_v6_tasks where id=room_task)
    or exists(select 1 from public.st_v6_task_audit where task_id=room_task)
    or not exists(select 1 from public.st_v6_tasks where id=direct_task)
    or exists(select 1 from public.st_v6_search('Planner receipt sentinel','board') where id=task)
    or exists(select 1 from public.st_v6_search('Planner receipt sentinel','board','{}') where id=task) then
    raise exception 'Password session leaked protected planning data or lost membership/direct tasks'; end if;
  begin
    perform public.st_v2_add_item(workspace,'event','Blocked event','',now());
    raise exception 'Password session wrote a protected event';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v2_complete_task(task,true);
    raise exception 'Password session completed a protected task' using errcode='P0004';
  exception when raise_exception then null;
  end;
  begin
    perform public.st_v4_task_change(task,'checklist.toggle',null,checklist,null,true);
    raise exception 'Password session toggled a protected checklist';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_task_update(room_task,'watch',p_enabled=>true);
    raise exception 'Password session subscribed to a protected room task' using errcode='P0004';
  exception when raise_exception then null;
  end;
  begin
    perform public.st_v6_task_create(gen_random_uuid(),room,null,'Blocked room task');
    raise exception 'Password session created a protected room task' using errcode='P0004';
  exception when raise_exception then null;
  end;
  perform public.st_v6_task_update(direct_task,'status','done');

  perform set_config('request.jwt.claims',sso_claim,true);
  if public.st_v8_workspace_planner_requires_sso(workspace)
    or not exists(select 1 from public.st_v2_items where id=event)
    or not exists(select 1 from public.st_v4_task_assignments where task_id=task and assignee=actor)
    or not exists(select 1 from public.st_v6_tasks where id=room_task)
    or not exists(select 1 from public.st_v6_search('Planner receipt sentinel','board') where id=task)
    or not exists(select 1 from public.st_v6_search('Planner receipt sentinel','board','{}') where id=task) then
    raise exception 'Current provider session lost protected planning data'; end if;
  perform public.st_v4_task_change(task,'checklist.toggle',null,checklist,null,true);
  perform public.st_v2_complete_task(task,true);
  if not exists(select 1 from public.st_v4_checklist where id=checklist and completed)
    or not exists(select 1 from public.st_v2_items where id=task and completed) then
    raise exception 'Current provider session could not update protected task state'; end if;
  perform public.st_v6_task_create(gen_random_uuid(),room,null,'Workspace provider room task');
  perform public.st_v6_task_update(room_task,'watch',p_enabled=>true);
  if public.st_v8_workspace_planner_policy(workspace,false)->>'required' is not null then
    raise exception 'Ordinary member could change the planning SSO policy'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;

  set local role authenticated;
  if not public.st_v8_workspace_planner_requires_sso(workspace)
    or exists(select 1 from public.st_v2_items where id=task) then
    raise exception 'Disconnected provider retained planning access'; end if;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_planner_policy(workspace,false)->>'required' is distinct from 'false' then
    raise exception 'Fresh owner could not recover planning access'; end if;
  if not exists(select 1 from public.st_v2_items where id=task) then
    raise exception 'Planning access remained blocked after owner recovery'; end if;
  reset role;
  if has_function_privilege('anon','public.st_v8_workspace_planner_policy(uuid,boolean)','execute')
    or has_function_privilege('anon','public.st_v8_workspace_planner_requires_sso(uuid)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v8_workspace_planner_sso','select') then
    raise exception 'Planning policy surface is exposed outside its intended roles'; end if;
end $$;
rollback;
