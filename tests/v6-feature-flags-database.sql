begin;
insert into auth.users(id,email,aud,role) values
  ('6b000000-0000-4000-8000-000000000001','flags-operator@example.invalid','authenticated','authenticated'),
  ('6b000000-0000-4000-8000-000000000002','flags-owner@example.invalid','authenticated','authenticated'),
  ('6b000000-0000-4000-8000-000000000003','flags-staff@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('6b000000-0000-4000-8000-000000000001','flag_operator','Test operator'),
  ('6b000000-0000-4000-8000-000000000002','flag_owner','Workspace owner'),
  ('6b000000-0000-4000-8000-000000000003','flag_staff','Ordinary staff');
insert into sectalk_private.staff(user_id) values
  ('6b000000-0000-4000-8000-000000000001'),('6b000000-0000-4000-8000-000000000003');
insert into sectalk_private.st_v6_flag_operators(account_id) values('6b000000-0000-4000-8000-000000000001');
insert into public.st_v2_workspaces(id,name,owner) values
  ('6b000000-0001-4000-8000-000000000001','Flags fixture','6b000000-0000-4000-8000-000000000002');
insert into public.st_v2_members(workspace_id,user_id,role) values
  ('6b000000-0001-4000-8000-000000000001','6b000000-0000-4000-8000-000000000002','owner');

do $$
begin
  if (select count(*) from generate_series(1,1000) n where
    sectalk_private.st_v6_flag_bucket('task_creation',md5(n::text)::uuid)<50) not between 400 and 600
    then raise exception 'Unexpected rollout distribution'; end if;
end $$;
set local role authenticated;
do $$
declare
  operator_id constant uuid:='6b000000-0000-4000-8000-000000000001';
  workspace_owner constant uuid:='6b000000-0000-4000-8000-000000000002';
  ordinary_staff constant uuid:='6b000000-0000-4000-8000-000000000003';
  workspace constant uuid:='6b000000-0001-4000-8000-000000000001';
  room constant uuid:='6b000000-0002-4000-8000-000000000001';
begin
  perform set_config('request.jwt.claims',json_build_object('sub',ordinary_staff,'role','authenticated','aal','aal2')::text,true);
  begin
    perform public.st_v6_flag_rules();
    raise exception 'Ordinary moderator gained release control access';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',operator_id,'role','authenticated','aal','aal1')::text,true);
  begin
    perform public.st_v6_save_flag_rule('task_creation','global',null,true,0);
    raise exception 'Operator changed an authenticated flag without MFA';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',operator_id,'role','authenticated','aal','aal2')::text,true);
  if not public.st_v6_can_manage_flags() then raise exception 'MFA operator denied'; end if;
  perform public.st_v6_save_flag_rule('task_creation','global',null,true,0);
  perform public.st_v6_save_flag_rule('task_creation','global',null,true,0);
  perform public.st_v6_save_flag_rule('task_creation','workspace',workspace,true,100);
  perform public.st_v6_save_flag_rule('task_creation','account',workspace_owner,false,100);
  perform public.st_v6_save_flag_rule('recurring_meetings','global',null,true,100,true);
  if public.st_v6_feature_available('task_creation',workspace) then raise exception 'Nonmember evaluated someone else’s workspace rollout'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',workspace_owner,'role','authenticated')::text,true);
  perform public.st_v6_room_create(room,workspace,'Flags room','private','project');
  if public.st_v6_feature_available('task_creation',workspace) then raise exception 'Account override did not outrank workspace'; end if;
  begin
    perform public.st_v6_task_create(gen_random_uuid(),room,null,'Must be unavailable');
    raise exception 'Raw task RPC bypassed feature flag' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_schedule_series(workspace,gen_random_uuid(),'Disabled series','',now()+interval '1 day',
      now()+interval '25 hours','daily',2,'UTC');
    raise exception 'Raw series RPC bypassed the emergency stop' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',operator_id,'role','authenticated','aal','aal2')::text,true);
  perform public.st_v6_save_flag_rule('task_creation','account',workspace_owner,true,100,false,true);
  perform set_config('request.jwt.claims',json_build_object('sub',workspace_owner,'role','authenticated')::text,true);
  if not public.st_v6_feature_available('task_creation',workspace)
    or public.st_v6_feature_available('task_creation',null) then raise exception 'Workspace override or zero-percent default failed'; end if;
  perform public.st_v6_task_create(gen_random_uuid(),room,null,'Workspace rollout allowed');
  perform set_config('request.jwt.claims',json_build_object('sub',operator_id,'role','authenticated','aal','aal2')::text,true);
  perform public.st_v6_save_flag_rule('task_creation','global',null,true,100,true);
  perform set_config('request.jwt.claims',json_build_object('sub',workspace_owner,'role','authenticated')::text,true);
  if public.st_v6_feature_available('task_creation',workspace) then raise exception 'Emergency stop did not override workspace'; end if;
end $$;
reset role;
do $$
begin
  if (select count(*) from sectalk_private.st_v6_flag_audit where actor='6b000000-0000-4000-8000-000000000001')<>6
    then raise exception 'No-op retry or rule change produced incorrect audit history'; end if;
end $$;
select 'passed: stable rollout distribution, account and workspace precedence, operator MFA, server gates, emergency override and audited changes' as result;
rollback;
