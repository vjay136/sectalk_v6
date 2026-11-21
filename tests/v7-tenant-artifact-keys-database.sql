begin;
create function pg_temp.key_actor(p_actor uuid,p_aal text default 'aal2')
returns void language sql security definer set search_path='' as $$
  select set_config('request.jwt.claims',jsonb_build_object('sub',p_actor,'aal',p_aal,'role','authenticated',
    'session_id',(select id from auth.sessions where user_id=p_actor limit 1))::text,true)::text::void;
$$;

do $$
declare
  owner_id uuid:=gen_random_uuid();
  reviewer_id uuid:=gen_random_uuid();
  foreign_id uuid:=gen_random_uuid();
  person uuid;
  factor uuid;
  native uuid;
  space uuid;
  other_space uuid;
  hold_key uuid:=gen_random_uuid();
  rotation_a uuid;
  rotation_b uuid;
  byok_ticket uuid;
  request_key uuid;
  note text:='Synthetic workspace key custody review';
  capsule text:=repeat('a',80);
begin
  foreach person in array array[owner_id,reviewer_id,foreign_id] loop
    factor:=gen_random_uuid();
    native:=gen_random_uuid();
    insert into auth.users(id,email) values(person,person||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(person,'keyqa_'||left(person::text,8),'Workspace key QA');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,person,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(native,person,'aal2',factor);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),native,'totp',now(),now());
  end loop;
  perform pg_temp.key_actor(owner_id);
  space:=public.st_v2_create_workspace('Synthetic key tenant');
  perform pg_temp.key_actor(foreign_id);
  other_space:=public.st_v2_create_workspace('Independent key tenant');
  insert into public.st_v2_members(workspace_id,user_id,role) values(space,reviewer_id,'admin');
  insert into sectalk_private.st_v7_tenant_destroy_reviewers values(space,reviewer_id);
  if has_table_privilege('authenticated','sectalk_private.st_v7_tenant_key_versions','select')
    or has_table_privilege('service_role','sectalk_private.st_v7_tenant_key_versions','select')
    or has_function_privilege('authenticated','public.st_v7_export_key_context(uuid,uuid,text)','execute') then
    raise exception 'Raw wrapping metadata escaped its service RPC boundary';
  end if;

  perform pg_temp.key_actor(owner_id,'aal1');
  set local role authenticated;
  if public.st_v7_tenant_key_status(space)->>'access'<>'mfa' then raise exception 'AAL1 exposed key status'; end if;
  begin
    perform public.st_v7_begin_tenant_key_rotation(space,'managed',note);
    raise exception 'AAL1 allocated a rotation';
  exception when insufficient_privilege then null; end;
  perform pg_temp.key_actor(owner_id);
  begin
    perform public.st_v7_begin_tenant_key_rotation(space,'byok',note);
    raise exception 'Free tenant could reserve external custody';
  exception when insufficient_privilege then null; end;
  rotation_a:=(public.st_v7_begin_tenant_key_rotation(space,'managed',note)->>'ticket')::uuid;
  rotation_b:=(public.st_v7_begin_tenant_key_rotation(space,'managed',note)->>'ticket')::uuid;
  reset role;

  if public.st_v7_commit_tenant_key_rotation(rotation_a,foreign_id,capsule,null)
    or not public.st_v7_commit_tenant_key_rotation(rotation_a,owner_id,capsule,null)
    or public.st_v7_commit_tenant_key_rotation(rotation_b,owner_id,capsule,null) then
    raise exception 'Rotation did not bind owner or reject the stale version';
  end if;
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values(foreign_id,'enterprise','active',now()+interval '30 days');
  perform pg_temp.key_actor(foreign_id);
  set local role authenticated;
  if public.st_v7_tenant_key_status(space)<>'{"access":"none"}'::jsonb then raise exception 'Foreign tenant key status exposed'; end if;
  byok_ticket:=(public.st_v7_begin_tenant_key_rotation(other_space,'byok',note)->>'ticket')::uuid;
  reset role;
  if not public.st_v7_commit_tenant_key_rotation(byok_ticket,foreign_id,capsule,'synthetic-ref') then
    raise exception 'Enterprise fixture reservation did not activate';
  end if;
  if not exists(select 1 from sectalk_private.st_v7_tenant_key_versions where workspace=other_space and custody='byok') then
    raise exception 'External custody provenance was lost'; end if;

  perform pg_temp.key_actor(owner_id);
  set local role authenticated;
  begin
    perform public.st_v7_request_tenant_key_destroy(space,other_space::text,note);
    raise exception 'Wrong target confirmation accepted';
  exception when invalid_parameter_value then null; end;
  request_key:=public.st_v7_request_tenant_key_destroy(space,space::text,note);
  begin
    perform public.st_v7_decide_tenant_key_destroy(request_key,true,space::text,note);
    raise exception 'Self approval accepted';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_key,space,reviewer_id,'Synthetic mandatory legal hold',owner_id);
  perform pg_temp.key_actor(reviewer_id,'aal1');
  set local role authenticated;
  begin
    perform public.st_v7_decide_tenant_key_destroy(request_key,true,space::text,note);
    raise exception 'Missing reviewer TOTP accepted';
  exception when insufficient_privilege then null; end;
  perform pg_temp.key_actor(reviewer_id);
  begin
    perform public.st_v7_decide_tenant_key_destroy(request_key,true,space::text,note);
    raise exception 'Destruction bypassed an active hold';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds set released_at=clock_timestamp(),released_by=owner_id,
    release_reason='End synthetic preservation hold' where id=hold_key;
  set local role authenticated;
  if public.st_v7_decide_tenant_key_destroy(request_key,true,space::text,note)<>'destroyed'
    or public.st_v7_decide_tenant_key_destroy(request_key,true,space::text,note)<>'destroyed' then
    raise exception 'Destruction did not finish idempotently'; end if;
  perform pg_temp.key_actor(owner_id);
  begin
    perform public.st_v7_begin_tenant_key_rotation(space,'managed',note);
    raise exception 'Destroyed key tenant could recreate a key';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  if exists(select 1 from sectalk_private.st_v7_tenant_key_versions where workspace=space)
    or not exists(select 1 from sectalk_private.st_v7_tenant_key_versions where workspace=other_space)
    or (select count(*) from sectalk_private.st_v7_tenant_key_audit where workspace=space and event='destroyed')<>1 then
    raise exception 'Destruction affected other custody or duplicated the audit'; end if;
  begin
    delete from sectalk_private.st_v7_tenant_key_audit where workspace=space;
    raise exception 'Destruction audit could be rewritten';
  exception when insufficient_privilege then null; end;
end $$;
rollback;
