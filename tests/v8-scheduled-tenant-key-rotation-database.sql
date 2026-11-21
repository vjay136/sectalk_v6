begin;

create function pg_temp.rotation_actor(p_actor uuid,p_aal text default 'aal2')
returns void language sql security definer set search_path='' as $$
  select set_config('request.jwt.claims',jsonb_build_object('sub',p_actor,'aal',p_aal,'role','authenticated',
    'session_id',(select id from auth.sessions where user_id=p_actor limit 1))::text,true)::text::void;
$$;

do $$
declare owner_id uuid:=gen_random_uuid();
  outsider uuid:=gen_random_uuid();
  person uuid;
  factor uuid;
  native uuid;
  space uuid;
  outside_space uuid;
  initial_revision uuid;
  refreshed_revision uuid;
  decision uuid;
  original text:=repeat('A',80);
  new_capsule text:=repeat('B',80);
begin
  foreach person in array array[owner_id,outsider] loop
    factor:=gen_random_uuid(); native:=gen_random_uuid();
    insert into auth.users(id,email) values(person,person||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(person,'sched_'||left(person::text,8),'Scheduled rotation QA');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor,person,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(native,person,'aal2',factor);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),native,'totp',now(),now());
    perform pg_temp.rotation_actor(person);
    if person=owner_id then
      space:=public.st_v2_create_workspace('Managed scheduled rotation QA');
    else
      outside_space:=public.st_v2_create_workspace('Independent external key QA');
    end if;
  end loop;
  insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values(space,1),(outside_space,1);
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,provider_ref,wrapped,created_at)
    values(space,1,'managed',null,original,now()-interval '100 days'),
      (outside_space,1,'byok','qa-custody',original,now()-interval '100 days');

  if has_table_privilege('authenticated','sectalk_private.st_v8_tenant_rotation_schedules','select')
    or has_table_privilege('service_role','sectalk_private.st_v8_tenant_rotation_schedules','select')
    or has_function_privilege('authenticated','public.st_v8_due_tenant_key_rotations()','execute')
    or has_function_privilege('anon','public.st_v8_tenant_rotation_schedule(uuid,integer)','execute')
    or has_function_privilege('authenticated','public.st_v8_commit_scheduled_tenant_key_rotation(uuid,integer,uuid,text)','execute') then
    raise exception 'Schedule or worker boundary exposed';
  end if;

  perform pg_temp.rotation_actor(outsider);
  set local role authenticated;
  if public.st_v8_tenant_rotation_schedule(space)->>'access'<>'none' then raise exception 'Cross-tenant status exposed'; end if;
  begin
    perform public.st_v8_tenant_rotation_schedule(outside_space,30);
    raise exception 'External key accepted managed scheduling';
  exception when sqlstate 'PT409' then null; end;
  perform pg_temp.rotation_actor(owner_id,'aal1');
  begin
    perform public.st_v8_tenant_rotation_schedule(space,30);
    raise exception 'AAL1 configured rotation';
  exception when insufficient_privilege then null; end;
  perform pg_temp.rotation_actor(owner_id);
  if public.st_v8_tenant_rotation_schedule(space,30)#>>'{schedule,days}' is distinct from '30' then raise exception 'Owner schedule not saved'; end if;
  reset role;
  if exists(select 1 from public.st_v8_due_tenant_key_rotations() where workspace=space) then
    raise exception 'An old key bypassed the new schedule interval';
  end if;
  update sectalk_private.st_v8_tenant_rotation_schedules set saved_at=now()-interval '100 days'
    where workspace=space returning revision into initial_revision;
  if not exists(select 1 from public.st_v8_due_tenant_key_rotations() where workspace=space and revision=initial_revision) then
    raise exception 'Due key not visible to worker';
  end if;

  insert into public.st_v2_members(workspace_id,user_id,role) values(space,outsider,'admin');
  insert into sectalk_private.st_v7_tenant_destroy_reviewers values(space,outsider);
  set local role authenticated;
  perform public.st_v8_tenant_rotation_schedule(space,60);
  reset role;
  update sectalk_private.st_v8_tenant_rotation_schedules set saved_at=now()-interval '100 days'
    where workspace=space returning revision into refreshed_revision;
  if initial_revision=refreshed_revision
    or public.st_v8_commit_scheduled_tenant_key_rotation(space,1,initial_revision,new_capsule)
    or public.st_v8_commit_scheduled_tenant_key_rotation(outside_space,1,refreshed_revision,new_capsule) then
    raise exception 'Stale policy or wrong tenant received a key';
  end if;

  set local role authenticated;
  decision:=public.st_v7_request_tenant_key_destroy(space,space::text,'Synthetic pending key preservation');
  if public.st_v8_tenant_rotation_schedule(space)#>>'{schedule,paused}' is distinct from 'true' then raise exception 'Pending review did not pause'; end if;
  reset role;
  if exists(select 1 from public.st_v8_due_tenant_key_rotations() where workspace=space)
    or public.st_v8_commit_scheduled_tenant_key_rotation(space,1,refreshed_revision,new_capsule) then
    raise exception 'Worker did not respect a pending destruction review';
  end if;
  perform pg_temp.rotation_actor(outsider);
  set local role authenticated;
  if public.st_v7_decide_tenant_key_destroy(decision,false,space::text,'Reject synthetic destruction request')<>'rejected' then
    raise exception 'Independent reviewer could not clear request';
  end if;
  reset role;

  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(gen_random_uuid(),space,owner_id,'Synthetic hold during scheduled rotation',owner_id);
  set local role service_role;
  if not public.st_v8_commit_scheduled_tenant_key_rotation(space,1,refreshed_revision,new_capsule)
    or public.st_v8_commit_scheduled_tenant_key_rotation(space,1,refreshed_revision,new_capsule) then
    raise exception 'Due rotation failed or a stale retry activated';
  end if;
  reset role;
  if (select current_version from sectalk_private.st_v7_tenant_key_state where workspace=space)<>2
    or not exists(select 1 from sectalk_private.st_v7_tenant_key_versions where workspace=space and version=1 and wrapped=original)
    or (select count(*) from sectalk_private.st_v7_tenant_key_audit where workspace=space and event='scheduled_rotation')<>1 then
    raise exception 'Historical custody or audit receipt lost';
  end if;

  perform pg_temp.rotation_actor(owner_id);
  set local role authenticated;
  if public.st_v8_tenant_rotation_schedule(space,0)->'schedule' is distinct from 'null'::jsonb then raise exception 'Owner disable did not clear'; end if;
  reset role;
  if exists(select 1 from public.st_v8_due_tenant_key_rotations() where workspace=space) then raise exception 'Disabled schedule remains eligible'; end if;
end $$;

select 'passed: native MFA, tenant and version binding, paused destruction review, held key history, and disable' as result;
rollback;
