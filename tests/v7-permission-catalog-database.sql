begin;
do $$
declare
  owner_id uuid:=gen_random_uuid();
  member_id uuid:=gen_random_uuid();
  outsider uuid:=gen_random_uuid();
  owner_session uuid:=gen_random_uuid();
  member_session uuid:=gen_random_uuid();
  other_session uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid();
  workspace uuid:=gen_random_uuid();
  other_workspace uuid:=gen_random_uuid();
  room uuid:=gen_random_uuid();
  other_room uuid:=gen_random_uuid();
  result jsonb;
begin
  insert into auth.users(id,email,email_confirmed_at) select id,id||'@example.invalid',now()
    from unnest(array[owner_id,member_id,outsider]) id;
  insert into public.st_profiles(id,handle,name) select id,'permission_'||left(id::text,8),'Permission fixture'
    from unnest(array[owner_id,member_id,outsider]) id;
  insert into public.st_v2_workspaces(id,name,owner) values
    (workspace,'Permission workspace',owner_id),(other_workspace,'Isolated workspace',outsider);
  insert into public.st_v2_members(workspace_id,user_id,role) values
    (workspace,owner_id,'owner'),(workspace,member_id,'member'),(other_workspace,outsider,'owner');
  insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator) values
    (room,workspace,'Scoped room','private','blank',owner_id),
    (other_room,other_workspace,'Isolated room','private','blank',outsider);
  insert into public.st_v6_room_members(room_id,user_id,role) values
    (room,owner_id,'owner'),(room,member_id,'read_only'),(other_room,outsider,'owner');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id,created_at) values
    (owner_session,owner_id,'aal2',factor,now()),(member_session,member_id,'aal1',null,now()),
    (other_session,outsider,'aal1',null,now());
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
    (gen_random_uuid(),owner_session,'totp',now()-interval '10 minutes',now()-interval '6 minutes'),
    (gen_random_uuid(),member_session,'password',now(),now()),(gen_random_uuid(),other_session,'password',now(),now());
  insert into sectalk_private.st_v7_account_operators(user_id,capability) values(owner_id,'reviewer');
  if has_function_privilege('anon','public.st_v7_permission_catalog(uuid,uuid)','execute') then
    raise exception 'Unverified anonymous caller received a permission catalog'; end if;

  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'role','authenticated',
    'session_id',owner_session,'aal','aal2')::text,true);
  result:=public.st_v7_permission_catalog(workspace,room);
  if result#>>'{workspace,admin.user.role.write}'<>'verification_required'
    or result#>>'{workspace,compliance.export.request}'<>'not_allowed'
    or result#>>'{workspace,compliance.export.review}'<>'verification_required'
    or result#>>'{platform,platform.session.revoke}'<>'not_allowed'
    or result#>>'{platform,platform.recovery.review}'<>'verification_required'
    or result#>>'{room,room.permission.write}'<>'verification_required' then raise exception 'Stale owner/reviewer explanation wrong'; end if;
  begin
    perform public.st_v2_set_member(workspace,member_id,'admin');
    raise exception 'Stale owner role mutation passed';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_set_room_role_overrides(room,'member','{"react":"deny"}');
    raise exception 'Stale owner room policy mutation passed';
  exception when insufficient_privilege then null; end;
  reset role;
  update auth.mfa_amr_claims set updated_at=clock_timestamp() where session_id=owner_session;
  set local role authenticated;
  result:=public.st_v7_permission_catalog(workspace,room);
  if result#>>'{workspace,admin.user.role.write}'<>'allowed' or
    result#>>'{room,room.permission.write}'<>'allowed' or result#>>'{platform,platform.recovery.review}'<>'allowed' then
    raise exception 'Fresh owner explanation failed to allow authorized controls'; end if;
  perform public.st_v6_set_room_role_overrides(room,'member','{"react":"deny"}');

  perform set_config('request.jwt.claims',jsonb_build_object('sub',member_id,'role','authenticated',
    'session_id',member_session,'aal','aal1')::text,true);
  result:=public.st_v7_permission_catalog(workspace,room);
  if result->>'workspace_role'<>'member' or result->>'room_role'<>'read_only'
    or result#>>'{room,messaging.message.send}'<>'not_allowed' or result#>>'{workspace,admin.user.suspend}'<>'not_allowed' then
    raise exception 'Read-only member permissions are overbroad'; end if;
  begin
    perform public.st_v6_set_room_role_overrides(room,'member','{}');
    raise exception 'Read-only actor edited room roles';
  exception when insufficient_privilege then null; end;
  result:=public.st_v7_permission_catalog(other_workspace,other_room);
  if result->>'workspace_role' is not null or result->>'room_role' is not null
    or result->'room'<>'{}'::jsonb or result->'rooms'<>'[]'::jsonb or result::text like '%Isolated%' then
    raise exception 'Foreign tenant or room leaked through the catalog'; end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'role','authenticated',
    'session_id',owner_session,'aal','aal2')::text,true);
  perform public.st_v2_set_member(workspace,member_id,'admin');
  perform set_config('request.jwt.claims',jsonb_build_object('sub',member_id,'role','authenticated',
    'session_id',member_session,'aal','aal1')::text,true);
  result:=public.st_v7_permission_catalog(workspace,room);
  if result->>'workspace_role'<>'admin' or result#>>'{workspace,compliance.export.request}'<>'verification_required'
    or result#>>'{workspace,admin.user.role.write}'<>'not_allowed' then raise exception 'Role change did not update effective authority'; end if;
end $$;
rollback;
