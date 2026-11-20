begin;
do $$
declare
  owner_id uuid:=gen_random_uuid();
  admin_id uuid:=gen_random_uuid();
  owner_session uuid:=gen_random_uuid();
  admin_session uuid:=gen_random_uuid();
  ws uuid;
  room uuid:=gen_random_uuid();
  held uuid:=gen_random_uuid();
  other_ws uuid;
  proof uuid;
  other_proof uuid;
  owner_claims text:=json_build_object('sub',owner_id,'role','authenticated','aal','aal1','session_id',owner_session)::text;
  admin_claims text:=json_build_object('sub',admin_id,'role','authenticated','aal','aal1','session_id',admin_session)::text;
begin
  insert into auth.users(id,email) values(owner_id,'org-owner@example.invalid'),(admin_id,'org-admin@example.invalid');
  insert into public.st_profiles(id,handle,name) values(owner_id,'org_settings_owner','Organization owner'),(admin_id,'org_settings_admin','Organization admin');
  insert into auth.sessions(id,user_id,aal) values(owner_session,owner_id,'aal1'),(admin_session,admin_id,'aal1');
  if has_function_privilege('authenticated','public.st_v7_finish_org_domain(uuid,uuid,uuid,uuid)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v7_org_domains','select') then
    raise exception 'Domain attestation or challenges exposed';
  end if;

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claims,true);
  ws:=public.st_v2_create_workspace('Organization scope');
  if public.st_v7_org_settings(ws)->>'retentionDays'<>'30' then raise exception 'Default changed unexpectedly'; end if;
  begin
    perform public.st_v7_org_settings(ws,'save','Denied change','teal',7,'eu');
    raise exception 'Stale sign-in changed settings';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(ws,admin_id,'admin');
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'password',now(),now()),(gen_random_uuid(),admin_session,'password',now(),now());

  set local role authenticated;
  if public.st_v7_org_settings(ws,'save','Renamed organization','teal',7,'eu')->>'region'<>'eu' then raise exception 'Preference lost'; end if;
  perform public.st_v6_room_create(room,ws,'Organization retirement','public','blank');
  if public.st_v6_room_retirement(room)->>'retention_days'<>'7' then raise exception 'Live default missing from room retirement'; end if;
  begin
    perform public.st_v7_org_settings(ws,'domain.start',p_domain=>'https://invalid.example.invalid/path');
    raise exception 'Accepted arbitrary URL instead of DNS domain';
  exception when invalid_parameter_value then null; end;
  perform public.st_v7_org_settings(ws,'domain.start',p_domain=>'controlled.example.invalid');
  proof:=(public.st_v7_org_settings(ws,'domain.proof',p_domain=>'controlled.example.invalid')->>'challenge')::uuid;
  perform set_config('request.jwt.claims',admin_claims,true);
  begin
    perform public.st_v7_org_settings(ws);
    raise exception 'Workspace admin opened owner settings';
  exception when insufficient_privilege then null; end;
  other_ws:=public.st_v2_create_workspace('Independent organization');
  perform public.st_v7_org_settings(other_ws,'domain.start',p_domain=>'controlled.example.invalid');
  other_proof:=(public.st_v7_org_settings(other_ws,'domain.proof',p_domain=>'controlled.example.invalid')->>'challenge')::uuid;
  reset role;

  set local role service_role;
  if public.st_v7_finish_org_domain(ws,proof,admin_id,admin_session)
    or public.st_v7_finish_org_domain(other_ws,proof,admin_id,admin_session)
    or not public.st_v7_finish_org_domain(ws,proof,owner_id,owner_session)
    or public.st_v7_finish_org_domain(other_ws,other_proof,admin_id,admin_session) then
    raise exception 'Domain verification violated scope or verified workspace exclusivity';
  end if;
  reset role;
  update sectalk_private.st_v7_org_domains set expires_at=now()-interval '1 minute' where challenge=other_proof;
  set local role authenticated;
  begin
    perform public.st_v7_org_settings(other_ws,'domain.proof',p_domain=>'controlled.example.invalid');
    raise exception 'Expired challenge approved';
  exception when invalid_parameter_value then null; end;
  reset role;

  insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator,archived)
    values(held,ws,'Held organization retirement','public','blank',owner_id,true);
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,room_id,reason,placed_by)
    values(gen_random_uuid(),ws,held,'Preserve synthetic records',owner_id);
  update public.st_v6_rooms set archived=true where id=room;
  insert into sectalk_private.st_v6_room_retirements(room_id,requested_by,requested_at)
    values(room,owner_id,now()-interval '8 days'),(held,owner_id,now()-interval '8 days');
  perform sectalk_private.st_v6_purge_retired_rooms();
  if exists(select 1 from public.st_v6_rooms where id=room)
    or not exists(select 1 from public.st_v6_rooms where id=held) then
    raise exception 'Retention was not consumed or bypassed the hold';
  end if;
end
$$;
select 'passed: owner and fresh auth, isolated domain proof, uniqueness and live hold-aware retention' as result;
rollback;
