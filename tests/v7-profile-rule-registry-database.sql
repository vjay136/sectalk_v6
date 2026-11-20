begin;

do $$
declare
  organizer uuid:=gen_random_uuid();
  manager uuid:=gen_random_uuid();
  member uuid:=gen_random_uuid();
  workspace uuid:=gen_random_uuid();
  state jsonb;
  stage_generation uuid;
  original_generation uuid:='00000000-0000-0000-0000-000000000000';
begin
  insert into auth.users(id,email) values
    (organizer,'rules-registry-owner@example.invalid'),(manager,'rules-registry-admin@example.invalid'),
    (member,'rules-registry-member@example.invalid');
  insert into public.st_profiles(id,handle,name) values
    (organizer,'rules_registry_owner','Rule fixture owner'),(manager,'rules_registry_admin','Rule fixture admin'),
    (member,'rules_registry_member','Rule fixture member');
  insert into public.st_v2_workspaces(id,name,owner) values(workspace,'Rule registry fixture',organizer);
  insert into public.st_v2_members(workspace_id,user_id,role) values
    (workspace,organizer,'owner'),(workspace,manager,'admin'),(workspace,member,'member');
  if has_table_privilege('authenticated','sectalk_private.st_v7_profile_rule_evaluation','select')
    or has_function_privilege('authenticated','public.st_v7_record_profile_rule_evaluation(uuid,uuid,uuid,text,integer[],integer[],integer)','execute')
    or has_function_privilege('anon','public.st_v7_workspace_rule_registry(uuid,text,text,uuid)','execute') then
    raise exception 'Direct registry or evaluation write access is exposed';
  end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',member,'aal','aal1')::text,true);
  set local role authenticated;
  begin
    perform public.st_v7_workspace_rule_registry(workspace);
    raise exception 'Member could view management registry';
  exception when insufficient_privilege then null; end;
  reset role;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',manager,'aal','aal1')::text,true);
  set local role authenticated;
  if (public.st_v7_workspace_rule_registry(workspace)->>'owner')::boolean is distinct from false
    or public.st_v7_workspace_active_profile_rules(workspace)<>'profile-rules-v1' then
    raise exception 'Workspace admin could not read active rule state';
  end if;
  begin
    perform public.st_v7_workspace_rule_registry(workspace,'stage','profile-rules-v2',original_generation);
    raise exception 'Admin changed the workspace release';
  exception when insufficient_privilege then null; end;
  reset role;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',organizer,'aal','aal1')::text,true);
  set local role authenticated;
  state:=public.st_v7_workspace_rule_registry(workspace,'stage','profile-rules-v2',original_generation);
  stage_generation:=(state->>'generation')::uuid;
  if state->>'shadow'<>'profile-rules-v2' or public.st_v7_workspace_active_profile_rules(workspace)<>'profile-rules-v1'
    or (state->>'canPromote')::boolean then raise exception 'Shadow altered the active runtime'; end if;
  begin
    perform public.st_v7_workspace_rule_registry(workspace,'promote',null,stage_generation);
    raise exception 'Unevaluated shadow was promoted';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_v7_workspace_rule_registry(workspace,'clear',null,original_generation);
    raise exception 'Stale operator generation changed state';
  exception when serialization_failure then null; end;
  reset role;

  if public.st_v7_record_profile_rule_evaluation(workspace,manager,stage_generation,
    'synthetic-profile-pairs-v1',array[4,2,2,0],array[3,1,3,1],2)
    or public.st_v7_record_profile_rule_evaluation(workspace,organizer,original_generation,
    'synthetic-profile-pairs-v1',array[4,2,2,0],array[3,1,3,1],2)
    or public.st_v7_record_profile_rule_evaluation(workspace,organizer,stage_generation,
    'unregistered-corpus',array[4,2,2,0],array[3,1,3,1],2) then
    raise exception 'Stale, unapproved actor, or unknown benchmark results could be recorded';
  end if;
  if not public.st_v7_record_profile_rule_evaluation(workspace,organizer,stage_generation,
    'synthetic-profile-pairs-v1',array[4,2,2,0],array[3,1,3,1],2) then
    raise exception 'Valid evaluation was not recorded';
  end if;
  perform public.st_v7_record_profile_rule_evaluation(workspace,organizer,stage_generation,
    'synthetic-profile-pairs-v1',array[4,2,2,0],array[3,1,3,1],2);
  if (select count(*) from sectalk_private.st_v7_profile_rule_evaluation where generation=stage_generation)<>1 then
    raise exception 'Repeated evaluation did not stay idempotent';
  end if;

  set local role authenticated;
  state:=public.st_v7_workspace_rule_registry(workspace,'promote',null,stage_generation);
  if state->>'active'<>'profile-rules-v2' or state->>'previous'<>'profile-rules-v1'
    or public.st_v7_workspace_active_profile_rules(workspace)<>'profile-rules-v2'
    or (state#>>'{evaluations,0,disagreements}')::integer<>2 then
    raise exception 'Promotion or aggregate drift could not be observed';
  end if;
  state:=public.st_v7_workspace_rule_registry(workspace,'rollback',null,(state->>'generation')::uuid);
  if state->>'active'<>'profile-rules-v1' or public.st_v7_workspace_active_profile_rules(workspace)<>'profile-rules-v1' then
    raise exception 'Rollback failed to restore the runtime';
  end if;
  reset role;
  if (select count(*) from public.st_v2_workspace_audit where workspace_id=workspace
    and event in ('workspace.ai_rule.stage','workspace.ai_rule.promote','workspace.ai_rule.rollback'))<>3 then
    raise exception 'Registry changes did not leave a workspace audit trail';
  end if;
end
$$;

select 'passed: owner/admin scope, immutable versions, synthetic-only evaluation, drift, generation checks and rollback' as result;
rollback;
