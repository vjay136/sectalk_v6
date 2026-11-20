begin;
insert into auth.users(id,email,email_confirmed_at) values
  ('3af965d3-6956-4bb4-b6ab-2512ccf36771','compliance-owner@example.invalid',now()),
  ('3af965d3-6956-4bb4-b6ab-2512ccf36772','compliance-other@example.invalid',now());
insert into public.st_profiles(id,handle,name) values
  ('3af965d3-6956-4bb4-b6ab-2512ccf36771','compliance_owner','Compliance owner'),
  ('3af965d3-6956-4bb4-b6ab-2512ccf36772','compliance_other','Compliance outsider');

do $$
declare
  owner_id constant uuid:='3af965d3-6956-4bb4-b6ab-2512ccf36771';
  other_id constant uuid:='3af965d3-6956-4bb4-b6ab-2512ccf36772';
  request_id uuid:=gen_random_uuid();
  workspace uuid;
  compliance text;
  token text;
begin
  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  if (select array_agg(id order by sort_order) from public.st_v6_compliance_profiles)
    <> array['healthcare','education','finance','gdpr'] then raise exception 'Preset catalog is incomplete'; end if;
  workspace:=public.st_v6_create_profiled_workspace(request_id,'Compliance test','business','finance');
  if public.st_v6_create_profiled_workspace(request_id,'Compliance test','business','finance')<>workspace
    then raise exception 'Preset creation was not idempotent'; end if;
  begin
    perform public.st_v6_create_profiled_workspace(request_id,'Compliance test','business','gdpr');
    raise exception 'A reused request changed the policy' using errcode='P0100';
  exception when raise_exception then null; end;
  if not exists(select 1 from public.st_v6_workspace_policy where workspace_id=workspace
      and compliance_profile='finance' and room_kinds=array['private','admin'] and not bulk_admit)
    then raise exception 'Preset did not restrict room types and admission'; end if;
  begin
    perform public.st_v6_room_create(gen_random_uuid(),workspace,'Disallowed room','public','blank');
    raise exception 'Preset allowed public rooms' using errcode='P0100';
  exception when raise_exception then
    if sqlerrm not like '%requires private%' then raise; end if;
  end;
  begin
    perform public.st_v6_workspace_link_create(workspace,'compliance-other@example.invalid',24);
    raise exception 'Preset allowed an invitation without configured domains' using errcode='P0100';
  exception when raise_exception then
    if sqlerrm not like '%outside the workspace%' then raise; end if;
  end;
  perform public.st_v6_workspace_link_policy_set(workspace,array['example.invalid']);
  begin
    perform public.st_v6_workspace_link_create(workspace,'compliance-other@example.invalid',72);
    raise exception 'Preset allowed an overlong invitation' using errcode='P0100';
  exception when raise_exception then
    if sqlerrm not like '%expiration limit%' then raise; end if;
  end;
  token:=public.st_v6_workspace_link_create(workspace,'compliance-other@example.invalid',24)->>'token';
  perform set_config('request.jwt.claims',json_build_object('sub',other_id,'role','authenticated')::text,true);
  select compliance_profile into compliance from public.st_v6_workspace_policy where workspace_id=workspace;
  if found then raise exception 'Outsider read a workspace policy'; end if;
  if public.st_v6_workspace_link_accept(token)<>workspace then raise exception 'Valid invitation failed'; end if;
  select compliance_profile into compliance from public.st_v6_workspace_policy where workspace_id=workspace;
  if compliance is distinct from 'finance' then raise exception 'Member could not read effective preset'; end if;
end $$;
select 'passed: four profiles, immutable setup choice, safe room and admission defaults, bound links and role scope' as result;
rollback;
