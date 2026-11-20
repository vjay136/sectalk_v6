begin;

insert into auth.users(id,email,aud,role) values
  ('73000000-0000-4000-8000-000000000001','setup-family@example.invalid','authenticated','authenticated'),
  ('73000000-0000-4000-8000-000000000002','setup-business@example.invalid','authenticated','authenticated'),
  ('73000000-0000-4000-8000-000000000003','setup-legacy@example.invalid','authenticated','authenticated'),
  ('73000000-0000-4000-8000-000000000004','setup-member@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('73000000-0000-4000-8000-000000000001','setup_family','Family host'),
  ('73000000-0000-4000-8000-000000000002','setup_business','Business host'),
  ('73000000-0000-4000-8000-000000000003','setup_legacy','Legacy host'),
  ('73000000-0000-4000-8000-000000000004','setup_member','Member');

set local role authenticated;
do $$
declare
  restricted_host constant uuid:='73000000-0000-4000-8000-000000000001';
  standard_host constant uuid:='73000000-0000-4000-8000-000000000002';
  legacy_host constant uuid:='73000000-0000-4000-8000-000000000003';
  member_id constant uuid:='73000000-0000-4000-8000-000000000004';
  request constant uuid:=gen_random_uuid();
  family uuid;
  business uuid;
  legacy uuid;
  invitation uuid;
  private_meeting uuid:=gen_random_uuid();
  standard_meeting uuid:=gen_random_uuid();
begin
  perform set_config('request.jwt.claims',json_build_object('sub',restricted_host,'role','authenticated')::text,true);
  family:=public.st_v6_create_typed_workspace(request,'Family setup fixture','family');
  if public.st_v6_create_typed_workspace(request,'Family setup fixture','family') is distinct from family
    or not exists(select 1 from public.st_v6_workspace_policy where workspace_id=family and workspace_type='family'
      and template='restricted' and room_kinds=array['private','admin'] and not bulk_admit)
    then raise exception 'Workspace setup did not apply the selected policy or retry safely'; end if;
  if (select count(*) from public.st_v2_workspace_audit where workspace_id=family and event='workspace.policy_initialized')<>1
    then raise exception 'Workspace setup audit missing or duplicated'; end if;
  begin
    perform public.st_v6_create_typed_workspace(request,'Other setup intent','family');
    raise exception 'A mismatched retry changed intent' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_create_typed_workspace(gen_random_uuid(),'Second workspace','family');
    raise exception 'Typed workspace bypassed the account quota' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_room_create(gen_random_uuid(),family,'Disallowed room','public','blank');
    raise exception 'Restricted workspace accepted a workspace-wide room' using errcode='P0004';
  exception when raise_exception then null; end;
  perform public.st_v6_room_create(gen_random_uuid(),family,'Private room','private','blank');
  perform public.st_v2_invite(family,'setup_member');
  perform public.st_v6_start_instant_meeting(private_meeting,family,'Private lobby',30);

  perform set_config('request.jwt.claims',json_build_object('sub',standard_host,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_workspace_policy where workspace_id=family)
    then raise exception 'Workspace settings leaked across tenants'; end if;
  business:=public.st_v6_create_typed_workspace(gen_random_uuid(),'Business setup fixture','business');
  if not exists(select 1 from public.st_v6_workspace_policy where workspace_id=business and template='standard'
      and 'public'=any(room_kinds) and bulk_admit)
    then raise exception 'Standard workspace did not get collaborative defaults'; end if;
  perform public.st_v6_room_create(gen_random_uuid(),business,'Shared room','public','blank');
  perform public.st_v2_invite(business,'setup_member');
  perform public.st_v6_start_instant_meeting(standard_meeting,business,'Standard lobby',30);

  perform set_config('request.jwt.claims',json_build_object('sub',legacy_host,'role','authenticated')::text,true);
  legacy:=public.st_v2_create_workspace('Legacy setup fixture');
  if exists(select 1 from public.st_v6_workspace_policy where workspace_id=legacy)
    then raise exception 'Legacy entry unexpectedly gained a policy row'; end if;
  perform public.st_v6_room_create(gen_random_uuid(),legacy,'Legacy shared room','public','blank');

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  select id into invitation from public.st_v2_invites where workspace_id=family;
  perform public.st_v2_reply_invite(invitation,true);
  select id into invitation from public.st_v2_invites where workspace_id=business;
  perform public.st_v2_reply_invite(invitation,true);
  if public.st_v3_request_admission(private_meeting) is distinct from 'waiting'
    or public.st_v3_request_admission(standard_meeting) is distinct from 'waiting'
    then raise exception 'Expected member to wait in both lobbies'; end if;
  begin
    update public.st_v6_workspace_policy set bulk_admit=true where workspace_id=family;
    raise exception 'A workspace member changed the policy directly' using errcode='P0004';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',restricted_host,'role','authenticated')::text,true);
  begin
    perform public.st_v6_admit_all(private_meeting);
    raise exception 'Restricted workspace admitted members in bulk' using errcode='P0004';
  exception when raise_exception then null; end;
  perform public.st_v3_admit(private_meeting,member_id,true);
  perform set_config('request.jwt.claims',json_build_object('sub',standard_host,'role','authenticated')::text,true);
  if public.st_v6_admit_all(standard_meeting)<>1 then raise exception 'Standard workspace bulk admission failed'; end if;
end $$;
reset role;

select 'passed: typed workspace setup, idempotency, quota, tenant RLS, room and admission policies, and legacy compatibility' as result;
rollback;
