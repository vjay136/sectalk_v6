begin;
do $$
declare
  owner_id uuid:=gen_random_uuid();
  peer_id uuid:=gen_random_uuid();
  clinical uuid;
  ordinary uuid;
  room uuid:=gen_random_uuid();
  post uuid:=gen_random_uuid();
  channel uuid;
  channel_message uuid:=gen_random_uuid();
  report_id uuid;
  clinical_rules jsonb;
begin
  insert into auth.users(id,email) values(owner_id,'clinical-owner@example.invalid'),(peer_id,'clinical-peer@example.invalid');
  insert into public.st_profiles(id,handle,name) values(owner_id,'clinical_owner','Clinical owner'),(peer_id,'clinical_peer','Clinical peer');
  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  clinical:=public.st_v6_create_profiled_workspace(gen_random_uuid(),'Healthcare synthetic fixture','business','healthcare');
  perform set_config('request.jwt.claims',json_build_object('sub',peer_id,'role','authenticated')::text,true);
  ordinary:=public.st_v2_create_workspace('Ordinary synthetic fixture');
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v6_room_create(room,clinical,'Healthcare verification room','private','blank');
  channel:=public.st_v2_create_channel(clinical,'clinical-fixture');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(clinical,peer_id,'member');
  select d.rules into clinical_rules from sectalk_private.st_v7_workspace_dlp d where d.workspace_id=clinical;
  if clinical_rules is distinct from '{"pii":"warn","phi":"block","payment_card":"block","credential":"redact"}'::jsonb
    or exists(select 1 from sectalk_private.st_v7_workspace_dlp where workspace_id=ordinary) then
    raise exception 'Profile defaults not persisted or leaked into ordinary workspace';
  end if;
  if not exists(select 1 from public.st_v6_rooms where id=room and classification='confidential' and not forwarding_allowed) then
    raise exception 'New room lacked confidential and no-forwarding flags';
  end if;
  begin
    update sectalk_private.st_v7_workspace_dlp set rules=st_v7_workspace_dlp.rules||'{"phi":"allow"}'::jsonb where workspace_id=clinical;
    raise exception 'PHI minimum could be weakened';
  exception when invalid_parameter_value then null; end;
  begin
    update public.st_v6_rooms set forwarding_allowed=true where id=room;
    raise exception 'Room forwarding could be enabled';
  exception when insufficient_privilege then null; end;
  begin
    insert into public.st_v6_room_members(room_id,user_id,role) values(room,peer_id,'guest');
    raise exception 'Healthcare room guest admitted';
  exception when insufficient_privilege then null; end;
  set local role authenticated;
  begin
    perform public.st_v6_room_post(room,post,'Patient ID: SYNTH-999');
    raise exception 'Managed room admitted a recognized health-record identifier';
  exception when others then if sqlstate<>'PT422' then raise; end if; end;
  begin
    perform public.st_v2_post(channel,channel_message,'MRN: SYNTH-123');
    raise exception 'Managed channel admitted a recognized health-record identifier';
  exception when others then if sqlstate<>'PT422' then raise; end if; end;
  perform public.st_v6_room_post(room,post,'Use API key=synthetic_example only in a test.');
  if not exists(select 1 from public.st_v6_room_posts where id=post and body='Use […] only in a test.') then
    raise exception 'Credential redaction did not persist the sanitized body';
  end if;
  perform public.st_v6_room_membership(room,'invite',peer_id,'member');
  perform set_config('request.jwt.claims',json_build_object('sub',peer_id,'role','authenticated')::text,true);
  perform public.st_v6_room_membership(room,'accept');
  report_id:=public.st_v6_submit_room_report(room,post,'threat','No private identifiers present.',true);
  reset role;
  begin
    insert into sectalk_private.st_v6_break_glass_requests(workspace_id,report_id,requester,justification)
      values(clinical,report_id,owner_id,'Reason contains MRN: SYNTH-5599');
    raise exception 'Emergency metadata accepted a health-record identifier';
  exception when invalid_parameter_value then null; end;
end
$$;
select 'passed: clinical defaults, role floor, managed PHI blocks, redaction and emergency metadata guard' as result;
rollback;
