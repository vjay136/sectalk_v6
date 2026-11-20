begin;
insert into auth.users(id,email,email_confirmed_at) values
 ('aa231000-0000-4000-8000-000000000001','usage-database-owner@example.invalid',now()),
 ('aa231000-0000-4000-8000-000000000002','usage-database-member@example.invalid',now());
insert into public.st_profiles(id,handle,name) values
 ('aa231000-0000-4000-8000-000000000001','usage_database_owner','Usage owner'),
 ('aa231000-0000-4000-8000-000000000002','usage_database_member','Usage member');
insert into auth.sessions(id,user_id,aal,created_at,updated_at) values
 ('aa231000-0000-4000-8000-000000000011','aa231000-0000-4000-8000-000000000001','aal1',now(),now()),
 ('aa231000-0000-4000-8000-000000000012','aa231000-0000-4000-8000-000000000002','aal1',now(),now());
insert into public.st_v2_workspaces(id,name,owner) values
 ('aa231000-0000-4000-8000-000000000021','Usage workspace','aa231000-0000-4000-8000-000000000001'),
 ('aa231000-0000-4000-8000-000000000022','Other usage workspace','aa231000-0000-4000-8000-000000000002');
insert into public.st_v2_members(workspace_id,user_id,role) values
 ('aa231000-0000-4000-8000-000000000021','aa231000-0000-4000-8000-000000000001','owner'),
 ('aa231000-0000-4000-8000-000000000021','aa231000-0000-4000-8000-000000000002','member'),
 ('aa231000-0000-4000-8000-000000000022','aa231000-0000-4000-8000-000000000002','owner');

do $$
declare
  actor constant uuid:='aa231000-0000-4000-8000-000000000001';
  member constant uuid:='aa231000-0000-4000-8000-000000000002';
  tenant constant uuid:='aa231000-0000-4000-8000-000000000021';
  other_tenant constant uuid:='aa231000-0000-4000-8000-000000000022';
  source_file constant uuid:='aa231000-0000-4000-8000-000000000031';
  usage jsonb;
begin
  insert into sectalk_private.st_v7_scan_allowances select e.plan,e.version,0
    from sectalk_private.st_v7_workspace_entitlements(tenant) e
    on conflict(plan,plan_version) do update set included_per_month=excluded.included_per_month;
  set local role service_role;
  if not public.st_v7_meter_file_scan('workspace',tenant,actor,source_file,repeat('a',64),'meter.txt')
    or not public.st_v7_meter_file_scan('workspace',tenant,actor,source_file,repeat('a',64),'meter.txt')
    or public.st_v7_meter_file_scan('workspace',other_tenant,actor,source_file,repeat('a',64),'meter.txt') then
    raise exception 'File scan scope or replay failed';
  end if;
  if public.st_v7_complete_metered_recording(tenant,source_file,'pretend',999) is not null
    or public.st_v7_publish_metered_caption(tenant,actor,'pretend',source_file,'not real',16000) is not null then
    raise exception 'Unknown producer was accepted';
  end if;
  reset role;
  perform sectalk_private.st_v7_write_usage(tenant,'recording_ms','previous',9999,date_trunc('month',now(),'UTC')-interval '1 ms');
  perform sectalk_private.st_v7_write_usage(tenant,'recording_ms','test',60001,now());
  perform sectalk_private.st_v7_write_usage(tenant,'recording_ms','test',90000,now());
  perform sectalk_private.st_v7_write_usage(other_tenant,'recording_ms','test',99999,now());
  perform set_config('request.jwt.claims',jsonb_build_object('sub',actor,'role','authenticated','aal','aal1',
    'session_id','aa231000-0000-4000-8000-000000000011')::text,true);
  set local role authenticated;
  usage:=public.st_v7_workspace_usage(tenant);
  if usage->>'recording_ms'<>'60001' or usage->>'ai_scans'<>'1' or usage->>'ai_scan_overage'<>'1'
    or usage->>'plan' is null or jsonb_array_length(public.st_v7_workspace_usage())<>1 then
    raise exception 'Unexpected usage summary %',usage;
  end if;
  begin
    perform public.st_v7_meter_file_scan('workspace',tenant,actor,source_file,repeat('b',64),'meter.txt');
    raise exception 'Authenticated usage write allowed';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_workspace_usage(other_tenant);
    raise exception 'Cross-tenant billing read allowed';
  exception when insufficient_privilege then null; end;
  reset role;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',member,'role','authenticated','aal','aal1',
    'session_id','aa231000-0000-4000-8000-000000000012')::text,true);
  set local role authenticated;
  begin
    perform public.st_v7_workspace_usage(tenant);
    raise exception 'Ordinary workspace member billing read allowed';
  exception when insufficient_privilege then null; end;
  reset role;
end $$;
rollback;
