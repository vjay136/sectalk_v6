\set ON_ERROR_STOP on
begin;

do $$
declare
  owner_id uuid:=gen_random_uuid();
  admin_id uuid:=gen_random_uuid();
  author_id uuid:=gen_random_uuid();
  reporter_id uuid:=gen_random_uuid();
  tenant uuid:=gen_random_uuid();
  managed_room uuid:=gen_random_uuid();
  post_id uuid:=gen_random_uuid();
  held_report uuid:=gen_random_uuid();
  active_hold uuid:=gen_random_uuid();
  actor uuid;
  capsule text:=repeat('d',160);
  sealed_revision text;
  snapshot jsonb;
begin
  if has_function_privilege('anon','public.st_v8_submit_consented_managed_room_report(uuid,uuid,text,text,text,boolean,boolean)','execute')
    or has_function_privilege('authenticated','public.st_v8_managed_room_compliance_keys(uuid)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v8_managed_room_evidence','select') then
    raise exception 'Managed-room export exposed a private operation';
  end if;

  foreach actor in array array[owner_id,admin_id,author_id,reporter_id] loop
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'mcex_'||left(actor::text,8),'Managed export fixture');
  end loop;
  insert into public.st_v2_workspaces(id,owner,name) values(tenant,owner_id,'Managed room export');
  insert into public.st_v2_members(workspace_id,user_id,role) values
    (tenant,owner_id,'owner'),(tenant,admin_id,'admin'),(tenant,author_id,'member'),(tenant,reporter_id,'member')
    on conflict (workspace_id,user_id) do nothing;
  insert into sectalk_private.st_v8_room_encryption_policy values(tenant,true);
  insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator)
    values(managed_room,tenant,'Managed export room','private','blank',owner_id);
  insert into public.st_v6_room_members(room_id,user_id,role) values
    (managed_room,owner_id,'owner'),(managed_room,admin_id,'member'),(managed_room,author_id,'member'),(managed_room,reporter_id,'member')
    on conflict (room_id,user_id) do nothing;
  insert into sectalk_private.st_v7_tenant_key_state values(tenant,1,null);
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,wrapped)
    values(tenant,1,'managed',repeat('w',80));
  insert into sectalk_private.st_v8_managed_room_posts(room,id,workspace,sender,key_version,fingerprint,body,nonce,tag,wrapped_dek)
    values(managed_room,post_id,tenant,author_id,1,decode(repeat('0',64),'hex'),'encrypted',repeat('n',16),repeat('t',22),capsule);
  sealed_revision:=encode(sha256(convert_to(concat_ws(':',managed_room,post_id,tenant,author_id,1,
    'encrypted',repeat('n',16),repeat('t',22),capsule),'UTF8')),'hex');
  insert into sectalk_private.st_v6_room_reports(id,workspace_id,room_id,post_id,reporter,subject,category,details,share_with_workspace)
    values(held_report,tenant,managed_room,post_id,reporter_id,author_id,'spam','Platform private notes',false);
  insert into sectalk_private.st_v8_managed_room_evidence values(held_report,managed_room,post_id,tenant,author_id,1,
    sealed_revision,'encrypted',repeat('n',16),repeat('t',22),capsule);
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,room_id,reason,placed_by)
    values(active_hold,tenant,managed_room,'Preserve the exact room revision',owner_id);

  if sectalk_private.st_v7_compliance_record(tenant,admin_id,owner_id,'managed_room_report',held_report::text) is not null then
    raise exception 'A platform-only report became workspace export data';
  end if;
  update sectalk_private.st_v6_room_reports set share_with_workspace=true where id=held_report;
  if sectalk_private.st_v7_compliance_record(tenant,admin_id,owner_id,'managed_room_report',held_report::text) is not null then
    raise exception 'A report became exportable before staff handoff';
  end if;
  update sectalk_private.st_v6_room_reports set handed_off_at=now() where id=held_report;
  snapshot:=sectalk_private.st_v7_compliance_record(tenant,admin_id,owner_id,'managed_room_report',held_report::text);
  if snapshot->>'encrypted_revision' is distinct from sealed_revision or snapshot->>'hold' is distinct from active_hold::text
    or snapshot->'envelope'->>'wrapped_dek' is distinct from capsule or position('Platform private notes' in snapshot::text)>0
    or sectalk_private.st_v7_compliance_record(tenant,admin_id,admin_id,'managed_room_report',held_report::text) is not null then
    raise exception 'Exact managed revision, provider envelope, or reviewer scope failed';
  end if;
  update sectalk_private.st_v8_managed_room_posts set body='changed' where room=managed_room and id=post_id;
  if sectalk_private.st_v7_compliance_record(tenant,admin_id,owner_id,'managed_room_report',held_report::text) is not null then
    raise exception 'An altered source revision remained exportable';
  end if;
  update sectalk_private.st_v8_managed_room_posts set body='encrypted' where room=managed_room and id=post_id;
  update sectalk_private.st_v6_workspace_holds set released_at=now(),released_by=owner_id,
    release_reason='Release the synthetic hold' where id=active_hold;
  if sectalk_private.st_v7_compliance_record(tenant,admin_id,owner_id,'managed_room_report',held_report::text) is not null then
    raise exception 'Released hold remained exportable';
  end if;
end $$;

rollback;
