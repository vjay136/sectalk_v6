\set ON_ERROR_STOP on
begin;
do $$
declare owner_id uuid:=gen_random_uuid(); tenant uuid:=gen_random_uuid(); standard_room uuid:=gen_random_uuid(); managed_room uuid:=gen_random_uuid();
begin
  if has_function_privilege('authenticated','public.st_v8_managed_room_work(uuid,uuid,text,jsonb)','EXECUTE')
    or has_table_privilege('authenticated','sectalk_private.st_v8_managed_room_posts','SELECT')
    or has_table_privilege('authenticated','sectalk_private.st_v8_managed_room_tickets','SELECT') then
    raise exception 'A client can reach a managed-room key or ciphertext';
  end if;
  insert into auth.users(id,email,created_at,updated_at) values(owner_id,owner_id::text||'@example.invalid',now(),now());
  insert into public.st_profiles(id,handle,name) values(owner_id,'mroom_'||substr(owner_id::text,1,8),'Room fixture');
  insert into public.st_v2_workspaces(id,owner,name) values(tenant,owner_id,'Managed room fixture');
  insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator)
    values(standard_room,tenant,'Old private','private','blank',owner_id);
  insert into sectalk_private.st_v8_room_encryption_policy values(tenant,true);
  insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator)
    values(managed_room,tenant,'New private','private','blank',owner_id);
  delete from sectalk_private.st_v8_room_encryption_policy where workspace=tenant;
  if (select encryption_mode from public.st_v6_rooms where id=standard_room) is distinct from 'standard'
    or (select encryption_mode from public.st_v6_rooms where id=managed_room) is distinct from 'managed' then
    raise exception 'Managed mode failed to pin when the room was created';
  end if;
  begin
    update public.st_v6_rooms set encryption_mode='standard' where id=managed_room;
    raise exception 'Managed room could be downgraded';
  exception when insufficient_privilege then null;
  end;
  begin
    insert into public.st_v6_room_posts(room_id,id,sender,body,kind)
      values(managed_room,gen_random_uuid(),owner_id,'synthetic plaintext','message');
    raise exception 'Legacy managed-room write was accepted';
  exception when insufficient_privilege then null;
  end;
  begin
    insert into sectalk_private.st_v6_room_files(room,workspace,id,uploader,filename,size_bytes,sha256)
      values(managed_room,tenant,gen_random_uuid(),owner_id,'synthetic.txt',1,repeat('0',64));
    raise exception 'Legacy managed-room attachment was accepted';
  exception when insufficient_privilege then null;
  end;
end $$;
rollback;
