begin;

insert into auth.users(id,email)
select ('a1170000-4459-4d00-9000-00000000000'||n)::uuid,'group-file-'||n||'@example.invalid' from generate_series(1,3) n;
insert into public.st_profiles(id,handle,name)
select ('a1170000-4459-4d00-9000-00000000000'||n)::uuid,'group_file_'||n,'Group File fixture' from generate_series(1,3) n;
insert into auth.sessions(id,user_id,aal)
select ('a1170001-4459-4d00-9000-00000000000'||n)::uuid,('a1170000-4459-4d00-9000-00000000000'||n)::uuid,'aal1'
from generate_series(1,3) n;
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
select gen_random_uuid(),('a1170001-4459-4d00-9000-00000000000'||n)::uuid,'password',now(),now() from generate_series(1,3) n;
insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature)
select ('a1170002-4459-4d00-9000-00000000000'||n)::uuid,('a1170000-4459-4d00-9000-00000000000'||n)::uuid,
  'trusted',repeat(chr(65+n),87),repeat(chr(75+n),87),repeat(chr(85+n),86)
from generate_series(1,3) n;
insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id)
select ('a1170001-4459-4d00-9000-00000000000'||n)::uuid,('a1170000-4459-4d00-9000-00000000000'||n)::uuid,
  ('a1170002-4459-4d00-9000-00000000000'||n)::uuid from generate_series(1,3) n;

create function pg_temp.group_file_actor(n int) returns void language sql as $$
  select set_config('request.jwt.claims',jsonb_build_object('sub','a1170000-4459-4d00-9000-00000000000'||n,
    'aal','aal1','session_id','a1170001-4459-4d00-9000-00000000000'||n)::text,true)::text::void
$$;

do $$
declare owner_id constant uuid:='a1170000-4459-4d00-9000-000000000001';
declare peer_id constant uuid:='a1170000-4459-4d00-9000-000000000002';
declare fixture_group uuid:=gen_random_uuid();
declare file_id uuid:=gen_random_uuid();
declare expired_id uuid:=gen_random_uuid();
declare message_id uuid:=gen_random_uuid();
declare envelope jsonb:=jsonb_build_object('id',message_id,'epoch',1,'payload',repeat('P',48),'signature',repeat('Q',86));
declare claim_id uuid;
begin
  insert into sectalk_private.st_group_chats values(fixture_group,owner_id,'Encrypted file test',1,2);
  insert into sectalk_private.st_group_members values(fixture_group,owner_id),(fixture_group,peer_id);
  insert into sectalk_private.st_group_envelopes(group_id,epoch,device,sealed,ephemeral)
    values(fixture_group,1,'a1170002-4459-4d00-9000-000000000001',repeat('A',80),repeat('B',87)),
          (fixture_group,1,'a1170002-4459-4d00-9000-000000000002',repeat('C',80),repeat('D',87));
  set local role authenticated;
  perform pg_temp.group_file_actor(1);
  perform public.st_v7_stage_group_file(fixture_group,file_id,1,60);
  perform public.st_v7_stage_group_file(fixture_group,file_id,1,60);
  if (public.st_v6_attachment_capacity()->>'reserved_bytes')::integer<>32
    or public.st_v7_group_file_access(file_id,'upload') is distinct from 60
    or public.st_v7_lease_group_file_upload(file_id,61)
    or not public.st_v7_lease_group_file_upload(file_id,60)
    or public.st_v7_group_file_access(file_id,'read',message_id) is not null then
    raise exception 'Incorrect uploaded-but-unpublished authority or usage';
  end if;
  begin
    perform public.st_v7_publish_group_file(file_id,envelope);
    raise exception 'An incomplete object was published';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  insert into storage.objects(bucket_id,name,metadata)
    values('sectalk-encrypted-group-files',file_id::text,jsonb_build_object('size',60,'mimetype','application/octet-stream'));
  set local role authenticated;
  perform pg_temp.group_file_actor(1);
  if public.st_v7_publish_group_file(file_id,envelope) is distinct from message_id
    or public.st_v7_publish_group_file(file_id,envelope) is distinct from message_id
    or (public.st_v6_attachment_capacity()->>'stored_bytes')::integer<>32 then
    raise exception 'Upload publication did not stay exact or idempotent';
  end if;
  perform pg_temp.group_file_actor(2);
  if public.st_v7_group_file_access(file_id,'read',message_id) is distinct from 60
    or public.st_v7_group_file_access(file_id,'read',gen_random_uuid()) is not null
    or exists(select 1 from storage.objects where bucket_id='sectalk-encrypted-group-files' and name=file_id::text) then
    raise exception 'Group file authorization or raw Storage privacy failed';
  end if;
  perform pg_temp.group_file_actor(3);
  if public.st_v7_group_file_access(file_id,'read',message_id) is not null then raise exception 'Group file leaked'; end if;
  reset role;
  delete from sectalk_private.st_group_members where st_group_members.group_id=fixture_group and actor=peer_id;
  set local role authenticated;
  perform pg_temp.group_file_actor(2);
  if public.st_v7_group_file_access(file_id,'read',message_id) is not null then raise exception 'Removed member retained file access'; end if;
  perform pg_temp.group_file_actor(1);
  perform public.st_v7_stage_group_file(fixture_group,expired_id,1,60);
  reset role;
  update sectalk_private.st_v7_group_files set expires_at=now()-interval '1 minute' where id=expired_id;
  set local role service_role;
  select t.lease into claim_id from public.st_v7_claim_group_file_cleanup() t where t.id=expired_id;
  if claim_id is null or public.st_v7_finish_group_file_cleanup(expired_id,gen_random_uuid())
    or not public.st_v7_finish_group_file_cleanup(expired_id,claim_id) then raise exception 'Cleanup lease scope failed'; end if;
  reset role;
end $$;

select 'passed: ciphertext-only object scope, combined capacity, atomic publication, epoch-device access and cleanup' as result;
rollback;
