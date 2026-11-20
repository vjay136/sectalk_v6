begin;

insert into auth.users(id,email)
select ('3e240000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'contact-key-'||n||'@example.invalid'
from generate_series(1,3) n;
insert into public.st_profiles(id,handle,name)
select ('3e240000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'contact_key_'||n,'Contact key fixture'
from generate_series(1,3) n;
insert into auth.sessions(id,user_id,aal)
select ('3e240001-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('3e240000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'aal1'
from generate_series(1,3) n;
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
select gen_random_uuid(),('3e240001-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'password',now(),now()
from generate_series(1,3) n;
insert into public.st_chats(id,member_a,member_b,requester,status)
values (gen_random_uuid(),'3e240000-0000-4000-8000-000000000001','3e240000-0000-4000-8000-000000000002',
  '3e240000-0000-4000-8000-000000000001','accepted');
insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature)
select ('3e240002-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('3e240000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  case when n=1 then 'trusted' when n=2 then 'managed' else 'known' end,
  repeat(chr(65+n),87),repeat(chr(75+n),87),repeat(chr(85+n),86)
from generate_series(1,3) n;
insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id)
select ('3e240001-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('3e240000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('3e240002-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid
from generate_series(1,3) n;

do $$
declare
  actor constant uuid:='3e240000-0000-4000-8000-000000000001';
  peer constant uuid:='3e240000-0000-4000-8000-000000000002';
  outsider constant uuid:='3e240000-0000-4000-8000-000000000003';
  peer_device constant uuid:='3e240002-0000-4000-8000-000000000002';
  actor_claims constant text:=jsonb_build_object('sub',actor,'session_id','3e240001-0000-4000-8000-000000000001','aal','aal1')::text;
  peer_claims constant text:=jsonb_build_object('sub',peer,'session_id','3e240001-0000-4000-8000-000000000002','aal','aal1')::text;
  number_of_notices bigint;
begin
  if has_function_privilege('anon','public.st_v7_contact_key_manifest(uuid)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v7_devices','select') then
    raise exception 'Key manifest is exposed outside the approved path';
  end if;
  perform set_config('request.jwt.claims',actor_claims,true);
  if (select count(*) from public.st_v7_contact_key_manifest(peer))<>2
    or exists(select from public.st_v7_contact_key_manifest(outsider)) then
    raise exception 'Manifest is outside the accepted pair';
  end if;
  perform set_config('request.jwt.claims',peer_claims,true);
  if (select count(*) from public.st_v7_contact_key_manifest(actor))<>2 then
    raise exception 'Manifest was asymmetric for verified participants';
  end if;
  select count(*) into number_of_notices from realtime.messages where topic='st:account:'||actor and event='contact_key_changed';
  update sectalk_private.st_v7_devices set state='blocked' where id=peer_device;
  if exists(select from public.st_v7_contact_key_manifest(actor)) then
    raise exception 'The blocked device could still request a manifest';
  end if;
  perform set_config('request.jwt.claims',actor_claims,true);
  if exists(select from public.st_v7_contact_key_manifest(peer) i where i.owner_id=peer)
    or (select count(*) from realtime.messages where topic='st:account:'||actor and event='contact_key_changed')<>number_of_notices+1
    or exists(select from realtime.messages where topic='st:account:'||outsider and event='contact_key_changed') then
    raise exception 'Key removal did not notify only the accepted contact';
  end if;
  insert into public.st_blocks(actor,target) values(actor,peer);
  if exists(select from public.st_v7_contact_key_manifest(peer)) then
    raise exception 'Blocking a contact did not close the manifest';
  end if;
end $$;

select 'passed: signed bundle manifest scope, blocked-device denial and private key-change notification' as result;
rollback;
