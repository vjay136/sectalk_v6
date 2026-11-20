begin;
do $$
declare
 owner_id uuid:=gen_random_uuid();
 peer_id uuid:=gen_random_uuid();
 other_id uuid:=gen_random_uuid();
 owner_session uuid:=gen_random_uuid();
 second_session uuid:=gen_random_uuid();
 peer_session uuid:=gen_random_uuid();
 outside_session uuid:=gen_random_uuid();
 first_device uuid:=gen_random_uuid();
 second_device uuid:=gen_random_uuid();
 peer_device uuid:=gen_random_uuid();
 challenge_id uuid;
 payload jsonb;
begin
 insert into auth.users(id,email) select x,x||'@example.invalid' from unnest(array[owner_id,peer_id,other_id]) x;
 insert into public.st_profiles(id,handle,name)
 select x,'device_'||left(x::text,8),'Device fixture' from unnest(array[owner_id,peer_id,other_id]) x;
 insert into auth.sessions(id,user_id,aal) values
  (owner_session,owner_id,'aal1'),(second_session,owner_id,'aal1'),(peer_session,peer_id,'aal1'),(outside_session,other_id,'aal1');
 insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
 select gen_random_uuid(),x,'password',now(),now() from unnest(array[owner_session,second_session,peer_session,outside_session])x;
 insert into public.st_chats(member_a,member_b,requester,status)
 values(least(owner_id,peer_id),greatest(owner_id,peer_id),owner_id,'accepted');
 if has_table_privilege('authenticated','sectalk_private.st_v7_devices','select')
  or has_function_privilege('authenticated','public.st_v7_finish_device_bundle(uuid,uuid,uuid,text)','execute')
  or has_function_privilege('authenticated','public.st_v7_mark_device_managed(uuid,uuid,boolean,text)','execute') then
   raise exception 'User could bypass public bundle proof or managed role'; end if;

 set local role authenticated;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'session_id',owner_session,'aal','aal1')::text,true);
 if exists(select from public.st_v7_list_devices()) then raise exception 'Unregistered session was already known'; end if;
 payload:=public.st_v7_begin_device_bundle(first_device,repeat('a',87),repeat('b',87));
 challenge_id:=(payload->>'challenge')::uuid;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'session_id',second_session,'aal','aal1')::text,true);
 if public.st_v7_pending_device_bundle(challenge_id) is not null then raise exception 'Other session read proof payload'; end if;
 reset role;
 if not public.st_v7_finish_device_bundle(owner_id,owner_session,challenge_id,repeat('c',86))
  or public.st_v7_finish_device_bundle(owner_id,owner_session,challenge_id,repeat('c',86))
 then raise exception 'Verified proof was not single-use'; end if;

 set local role authenticated;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'session_id',owner_session,'aal','aal1')::text,true);
 if (select state from public.st_v7_list_devices() where current_device) is distinct from 'known'
  or not public.st_v7_set_device_trust(first_device,'trusted') then
   raise exception 'First verified device could not become trusted'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'session_id',second_session,'aal','aal1')::text,true);
 challenge_id:=(public.st_v7_begin_device_bundle(second_device,repeat('d',87),repeat('e',87))->>'challenge')::uuid;
 reset role;
 if not public.st_v7_finish_device_bundle(owner_id,second_session,challenge_id,repeat('f',86)) then raise exception 'Second bind failed'; end if;
 set local role authenticated;
 begin perform public.st_v7_set_device_trust(second_device,'trusted');
   raise exception 'Untrusted second device approved itself'; exception when insufficient_privilege then null; end;
 begin perform public.st_v7_set_device_trust(first_device,'known');
   raise exception 'Untrusted session could demote an existing trusted device'; exception when insufficient_privilege then null; end;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'session_id',owner_session,'aal','aal1')::text,true);
 if not public.st_v7_set_device_trust(second_device,'trusted') then raise exception 'Existing trusted approval failed'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',peer_id,'session_id',peer_session,'aal','aal1')::text,true);
 if exists(select from public.st_v7_peer_device_bundles(owner_id)) then raise exception 'Unknown session read peer keys'; end if;
 challenge_id:=(public.st_v7_begin_device_bundle(peer_device,repeat('g',87),repeat('h',87))->>'challenge')::uuid;
 reset role;
 if not public.st_v7_finish_device_bundle(peer_id,peer_session,challenge_id,repeat('i',86))
  or not public.st_v7_mark_device_managed(peer_id,peer_device,true,'scoped-provider-fixture') then
   raise exception 'Privileged management provisioning failed'; end if;
 set local role authenticated;
 if (select count(*) from public.st_v7_peer_device_bundles(owner_id))<>2
  or (select state from public.st_v7_list_devices() where current_device) is distinct from 'managed' then
   raise exception 'Managed peer did not receive approved key projections'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',other_id,'session_id',outside_session,'aal','aal1')::text,true);
 if exists(select from public.st_v7_list_devices())
  or exists(select from public.st_v7_peer_device_bundles(owner_id))
  or public.st_v7_set_device_trust(second_device,'blocked') then raise exception 'Unrelated account gained rights'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'session_id',owner_session,'aal','aal1')::text,true);
 if not public.st_v7_set_device_trust(second_device,'blocked') then raise exception 'Owner failed to block'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',peer_id,'session_id',peer_session,'aal','aal1')::text,true);
 if (select count(*) from public.st_v7_peer_device_bundles(owner_id))<>1 then raise exception 'Blocked bundle still shared'; end if;
 reset role;
 if exists(select from auth.sessions where id=second_session)
  or not exists(select from sectalk_private.st_v7_device_trust_audit where device_id=peer_device
    and source='provider' and state='managed') then raise exception 'Session revocation or audit failed'; end if;
end $$;
rollback;
