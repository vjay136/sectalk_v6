begin;
do $$
declare
 account uuid:=gen_random_uuid();
 stranger uuid:=gen_random_uuid();
 controller uuid:=gen_random_uuid();
 target_session uuid:=gen_random_uuid();
 reauth uuid:=gen_random_uuid();
 foreign_session uuid:=gen_random_uuid();
 device uuid:=gen_random_uuid();
 nonce uuid:=gen_random_uuid();
 command uuid;
 challenge uuid;
 claim jsonb;
begin
 insert into auth.users(id,email) select id,id||'@example.invalid' from unnest(array[account,stranger]) id;
 insert into auth.sessions(id,user_id,aal) values
  (controller,account,'aal1'),(target_session,account,'aal1'),(reauth,account,'aal1'),(foreign_session,stranger,'aal1');
 insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
 select gen_random_uuid(),id,'password',now(),now() from unnest(array[controller,target_session,reauth,foreign_session]) id;
 insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature)
 values(device,account,'trusted',repeat('m',87),repeat('n',87),repeat('o',86));
 insert into sectalk_private.st_v7_device_sessions values(target_session,account,device);
 if has_function_privilege('authenticated','public.st_v7_claim_device_command(uuid,uuid,uuid,timestamptz)','execute')
  or has_function_privilege('authenticated','public.st_v7_ack_device_command(uuid,uuid,text)','execute')
  or has_table_privilege('authenticated','sectalk_private.st_v7_device_commands','select') then
  raise exception 'Command proof or receipt bypass exposed'; end if;
 set local role authenticated;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',stranger,'session_id',foreign_session,'aal','aal1')::text,true);
 if public.st_v7_issue_device_command(device,'wipe') or exists(select from public.st_v7_list_device_commands()) then
   raise exception 'Foreign account controlled or observed the device'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',account,'session_id',controller,'aal','aal1')::text,true);
 if not public.st_v7_issue_device_command(device,'lock') then raise exception 'Pending lock failed'; end if;
 select a.command into command from public.st_v7_list_device_commands() a where a.state='pending' and a.locked;
 if command is null or not public.st_v7_issue_device_command(device,'cancel',command) then
   raise exception 'Pending cancellation did not succeed'; end if;
 if not exists(select from public.st_v7_list_device_commands() where state='cancelled' and not locked) then
   raise exception 'Cancellation retained lock'; end if;
 if not public.st_v7_issue_device_command(device,'lock') then raise exception 'Second lock failed'; end if;
 reset role;
 if exists(select from auth.sessions where id=target_session) then raise exception 'Lock or cancellation restored revoked access'; end if;
 if public.st_v7_claim_device_command(stranger,device,nonce,now()) is not null
  or public.st_v7_claim_device_command(account,device,nonce,now()-interval '3 minutes') is not null then
   raise exception 'Foreign or stale challenge became eligible'; end if;
 claim:=public.st_v7_claim_device_command(account,device,nonce,now());
 command:=(claim#>>'{command,id}')::uuid;
 if claim->>'locked' is distinct from 'true' or claim#>>'{command,kind}' is distinct from 'lock'
  or public.st_v7_claim_device_command(account,device,nonce,now()) is not null then
   raise exception 'Lock delivery or replay prevention failed'; end if;

 set local role authenticated;
 if public.st_v7_issue_device_command(device,'cancel',command) then raise exception 'Dispatched command was cancellable'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',account,'session_id',reauth,'aal','aal1')::text,true);
 challenge:=(public.st_v7_begin_device_bundle(device,repeat('m',87),repeat('n',87))->>'challenge')::uuid;
 reset role;
 if public.st_v7_finish_device_bundle(account,reauth,challenge,repeat('o',86)) then raise exception 'Locked identity re-enrolled'; end if;
 if public.st_v7_ack_device_command(device,command,repeat('0',64))
  or not public.st_v7_ack_device_command(device,command,claim#>>'{command,receipt}')
  or not public.st_v7_ack_device_command(device,command,claim#>>'{command,receipt}') then
   raise exception 'Receipt validation or idempotence failed'; end if;

 set local role authenticated;
 if not public.st_v7_issue_device_command(device,'unlock') then raise exception 'Fresh own current-device recovery failed'; end if;
 challenge:=(public.st_v7_begin_device_bundle(device,repeat('m',87),repeat('n',87))->>'challenge')::uuid;
 reset role;
 if not public.st_v7_finish_device_bundle(account,reauth,challenge,repeat('o',86)) then raise exception 'Unlocked keys could not bind'; end if;
 set local role authenticated;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',account,'session_id',controller,'aal','aal1')::text,true);
 if not public.st_v7_issue_device_command(device,'wipe') then raise exception 'Wipe could not queue'; end if;
 reset role;
 claim:=public.st_v7_claim_device_command(account,device,gen_random_uuid(),now());
 command:=(claim#>>'{command,id}')::uuid;
 if claim->>'wiped' is distinct from 'true' or claim#>>'{command,kind}' is distinct from 'wipe'
  or not public.st_v7_ack_device_command(device,command,claim#>>'{command,receipt}') then
   raise exception 'Wipe receipt failed'; end if;
 set local role authenticated;
 if public.st_v7_issue_device_command(device,'unlock') then raise exception 'Wiped identity unlocked'; end if;
 if not exists(select from public.st_v7_list_device_commands() where state='acknowledged'
    and wiped and acknowledged_at is not null) then raise exception 'Durable acknowledgment missing'; end if;
end $$;
rollback;
