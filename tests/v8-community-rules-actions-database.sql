begin;
do $$
declare
  actor uuid:=gen_random_uuid(); peer uuid:=gen_random_uuid(); native_session uuid:=gen_random_uuid();
  peer_session uuid:=gen_random_uuid(); device uuid:=gen_random_uuid(); peer_device uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid();
  actor_claims text:=jsonb_build_object('sub',actor,'role','authenticated','session_id',native_session,'aal','aal2')::text;
  peer_claims text:=jsonb_build_object('sub',peer,'role','authenticated','session_id',peer_session,'aal','aal1')::text;
  workspace uuid; room uuid:=gen_random_uuid(); channel uuid; conversation uuid:=gen_random_uuid();
  group_chat uuid:=gen_random_uuid(); direct_call uuid; group_call uuid; old_message uuid:=gen_random_uuid();
  scheduled uuid:=gen_random_uuid(); proposal jsonb; keys jsonb; envelope jsonb;
  managed_room uuid:=gen_random_uuid(); managed_channel uuid; room_ticket uuid; channel_ticket uuid;
begin
  insert into auth.users(id,email) values(actor,actor||'@example.invalid'),(peer,peer||'@example.invalid');
  insert into public.st_profiles(id,handle,name) values
    (actor,'rules_'||left(actor::text,8),'Rules owner'),(peer,'rules_'||left(peer::text,8),'Rules member');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,actor,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(native_session,actor,'aal2',factor),(peer_session,peer,'aal1',null);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
    (gen_random_uuid(),native_session,'password',now(),now()),(gen_random_uuid(),native_session,'totp',now(),now()),
    (gen_random_uuid(),peer_session,'password',now(),now());
  insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature) values
    (device,actor,'trusted',repeat('A',87),repeat('B',87),repeat('C',86)),
    (peer_device,peer,'trusted',repeat('D',87),repeat('E',87),repeat('F',86));
  insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id) values
    (native_session,actor,device),(peer_session,peer,peer_device);
  insert into public.st_chats(id,member_a,member_b,requester,status)
    values(conversation,least(actor,peer),greatest(actor,peer),actor,'accepted');
  insert into sectalk_private.st_v8_community_rules values
    ('fixture-future',now()+interval '30 days','Future rules','["Fixture"]');
  set local role authenticated;
  perform set_config('request.jwt.claims',actor_claims,true);
  workspace:=public.st_v2_create_workspace('Community rules controls');
  perform public.st_v6_room_create(room,workspace,'Community room','private','blank');
  channel:=public.st_v2_create_channel(workspace,'community-fixture');
  perform public.st_v8_set_channel_mode_policy(workspace,true);
  managed_channel:=public.st_v2_create_channel(workspace,'community-managed-fixture');
  perform public.st_v8_managed_room_policy(workspace,true);
  perform public.st_v6_room_create(managed_room,workspace,'Managed community room','private','blank');
  room_ticket:=(public.st_v8_managed_room_ticket(managed_room,gen_random_uuid(),'Issued before rules')->>'ticket')::uuid;
  channel_ticket:=(public.st_v8_managed_channel_ticket(managed_channel,'send',gen_random_uuid(),'Issued before rules')->>'ticket')::uuid;
  proposal:=jsonb_build_object('name','Community group','cap',2,'members',jsonb_build_array(peer),'previous_epoch',0);
  select jsonb_object_agg(d->>'device',jsonb_build_object('sealed',repeat('A',80),'ephemeral',repeat('B',87)))
    into keys from jsonb_array_elements(public.st_group_chat('preview',group_chat,proposal)->'devices') d;
  perform public.st_group_chat('rotate',group_chat,proposal||jsonb_build_object('epoch',1,'envelopes',keys));
  perform public.st_send(conversation,old_message,'Before rules');
  perform public.st_v6_schedule_message(conversation,scheduled,'Queued before rules',now()+interval '1 hour');
  direct_call:=public.st_v6_start_call(conversation,false,device);
  group_call:=(public.st_v6_group_call('create',p_device=>device,p_targets=>array[peer])->>'id')::uuid;
  if direct_call is null or group_call is null then raise exception 'Future rules blocked call creation'; end if;
  reset role;
  set local role service_role;
  if public.st_v8_managed_room_work(room_ticket,actor,'key') is null
    or public.st_v8_channel_write_key(channel_ticket,actor) is null then
    raise exception 'Future rules blocked managed content tickets'; end if;
  reset role;

  update public.st_v6_scheduled_messages set send_at=now()-interval '1 minute' where id=scheduled;
  insert into sectalk_private.st_v8_community_rules values
    ('fixture-v1',now()-interval '2 seconds','Community Rules','["Treat other people with respect."]');
  perform set_config('request.jwt.claims','{}',true);
  set local role service_role;
  if public.st_v8_managed_room_work(room_ticket,actor,'key') is not null
    or public.st_v8_channel_write_key(channel_ticket,actor) is not null then
    raise exception 'Managed post ticket issued before the policy bypassed current rules'; end if;
  reset role;
  perform sectalk_private.st_v6_dispatch_scheduled_messages();
  if not exists(select 1 from public.st_v6_scheduled_messages where id=scheduled and state='pending') then
    raise exception 'An older queued message was sent without current acceptance'; end if;

  set local role authenticated;
  perform set_config('request.jwt.claims',actor_claims,true);
  perform public.st_v6_call_action(direct_call,'end',device);
  perform public.st_v6_group_call('leave',p_call=>group_call,p_device=>device);
  if not exists(select 1 from public.st_messages where id=old_message) then
    raise exception 'Rules changed access to existing conversation data'; end if;
  envelope:=jsonb_build_object('id',gen_random_uuid(),'epoch',1,'payload',repeat('C',42),'signature',repeat('D',86));
  begin
    perform public.st_send(conversation,gen_random_uuid(),'Denied direct message');
    raise exception 'Direct send bypassed its Community Rules gate';
  exception when sqlstate 'PT428' then null; end;
  begin
    perform public.st_v6_room_post(room,gen_random_uuid(),'Denied room message');
    raise exception 'Room post bypassed its Community Rules gate';
  exception when sqlstate 'PT428' then null; end;
  begin
    perform public.st_v2_post(channel,gen_random_uuid(),'Denied channel message');
    raise exception 'Channel post bypassed its Community Rules gate';
  exception when sqlstate 'PT428' then null; end;
  begin
    perform public.st_group_chat('send',group_chat,envelope);
    raise exception 'Encrypted group send bypassed its Community Rules gate';
  exception when sqlstate 'PT428' then null; end;
  begin
    perform public.st_v6_start_call(conversation,true,device);
    raise exception 'Direct video call bypassed its Community Rules gate';
  exception when sqlstate 'PT428' then null; end;
  begin
    perform public.st_v6_group_call('create',p_device=>device,p_targets=>array[peer]);
    raise exception 'Group call bypassed its Community Rules gate';
  exception when sqlstate 'PT428' then null; end;
  begin
    perform public.st_v6_start_room_call(room,gen_random_uuid(),'Denied room call');
    raise exception 'Room call bypassed its Community Rules gate';
  exception when sqlstate 'PT428' then null; end;
  begin
    perform public.st_v6_schedule_message(conversation,gen_random_uuid(),'Denied queue',now()+interval '1 hour');
    raise exception 'Schedule submission bypassed its Community Rules gate';
  exception when sqlstate 'PT428' then null; end;
  begin
    perform public.st_v8_managed_room_ticket(managed_room,gen_random_uuid(),'Unaccepted managed room message');
    raise exception 'Managed room ticket issuance bypassed current rules';
  exception when sqlstate 'PT428' then null; end;
  begin
    perform public.st_v8_managed_channel_ticket(managed_channel,'send',gen_random_uuid(),'Unaccepted managed channel message');
    raise exception 'Managed channel ticket issuance bypassed current rules';
  exception when sqlstate 'PT428' then null; end;
  perform public.st_v8_community_rules_check('fixture-v1');
  perform public.st_send(conversation,gen_random_uuid(),'Allowed direct message');
  perform public.st_v6_room_post(room,gen_random_uuid(),'Allowed room message');
  perform public.st_v2_post(channel,gen_random_uuid(),'Allowed channel message');
  perform public.st_group_chat('send',group_chat,envelope);
  perform public.st_v6_start_call(conversation,true,device);
  perform public.st_v6_group_call('create',p_device=>device,p_targets=>array[peer]);
  perform public.st_v6_start_room_call(room,gen_random_uuid(),'Allowed room call');

  perform set_config('request.jwt.claims',jsonb_build_object('sub',actor,'role','authenticated','session_id',peer_session)::text,true);
  begin
    perform public.st_send(conversation,gen_random_uuid(),'Accepted account with wrong native session');
    raise exception 'An accepted account used a different native session';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',peer_claims,true);
  begin
    perform public.st_send(conversation,gen_random_uuid(),'Independent recipient acceptance needed');
    raise exception 'One account acceptance applied to another';
  exception when sqlstate 'PT428' then null; end;
  reset role;
  perform set_config('request.jwt.claims','{}',true);
  perform sectalk_private.st_v6_dispatch_scheduled_messages();
  if not exists(select 1 from public.st_messages where id=scheduled) then
    raise exception 'Queued message failed to resume after current acceptance'; end if;
  insert into sectalk_private.st_v8_community_rules values
    ('fixture-v2',now()-interval '1 second','Updated rules','["Report abuse through SecTalk."]');
  set local role authenticated;
  perform set_config('request.jwt.claims',actor_claims,true);
  begin
    perform public.st_send(conversation,gen_random_uuid(),'Old receipt');
    raise exception 'A superseded receipt authorized a new send';
  exception when sqlstate 'PT428' then null; end;
  perform public.st_v8_community_rules_check('fixture-v2');
  perform public.st_send(conversation,gen_random_uuid(),'Accepted updated Community Rules');
end $$;
rollback;
