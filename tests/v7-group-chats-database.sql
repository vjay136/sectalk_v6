begin;

insert into auth.users(id,email)
select ('4e250000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'group-chat-'||n||'@example.invalid'
from generate_series(1,5) n;
insert into public.st_profiles(id,handle,name)
select ('4e250000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'group_chat_'||n,'Group chat fixture'
from generate_series(1,5) n;
insert into auth.sessions(id,user_id,aal)
select ('4e250001-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('4e250000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'aal1'
from generate_series(1,5) n;
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
select gen_random_uuid(),('4e250001-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'password',now(),now()
from generate_series(1,5) n;
insert into public.st_chats(id,member_a,member_b,requester,status)
values (gen_random_uuid(),'4e250000-0000-4000-8000-000000000001','4e250000-0000-4000-8000-000000000002',
  '4e250000-0000-4000-8000-000000000001','accepted');
insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature)
select ('4e250002-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('4e250000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  case when n=2 then 'managed' else 'trusted' end,
  repeat(chr(65+n),87),repeat(chr(75+n),87),repeat(chr(85+n),86)
from generate_series(1,5) n;
insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id)
select ('4e250001-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('4e250000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('4e250002-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid
from generate_series(1,5) n;

insert into public.st_chats(id,member_a,member_b,requester,status)
select gen_random_uuid(),'4e250000-0000-4000-8000-000000000001',
  ('4e250000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  '4e250000-0000-4000-8000-000000000001','accepted' from generate_series(3,5) n;

do $$
declare
  owner constant uuid:='4e250000-0000-4000-8000-000000000001';
  peer constant uuid:='4e250000-0000-4000-8000-000000000002';
  newcomer constant uuid:='4e250000-0000-4000-8000-000000000003';
  outsider constant uuid:='4e250000-0000-4000-8000-000000000004';
  fifth constant uuid:='4e250000-0000-4000-8000-000000000005';
  owner_claims constant text:=jsonb_build_object('sub',owner,'session_id','4e250001-0000-4000-8000-000000000001','aal','aal1')::text;
  peer_claims constant text:=jsonb_build_object('sub',peer,'session_id','4e250001-0000-4000-8000-000000000002','aal','aal1')::text;
  newcomer_claims constant text:=jsonb_build_object('sub',newcomer,'session_id','4e250001-0000-4000-8000-000000000003','aal','aal1')::text;
  outsider_claims constant text:=jsonb_build_object('sub',outsider,'session_id','4e250001-0000-4000-8000-000000000004','aal','aal1')::text;
  g constant uuid:=gen_random_uuid();
  body jsonb:=jsonb_build_object('name','SQL fixture','cap',2,'members',jsonb_build_array(peer),'previous_epoch',0);
  preview jsonb;
  keys jsonb;
  msg jsonb:=jsonb_build_object('id',gen_random_uuid(),'epoch',1,'payload',repeat('C',42),'signature',repeat('D',86));
begin
  if has_function_privilege('anon','public.st_group_chat(text,uuid,jsonb)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_group_envelopes','select')
    or has_table_privilege('authenticated','sectalk_private.st_group_messages','insert') then raise exception 'Group storage is public'; end if;
  perform set_config('request.jwt.claims',owner_claims,true);
  begin
    perform public.st_group_chat('preview',g,body||jsonb_build_object('members',jsonb_build_array(peer,newcomer)));
    raise exception 'Owner cap was ignored';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_group_chat('preview',g,body||jsonb_build_object('cap',32,'members',jsonb_build_array(peer,newcomer,outsider,fifth)));
    raise exception 'Free plan cap was ignored';
  exception when invalid_parameter_value then null; end;
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values(owner,'basic','active',now()+interval '1 day');
  preview:=public.st_group_chat('preview',g,body||jsonb_build_object('cap',8,'members',jsonb_build_array(peer,newcomer,outsider,fifth)));
  if (preview->>'plan_cap')::integer<>8 or jsonb_array_length(preview->'devices')<>5 then
    raise exception 'Active Basic plan did not raise the cap';
  end if;
  delete from public.st_v2_subscriptions where user_id=owner;

  preview:=public.st_group_chat('preview',g,body);
  if (preview->>'plan_cap')::integer<>4 or jsonb_array_length(preview->'devices')<>2 then
    raise exception 'Unexpected plan or manifest';
  end if;
  select jsonb_object_agg(d->>'device',jsonb_build_object('sealed',repeat('A',80),'ephemeral',repeat('B',87)))
    into keys from jsonb_array_elements(preview->'devices') d;
  begin
    perform public.st_group_chat('rotate',g,body||jsonb_build_object('epoch',1,'envelopes','{}'::jsonb));
    raise exception 'Rotation accepted incomplete envelopes';
  exception when serialization_failure then null; end;
  perform public.st_group_chat('rotate',g,body||jsonb_build_object('epoch',1,'envelopes',keys));
  perform public.st_group_chat('send',g,msg);
  perform set_config('request.jwt.claims',peer_claims,true);
  if jsonb_array_length(public.st_group_chat('read',g)->'messages')<>1 then raise exception 'Current peer cannot read'; end if;
  begin
    perform public.st_group_chat('preview',g,body);
    raise exception 'Member can edit roster';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',outsider_claims,true);
  begin
    perform public.st_group_chat('read',g);
    raise exception 'Outsider can read';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',owner_claims,true);
  begin
    perform public.st_group_chat('preview',g,body);
    raise exception 'Stale roster could overwrite current state';
  exception when serialization_failure then null; end;
  body:=body||jsonb_build_object('previous_epoch',1,'members',jsonb_build_array(newcomer));
  preview:=public.st_group_chat('preview',g,body);
  select jsonb_object_agg(d->>'device',jsonb_build_object('sealed',repeat('E',80),'ephemeral',repeat('F',87)))
    into keys from jsonb_array_elements(preview->'devices') d;
  perform public.st_group_chat('rotate',g,body||jsonb_build_object('epoch',2,'envelopes',keys));
  begin
    perform public.st_group_chat('send',g,msg||jsonb_build_object('id',gen_random_uuid()));
    raise exception 'Stale epoch accepted after rotation';
  exception when serialization_failure then null; end;
  perform public.st_group_chat('send',g,msg||jsonb_build_object('id',gen_random_uuid(),'epoch',2));
  perform set_config('request.jwt.claims',newcomer_claims,true);
  if jsonb_array_length(public.st_group_chat('read',g)->'messages')<>1
    or (public.st_group_chat('read',g)#>>'{messages,0,epoch}')::integer<>2 then
    raise exception 'New member received historic ciphertext';
  end if;
  perform set_config('request.jwt.claims',peer_claims,true);
  begin
    perform public.st_group_chat('send',g,msg||jsonb_build_object('id',gen_random_uuid(),'epoch',2));
    raise exception 'Removed peer can send';
  exception when insufficient_privilege then null; end;
  if not (public.st_group_chat('list')='[]'::jsonb) then raise exception 'Removed peer can discover group'; end if;
  perform set_config('request.jwt.claims',owner_claims,true);
  update sectalk_private.st_v7_devices d set state='blocked' where d.owner=newcomer;
  begin
    perform public.st_group_chat('send',g,msg||jsonb_build_object('id',gen_random_uuid(),'epoch',2));
    raise exception 'Revoked device remained in sending epoch';
  exception when serialization_failure then null; end;
end $$;

select 'passed: plan and owner caps, device coverage, key epochs, removal and revoked device guard' as result;
rollback;
