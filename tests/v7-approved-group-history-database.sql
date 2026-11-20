begin;

insert into auth.users(id,email) values
  ('ae000000-5db2-42df-8001-000000000001','history-owner@example.invalid'),
  ('ae000000-5db2-42df-8001-000000000002','history-peer@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('ae000000-5db2-42df-8001-000000000001','history_owner','Encrypted history fixture'),
  ('ae000000-5db2-42df-8001-000000000002','history_peer','Encrypted history fixture');
insert into auth.sessions(id,user_id,aal) values
  ('ae001000-5db2-42df-8001-000000000001','ae000000-5db2-42df-8001-000000000001','aal1'),
  ('ae001000-5db2-42df-8001-000000000002','ae000000-5db2-42df-8001-000000000001','aal1'),
  ('ae001000-5db2-42df-8001-000000000003','ae000000-5db2-42df-8001-000000000002','aal1');
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
select gen_random_uuid(),('ae001000-5db2-42df-8001-00000000000'||n)::uuid,'password',now(),now() from generate_series(1,3) n;
insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature)
select ('ae002000-5db2-42df-8001-00000000000'||n)::uuid,
  ('ae000000-5db2-42df-8001-00000000000'||case when n=3 then '2' else '1' end)::uuid,
  case when n=4 then 'known' else 'trusted' end,repeat(chr(65+n),87),repeat(chr(75+n),87),repeat(chr(85+n),86)
from generate_series(1,4) n;
insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id)
select ('ae001000-5db2-42df-8001-00000000000'||n)::uuid,
  ('ae000000-5db2-42df-8001-00000000000'||case when n=3 then '2' else '1' end)::uuid,
  ('ae002000-5db2-42df-8001-00000000000'||n)::uuid from generate_series(1,3) n;

create function pg_temp.history_fixture_actor(n int) returns void language sql as $$
  select set_config('request.jwt.claims',jsonb_build_object('sub','ae000000-5db2-42df-8001-00000000000'||case when n=3 then '2' else '1' end,
    'session_id','ae001000-5db2-42df-8001-00000000000'||n,'aal','aal1')::text,true)::text::void
$$;

do $$
declare history_group uuid:=gen_random_uuid();
declare owner_actor constant uuid:='ae000000-5db2-42df-8001-000000000001';
declare peer_actor constant uuid:='ae000000-5db2-42df-8001-000000000002';
declare source_device constant uuid:='ae002000-5db2-42df-8001-000000000001';
declare target_device constant uuid:='ae002000-5db2-42df-8001-000000000002';
declare own_session constant uuid:='ae001000-5db2-42df-8001-000000000001';
declare new_session constant uuid:='ae001000-5db2-42df-8001-000000000002';
declare first_receipt jsonb;
declare nonce uuid;
declare wrapped jsonb:=jsonb_build_array(jsonb_build_object('epoch',1,'sealed',repeat('Z',80),'ephemeral',repeat('Y',87)));
begin
  insert into sectalk_private.st_group_chats values(history_group,owner_actor,'Approved history fixture',2,2);
  insert into sectalk_private.st_group_members values(history_group,owner_actor),(history_group,peer_actor);
  insert into sectalk_private.st_group_envelopes(group_id,epoch,device,sealed,ephemeral) values
    (history_group,1,source_device,repeat('A',80),repeat('B',87)),
    (history_group,2,source_device,repeat('C',80),repeat('D',87)),
    (history_group,2,target_device,repeat('G',80),repeat('H',87));
  set local role authenticated;
  perform pg_temp.history_fixture_actor(1);
  if jsonb_array_length(public.st_v7_group_history_targets(history_group))<>1
    or public.st_v7_group_history_targets(history_group)->0->>'id' is distinct from target_device::text then
    raise exception 'Target selector leaked or omitted same-account approved browser';
  end if;
  begin
    perform public.st_v7_prepare_group_history(history_group,'ae002000-5db2-42df-8001-000000000003');
    raise exception 'A group peer was an eligible transfer destination';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_prepare_group_history(history_group,'ae002000-5db2-42df-8001-000000000004');
    raise exception 'A known but unapproved browser was an eligible destination';
  exception when insufficient_privilege then null; end;
  first_receipt:=public.st_v7_prepare_group_history(history_group,target_device);
  nonce:=(first_receipt->>'nonce')::uuid;
  if nonce is null or jsonb_array_length(first_receipt->'original')<>1
    or first_receipt->'original'->0->>'epoch' is distinct from '1' then raise exception 'Wrong historical keys targeted'; end if;
  perform pg_temp.history_fixture_actor(2);
  if public.st_v7_group_history_proof(nonce) is not null then raise exception 'Different session claimed source authority'; end if;
  reset role;
  update sectalk_private.st_v7_devices set state='blocked' where id=target_device;
  set local role service_role;
  if public.st_v7_finish_group_history(nonce,owner_actor,own_session,wrapped) is not null then
    raise exception 'Revoked target accepted a prepared transfer'; end if;
  reset role;
  update sectalk_private.st_v7_devices set state='trusted' where id=target_device;
  set local role service_role;
  if public.st_v7_finish_group_history(nonce,owner_actor,new_session,wrapped) is not null
    or public.st_v7_finish_group_history(nonce,owner_actor,own_session,jsonb_build_array(wrapped->0||'{"epoch":2}'::jsonb)) is not null
    or public.st_v7_finish_group_history(nonce,owner_actor,own_session,wrapped) is distinct from 1
    or public.st_v7_finish_group_history(nonce,owner_actor,own_session,wrapped) is distinct from 1 then
    raise exception 'Session binding, candidate epoch policy or exact retry failed';
  end if;
  reset role;
  if (select count(*) from sectalk_private.st_group_envelopes where group_id=history_group and device=target_device)<>2
    or (select sealed from sectalk_private.st_group_envelopes where group_id=history_group and device=target_device and epoch=2)<>repeat('G',80) then
    raise exception 'Existing destination key overwritten or historical key duplicated';
  end if;
end $$;

select 'passed: approved source session, same-account target, epoch scope, revocation and exact transfer retry' as result;
rollback;
