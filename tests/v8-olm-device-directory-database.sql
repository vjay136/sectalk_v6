begin;

do $$
declare a uuid:=gen_random_uuid(); b uuid:=gen_random_uuid(); stranger uuid:=gen_random_uuid();
  sa uuid:=gen_random_uuid(); sb uuid:=gen_random_uuid(); sx uuid:=gen_random_uuid();
  first_device uuid:=gen_random_uuid(); second_device uuid:=gen_random_uuid(); foreign_device uuid:=gen_random_uuid();
  pair uuid:=gen_random_uuid(); proof text:=repeat('B',86); bundle jsonb;
  batch jsonb:='{"signed_curve25519:AAAA":{"key":"synthetic key"}}';
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (a,'olm-a@example.invalid',now()),(b,'olm-b@example.invalid',now()),(stranger,'olm-x@example.invalid',now());
  insert into public.st_profiles(id,handle,name) values(a,'olm_directory_a','Approved first browser'),
    (b,'olm_directory_b','Approved second browser'),(stranger,'olm_directory_x','Unrelated browser');
  insert into auth.sessions(id,user_id,aal) values(sa,a,'aal1'),(sb,b,'aal1'),(sx,stranger,'aal1');
  insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature) values
    (first_device,a,'trusted',repeat('A',87),repeat('B',87),proof),
    (second_device,b,'trusted',repeat('C',87),repeat('D',87),proof),
    (foreign_device,stranger,'trusted',repeat('E',87),repeat('F',87),proof);
  insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id) values
    (sa,a,first_device),(sb,b,second_device),(sx,stranger,foreign_device);
  insert into public.st_chats(id,member_a,member_b,requester,status)
    values(pair,least(a,b),greatest(a,b),a,'accepted');
  if has_function_privilege('authenticated','public.st_v8_olm_register_device(uuid,uuid,uuid,jsonb,text,jsonb)','EXECUTE')
    or has_table_privilege('authenticated','sectalk_private.st_v8_olm_prekeys','SELECT,INSERT,UPDATE,DELETE') then
    raise exception 'Browser credential may not write or inspect the private prekey archive';
  end if;

  bundle:=jsonb_build_object('user_id','@'||b::text||':sectalk.invalid','device_id',second_device,'test_marker','immutable fixture');
  set local role service_role;
  if public.st_v8_olm_register_device(b,second_device,sb,bundle,proof,batch)->>'signed_curve25519'<>'1' then
    raise exception 'The approved device registration did not make the prekey available';
  end if;
  begin
    perform public.st_v8_olm_register_device(b,second_device,sa,bundle,proof,batch);
    raise exception 'A different account session bound a prekey bundle';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_olm_register_device(b,second_device,sb,bundle || '{"test_marker":"changed"}',proof,'{}');
    raise exception 'Reassigned device identity';
  exception when unique_violation then null; end;
  reset role;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',a,'session_id',sa,'aal','aal1')::text,true);
  set local role authenticated;
  if public.st_v8_olm_device_proof()->>'device'<>first_device::text
    or jsonb_array_length(public.st_v8_olm_pair_directory(pair)->'roster')<>2
    or public.st_v8_olm_claim_prekey(pair,second_device)<>batch then raise exception 'Approved pair key exchange failed'; end if;
  if public.st_v8_olm_claim_prekey(pair,second_device) is not null then raise exception 'One-time key was consumed twice'; end if;
  reset role;
  set local role service_role;
  if public.st_v8_olm_register_device(b,second_device,sb,bundle,proof,batch)->>'signed_curve25519'<>'0' then
    raise exception 'A retry restored a consumed one-time key';
  end if;
  reset role;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',stranger,'session_id',sx,'aal','aal1')::text,true);
  set local role authenticated;
  begin
    perform public.st_v8_olm_pair_directory(pair);
    raise exception 'Unrelated browser discovered the pair registry';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_olm_claim_prekey(pair,second_device);
    raise exception 'Unrelated browser acquired a prekey';
  exception when insufficient_privilege then null; end;
  reset role;

  update sectalk_private.st_v7_devices set state='blocked' where id=second_device;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',a,'session_id',sa,'aal','aal1')::text,true);
  set local role authenticated;
  if jsonb_array_length(public.st_v8_olm_pair_directory(pair)->'roster')<>1 then raise exception 'Revoked browser stayed in live roster'; end if;
  begin
    perform public.st_v8_olm_claim_prekey(pair,second_device);
    raise exception 'A blocked browser still received prekey traffic';
  exception when insufficient_privilege then null; end;
  reset role;
end;
$$;

rollback;
