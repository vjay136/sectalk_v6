begin;
create function pg_temp.managed_actor(p_actor uuid,p_aal text default 'aal2')
returns void language sql security definer set search_path='' as $$
  select set_config('request.jwt.claims',jsonb_build_object('sub',p_actor,'aal',p_aal,'role','authenticated',
    'session_id',(select id from auth.sessions where user_id=p_actor limit 1))::text,true)::text::void;
$$;
do $$
declare
  owner_id uuid:=gen_random_uuid();
  reader uuid:=gen_random_uuid();
  outsider uuid:=gen_random_uuid();
  actor uuid;
  native uuid;
  factor uuid;
  tenant uuid;
  standard uuid;
  managed uuid;
  message uuid:=gen_random_uuid();
  ticket uuid;
  read_ticket uuid;
  prepared jsonb;
  packet jsonb:=jsonb_build_object('body','cHJvdGVjdGVkLWZpeHR1cmU','nonce',repeat('n',16),'tag',repeat('t',22),
    'wrapped_dek',repeat('k',80));
begin
  foreach actor in array array[owner_id,reader,outsider] loop
    native:=gen_random_uuid();
    factor:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'mcqa_'||left(actor::text,8),'Managed channel QA');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(native,actor,'aal2',factor);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),native,'totp',now(),now());
  end loop;
  perform pg_temp.managed_actor(owner_id);
  tenant:=public.st_v2_create_workspace('Disposable managed channel');
  standard:=public.st_v2_create_channel(tenant,'standard-channel');
  insert into public.st_v2_members(workspace_id,user_id,role) values(tenant,reader,'member');
  if has_table_privilege('authenticated','sectalk_private.st_v8_channel_payloads','select')
    or has_function_privilege('authenticated','public.st_v8_read_managed_channel(uuid,uuid,timestamptz,uuid,integer)','execute')
    or has_function_privilege('authenticated','public.st_v8_channel_write_key(uuid,uuid,text)','execute') then
    raise exception 'Managed key or ciphertext service path exposed';
  end if;
  perform pg_temp.managed_actor(owner_id,'aal1');
  set local role authenticated;
  begin
    perform public.st_v8_set_channel_mode_policy(tenant,true);
    raise exception 'AAL1 updated the managed channel policy';
  exception when insufficient_privilege then null; end;
  perform pg_temp.managed_actor(owner_id);
  perform public.st_v8_set_channel_mode_policy(tenant,true);
  managed:=public.st_v2_create_channel(tenant,'managed-channel');
  perform public.st_v8_set_channel_mode_policy(tenant,false);
  reset role;
  insert into sectalk_private.st_v7_workspace_dlp(workspace_id,revision,rules) values(tenant,1,
    '{"pii":"redact","credential":"block","phi":"warn","payment_card":"off"}');
  set local role authenticated;
  perform pg_temp.managed_actor(reader);
  if (select encryption_mode from public.st_v2_channels where id=standard)<>'standard'
    or (select encryption_mode from public.st_v2_channels where id=managed)<>'managed' then
    raise exception 'Creation policies were not fixed per channel';
  end if;
  begin
    perform public.st_v2_post(managed,message,'Direct plaintext attempt');
    raise exception 'Managed mode accepted native cleartext';
  exception when insufficient_privilege then null; end;
  perform public.st_v2_post(standard,gen_random_uuid(),'Legacy native post remains available');
  prepared:=public.st_v8_managed_channel_ticket(managed,'send',gen_random_uuid(),'Fixture qa@example.invalid');
  if prepared->>'body'<>'Fixture […]' then raise exception 'Managed plan skipped the workspace redaction'; end if;
  begin
    perform public.st_v8_managed_channel_ticket(managed,'send',gen_random_uuid(),'Synthetic password: dummy-fixture-value');
    raise exception 'Managed plan skipped the workspace block';
  exception when sqlstate 'PT422' then null; end;
  begin
    perform public.st_v8_managed_channel_ticket(managed,'send',gen_random_uuid(),'Synthetic patient ID: QA123456');
    raise exception 'Managed plan skipped the workspace warning';
  exception when sqlstate 'PT428' then null; end;
  ticket:=(public.st_v8_managed_channel_ticket(managed,'send',message,'Protected fixture text')->>'ticket')::uuid;
  reset role;
  if public.st_v8_channel_write_key(ticket,outsider,repeat('a',80)) is not null then
    raise exception 'Outsider obtained key context using another actor ticket';
  end if;
  if public.st_v8_channel_write_key(ticket,reader,repeat('a',80))->>'version'<>'1'
    or not public.st_v8_finish_managed_channel_send(ticket,reader,1,packet)
    or public.st_v8_finish_managed_channel_send(ticket,reader,1,packet) then
    raise exception 'Managed publication and ticket replay are inconsistent';
  end if;
  set constraints st_v8_guard_managed_channel_post immediate;
  set local role authenticated;
  if public.st_v8_managed_channel_ticket(managed,'send',message,'Protected fixture text')->>'already_sent'<>'true' then
    raise exception 'Exact delivery retry did not reuse the existing post';
  end if;
  begin
    perform public.st_v8_managed_channel_ticket(managed,'send',message,'Different fixture text');
    raise exception 'Changed message could reuse a delivery ID';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  if not exists(select 1 from public.st_v2_posts where id=message and body='Managed encrypted message')
    or exists(select 1 from sectalk_private.st_v7_search_sources where id=message) then
    raise exception 'Ordinary body or generic search exposed a managed payload';
  end if;
  begin
    update public.st_v2_channels set encryption_mode='standard' where id=managed;
    raise exception 'Mode could be changed after creation';
  exception when insufficient_privilege then null; end;
  begin
    delete from sectalk_private.st_v7_tenant_key_versions where workspace=tenant;
    raise exception 'Existing managed conversation lost its key version';
  exception when foreign_key_violation then null; end;
  set local role authenticated;
  perform pg_temp.managed_actor(outsider);
  begin
    perform public.st_v8_managed_channel_ticket(managed,'read');
    raise exception 'Outsider obtained a managed read ticket';
  exception when insufficient_privilege then null; end;
  perform pg_temp.managed_actor(reader);
  read_ticket:=(public.st_v8_managed_channel_ticket(managed,'read')->>'ticket')::uuid;
  reset role;
  if public.st_v8_read_managed_channel(read_ticket,outsider,null,null,51) is not null
    or public.st_v8_read_managed_channel(read_ticket,reader,null,null,51)#>>'{0,envelope,body}' is distinct from packet->>'body'
    or public.st_v8_read_managed_channel(read_ticket,reader,null,null,51) is not null then
    raise exception 'Read ticket or replay scope changed';
  end if;
  set local role authenticated;
  read_ticket:=(public.st_v8_managed_channel_ticket(managed,'read')->>'ticket')::uuid;
  reset role;
  update public.st_v2_members set suspended_at=clock_timestamp() where workspace_id=tenant and user_id=reader;
  if public.st_v8_read_managed_channel(read_ticket,reader,null,null,51) is not null then
    raise exception 'A revoked member could redeem a read ticket';
  end if;
end $$;
rollback;
