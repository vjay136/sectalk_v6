begin;
do $$
declare
  owner_id uuid:=gen_random_uuid();
  bystander uuid:=gen_random_uuid();
  native_passkey uuid:=gen_random_uuid();
  password_session uuid:=gen_random_uuid();
  outsider_session uuid:=gen_random_uuid();
  credential uuid:=gen_random_uuid();
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (owner_id,owner_id||'@example.invalid',now()),(bystander,bystander||'@example.invalid',now());
  insert into auth.sessions(id,user_id,aal,created_at) values
    (native_passkey,owner_id,'aal1',now()),(password_session,owner_id,'aal1',now()),(outsider_session,bystander,'aal1',now());
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
    (gen_random_uuid(),native_passkey,'passkey',now()-interval '10 minutes',now()),
    (gen_random_uuid(),password_session,'password',now(),now()),
    (gen_random_uuid(),outsider_session,'password',now(),now());
  insert into auth.webauthn_credentials(id,user_id,credential_id,public_key,aaguid)
    values(credential,owner_id,extensions.gen_random_bytes(32),extensions.gen_random_bytes(32),gen_random_uuid());

  if has_table_privilege('authenticated','sectalk_private.st_v7_passkey_mode','select')
    or has_function_privilege('anon','public.st_v7_passkey_only(boolean)','execute') then
    raise exception 'Passkey mode leaked to anonymous or direct access'; end if;
  perform set_config('request.jwt.claims',
    jsonb_build_object('role','authenticated','sub',owner_id,'session_id',native_passkey,'aal','aal1')::text,true);
  set local role authenticated;
  begin perform public.st_v7_passkey_only(true);
    raise exception 'Expired passkey evidence accepted'; exception when insufficient_privilege then null; end;
  reset role;
  update auth.mfa_amr_claims set created_at=clock_timestamp() where session_id=native_passkey;
  set local role authenticated;
  if not public.st_v7_passkey_only(true) then raise exception 'Fresh passkey could not enable mode'; end if;
  reset role;
  if exists(select 1 from auth.sessions where id=password_session)
    or not exists(select 1 from auth.sessions where id in (native_passkey,outsider_session)) then
    raise exception 'Mode removed the wrong sessions'; end if;
  begin
    delete from auth.webauthn_credentials where id=credential;
    raise exception 'Final credential was removable with passwordless-only enabled';
  exception when insufficient_privilege then null; end;
  insert into auth.sessions(id,user_id,aal,created_at) values(password_session,owner_id,'aal1',now());
  begin
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),password_session,'otp',now(),now());
    raise exception 'Alternative native login bypassed passkey-only mode';
  exception when insufficient_privilege then null; end;
  delete from auth.sessions where id=password_session;
  perform set_config('request.jwt.claims',
    jsonb_build_object('role','authenticated','sub',owner_id,'session_id',password_session,'aal','aal1')::text,true);
  if not public.st_v7_account_data_unavailable() or not public.st_v7_step_up_pending() then
    raise exception 'Old session bearer could reach data or Realtime'; end if;
  perform set_config('request.jwt.claims',
    jsonb_build_object('role','authenticated','sub',bystander,'session_id',outsider_session,'aal','aal1')::text,true);
  set local role authenticated;
  if public.st_v7_passkey_only() then raise exception 'Foreign mode visible'; end if;
  reset role;
  perform set_config('request.jwt.claims',
    jsonb_build_object('role','authenticated','sub',owner_id,'session_id',native_passkey,'aal','aal1')::text,true);
  set local role authenticated;
  if public.st_v7_passkey_only(false) then raise exception 'Mode failed to disable'; end if;
  reset role;
  delete from auth.webauthn_credentials where id=credential;
  if not found then raise exception 'Could not remove last passkey in mixed mode'; end if;
end $$;
rollback;
