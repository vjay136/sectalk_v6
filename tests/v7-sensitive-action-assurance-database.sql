begin;
do $$
declare
  actor uuid:=gen_random_uuid();
  password_session uuid:=gen_random_uuid();
  passkey_session uuid:=gen_random_uuid();
  otp_session uuid:=gen_random_uuid();
  verified_session uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid();
  workspace uuid;
  created_key uuid;
begin
  insert into auth.users(id,email,email_confirmed_at) values(actor,actor||'@example.invalid',now());
  insert into public.st_profiles(id,handle,name) values(actor,'assure_'||left(actor::text,8),'Assurance fixture');
  perform public.st_v2_sync_billing('assurance_'||actor,actor,'cus_'||actor,'sub_'||actor,'business','active',
    now()+interval '1 day',false,now());
  insert into auth.sessions(id,user_id,aal,created_at) values
    (password_session,actor,'aal1',now()),(passkey_session,actor,'aal1',now()),(otp_session,actor,'aal1',now());
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
    (gen_random_uuid(),password_session,'password',now()-interval '10 minutes',now()-interval '6 minutes'),
    (gen_random_uuid(),passkey_session,'passkey',now(),now()),
    (gen_random_uuid(),otp_session,'otp',now(),now());
  if has_function_privilege('anon','public.st_v7_sensitive_action_status(text)','execute') then
    raise exception 'Anonymous caller gained sensitive-action assurance access'; end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',
    jsonb_build_object('sub',actor,'role','authenticated','session_id',password_session,'aal','aal1')::text,true);
  if public.st_v7_sensitive_action_status('billing')<>'password' or
    public.st_v7_sensitive_action_status('unknown')<>'unavailable' then raise exception 'Stale proof or scope accepted'; end if;
  perform set_config('request.jwt.claims',
    jsonb_build_object('sub',actor,'role','authenticated','session_id',otp_session,'aal','aal1')::text,true);
  if public.st_v7_sensitive_action_status('billing')<>'password' then raise exception 'Mailbox OTP used as billing proof'; end if;
  perform set_config('request.jwt.claims',
    jsonb_build_object('sub',actor,'role','authenticated','session_id',passkey_session,'aal','aal1')::text,true);
  if public.st_v7_sensitive_action_status('room_role')<>'verified' or
    public.st_v7_sensitive_action_status('export')<>'totp' then raise exception 'Passkey bypassed distinct export proof'; end if;
  reset role;
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,actor,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id,created_at)
    values(verified_session,actor,'aal2',factor,now());
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
    (gen_random_uuid(),verified_session,'totp',now()-interval '10 minutes',now()-interval '6 minutes');

  set local role authenticated;
  perform set_config('request.jwt.claims',
    jsonb_build_object('sub',actor,'role','authenticated','session_id',verified_session,'aal','aal2')::text,true);
  if public.st_v7_sensitive_action_status('export')<>'totp' or
    public.st_v7_sensitive_action_status('room_role')<>'totp' then raise exception 'Stale TOTP still counted as recent'; end if;
  reset role;
  update auth.mfa_amr_claims set updated_at=clock_timestamp() where session_id=verified_session;
  set local role authenticated;
  if public.st_v7_sensitive_action_status('export')<>'verified' or
    public.st_v7_sensitive_action_status('room_role')<>'verified' or
    public.st_v7_sensitive_action_status('billing')<>'verified' then raise exception 'Fresh native TOTP denied'; end if;
  workspace:=public.st_v2_create_workspace('Assurance key fixture');
  created_key:=public.st_v6_create_integration_key(workspace,'Fixture key','aaaaaaaaaa',
    repeat('a',64),array['workspace:read'],7);
  if created_key is null then raise exception 'Fresh scoped owner could not issue a key'; end if;

  reset role;
  update auth.mfa_amr_claims set updated_at=now()-interval '6 minutes' where session_id=verified_session;
  set local role authenticated;
  begin
    perform public.st_v6_revoke_integration_key(workspace,created_key);
    raise exception 'Stale TOTP could still revoke an integration key';
  exception when insufficient_privilege then null; end;
  reset role;
  update auth.mfa_amr_claims set updated_at=clock_timestamp() where session_id=verified_session;
  set local role authenticated;
  perform public.st_v6_revoke_integration_key(workspace,created_key);
  if not exists(select 1 from public.st_v6_integration_key_list(workspace) k where k.id=created_key and revoked_at is not null)
    then raise exception 'Fresh scoped owner could not revoke a key'; end if;
end $$;
rollback;
