begin;

do $$
declare
  owner_id uuid:=gen_random_uuid();
  other_id uuid:=gen_random_uuid();
  mfa_session uuid:=gen_random_uuid();
  password_session uuid:=gen_random_uuid();
  other_session uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid();
  original text;
  rotated text;
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (owner_id,owner_id||'@example.invalid',now()),(other_id,other_id||'@example.invalid',now());
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id,created_at) values
    (mfa_session,owner_id,'aal2',factor,now()),(password_session,owner_id,'aal1',null,now()),
    (other_session,other_id,'aal1',null,now());
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
    (gen_random_uuid(),mfa_session,'totp',now()-interval '10 minutes',now()-interval '10 minutes'),
    (gen_random_uuid(),password_session,'password',now(),now()),
    (gen_random_uuid(),other_session,'password',now(),now());

  if has_table_privilege('authenticated','sectalk_private.st_v7_recovery_keys','select')
    or has_table_privilege('service_role','sectalk_private.st_v7_recovery_device_approvals','select')
    or has_function_privilege('anon','public.st_v7_manage_recovery_key(text)','execute')
    or has_function_privilege('authenticated','public.st_v7_finish_device_recovery_approval(uuid,uuid,uuid,text,uuid)','execute') then
    raise exception 'Recovery state or privileged proof completion exposed'; end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'session_id',mfa_session,'aal','aal2')::text,true);
  set local role authenticated;
  if public.st_v7_manage_recovery_key('issue')<>'unavailable' then raise exception 'Stale TOTP issued a key'; end if;
  reset role;
  update auth.mfa_amr_claims set updated_at=now() where session_id=mfa_session;

  set local role authenticated;
  original:=public.st_v7_manage_recovery_key('issue');
  if original !~ '^[0-9A-F]{64}$' or public.st_v7_manage_recovery_key('status')<>'configured' then
    raise exception 'Fresh TOTP did not issue and configure a recovery key'; end if;
  if public.st_v7_manage_recovery_key(null)<>'unavailable' or public.st_v7_manage_recovery_key('status')<>'configured' then
    raise exception 'Unrecognized lifecycle action mutated the recovery key'; end if;
  reset role;
  if not exists(select 1 from sectalk_private.st_v7_recovery_keys where user_id=owner_id
    and key_hash=extensions.digest(original,'sha256')) then raise exception 'Recovery key hash mismatch'; end if;

  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',other_id,'session_id',other_session,'aal','aal1')::text,true);
  if public.st_v7_recovery_security_reset(original)<>'unavailable' or public.st_v7_device_recovery_to_approve() is not null then
    raise exception 'Foreign account can apply recovery proof'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'session_id',password_session,'aal','aal1')::text,true);
  if public.st_v7_recovery_security_reset(lower(original))<>'pending' or public.st_v7_recovery_security_reset(original)<>'pending' then
    raise exception 'Key failed to schedule or bypassed cooling-off'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'session_id',mfa_session,'aal','aal2')::text,true);
  rotated:=public.st_v7_manage_recovery_key('issue');
  reset role;
  if rotated !~ '^[0-9A-F]{64}$' or rotated=original or
    (select state from sectalk_private.st_v7_account_security_changes where user_id=owner_id)<>'cancelled' then
    raise exception 'Rotation failed to cancel the old recovery'; end if;

  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'session_id',password_session,'aal','aal1')::text,true);
  if public.st_v7_recovery_security_reset(original)<>'unavailable'
    or public.st_v7_recovery_security_reset(rotated)<>'pending' then raise exception 'Rotation kept the old key live'; end if;
  reset role;
  update sectalk_private.st_v7_account_security_changes set ready_at=now()-interval '1 minute' where user_id=owner_id;
  set local role authenticated;
  if public.st_v7_recovery_security_reset(rotated)<>'completed' then raise exception 'Key did not complete recovery'; end if;
  if not public.st_v7_account_data_unavailable() then raise exception 'Recovery left old token data access enabled'; end if;
  if public.st_v7_recovery_security_reset(rotated)<>'unavailable' then raise exception 'Recovery key was replayed'; end if;
  reset role;
  if exists(select 1 from sectalk_private.st_v7_recovery_keys where user_id=owner_id)
    or exists(select 1 from auth.sessions where user_id=owner_id)
    or exists(select 1 from auth.mfa_factors where user_id=owner_id) then
    raise exception 'Recovery data or credentials survived the final reset'; end if;
end $$;

rollback;
