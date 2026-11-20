begin;
do $$
declare
 owner_id uuid:=gen_random_uuid();
 foreign_id uuid:=gen_random_uuid();
 old_session uuid:=gen_random_uuid();
 normal_session uuid:=gen_random_uuid();
 risky uuid:=gen_random_uuid();
 risky_factor uuid:=gen_random_uuid();
 proof uuid:=gen_random_uuid();
 foreign_proof uuid:=gen_random_uuid();
 factor_key uuid:=gen_random_uuid();
 trusted uuid:=gen_random_uuid();
 verify_key uuid;
 auth_proof_at timestamptz;
begin
 insert into auth.users(id,email,email_confirmed_at)
 select id,id||'@example.invalid',now() from unnest(array[owner_id,foreign_id]) id;
 insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature,created_at)
  values(trusted,owner_id,'trusted',repeat('p',87),repeat('q',87),repeat('r',86),now()-interval '1 hour');
 insert into auth.sessions(id,user_id,aal,created_at,ip,user_agent) values
  (old_session,owner_id,'aal1',now()-interval '1 hour','192.0.2.1','Firefox/113'),
  (normal_session,owner_id,'aal1',now()-interval '2 minutes','192.0.2.10','Chrome/130'),
  (risky,owner_id,'aal1',now()-interval '1 minute','198.51.100.10','Chrome/130'),
  (risky_factor,owner_id,'aal1',now()-interval '1 minute','198.51.100.11','Edg/130');
 insert into sectalk_private.st_v7_device_sessions values(old_session,owner_id,trusted);
 insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
 select gen_random_uuid(),id,'password',now(),now() from unnest(array[old_session,normal_session,risky,risky_factor]) id;
 if (select count(*) from sectalk_private.st_v7_signin_risk where user_id=owner_id)<>2 then
   raise exception 'Native successful password evidence was not classified correctly'; end if;

 set local role authenticated;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',normal_session,'aal','aal1')::text,true);
 if public.st_v7_login_risk_status()<>'clear' then raise exception 'Normal login was gated'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',risky,'aal','aal1',
   'iat',extract(epoch from now()-interval '1 minute')::bigint)::text,true);
 if public.st_v7_login_risk_status()<>'email' then raise exception 'Risky login did not require verification'; end if;
 begin perform public.st_v7_begin_device_bundle(trusted,repeat('w',87),repeat('x',87));
   raise exception 'A risk session supplied replacement keys for a trusted device'; exception when insufficient_privilege then null; end;
 perform set_config('request.path','/st_profiles',true);
 begin perform public.st_v7_guard_account_lockdown(); raise exception 'Unverified session used protected data';
   exception when sqlstate 'PT403' then null; end;
 perform set_config('request.path','/rpc/st_v7_request_signin_code',true);
 perform public.st_v7_guard_account_lockdown();
 verify_key:=public.st_v7_request_signin_code();
 if verify_key is null or public.st_v7_confirm_signin_code(verify_key) then raise exception 'Password session made OTP proof'; end if;
 reset role;
 insert into auth.sessions(id,user_id,aal,created_at) values(proof,owner_id,'aal1',clock_timestamp()),
   (foreign_proof,foreign_id,'aal1',clock_timestamp());
 insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
 select gen_random_uuid(),id,'otp',clock_timestamp(),clock_timestamp() from unnest(array[proof,foreign_proof]) id;

 set local role authenticated;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',foreign_id,'session_id',foreign_proof,'aal','aal1')::text,true);
 if public.st_v7_confirm_signin_code(verify_key) then raise exception 'Foreign mailbox proof succeeded'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',proof,'aal','aal1')::text,true);
 if not public.st_v7_confirm_signin_code(verify_key) or public.st_v7_confirm_signin_code(verify_key) then
   raise exception 'Valid mailbox proof was rejected or replayed'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',risky,'aal','aal1',
   'iat',extract(epoch from now()-interval '1 minute')::bigint)::text,true);
 if public.st_v7_login_risk_status()<>'refresh' then raise exception 'Original JWT became privileged'; end if;
 reset role;
 select r.mailbox_verified_at into auth_proof_at from sectalk_private.st_v7_signin_risk r where r.session_id=risky;
 set local role authenticated;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',risky,'aal','aal1',
   'iat',extract(epoch from auth_proof_at+interval '2 seconds')::bigint)::text,true);
 if public.st_v7_login_risk_status()<>'clear' then raise exception 'New authenticated JWT was not authorized'; end if;

 reset role;
 insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
 values(factor_key,owner_id,'totp','verified',now(),now());
 set local role authenticated;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',risky_factor,'aal','aal2')::text,true);
 if public.st_v7_login_risk_status()<>'authenticator' then raise exception 'A JWT-only AAL2 claim was accepted'; end if;
 begin perform public.st_v7_request_signin_code(); raise exception 'Email bypassed required authenticator';
   exception when insufficient_privilege then null; end;
 reset role;
 update auth.sessions set aal='aal2',factor_id=factor_key where id=risky_factor;
 insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
 values(gen_random_uuid(),risky_factor,'totp',now(),now());
 set local role authenticated;
 if public.st_v7_login_risk_status()<>'clear' then raise exception 'Real native authenticator was rejected'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',risky_factor,'aal','aal1')::text,true);
 if public.st_v7_login_risk_status()<>'authenticator' then raise exception 'Original AAL1 JWT became privileged'; end if;
end $$;
rollback;
