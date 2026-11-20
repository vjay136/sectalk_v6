begin;
do $$
declare
 owner_id uuid:=gen_random_uuid();
 outsider_id uuid:=gen_random_uuid();
 known_session uuid:=gen_random_uuid();
 ordinary uuid:=gen_random_uuid();
 unusual uuid:=gen_random_uuid();
 outsider_session uuid:=gen_random_uuid();
 fresh_session uuid:=gen_random_uuid();
 otp_session uuid:=gen_random_uuid();
 trusted uuid:=gen_random_uuid();
 alert_id uuid;
 old_password_time timestamptz;
begin
 insert into auth.users(id,email,email_confirmed_at,encrypted_password) values
  (owner_id,owner_id||'@example.invalid',now(),'original-fixture-password'),
  (outsider_id,outsider_id||'@example.invalid',now(),'outsider-fixture-password');
 insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature,created_at)
  values(trusted,owner_id,'trusted',repeat('j',87),repeat('k',87),repeat('l',86),now()-interval '1 hour');
 insert into auth.sessions(id,user_id,aal,created_at,ip,user_agent) values
  (known_session,owner_id,'aal1',now()-interval '1 hour','192.0.2.1','Firefox/113.0'),
  (ordinary,owner_id,'aal1',now()-interval '2 minutes','192.0.2.99','Chrome/130.0'),
  (unusual,owner_id,'aal1',now()-interval '1 minute','198.51.100.12','Edg/130.0'),
  (outsider_session,outsider_id,'aal1',now(),'203.0.113.19','Safari/125.0');
 insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
  select gen_random_uuid(),s,'password',now(),now() from unnest(array[known_session,ordinary,unusual,outsider_session]) s;
 insert into sectalk_private.st_v7_device_sessions values(known_session,owner_id,trusted);
 update sectalk_private.st_v7_login_candidates set ready_at=now()-interval '1 second'
   where session_id in (known_session,ordinary,unusual,outsider_session);
 perform sectalk_private.st_v7_detect_login_anomalies();
 perform sectalk_private.st_v7_detect_login_anomalies();
 if (select count(*) from sectalk_private.st_v7_login_anomalies where user_id=owner_id)<>1
   or not exists(select from sectalk_private.st_v7_login_anomalies where observed_session=unusual) then
   raise exception 'Normal login, deduplication or real native outlier evidence failed'; end if;
 if (select count(*) from realtime.messages where event='login_anomaly' and private and topic='st:account:'||owner_id
   and payload-'id'='{}')<>1 then raise exception 'Anomaly notification exposed private details or was duplicated'; end if;
 select a.id into alert_id from sectalk_private.st_v7_login_anomalies a where a.observed_session=unusual;

 set local role authenticated;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',outsider_id,'session_id',outsider_session,'aal','aal1')::text,true);
 if exists(select from public.st_v7_list_login_anomalies()) or public.st_v7_review_login_anomaly(alert_id,'lockdown') then
   raise exception 'Foreign account observed or acted on another alert'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',unusual,'aal','aal1')::text,true);
 begin perform public.st_v7_review_login_anomaly(alert_id,'recognize');
   raise exception 'Suspicious session approved itself'; exception when insufficient_privilege then null; end;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',known_session,'aal','aal1')::text,true);
 if not public.st_v7_review_login_anomaly(alert_id,'lockdown') then raise exception 'Trusted lockdown failed'; end if;
 perform set_config('request.path','/st_profiles',true);
 begin perform public.st_v7_guard_account_lockdown(); raise exception 'Lockdown did not restrict application data';
   exception when sqlstate 'PT423' then null; end;
 perform set_config('request.path','/rpc/st_v7_account_lock_status',true);
 perform public.st_v7_guard_account_lockdown();
 reset role;

 if exists(select from auth.sessions where user_id=owner_id)
   or not exists(select from auth.sessions where id=outsider_session) then raise exception 'Lockdown invalidated the wrong sessions'; end if;
 insert into auth.sessions(id,user_id,aal) values(fresh_session,owner_id,'aal1'),(otp_session,owner_id,'aal1');
 insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
  (gen_random_uuid(),fresh_session,'password',now(),now()),(gen_random_uuid(),otp_session,'otp',now(),now());
 insert into sectalk_private.st_v7_device_sessions values(fresh_session,owner_id,trusted);
 set local role authenticated;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',fresh_session,'aal','aal1')::text,true);
 if public.st_v7_recover_account_lockdown() or public.st_v7_note_lockdown_password_recovery() then
   raise exception 'Password-only session completed a recovery step'; end if;
 begin perform public.st_v7_begin_device_bundle(gen_random_uuid(),repeat('x',87),repeat('y',87));
   raise exception 'Lockdown enrolled a new identity'; exception when insufficient_privilege then null; end;
 reset role;
 update auth.users set encrypted_password='rotated-fixture-password' where id=owner_id;
 select max(e.occurred_at) into old_password_time from sectalk_private.st_v7_account_security_events e where e.user_id=owner_id and e.kind='password';
 if old_password_time is null then raise exception 'Provider password change event missing'; end if;
 set local role authenticated;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',otp_session,'aal','aal1')::text,true);
 if not public.st_v7_note_lockdown_password_recovery() then raise exception 'Email OTP password evidence was rejected'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',fresh_session,'aal','aal1')::text,true);
 if public.st_v7_recover_account_lockdown() then raise exception 'Recovery bypassed the hold'; end if;
 reset role;
 update sectalk_private.st_v7_account_lockdowns set ready_at=now()-interval '1 minute' where user_id=owner_id;
 set local role authenticated;
 if not public.st_v7_recover_account_lockdown() then raise exception 'Measured recovery failed'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',otp_session,'aal','aal1')::text,true);
 if public.st_v7_current_session_valid() then raise exception 'Another locked-era session survived recovery'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',fresh_session,'aal','aal1')::text,true);
 perform set_config('request.path','/st_profiles',true);
 perform public.st_v7_guard_account_lockdown();
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',unusual,'aal','aal1')::text,true);
 begin perform public.st_v7_guard_account_lockdown(); raise exception 'Previously revoked token gained access after recovery';
   exception when sqlstate 'PT401' then null; end;
end $$;
rollback;
