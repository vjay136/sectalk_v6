begin;

do $$
declare
  owner_id uuid:=gen_random_uuid();
  native_session uuid:=gen_random_uuid();
  recovery_session uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid();
  verify_claim uuid:=gen_random_uuid();
  legacy_code text:=repeat('A',32);
begin
  insert into auth.users(id,email,email_confirmed_at)
    values(owner_id,owner_id||'@example.invalid',now());
  insert into auth.sessions(id,user_id,aal,created_at)
    values(native_session,owner_id,'aal1',now());
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),native_session,'password',now(),now());
  perform set_config('request.jwt.claims',
    jsonb_build_object('role','authenticated','sub',owner_id,'session_id',native_session,'aal','aal1')::text,true);
  if public.st_v7_login_risk_status()<>'clear' then raise exception 'Account without TOTP was challenged'; end if;
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,owner_id,'totp','unverified',now(),now());
  if public.st_v7_login_risk_status()<>'clear' then raise exception 'Unverified enrollment blocked access'; end if;
  update auth.mfa_factors set status='verified' where id=factor;
  insert into sectalk_private.account_recovery_sets(user_id,factor_id,generated_at,code_hashes)
    values(owner_id,factor,now()-interval '30 days',array_fill(extensions.digest(legacy_code,'sha256'),array[8]));

  set local role authenticated;
  perform set_config('request.path','/rest/v1/st_profiles',true);
  begin
    perform public.st_v7_guard_account_lockdown();
    raise exception 'AAL1 session passed Data API middleware';
  exception when sqlstate 'PT403' then null; end;
  perform set_config('request.path','/rest/v1/rpc/st_v7_recover_authenticator',true);
  perform public.st_v7_guard_account_lockdown();
  if public.st_v7_account_recovery_status()<>'ready' or public.st_v7_recover_authenticator(legacy_code) then
    raise exception 'Legacy recovery was lost or completed before the 24-hour hold';
  end if;
  perform set_config('request.jwt.claims',
    jsonb_build_object('role','authenticated','sub',owner_id,'session_id',native_session,'aal','aal2')::text,true);
  if public.st_v7_login_risk_status()<>'authenticator' then raise exception 'AAL2 claim accepted without native proof'; end if;
  reset role;
  update auth.sessions set aal='aal2',factor_id=factor where id=native_session;
  if public.st_v7_login_risk_status()<>'authenticator' then raise exception 'AAL2 row accepted without TOTP AMR'; end if;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(verify_claim,native_session,'totp',now(),now());
  if public.st_v7_login_risk_status()<>'clear' then raise exception 'Verified native TOTP evidence was rejected'; end if;
  perform set_config('request.jwt.claims',
    jsonb_build_object('role','authenticated','sub',owner_id,'session_id',native_session,'aal','aal1')::text,true);
  if public.st_v7_login_risk_status()<>'authenticator' then raise exception 'Original pre-proof JWT was accepted'; end if;

  if exists(select 1 from pg_publication_tables p
    join pg_namespace n on n.nspname=p.schemaname
    join pg_class c on c.relnamespace=n.oid and c.relname=p.tablename
    where p.pubname='supabase_realtime' and p.schemaname='public' and (
      not c.relrowsecurity or not exists(select 1 from pg_policy pl where pl.polrelid=c.oid
        and not pl.polpermissive and pl.polcmd='r' and pg_get_expr(pl.polqual,pl.polrelid) like '%st_v7_step_up_pending%'))) then
    raise exception 'A published application table lacks the SELECT assurance gate'; end if;

  insert into auth.sessions(id,user_id,aal,created_at) values(recovery_session,owner_id,'aal1',now());
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),recovery_session,'password',now(),now());
  update sectalk_private.st_v7_account_security_changes set ready_at=now()-interval '1 minute' where user_id=owner_id;
  perform set_config('request.jwt.claims',
    jsonb_build_object('role','authenticated','sub',owner_id,'session_id',recovery_session,'aal','aal1')::text,true);
  set local role authenticated;
  if not public.st_v7_recover_authenticator(legacy_code) then raise exception 'Legacy hashed recovery failed after cooling off'; end if;
  reset role;
  if exists(select 1 from sectalk_private.account_recovery_sets where user_id=owner_id) then
    raise exception 'Legacy set survived completed recovery'; end if;
end $$;

rollback;
