\set ON_ERROR_STOP on
begin;

do $$
declare
  account uuid := gen_random_uuid();
  staff_user uuid := gen_random_uuid();
  first_session uuid := gen_random_uuid();
  other_session uuid := gen_random_uuid();
  staff_session uuid := gen_random_uuid();
  factor uuid := gen_random_uuid();
  first_batch text[];
  replacement text[];
  hashes bytea[];
begin
  insert into auth.users(id,email) values
    (account,account||'@example.invalid'),(staff_user,staff_user||'@example.invalid');
  insert into public.st_profiles(id,handle,name) values
    (account,'mfaq_'||left(account::text,8),'Recovery QA'),(staff_user,'mfaq_'||left(staff_user::text,8),'Recovery staff QA');
  insert into sectalk_private.staff values(staff_user);
  insert into auth.mfa_factors(id,user_id,friendly_name,factor_type,status,created_at,updated_at) values
    (factor,account,'QA authenticator','totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values
    (first_session,account,'aal2',factor),(other_session,account,'aal1',null),(staff_session,staff_user,'aal1',null);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
    (gen_random_uuid(),first_session,'totp',now(),now()),
    (gen_random_uuid(),other_session,'password',now(),now()),
    (gen_random_uuid(),staff_session,'password',now(),now());

  if has_table_privilege('authenticated','sectalk_private.account_recovery_sets','select')
      or has_function_privilege('anon','public.st_v7_generate_recovery_codes()','execute')
      or has_function_privilege('anon','public.st_v7_recover_authenticator(text)','execute') then
    raise exception 'Recovery data or procedures are exposed outside the authenticated recovery flow';
  end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',account,'session_id',first_session,'aal','aal2')::text,true);
  first_batch := public.st_v7_generate_recovery_codes();
  select code_hashes into hashes from sectalk_private.account_recovery_sets where user_id=account;
  if cardinality(first_batch)<>8 or cardinality(hashes)<>8 or exists (
    select 1 from unnest(first_batch) as code
    where not (extensions.digest(replace(code,'-',''),'sha256')=any(hashes))
  ) then raise exception 'Expected only hashes of the returned eight codes to be stored'; end if;

  begin
    perform public.st_v7_generate_recovery_codes();
    raise exception 'Code rotation accepted a reused verification';
  exception when insufficient_privilege then null;
  end;

  update auth.mfa_amr_claims set updated_at=clock_timestamp() where session_id=first_session;
  replacement := public.st_v7_generate_recovery_codes();
  if first_batch && replacement then raise exception 'Rotation reused an old recovery code'; end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',staff_user,'session_id',staff_session,'aal','aal1')::text,true);
  if public.st_v7_account_recovery_status()<>'staff' or public.st_v7_recover_authenticator(replacement[1])
      or public.st_staff_status()<>'mfa' then
    raise exception 'A recovery code enabled staff access or revealed another account code set';
  end if;

  insert into sectalk_private.staff values(account);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',account,'session_id',first_session,'aal','aal2')::text,true);
  update auth.mfa_amr_claims set updated_at=clock_timestamp() where session_id=first_session;
  begin
    perform public.st_v7_generate_recovery_codes();
    raise exception 'A staff session generated recovery codes';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',account,'session_id',other_session,'aal','aal1')::text,true);
  if public.st_v7_recover_authenticator(replacement[1]) or public.st_staff_status()<>'mfa' then
    raise exception 'A previously issued code remained usable after staff promotion';
  end if;
  delete from sectalk_private.staff where user_id=account;

  begin
    perform public.st_v7_generate_recovery_codes();
    raise exception 'A password-only session generated recovery codes';
  exception when insufficient_privilege then null;
  end;
  if public.st_v7_recover_authenticator(first_batch[1]) then raise exception 'A rotated code was accepted'; end if;
  if not public.st_v7_recover_authenticator(lower(replacement[1])) then raise exception 'A current recovery code was rejected'; end if;
  if exists(select 1 from auth.sessions where user_id=account)
      or exists(select 1 from auth.mfa_factors where user_id=account)
      or exists(select 1 from sectalk_private.account_recovery_sets where user_id=account)
      or not exists(select 1 from sectalk_private.account_recovery_events where user_id=account)
      or public.st_v7_recover_authenticator(replacement[1]) then
    raise exception 'Recovery did not atomically clear the account session, factor and code state';
  end if;
end;
$$;

rollback;
