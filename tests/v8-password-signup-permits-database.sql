begin;

do $$
declare
  address text:='password-qa-'||replace(gen_random_uuid()::text,'-','a')||'@example.invalid';
  permit text;
  token text:=repeat('a',64);
begin
  if has_function_privilege('anon','public.st_v8_consume_password_signup_permit(text,text)','EXECUTE')
    or has_function_privilege('authenticated','public.st_v8_consume_password_signup_permit(text,text)','EXECUTE')
    or has_function_privilege('supabase_auth_admin','public.st_v8_consume_password_signup_permit(text,text)','EXECUTE') then
    raise exception 'Only the server gateway can directly consume an admission permit';
  end if;
  address:=translate(address,'0123456789','ghijklmnop');
  set local role service_role;
  permit:=public.st_v7_signup_admission(address)->>'permit';
  if permit is null then raise exception 'Expected an unchallenged admission permit'; end if;
  if public.st_v8_consume_password_signup_permit('other@example.invalid',permit) then
    raise exception 'An admission permit crossed email addresses';
  end if;
  if not public.st_v8_consume_password_signup_permit(upper(address),permit)
    or public.st_v8_consume_password_signup_permit(address,permit) then
    raise exception 'Permit was not canonical and single-use';
  end if;
  reset role;
  insert into sectalk_private.st_v7_signup_proofs(token_hash,email_key,kind,expires_at)
    values(extensions.digest(token,'sha256'),sectalk_private.st_v7_rate_bucket('signup_address',address),'permit',now()-interval '1 second');
  if public.st_v8_consume_password_signup_permit(address,token) then raise exception 'An expired permit was accepted'; end if;
end;
$$;

rollback;
