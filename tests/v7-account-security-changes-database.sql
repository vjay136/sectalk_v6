begin;
create temporary table provider_email_fixture(
  id uuid, email text, email_confirmed_at timestamptz, email_change text,
  email_change_sent_at timestamptz, email_change_confirm_status smallint
);
create trigger verify_email before update of email,email_change,email_change_sent_at on provider_email_fixture
  for each row execute function sectalk_private.st_v7_guard_account_email();
grant select,update on provider_email_fixture to authenticated;
create temporary table provider_mfa_fixture(id uuid,user_id uuid,status text,factor_type text);
create trigger verify_factor before delete on provider_mfa_fixture
  for each row execute function sectalk_private.st_v7_guard_factor_removal();
grant select,delete on provider_mfa_fixture to authenticated;
do $$
declare
 account uuid:=gen_random_uuid();
 outsider uuid:=gen_random_uuid();
 first_session uuid:=gen_random_uuid();
 outsider_session uuid:=gen_random_uuid();
 factor uuid:=gen_random_uuid();
 target text:='new-security-'||account||'@example.invalid';
 original text:='old-security-'||account||'@example.invalid';
begin
 insert into auth.users(id,email,email_confirmed_at,encrypted_password) values
  (account,original,now(),'fixture-first'),(outsider,outsider||'@example.invalid',now(),'fixture-other');
 insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
 values(factor,account,'totp','verified',now(),now());
 insert into provider_email_fixture values(account,original,now(),'',null,0);
 insert into provider_mfa_fixture values(factor,account,'verified','totp');
 insert into auth.sessions(id,user_id,aal,factor_id)
 values(first_session,account,'aal2',factor),(outsider_session,outsider,'aal1',null);
 insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
 values(gen_random_uuid(),first_session,'totp',now()-interval '10 minutes',now()-interval '10 minutes'),
   (gen_random_uuid(),outsider_session,'password',now(),now());
 if has_function_privilege('anon','public.st_v7_account_security_events()','execute')
 or has_table_privilege('authenticated','sectalk_private.st_v7_account_security_changes','select')
 then raise exception 'Private account state was exposed'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',account,'session_id',first_session,'aal','aal2')::text,true);
 set local role authenticated;
 begin perform public.st_v7_account_security_change('request','email',target);
   raise exception 'Stale MFA authorized the email change'; exception when insufficient_privilege then null; end;
 reset role;
 update auth.mfa_amr_claims set updated_at=now() where session_id=first_session;
 set local role authenticated;
 if public.st_v7_account_security_change('request','email',target)<>'pending' then
  raise exception 'Fresh MFA did not schedule the email change'; end if;
 begin perform public.st_v7_account_security_change('continue','email',target);
   raise exception 'Email released during cooling-off'; exception when invalid_parameter_value then null; end;
 reset role;

 set local role authenticated;
 begin update provider_email_fixture set email_change=target,email_change_sent_at=now() where id=account;
   raise exception 'Provider seeded confirmation without authorization'; exception when insufficient_privilege then null; end;
 reset role;
 update sectalk_private.st_v7_account_security_changes set ready_at=now()-interval '1 minute' where user_id=account;
 set local role authenticated;
 begin perform public.st_v7_account_security_change('continue','email','different@example.invalid');
   raise exception 'Request approved another destination'; exception when invalid_parameter_value then null; end;
 if public.st_v7_account_security_change('continue','email',target)<>'send_confirmation' then
   raise exception 'Approved email could not start provider confirmations'; end if;
 reset role;

 set local role authenticated;
 update provider_email_fixture set email_change=target,email_change_sent_at=now() where id=account;
 begin update provider_email_fixture set email=target where id=account;
   raise exception 'Single mailbox could approve'; exception when insufficient_privilege then null; end;
 update provider_email_fixture set email_change_confirm_status=1 where id=account;
 update provider_email_fixture set email=target,email_change='',email_change_confirm_status=0 where id=account;
 begin delete from provider_mfa_fixture where id=factor; raise exception 'Direct provider unenrollment succeeded';
   exception when insufficient_privilege then null; end;
 reset role;
 if (select email from provider_email_fixture where id=account)<>target then raise exception 'Double confirmation failed'; end if;
 if (select state from sectalk_private.st_v7_account_security_changes where user_id=account)<>'completed' then
   raise exception 'Email completion was not committed'; end if;

 set local role authenticated;
 if public.st_v7_account_security_change('request','authenticator')<>'pending' then
   raise exception 'Authenticator reset did not start'; end if;
 begin perform public.st_v7_account_security_change('continue','authenticator');
   raise exception 'Authenticator reset ignored cooling-off'; exception when invalid_parameter_value then null; end;
 if public.st_v7_account_security_change('cancel')<>'cancelled' then raise exception 'Owner could not cancel reset'; end if;
 if public.st_v7_account_security_change('request','authenticator')<>'pending' then
   raise exception 'New deliberate request was denied'; end if;
 reset role;
 update sectalk_private.st_v7_account_security_changes set ready_at=now()-interval '1 minute' where user_id=account;
 set local role authenticated;
 if public.st_v7_account_security_change('continue','authenticator')<>'completed' then
   raise exception 'MFA reset did not complete'; end if;
 if exists(select 1 from public.st_v7_account_security_events() where kind not in ('email','authenticator')) then
   raise exception 'Owner event projection exposed unrelated data'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',outsider,'session_id',outsider_session,'aal','aal1')::text,true);
 if exists(select 1 from public.st_v7_account_security_events()) then raise exception 'Cross-account event disclosure'; end if;
 reset role;
 if exists(select from auth.sessions where user_id=account) or exists(select from auth.mfa_factors where user_id=account) then
   raise exception 'MFA reset did not revoke sessions and factors'; end if;
 update auth.users set encrypted_password='fixture-password-changed' where id=account;
 if (select count(*) from realtime.messages where topic='st:account:'||account and private
   and event='account_security_lifecycle' and payload-'id'='{}')<>7 then
   raise exception 'Expected metadata-free private events for requests, cancel, and completed password, email and MFA'; end if;
end $$;
rollback;
