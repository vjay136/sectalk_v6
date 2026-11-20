begin;
do $$
declare
 owner_id uuid:=gen_random_uuid();
 other_id uuid:=gen_random_uuid();
 current_id uuid:=gen_random_uuid();
 second_id uuid:=gen_random_uuid();
 third_party uuid:=gen_random_uuid();
 idle uuid:=gen_random_uuid();
 absolute uuid:=gen_random_uuid();
 tighter uuid:=gen_random_uuid();
 factor uuid:=gen_random_uuid();
begin
 insert into auth.users(id,email) values(owner_id,owner_id||'@example.invalid'),(other_id,other_id||'@example.invalid');
 insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
 insert into auth.sessions(id,user_id,created_at,refreshed_at,aal,factor_id,not_after,user_agent,ip) values
  (current_id,owner_id,now(),null,'aal2',factor,null,'Mozilla Windows Chrome/99 Edg/99',inet '192.0.2.12'),
  (second_id,owner_id,now(),null,'aal1',null,null,'Mozilla Android Chrome/99',null),
  (third_party,other_id,now(),null,'aal1',null,null,'Unrelated Browser',null),
  (idle,owner_id,now()-interval '8 days',null,'aal1',null,null,null,null),
  (absolute,owner_id,now()-interval '31 days',now() at time zone 'UTC','aal1',null,null,null,null),
  (tighter,owner_id,now(),null,'aal1',null,now()+interval '1 minute',null,null);
 if (select s.not_after-s.created_at from auth.sessions s where s.id=current_id) is distinct from interval '30 days'
 or (select s.not_after-s.created_at from auth.sessions s where s.id=tighter) is distinct from interval '1 minute'
 then raise exception 'Native deadline did not preserve the shorter cap'; end if;
 begin update auth.sessions set refreshed_at=clock_timestamp() at time zone 'UTC' where id=idle;
   raise exception 'Refresh extended an idle session'; exception when insufficient_privilege then null; end;
 begin update auth.sessions set refreshed_at=(clock_timestamp()+interval '1 second') at time zone 'UTC' where id=absolute;
   raise exception 'Refresh extended a timeboxed session'; exception when insufficient_privilege then null; end;

 perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'session_id',second_id,'aal','aal1')::text,true);
 set local role authenticated;
 if not public.st_v7_current_session_valid() then raise exception 'An active MFA-challenge session was not valid'; end if;
 begin perform public.st_v7_list_sessions(); raise exception 'MFA-only credentials authorized device access';
   exception when insufficient_privilege then null; end;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'session_id',current_id,'aal','aal2')::text,true);
 if (select count(*) from public.st_v7_list_sessions())<>3
 or (select device from public.st_v7_list_sessions() where current_device) is distinct from 'Edge on Windows'
 or exists(select from public.st_v7_list_sessions() where id in (idle,absolute,third_party))
 then raise exception 'Device projection leaked or lacked scoped native sessions'; end if;
 if public.st_v7_revoke_session(third_party) or public.st_v7_revoke_session(gen_random_uuid())
   or not public.st_v7_revoke_session(second_id) or public.st_v7_revoke_session(second_id) then
   raise exception 'Cross-account revoke, valid revoke or replay did not behave correctly'; end if;
 perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'session_id',second_id,'aal','aal1')::text,true);
 if public.st_v7_current_session_valid() then raise exception 'Revoked session still valid'; end if;
 reset role;
 if not exists(select from auth.sessions where id=third_party) then raise exception 'Other account session was revoked'; end if;
 if (select count(*) from realtime.messages where topic='st:account:'||owner_id and event='session_lifecycle'
   and private and payload-'id'='{}')<>1 then raise exception 'Session event included unscoped device data'; end if;
 perform sectalk_private.st_v7_prune_auth_sessions();
 if exists(select from auth.sessions where id in (idle,absolute))
 or not exists(select from auth.sessions where id=current_id) then raise exception 'Bounded session worker removed wrong rows'; end if;
 if has_function_privilege('anon','public.st_v7_list_sessions()','execute')
 or has_function_privilege('authenticated','sectalk_private.st_v7_prune_auth_sessions()','execute') then
   raise exception 'Session controls are exposed directly'; end if;
end $$;
rollback;
