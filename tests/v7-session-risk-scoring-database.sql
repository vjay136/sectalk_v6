begin;
do $$
declare
  owner_id uuid:=gen_random_uuid();
  other_id uuid:=gen_random_uuid();
  baseline uuid:=gen_random_uuid();
  traveler uuid:=gen_random_uuid();
  uncertain uuid:=gen_random_uuid();
  device_id uuid:=gen_random_uuid();
  latest_session uuid;
  identifier text:=repeat('9',64);
  home jsonb:='{"asn":64512,"reputation":"normal","tor":false,"vpn":false,"latitude":51.5,"longitude":0.1,"radiusKm":20,"confidence":90}';
  away jsonb:='{"asn":64513,"reputation":"normal","tor":false,"vpn":false,"latitude":37.7,"longitude":-122.4,"radiusKm":20,"confidence":90}';
begin
 insert into auth.users(id,email,email_confirmed_at)
  select id,id||'@example.invalid',now() from unnest(array[owner_id,other_id]) id;
 insert into auth.sessions(id,user_id,aal,created_at,ip,user_agent) values
  (baseline,owner_id,'aal1',now()-interval '4 minutes','192.0.2.1','Chrome/139'),
  (traveler,owner_id,'aal1',now()-interval '1 minute','198.51.100.10','Chrome/139'),
  (uncertain,owner_id,'aal1',now()-interval '1 minute','192.0.2.6','Firefox/139');
 insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
  select gen_random_uuid(),id,'password',now(),now() from unnest(array[baseline,traveler,uncertain]) id;
 insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature,created_at)
  values(device_id,owner_id,'trusted',repeat('p',87),repeat('q',87),repeat('r',86),now()-interval '1 hour');
 insert into sectalk_private.st_v7_device_sessions values(baseline,owner_id,device_id);

 set local role service_role;
 if public.st_v7_risk_session_network(other_id,traveler) is not null
   or public.st_v7_risk_session_network(owner_id,traveler)<>'198.51.100.10' then
   raise exception 'Native IP lookup escaped session ownership'; end if;
 perform public.st_v7_score_password_session(owner_id,baseline,identifier,home);
 reset role;
 update sectalk_private.st_v7_session_scores set assessed_at=now()-interval '3 minutes' where session_id=baseline;
 set local role service_role;
 perform public.st_v7_score_password_session(owner_id,traveler,identifier,away);
 perform public.st_v7_score_password_session(owner_id,traveler,identifier,home);
 perform public.st_v7_score_password_session(owner_id,uncertain,identifier,away||'{"confidence":79}');
 begin perform public.st_v7_score_password_session(other_id,traveler,identifier,away);
   raise exception 'Foreign session score accepted'; exception when insufficient_privilege then null; end;

 reset role;
 if not exists(select 1 from sectalk_private.st_v7_session_scores where session_id=traveler and score=65
    and signals=array['impossible_travel']) then raise exception 'Confident impossible travel was missed or re-scored'; end if;
 if not exists(select 1 from sectalk_private.st_v7_session_scores where session_id=uncertain and score=20
    and signals=array['unfamiliar_device'] and latitude is null) then raise exception 'Uncertain travel was trusted'; end if;

 insert into auth.sessions(id,user_id,aal,created_at,ip,user_agent)
  select gen_random_uuid(),owner_id,'aal1',now()-interval '30 seconds','192.0.2.20','Chrome/139' from generate_series(1,5);
 insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
  select gen_random_uuid(),s.id,'password',now(),now() from auth.sessions s
   where s.user_id=owner_id and s.ip='192.0.2.20';
 select id into latest_session from auth.sessions where user_id=owner_id and ip='192.0.2.20' limit 1;
 set local role service_role;
 perform public.st_v7_record_password_failure(identifier) from generate_series(1,4);
 perform public.st_v7_score_password_session(owner_id,
   latest_session,identifier,null);
 reset role;
 if not exists(select 1 from sectalk_private.st_v7_session_scores where user_id=owner_id and score=65
    and signals=array['sign_in_velocity','failed_sign_ins'] and provider='unavailable') then
   raise exception 'Velocity and failures did not combine into a step-up'; end if;

 set local role authenticated;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',traveler,'aal','aal1')::text,true);
 if public.st_v7_login_risk_status()<>'email' then raise exception 'Travel did not require native step-up'; end if;
 begin perform public.st_v7_list_session_risk();
  raise exception 'Unverified session can inspect device risk'; exception when insufficient_privilege then null; end;
 perform set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',owner_id,'session_id',baseline,'aal','aal1')::text,true);
 if (select count(*) from public.st_v7_list_session_risk() r where to_jsonb(r) ?& array['session_id','band','signals','provider']
   and jsonb_typeof(to_jsonb(r)->'signals')='array' and not to_jsonb(r) ?| array['ip','asn','latitude','longitude','identifier'])<>4 then
   raise exception 'Verified owner did not receive the safe assessment projection'; end if;
 begin perform public.st_v7_risk_session_network(owner_id,traveler);
  raise exception 'Client can read a raw session IP'; exception when insufficient_privilege then null; end;
 begin perform public.st_v7_record_password_failure(identifier);
  raise exception 'Client can write failure aggregates'; exception when insufficient_privilege then null; end;
end $$;
rollback;
