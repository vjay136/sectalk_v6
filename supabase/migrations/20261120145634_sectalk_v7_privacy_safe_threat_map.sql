begin;

select vault.create_secret(encode(extensions.gen_random_bytes(32),'hex'),
  'sectalk_v7_threat_map_hmac','Pseudonymous distinct counts for short-lived threat aggregates');

create table sectalk_private.st_v7_threat_observations (
  session_tag bytea not null check(octet_length(session_tag)=32),
  subject_tag bytea not null check(octet_length(subject_tag)=32),
  event text not null check(event in ('high_risk_sign_in','step_up_requested','session_terminated')),
  observed_day date not null,
  latitude_band smallint check(latitude_band between 0 and 8),
  longitude_band smallint check(longitude_band between 0 and 17),
  asn bigint check(asn between 1 and 4294967295),
  primary key(session_tag,event),
  check((latitude_band is null)=(longitude_band is null)),
  check(latitude_band is not null or asn is not null)
);
create index st_v7_threat_observations_day on sectalk_private.st_v7_threat_observations(observed_day);
alter table sectalk_private.st_v7_threat_observations enable row level security;
revoke all on sectalk_private.st_v7_threat_observations from public,anon,authenticated,service_role;

alter function public.st_v7_score_password_session(uuid,uuid,text,jsonb) set schema sectalk_private;
alter function sectalk_private.st_v7_score_password_session(uuid,uuid,text,jsonb) rename to st_v7_score_password_session_base;
revoke all on function sectalk_private.st_v7_score_password_session_base(uuid,uuid,text,jsonb)
  from public,anon,authenticated,service_role;

create function public.st_v7_score_password_session(p_actor uuid,p_session uuid,p_identifier text,p_network jsonb)
returns void language plpgsql security definer set search_path='' as $$
declare
  snapshot sectalk_private.st_v7_session_scores;
  digest_key text;
  network_asn bigint;
begin
  perform sectalk_private.st_v7_score_password_session_base(p_actor,p_session,p_identifier,p_network);
  select s.* into snapshot from sectalk_private.st_v7_session_scores s
    where s.session_id=p_session and s.user_id=p_actor and s.score>=60 and s.provider='matched';
  if not found then return; end if;
  if p_network->>'asn' ~ '^[0-9]{1,10}$' and (p_network->>'asn')::bigint between 1 and 4294967295 then
    network_asn:=(p_network->>'asn')::bigint;
  end if;
  if snapshot.latitude is null and network_asn is null then return; end if;
  select decrypted_secret into strict digest_key from vault.decrypted_secrets where name='sectalk_v7_threat_map_hmac';
  insert into sectalk_private.st_v7_threat_observations(session_tag,subject_tag,event,observed_day,latitude_band,longitude_band,asn)
    values(extensions.hmac('session:'||p_session::text,digest_key,'sha256'),
      extensions.hmac('account:'||p_actor::text,digest_key,'sha256'),'high_risk_sign_in',
      (snapshot.assessed_at at time zone 'UTC')::date,
      case when snapshot.latitude is not null then least(8,floor((snapshot.latitude+90)/20))::smallint end,
      case when snapshot.longitude is not null then least(17,floor((snapshot.longitude+180)/20))::smallint end,network_asn)
    on conflict(session_tag,event) do nothing;
end $$;

create function sectalk_private.st_v7_threat_response_observation()
returns trigger language plpgsql security definer set search_path='' as $$
declare digest_key text;
begin
  if new.request_id is null or new.action not in ('session_step_up','session_revoked') then return new; end if;
  select decrypted_secret into strict digest_key from vault.decrypted_secrets where name='sectalk_v7_threat_map_hmac';
  insert into sectalk_private.st_v7_threat_observations(session_tag,subject_tag,event,observed_day,latitude_band,longitude_band,asn)
    select s.session_tag,s.subject_tag,case when new.action='session_step_up' then 'step_up_requested' else 'session_terminated' end,
      (new.occurred_at at time zone 'UTC')::date,s.latitude_band,s.longitude_band,s.asn
    from sectalk_private.st_v7_threat_observations s
    where s.session_tag=extensions.hmac('session:'||new.request_id::text,digest_key,'sha256')
      and s.subject_tag=extensions.hmac('account:'||new.target::text,digest_key,'sha256') and s.event='high_risk_sign_in'
      and s.observed_day>=(now() at time zone 'UTC')::date-14
    on conflict(session_tag,event) do nothing;
  return new;
end $$;

create trigger st_v7_threat_response_observation after insert on sectalk_private.st_v7_account_admin_audit
  for each row execute function sectalk_private.st_v7_threat_response_observation();

create function public.st_v7_security_threat_map(p_day date)
returns jsonb language plpgsql security definer set search_path='' as $$
declare utc_today date:=(statement_timestamp() at time zone 'UTC')::date;
begin
  if public.st_v7_account_operator_access() not in ('operator','reviewer') then
    raise exception 'Security aggregates are unavailable' using errcode='42501';
  end if;
  if p_day is null or p_day>=utc_today or p_day<utc_today-14 then
    raise exception 'Choose a completed UTC day in the last 14 days' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v7_security_threat_map',45);
  return jsonb_build_object('day',p_day,'minimum_accounts',5,'cells',coalesce((
    select jsonb_agg(jsonb_build_object('latitude_band',t.latitude_band,'longitude_band',t.longitude_band,
      'event',t.event,'accounts_floor',t.cohort) order by t.event,t.latitude_band,t.longitude_band)
    from (select o.latitude_band,o.longitude_band,o.event,count(distinct o.subject_tag)/5*5 as cohort
      from sectalk_private.st_v7_threat_observations o where o.observed_day=p_day and o.latitude_band is not null
      group by o.latitude_band,o.longitude_band,o.event having count(distinct o.subject_tag)>=5) t
  ),'[]'::jsonb),'networks',coalesce((
    select jsonb_agg(jsonb_build_object('asn',t.asn,'event',t.event,'accounts_floor',t.cohort) order by t.event,t.cohort desc,t.asn)
    from (select o.asn,o.event,count(distinct o.subject_tag)/5*5 as cohort from sectalk_private.st_v7_threat_observations o
      where o.observed_day=p_day and o.asn is not null group by o.asn,o.event having count(distinct o.subject_tag)>=5
      order by cohort desc,o.asn,o.event limit 100) t
  ),'[]'::jsonb));
end $$;

create function sectalk_private.st_v7_expire_threat_observations()
returns void language sql set search_path='' as $$
  delete from sectalk_private.st_v7_threat_observations where observed_day<(now() at time zone 'UTC')::date-14;
$$;
select cron.schedule('sectalk-v7-expire-threat-observations','27 2 * * *',
  'select sectalk_private.st_v7_expire_threat_observations()');

revoke all on function public.st_v7_score_password_session(uuid,uuid,text,jsonb),public.st_v7_security_threat_map(date),
  sectalk_private.st_v7_threat_response_observation(),sectalk_private.st_v7_expire_threat_observations()
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_score_password_session(uuid,uuid,text,jsonb) to service_role;
grant execute on function public.st_v7_security_threat_map(date) to authenticated;

commit;
