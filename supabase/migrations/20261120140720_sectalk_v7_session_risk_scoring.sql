begin;

create table sectalk_private.st_v7_password_failures (
  identifier text not null check (identifier ~ '^[a-f0-9]{64}$'),
  minute timestamptz not null,
  attempts smallint not null check (attempts between 1 and 100),
  primary key (identifier,minute)
);
create index on sectalk_private.st_v7_password_failures(minute);
create table sectalk_private.st_v7_session_scores (
  session_id uuid primary key references auth.sessions on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  assessed_at timestamptz not null default statement_timestamp(),
  score smallint not null check (score between 0 and 100),
  signals text[] not null,
  provider text not null check(provider in ('matched','unavailable')),
  latitude numeric(3,0),
  longitude numeric(3,0),
  radius_km integer
);
create index on sectalk_private.st_v7_session_scores(user_id,assessed_at desc);
alter table sectalk_private.st_v7_password_failures enable row level security;
alter table sectalk_private.st_v7_session_scores enable row level security;
revoke all on sectalk_private.st_v7_password_failures,sectalk_private.st_v7_session_scores from public,anon,authenticated,service_role;

create function public.st_v7_record_password_failure(p_identifier text)
returns void language sql security definer set search_path='' as $$
  insert into sectalk_private.st_v7_password_failures as f values(p_identifier,date_trunc('minute',statement_timestamp()),1)
  on conflict(identifier,minute) do update set attempts=least(100,f.attempts+1);
$$;

create function public.st_v7_risk_session_network(p_actor uuid,p_session uuid)
returns text language sql stable security definer set search_path='' as $$
  select host(s.ip) from auth.sessions s where s.id=p_session and s.user_id=p_actor
    and s.created_at>statement_timestamp()-interval '5 minutes'
    and exists(select 1 from auth.mfa_amr_claims a where a.session_id=s.id and a.authentication_method='password')
$$;

create function public.st_v7_score_password_session(
  p_actor uuid,p_session uuid,p_identifier text,p_network jsonb
) returns void language plpgsql security definer set search_path='' as $$
declare
  observed auth.sessions;
  baseline sectalk_private.st_v7_session_scores;
  labels text[]:='{}';
  points integer:=0;
  lat numeric;
  lon numeric;
  radius integer;
  km double precision;
  hours double precision;
  assessed_provider text:='unavailable';
begin
  select s.* into observed from auth.sessions s where s.id=p_session and s.user_id=p_actor
    and s.created_at>statement_timestamp()-interval '5 minutes'
    and exists(select 1 from auth.mfa_amr_claims a where a.session_id=s.id and a.authentication_method='password')
    for update;
  if not found then raise exception 'Invalid native password session' using errcode='42501'; end if;
  if exists(select 1 from sectalk_private.st_v7_session_scores where session_id=p_session) then return; end if;

  if sectalk_private.st_v7_password_session_outlier(observed) then
    labels:=array_append(labels,'unfamiliar_device'); points:=points+60;
  elsif exists(
    select 1 from sectalk_private.st_v7_device_sessions b
    join sectalk_private.st_v7_devices d on d.id=b.device_id and d.owner=b.owner
    join auth.sessions s on s.id=b.session_id and s.user_id=b.owner
    where b.owner=p_actor and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null
      and s.created_at<observed.created_at and sectalk_private.st_v7_login_browser(s.user_agent) is not null
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
    having bool_and(sectalk_private.st_v7_login_browser(s.user_agent)
      <>coalesce(sectalk_private.st_v7_login_browser(observed.user_agent),'other'))
  ) then
    labels:=array_append(labels,'unfamiliar_device'); points:=points+20;
  end if;

  if 8 <= (select count(*) from (
    select s.id from auth.sessions s where s.user_id=p_actor and s.created_at>statement_timestamp()-interval '10 minutes'
      and exists(select 1 from auth.mfa_amr_claims a where a.session_id=s.id and a.authentication_method='password')
      limit 8) recent) then
    labels:=array_append(labels,'sign_in_velocity'); points:=points+35;
  end if;
  if 4 <= (select coalesce(sum(f.attempts),0) from sectalk_private.st_v7_password_failures f
      where f.identifier=p_identifier and f.minute>=date_trunc('minute',statement_timestamp())-interval '9 minutes') then
    labels:=array_append(labels,'failed_sign_ins'); points:=points+30;
  end if;

  if observed.ip is not null and jsonb_typeof(p_network)='object' then
    assessed_provider:='matched';
    if p_network->>'reputation'='poor' and (p_network->>'asn')::bigint between 1 and 4294967295 then
      labels:=array_append(labels,'asn_reputation'); points:=points+40;
    end if;
    if p_network->'tor'='true'::jsonb then labels:=array_append(labels,'tor'); points:=points+65; end if;
    if p_network->'vpn'='true'::jsonb then labels:=array_append(labels,'vpn'); points:=points+25; end if;
    if not (p_network->'tor'='true'::jsonb or p_network->'vpn'='true'::jsonb)
      and (p_network->>'confidence')::numeric between 80 and 100
      and (p_network->>'radiusKm')::numeric between 0 and 250
      and (p_network->>'latitude')::numeric between -90 and 90
      and (p_network->>'longitude')::numeric between -180 and 180 then
      lat:=round((p_network->>'latitude')::numeric);
      lon:=round((p_network->>'longitude')::numeric);
      radius:=ceil((p_network->>'radiusKm')::numeric)+80;

      select r.* into baseline from sectalk_private.st_v7_session_scores r
      join sectalk_private.st_v7_device_sessions b on b.session_id=r.session_id and b.owner=r.user_id
      join sectalk_private.st_v7_devices d on d.id=b.device_id and d.owner=b.owner
      join auth.sessions s on s.id=r.session_id and s.user_id=r.user_id
      where r.user_id=p_actor and r.latitude is not null and r.score<30
        and r.assessed_at between observed.created_at-interval '6 hours' and observed.created_at-interval '1 second'
        and d.state in ('trusted','managed') and d.locked_at is null and d.wiped_at is null
        and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
      order by r.assessed_at desc limit 1;
      if found then
        hours:=greatest(300,extract(epoch from observed.created_at-baseline.assessed_at))/3600;
        km:=12742*asin(sqrt(least(1,power(sin(radians(lat-baseline.latitude)/2),2)
          +cos(radians(lat))*cos(radians(baseline.latitude))*power(sin(radians(lon-baseline.longitude)/2),2))))
          -radius-baseline.radius_km;
        if km>500 and km/hours>1000 then
          labels:=array_append(labels,'impossible_travel'); points:=points+65;
        end if;
      end if;
    end if;
  end if;

  insert into sectalk_private.st_v7_session_scores(session_id,user_id,score,signals,provider,latitude,longitude,radius_km)
    values(p_session,p_actor,least(points,100),labels,assessed_provider,lat,lon,radius);
  if points>=60 then
    insert into sectalk_private.st_v7_signin_risk(session_id,user_id) values(p_session,p_actor) on conflict do nothing;
  end if;
end $$;

create function public.st_v7_list_session_risk()
returns table(session_id uuid,band text,signals text[],provider text)
language plpgsql stable security definer set search_path='' as $$
begin
  if not coalesce(sectalk_private.st_v7_manage_sessions(),false) or public.st_v7_login_risk_status()<>'clear' then
    raise exception 'Verify this session before reviewing other devices' using errcode='42501';
  end if;
  return query select r.session_id,
    case when r.score>=60 then 'high' when r.score>=25 then 'elevated' else 'low' end,
    r.signals,r.provider from sectalk_private.st_v7_session_scores r
    where r.user_id=auth.uid() order by r.assessed_at desc limit 100;
end $$;

revoke all on function public.st_v7_record_password_failure(text),public.st_v7_risk_session_network(uuid,uuid),
  public.st_v7_score_password_session(uuid,uuid,text,jsonb),public.st_v7_list_session_risk()
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_record_password_failure(text),public.st_v7_risk_session_network(uuid,uuid),
  public.st_v7_score_password_session(uuid,uuid,text,jsonb) to service_role;
grant execute on function public.st_v7_list_session_risk() to authenticated;

select cron.schedule('sectalk-v7-prune-session-risk','*/15 * * * *',
  $job$delete from sectalk_private.st_v7_password_failures where minute<statement_timestamp()-interval '30 minutes';
  update sectalk_private.st_v7_session_scores set latitude=null,longitude=null,radius_km=null
    where latitude is not null and assessed_at<statement_timestamp()-interval '6 hours';$job$);
commit;
