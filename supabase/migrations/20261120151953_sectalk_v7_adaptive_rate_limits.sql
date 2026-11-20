begin;

create table sectalk_private.st_v7_rate_secret (
  single_row boolean primary key default true check(single_row),
  salt bytea not null check(octet_length(salt)=32)
);
insert into sectalk_private.st_v7_rate_secret(salt) values(extensions.gen_random_bytes(32));
create table sectalk_private.st_v7_rate_buckets (
  action text not null,
  dimension text not null,
  bucket bytea not null check(octet_length(bucket)=32),
  tokens numeric not null check(tokens>=0),
  measured_at timestamptz not null,
  primary key(action,dimension,bucket)
);
create index on sectalk_private.st_v7_rate_buckets(measured_at);
alter table sectalk_private.st_v7_rate_secret enable row level security;
alter table sectalk_private.st_v7_rate_buckets enable row level security;
revoke all on sectalk_private.st_v7_rate_secret,sectalk_private.st_v7_rate_buckets from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_rate_bucket(p_dimension text,p_id text)
returns bytea language sql stable set search_path='' as $$
  select extensions.hmac(convert_to(p_dimension||':'||p_id,'UTF8'),s.salt,'sha256')
    from sectalk_private.st_v7_rate_secret s
$$;

-- Take all dimensions together, or leave every dimension untouched.
create function sectalk_private.st_v7_rate_take(p_action text,p_dimensions jsonb)
returns integer language plpgsql security definer set search_path='' as $$
declare
  d record;
  bucket_id bytea;
  old_row sectalk_private.st_v7_rate_buckets;
  stamp timestamptz;
  available numeric;
  retry integer:=0;
  latest jsonb:='[]';
begin
  for d in select * from jsonb_to_recordset(p_dimensions) as x(dimension text,id text,capacity integer,seconds integer)
    order by dimension,id
  loop
    bucket_id:=sectalk_private.st_v7_rate_bucket(d.dimension,d.id);
    perform pg_advisory_xact_lock(hashtextextended(p_action||':'||d.dimension||':'||encode(bucket_id,'hex'),719));
  end loop;
  stamp:=clock_timestamp();
  for d in select * from jsonb_to_recordset(p_dimensions) as x(dimension text,id text,capacity integer,seconds integer)
  loop
    bucket_id:=sectalk_private.st_v7_rate_bucket(d.dimension,d.id);
    select b.* into old_row from sectalk_private.st_v7_rate_buckets b
      where b.action=p_action and b.dimension=d.dimension and b.bucket=bucket_id;
    available:=case when found then least(d.capacity,old_row.tokens+
      greatest(0,extract(epoch from stamp-old_row.measured_at))*d.capacity/d.seconds) else d.capacity end;
    if available<1 then retry:=greatest(retry,ceil((1-available)*d.seconds/d.capacity)::integer); end if;
    latest:=latest||jsonb_build_array(jsonb_build_object('dimension',d.dimension,'bucket',encode(bucket_id,'hex'),'tokens',available));
  end loop;
  if retry>0 then return retry; end if;
  insert into sectalk_private.st_v7_rate_buckets(action,dimension,bucket,tokens,measured_at)
    select p_action,result.dimension,decode(result.bucket,'hex'),result.tokens-1,stamp
      from jsonb_to_recordset(latest) as result(dimension text,bucket text,tokens numeric)
    on conflict(action,dimension,bucket) do update set tokens=excluded.tokens,measured_at=excluded.measured_at;
  return 0;
end $$;

create function public.st_v7_admit_password_request(p_identifier text,p_ip inet default null)
returns integer language plpgsql security definer set search_path='' as $$
declare
  pressure boolean;
  network text:=sectalk_private.st_v7_login_network(p_ip)::text;
begin
  if p_identifier is null or p_identifier !~ '^[a-f0-9]{64}$' then
    raise exception 'Invalid rate-limit subject' using errcode='22023';
  end if;
  select coalesce(sum(f.attempts),0)>=4 into pressure from sectalk_private.st_v7_password_failures f
    where f.identifier=p_identifier and f.minute>=date_trunc('minute',statement_timestamp())-interval '9 minutes';
  return sectalk_private.st_v7_rate_take('password',jsonb_build_array(
    jsonb_build_object('dimension','identifier','id',p_identifier,'capacity',case when pressure then 4 else 10 end,'seconds',60),
    jsonb_build_object('dimension','network','id',coalesce(network,'trusted-network-unavailable'),
      'capacity',case when network is null then 300 else 60 end,'seconds',60)));
end $$;

create function public.st_v7_admit_file_request(p_action text,p_scope_type text default null,p_scope uuid default null)
returns integer language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  native_session auth.sessions;
  device uuid;
  tenant uuid;
  pressure boolean;
  network text;
  budget integer;
  dimensions jsonb;
begin
  if not coalesce(public.st_v7_current_session_valid(),false) or public.st_v7_account_under_lockdown()
    or public.st_v7_login_risk_status()<>'clear' then
    raise exception 'File rate limit requires a current session' using errcode='42501';
  end if;
  if p_action is null or p_action not in ('file_read','file_write','file_chunk')
    or (p_scope_type is not null and p_scope_type not in ('workspace','room'))
    or ((p_scope_type is null)<>(p_scope is null)) then raise exception 'Invalid rate-limit scope' using errcode='22023'; end if;
  select s.* into native_session from auth.sessions s where s.id::text=auth.jwt()->>'session_id' and s.user_id=actor;
  network:=sectalk_private.st_v7_login_network(native_session.ip)::text;

  select b.device_id into device from sectalk_private.st_v7_device_sessions b
    join sectalk_private.st_v7_devices d on d.id=b.device_id and d.owner=b.owner
    where b.session_id=native_session.id and b.owner=actor and d.state<>'blocked'
      and d.locked_at is null and d.wiped_at is null;
  if p_scope_type='workspace' and sectalk_private.st_v2_active(actor)
    and sectalk_private.st_v2_role(p_scope,actor) is not null then
    tenant:=p_scope;
  elsif p_scope_type='room' then
    select r.workspace_id into tenant from public.st_v6_rooms r where r.id=p_scope and not r.archived
      and sectalk_private.st_v2_active(actor)
      and sectalk_private.st_v2_role(r.workspace_id,actor) is not null
      and sectalk_private.st_v6_room_role(r.id,actor) is not null;
  end if;
  select exists(select 1 from sectalk_private.st_v7_session_scores s where s.session_id=native_session.id and s.user_id=actor
    and s.score>=25) into pressure;
  budget:=case p_action when 'file_read' then 120 when 'file_chunk' then 180 else 24 end;
  dimensions:=jsonb_build_array(jsonb_build_object('dimension','account','id',actor,
    'capacity',case when pressure then budget/2 else budget end,'seconds',60));
  if device is not null then dimensions:=dimensions||jsonb_build_array(
    jsonb_build_object('dimension','device','id',device,'capacity',
      case when pressure then budget/3 else budget*3/4 end,'seconds',60)); end if;
  if network is not null then dimensions:=dimensions||jsonb_build_array(
    jsonb_build_object('dimension','network','id',network,'capacity',budget*5,'seconds',60)); end if;
  if tenant is not null then dimensions:=dimensions||jsonb_build_array(
    jsonb_build_object('dimension','tenant','id',tenant,'capacity',budget*6,'seconds',60)); end if;
  return sectalk_private.st_v7_rate_take(p_action,dimensions);
end $$;

revoke all on function sectalk_private.st_v7_rate_bucket(text,text),sectalk_private.st_v7_rate_take(text,jsonb),
  public.st_v7_admit_password_request(text,inet),public.st_v7_admit_file_request(text,text,uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_admit_password_request(text,inet) to service_role;
grant execute on function public.st_v7_admit_file_request(text,text,uuid) to authenticated;
select cron.schedule('sectalk-v7-prune-rate-buckets','*/15 * * * *',
  $job$delete from sectalk_private.st_v7_rate_buckets where measured_at<clock_timestamp()-interval '30 minutes'$job$);

commit;
