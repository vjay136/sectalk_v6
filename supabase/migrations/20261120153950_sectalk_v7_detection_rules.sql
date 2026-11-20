begin;

create table sectalk_private.st_v7_detection_operators (
  user_id uuid primary key references auth.users on delete cascade
);
create table sectalk_private.st_v7_detection_rules (
  id uuid primary key default gen_random_uuid(),
  label text not null check(char_length(label) between 3 and 80),
  latest_version integer not null default 1 check(latest_version between 1 and 25),
  active_version integer,
  mode text check(mode in ('shadow','enabled')),
  activation uuid,
  baseline_bucket timestamptz,
  baseline_count bigint,
  created_at timestamptz not null default clock_timestamp(),
  check ((active_version is null and mode is null and activation is null and baseline_bucket is null and baseline_count is null)
    or (active_version is not null and mode is not null and activation is not null and baseline_bucket is not null and baseline_count is not null))
);
create table sectalk_private.st_v7_detection_versions (
  rule_id uuid not null references sectalk_private.st_v7_detection_rules,
  version integer not null check(version between 1 and 25),
  source text not null check(source in ('operations','login_anomalies')),
  scope text not null,
  metric text not null,
  threshold integer not null check(threshold between 1 and 1000000),
  authored_by uuid not null,
  created_at timestamptz not null default clock_timestamp(),
  primary key(rule_id,version),
  check ((source='operations' and scope in ('file_upload','file_publish','file_download_grant','file_download',
    'call_ice','meeting_token','billing_action','billing_webhook')
    and metric in ('requests','client_errors','server_errors','throttled','unavailable'))
    or (source='login_anomalies' and scope='platform' and metric='anomalies' and threshold>=3))
);
alter table sectalk_private.st_v7_detection_rules add constraint st_v7_detection_active_fk
  foreign key(id,active_version) references sectalk_private.st_v7_detection_versions(rule_id,version);
create index st_v7_detection_version_sources on sectalk_private.st_v7_detection_versions(source,scope,rule_id,version);

create table sectalk_private.st_v7_detection_audit (
  id bigint generated always as identity primary key,
  rule_id uuid not null references sectalk_private.st_v7_detection_rules,
  version integer not null,
  actor uuid not null,
  action text not null check(action in ('created','revised','tested','shadow','enabled','paused','rollback')),
  mode text check(mode in ('shadow','enabled')),
  reason text,
  result jsonb,
  occurred_at timestamptz not null default clock_timestamp(),
  foreign key(rule_id,version) references sectalk_private.st_v7_detection_versions
);
create index st_v7_detection_audit_version on sectalk_private.st_v7_detection_audit(rule_id,version,id desc);
create index st_v7_detection_audit_history on sectalk_private.st_v7_detection_audit(rule_id,id desc);
create table sectalk_private.st_v7_detection_matches (
  id bigint generated always as identity primary key,
  rule_id uuid not null,
  version integer not null,
  activation uuid not null,
  mode text not null check(mode in ('shadow','enabled')),
  bucket timestamptz not null,
  observed bigint not null,
  occurred_at timestamptz not null default clock_timestamp(),
  unique(rule_id,activation,bucket),
  foreign key(rule_id,version) references sectalk_private.st_v7_detection_versions
);
create index st_v7_detection_match_feed on sectalk_private.st_v7_detection_matches(rule_id,id desc);
create index st_v7_detection_match_expiry on sectalk_private.st_v7_detection_matches(bucket);

create table sectalk_private.st_v7_detection_login_windows (
  bucket timestamptz primary key,
  anomalies bigint not null check(anomalies>0)
);
alter table sectalk_private.st_v7_detection_operators enable row level security;
alter table sectalk_private.st_v7_detection_rules enable row level security;
alter table sectalk_private.st_v7_detection_versions enable row level security;
alter table sectalk_private.st_v7_detection_audit enable row level security;
alter table sectalk_private.st_v7_detection_matches enable row level security;
alter table sectalk_private.st_v7_detection_login_windows enable row level security;
revoke all on sectalk_private.st_v7_detection_operators,sectalk_private.st_v7_detection_rules,
  sectalk_private.st_v7_detection_versions,sectalk_private.st_v7_detection_audit,sectalk_private.st_v7_detection_matches,
  sectalk_private.st_v7_detection_login_windows from public,anon,authenticated,service_role;

create function public.st_v7_detection_rule_access()
returns text language sql stable security definer set search_path='' as $$
  select coalesce((select case when sectalk_private.st_v7_admin_fresh() then 'verified' else 'mfa' end
    from sectalk_private.st_v7_detection_operators o where o.user_id=auth.uid()
      and public.st_v7_current_session_valid() and sectalk_private.st_v2_active(o.user_id)),'none');
$$;

create function sectalk_private.st_v7_detection_window(p_at timestamptz)
returns timestamptz language sql immutable set search_path='' as $$
  select date_bin(interval '5 minutes',p_at,'2000-01-01 00:00:00+00'::timestamptz);
$$;

create function sectalk_private.st_v7_detection_values(
  p_source text,p_scope text,p_metric text,p_start timestamptz,p_end timestamptz
)
returns table(bucket timestamptz,value bigint)
language sql stable set search_path='' as $$
  select r.bucket,case p_metric when 'requests' then r.requests when 'client_errors' then r.client_errors
    when 'server_errors' then r.server_errors when 'throttled' then r.throttled when 'unavailable' then r.unavailable end
  from sectalk_private.st_v6_operation_rollups r
  where p_source='operations' and r.operation=p_scope and r.bucket between p_start and p_end
  union all
  select a.bucket,a.anomalies from sectalk_private.st_v7_detection_login_windows a
  where p_source='login_anomalies' and p_scope='platform' and p_metric='anomalies' and a.bucket between p_start and p_end;
$$;

create function sectalk_private.st_v7_observe_detection_window(p_source text,p_scope text,p_bucket timestamptz)
returns void language sql set search_path='' as $$
  insert into sectalk_private.st_v7_detection_matches(rule_id,version,activation,mode,bucket,observed)
  select r.id,v.version,r.activation,r.mode,p_bucket,
    x.value-case when p_bucket=r.baseline_bucket then r.baseline_count else 0 end
  from sectalk_private.st_v7_detection_rules r
  join sectalk_private.st_v7_detection_versions v on (v.rule_id,v.version)=(r.id,r.active_version)
  cross join lateral sectalk_private.st_v7_detection_values(v.source,v.scope,v.metric,p_bucket,p_bucket) x
  where (v.source,v.scope)=(p_source,p_scope) and p_bucket>=r.baseline_bucket
    and x.value-case when p_bucket=r.baseline_bucket then r.baseline_count else 0 end>=v.threshold
  on conflict(rule_id,activation,bucket) do nothing;
$$;

create function sectalk_private.st_v7_observe_operation_detection()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_v7_observe_detection_window('operations',new.operation,new.bucket);
  return new;
end $$;
create trigger st_v7_observe_operation_detection after insert or update on sectalk_private.st_v6_operation_rollups
  for each row execute function sectalk_private.st_v7_observe_operation_detection();

create function sectalk_private.st_v7_observe_login_detection()
returns trigger language plpgsql security definer set search_path='' as $$
declare window_start timestamptz:=sectalk_private.st_v7_detection_window(new.detected_at);
begin
  insert into sectalk_private.st_v7_detection_login_windows as a(bucket,anomalies) values(window_start,1)
    on conflict(bucket) do update set anomalies=a.anomalies+1;
  perform sectalk_private.st_v7_observe_detection_window('login_anomalies','platform',window_start);
  return new;
end $$;
lock table sectalk_private.st_v7_login_anomalies in share row exclusive mode;
insert into sectalk_private.st_v7_detection_login_windows(bucket,anomalies)
  select sectalk_private.st_v7_detection_window(a.detected_at),count(*)
  from sectalk_private.st_v7_login_anomalies a where a.detected_at>=statement_timestamp()-interval '7 days' group by 1;
create trigger st_v7_observe_login_detection after insert on sectalk_private.st_v7_login_anomalies
  for each row execute function sectalk_private.st_v7_observe_login_detection();

select cron.schedule('sectalk-v7-prune-detection-observations','43 3 * * *',
  $job$delete from sectalk_private.st_v7_detection_matches where bucket<now()-interval '7 days';
    delete from sectalk_private.st_v7_detection_login_windows where bucket<now()-interval '7 days';$job$);

create function sectalk_private.st_v7_detection_operator_write()
returns void language plpgsql set search_path='' as $$
begin
  if public.st_v7_detection_rule_access()<>'verified' then
    raise exception 'Fresh detection operator verification required' using errcode='42501'; end if;
  perform 1 from sectalk_private.st_v7_detection_operators o where o.user_id=auth.uid() for share;
  if not found then raise exception 'Detection operator access changed' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v7_detection_rule_write',20);
end $$;

create function public.st_v7_save_detection_rule(p_rule uuid,p_expected integer,p_label text,p_source text,
  p_scope text,p_metric text,p_threshold integer)
returns uuid language plpgsql security definer set search_path='' as $$
declare definition sectalk_private.st_v7_detection_rules; rule_key uuid:=p_rule;
  next_version integer:=1; clean_label text:=btrim(p_label);
begin
  perform sectalk_private.st_v7_detection_operator_write();
  if (p_threshold between 1 and 1000000) is not true
    or ((p_source='operations' and p_scope in ('file_upload','file_publish','file_download_grant','file_download',
      'call_ice','meeting_token','billing_action','billing_webhook')
      and p_metric in ('requests','client_errors','server_errors','throttled','unavailable'))
      or (p_source='login_anomalies' and p_scope='platform' and p_metric='anomalies' and p_threshold>=3)) is not true then
    raise exception 'Choose a supported signal, scope, and threshold' using errcode='22023';
  end if;
  if p_rule is null then
    if clean_label is null or char_length(clean_label) not between 3 and 80 then
      raise exception 'Enter a name between 3 and 80 characters' using errcode='22023'; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-detection-rules',0));
    if (select count(*) from sectalk_private.st_v7_detection_rules)>=100 then
      raise exception 'The detection registry has reached its rule limit' using errcode='PT409'; end if;
    insert into sectalk_private.st_v7_detection_rules(label) values(clean_label) returning id into rule_key;
  else
    select r.* into definition from sectalk_private.st_v7_detection_rules r where r.id=p_rule for update;
    if definition.id is null or definition.latest_version is distinct from p_expected then
      raise exception 'Refresh the rule before saving another version' using errcode='PT409'; end if;
    if definition.latest_version>=25 then raise exception 'This rule has reached its version limit' using errcode='PT409'; end if;
    next_version:=definition.latest_version+1;
    update sectalk_private.st_v7_detection_rules set latest_version=next_version where id=p_rule;
  end if;
  insert into sectalk_private.st_v7_detection_versions(rule_id,version,source,scope,metric,threshold,authored_by)
    values(rule_key,next_version,p_source,p_scope,p_metric,p_threshold,auth.uid());
  insert into sectalk_private.st_v7_detection_audit(rule_id,version,actor,action)
    values(rule_key,next_version,auth.uid(),case when p_rule is null then 'created' else 'revised' end);
  return rule_key;
end $$;

create function public.st_v7_test_detection_rule(p_rule uuid,p_version integer)
returns jsonb language plpgsql security definer set search_path='' as $$
declare v sectalk_private.st_v7_detection_versions; end_bucket timestamptz:=sectalk_private.st_v7_detection_window(statement_timestamp());
  report jsonb;
begin
  perform sectalk_private.st_v7_detection_operator_write();
  select d.* into v from sectalk_private.st_v7_detection_versions d where (d.rule_id,d.version)=(p_rule,p_version);
  if v.rule_id is null then raise exception 'Detection version unavailable' using errcode='22023'; end if;
  select jsonb_build_object('recorded_windows',count(*),'matched_windows',count(*) filter(where s.value>=v.threshold),
    'peak',max(s.value),'latest_match',max(s.bucket) filter(where s.value>=v.threshold))
  into report from sectalk_private.st_v7_detection_values(v.source,v.scope,v.metric,end_bucket-interval '23 hours 55 minutes',end_bucket) s
  where v.source<>'login_anomalies' or s.value>=3;
  insert into sectalk_private.st_v7_detection_audit(rule_id,version,actor,action,result)
    values(p_rule,p_version,auth.uid(),'tested',report);
  return report;
end $$;

create function public.st_v7_deploy_detection_rule(p_rule uuid,p_version integer,p_action text,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare r sectalk_private.st_v7_detection_rules; v sectalk_private.st_v7_detection_versions;
  requested_mode text; next_version integer:=p_version; initial_bucket timestamptz; initial_count bigint;
  note text:=btrim(p_reason);
begin
  perform sectalk_private.st_v7_detection_operator_write();
  if p_action is null or p_action not in ('shadow','enabled','paused','rollback')
    or note is null or char_length(note) not between 10 and 240 then
    raise exception 'Choose a deployment action and enter a reason between 10 and 240 characters' using errcode='22023'; end if;
  select q.* into r from sectalk_private.st_v7_detection_rules q where q.id=p_rule for update;
  if r.id is null then raise exception 'Detection rule unavailable' using errcode='22023'; end if;
  if p_action='paused' then
    if r.active_version is null or r.active_version is distinct from p_version then
      raise exception 'Refresh the current deployment before pausing it' using errcode='PT409'; end if;
    next_version:=r.active_version;
    update sectalk_private.st_v7_detection_rules set active_version=null,mode=null,activation=null,baseline_bucket=null,baseline_count=null
      where id=p_rule;
  else
    select d.* into v from sectalk_private.st_v7_detection_versions d where (d.rule_id,d.version)=(p_rule,p_version);
    if v.rule_id is null or not exists(select 1 from sectalk_private.st_v7_detection_audit a
      where (a.rule_id,a.version)=(p_rule,p_version) and a.action='tested') then
      raise exception 'Test this version before deployment' using errcode='PT409'; end if;
    if p_action='rollback' then
      select a.mode into requested_mode from sectalk_private.st_v7_detection_audit a
        where (a.rule_id,a.version)=(p_rule,p_version) and a.mode is not null order by a.id desc limit 1;
      if requested_mode is null or r.active_version is not distinct from p_version then
        raise exception 'Choose a different previously deployed version to restore' using errcode='PT409'; end if;
    elsif p_action='enabled' then
      if r.active_version is distinct from p_version or r.mode is distinct from 'shadow' then
        raise exception 'Run this version in shadow before enabling it' using errcode='PT409'; end if;
      requested_mode:='enabled';
    else
      if r.active_version=p_version and r.mode='shadow' then
        raise exception 'This version is already running in shadow' using errcode='PT409'; end if;
      requested_mode:='shadow';
    end if;
    initial_bucket:=sectalk_private.st_v7_detection_window(clock_timestamp());
    select s.value into initial_count from sectalk_private.st_v7_detection_values(v.source,v.scope,v.metric,initial_bucket,initial_bucket) s;
    update sectalk_private.st_v7_detection_rules set active_version=p_version,mode=requested_mode,activation=gen_random_uuid(),
      baseline_bucket=initial_bucket,baseline_count=coalesce(initial_count,0) where id=p_rule;
  end if;
  insert into sectalk_private.st_v7_detection_audit(rule_id,version,actor,action,mode,reason)
    values(p_rule,next_version,auth.uid(),p_action,requested_mode,note);
end $$;

create function public.st_v7_detection_rules()
returns table(id uuid,label text,latest_version integer,active_version integer,mode text)
language plpgsql stable security definer set search_path='' as $$
begin
  if public.st_v7_detection_rule_access()<>'verified' then
    raise exception 'Fresh detection operator verification required' using errcode='42501'; end if;
  return query select r.id,r.label,r.latest_version,r.active_version,r.mode
    from sectalk_private.st_v7_detection_rules r order by r.created_at desc,r.id limit 100;
end $$;

create function public.st_v7_detection_rule_detail(p_rule uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
begin
  if public.st_v7_detection_rule_access()<>'verified' then
    raise exception 'Fresh detection operator verification required' using errcode='42501'; end if;
  return (select jsonb_build_object('id',r.id,'label',r.label,'latest_version',r.latest_version,
    'active_version',r.active_version,'mode',r.mode,
    'versions',(select jsonb_agg(jsonb_build_object('version',v.version,'source',v.source,'scope',v.scope,'metric',v.metric,
      'threshold',v.threshold,'tested',(select a.result from sectalk_private.st_v7_detection_audit a
        where (a.rule_id,a.version)=(v.rule_id,v.version) and a.action='tested' order by a.id desc limit 1),
      'deployed',exists(select 1 from sectalk_private.st_v7_detection_audit a where (a.rule_id,a.version)=(v.rule_id,v.version)
        and a.mode is not null)) order by v.version desc) from sectalk_private.st_v7_detection_versions v where v.rule_id=r.id),
    'matches',(select coalesce(jsonb_agg(to_jsonb(m) order by m.id desc),'[]'::jsonb) from (
        select d.id,d.version,d.mode,d.bucket,d.observed,d.occurred_at from sectalk_private.st_v7_detection_matches d
        where d.rule_id=r.id order by d.id desc limit 30) m),
    'history',(select coalesce(jsonb_agg(to_jsonb(h) order by h.id desc),'[]'::jsonb) from (
        select a.id,a.version,a.action,a.mode,a.reason,a.occurred_at from sectalk_private.st_v7_detection_audit a
        where a.rule_id=r.id order by a.id desc limit 30) h))
    from sectalk_private.st_v7_detection_rules r where r.id=p_rule);
end $$;

create function sectalk_private.st_v7_immutable_detection_records()
returns trigger language plpgsql set search_path='' as $$
begin
  raise exception 'Detection rule versions and history are immutable' using errcode='42501';
end $$;
create trigger st_v7_immutable_detection_versions before update or delete on sectalk_private.st_v7_detection_versions
  for each row execute function sectalk_private.st_v7_immutable_detection_records();
create trigger st_v7_immutable_detection_audit before update or delete on sectalk_private.st_v7_detection_audit
  for each row execute function sectalk_private.st_v7_immutable_detection_records();

revoke all on function public.st_v7_detection_rule_access(),public.st_v7_detection_rules(),public.st_v7_detection_rule_detail(uuid),
  public.st_v7_save_detection_rule(uuid,integer,text,text,text,text,integer),public.st_v7_test_detection_rule(uuid,integer),
  public.st_v7_deploy_detection_rule(uuid,integer,text,text),sectalk_private.st_v7_detection_operator_write(),
  sectalk_private.st_v7_detection_window(timestamptz),sectalk_private.st_v7_detection_values(text,text,text,timestamptz,timestamptz),
  sectalk_private.st_v7_observe_detection_window(text,text,timestamptz),sectalk_private.st_v7_observe_operation_detection(),
  sectalk_private.st_v7_observe_login_detection(),sectalk_private.st_v7_immutable_detection_records()
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_detection_rule_access(),public.st_v7_detection_rules(),public.st_v7_detection_rule_detail(uuid),
  public.st_v7_save_detection_rule(uuid,integer,text,text,text,text,integer),public.st_v7_test_detection_rule(uuid,integer),
  public.st_v7_deploy_detection_rule(uuid,integer,text,text) to authenticated;
notify pgrst,'reload schema';
commit;
