begin;
create table sectalk_private.st_v7_usage_events (
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  metric text not null check(metric in ('recording_ms','transcription_samples','ai_scans','storage_byte_hours')),
  source text not null check(length(source) between 1 and 160),
  amount bigint not null check(amount>=0),
  plan text not null,
  plan_version integer not null,
  occurred_at timestamptz not null,
  primary key(workspace,metric,source),
  foreign key(plan,plan_version) references sectalk_private.st_v7_plan_entitlements(plan,version)
);
create index on sectalk_private.st_v7_usage_events(workspace,occurred_at,metric);
alter table sectalk_private.st_v7_usage_events enable row level security;
revoke all on sectalk_private.st_v7_usage_events from public,anon,authenticated,service_role;

create table sectalk_private.st_v7_scan_allowances (
  plan text not null,
  plan_version integer not null,
  included_per_month integer not null check(included_per_month between 0 and 10000000),
  primary key(plan,plan_version),
  foreign key(plan,plan_version) references sectalk_private.st_v7_plan_entitlements(plan,version)
);
alter table sectalk_private.st_v7_scan_allowances enable row level security;
revoke all on sectalk_private.st_v7_scan_allowances from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_write_usage(tenant uuid, metric_name text, source_key text, units bigint, occurred timestamptz)
returns void language sql security definer set search_path='' as $$
  insert into sectalk_private.st_v7_usage_events(workspace,metric,source,amount,plan,plan_version,occurred_at)
  select tenant,metric_name,source_key,units,e.plan,e.version,occurred
  from sectalk_private.st_v7_workspace_entitlements(tenant) e where e.plan is not null
  on conflict(workspace,metric,source) do nothing;
$$;

create function public.st_v7_complete_metered_recording(p_meeting uuid,p_recording uuid,p_egress text,p_duration_ms bigint)
returns jsonb language plpgsql security definer set search_path='' as $$
declare state jsonb; tenant uuid;
begin
  if p_duration_ms is null or p_duration_ms not between 1 and 86400000
    or p_egress is null or length(p_egress) not between 1 and 80 or p_recording is null then return null; end if;
  state:=public.st_v6_recording_command(p_meeting,null,'complete',p_recording,null,p_egress);
  if state is null then return null; end if;
  select workspace_id into tenant from public.st_v3_meetings where id=p_meeting;
  perform sectalk_private.st_v7_write_usage(tenant,'recording_ms',p_recording::text,p_duration_ms,statement_timestamp());
  return state;
end $$;

create function public.st_v7_publish_metered_caption(p_meeting uuid,p_actor uuid,p_sid text,p_lease uuid,p_text text,p_samples integer)
returns jsonb language plpgsql security definer set search_path='' as $$
declare state jsonb; tenant uuid;
begin
  if p_samples is null or p_samples not between 500 and 96000 then return null; end if;
  state:=public.st_v6_meeting_caption_command(p_meeting,p_actor,'publish',p_sid,null,p_lease,p_text,0);
  if state is null then return null; end if;
  select workspace_id into tenant from public.st_v3_meetings where id=p_meeting;
  perform sectalk_private.st_v7_write_usage(tenant,'transcription_samples',p_lease::text,p_samples,statement_timestamp());
  return state;
end $$;

create function public.st_v7_meter_file_scan(p_scope text,p_container uuid,p_actor uuid,p_file uuid,p_digest text,p_name text)
returns boolean language plpgsql security definer set search_path='' as $$
declare tenant uuid; scope_state jsonb;
begin
  if p_file is null or p_digest is null or p_digest !~ '^[a-f0-9]{64}$' then return false; end if;
  if p_scope='room' then
    scope_state:=public.st_v6_room_file_command(p_container,p_actor,'access',p_file,p_name,null,null);
    if scope_state is not null then select workspace_id into tenant from public.st_v6_rooms where id=p_container; end if;
  elsif p_scope='workspace' then
    scope_state:=public.st_v6_workspace_file_command(p_container,p_actor,'access',p_file,p_name,null,null);
    if scope_state is not null then tenant:=p_container; end if;
  end if;
  if tenant is null then return false; end if;
  perform sectalk_private.st_v7_write_usage(tenant,'ai_scans',
    p_scope||':'||p_container::text||':'||p_file::text||':'||p_digest,1,statement_timestamp());
  return true;
end $$;

create function sectalk_private.st_v7_workspace_storage()
returns table(workspace uuid,bytes bigint) language sql stable security definer set search_path='' as $$
  select source.workspace,sum(source.bytes)::bigint from (
    select w.id as workspace,(o.metadata->>'size')::bigint bytes from storage.objects o join public.st_v2_workspaces w
      on w.id::text=split_part(o.name,'/',1)
    where o.bucket_id='sectalk-workspace-files'
      and o.name ~ '^[a-f0-9-]{36}/([a-f0-9-]{36}|rooms/[a-f0-9-]{36}/[a-f0-9-]{36})$'
      and o.metadata->>'size' ~ '^[0-9]{1,15}$'
    union all
    select m.workspace_id as workspace,(o.metadata->>'size')::bigint bytes from storage.objects o join public.st_v3_meetings m
      on m.id::text=split_part(o.name,'/',1)
    where o.bucket_id='recordings' and m.workspace_id is not null
      and o.name ~ '^[a-f0-9-]{36}/[a-f0-9-]{36}/meeting\.(ogg|mp4)$'
      and o.metadata->>'size' ~ '^[0-9]{1,15}$'
  ) source group by source.workspace;
$$;

create function sectalk_private.st_v7_sample_workspace_storage()
returns void language sql security definer set search_path='' as $$
  insert into sectalk_private.st_v7_usage_events(workspace,metric,source,amount,plan,plan_version,occurred_at)
  select s.workspace,'storage_byte_hours',
    to_char(date_trunc('hour',statement_timestamp(),'UTC') at time zone 'UTC','YYYY-MM-DD"T"HH24"Z"'),
    s.bytes,e.plan,e.version,date_trunc('hour',statement_timestamp(),'UTC')
  from sectalk_private.st_v7_workspace_storage() s
  cross join lateral sectalk_private.st_v7_workspace_entitlements(s.workspace) e
  where s.bytes>0 and e.plan is not null
  on conflict(workspace,metric,source) do nothing;
$$;

create function public.st_v7_workspace_usage(p_workspace uuid default null)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  span timestamptz:=date_trunc('month',now(),'UTC');
  usage_totals jsonb;
  plan sectalk_private.st_v7_plan_entitlements;
  stored bigint;
  allowance integer;
  scans bigint;
begin
  if actor is null or not coalesce(public.st_v7_current_session_valid(),false)
    or not coalesce(sectalk_private.st_v2_active(actor),false)
    or public.st_v7_login_risk_status()<>'clear' or public.st_v7_account_under_lockdown() then
    raise exception 'Current session required' using errcode='42501';
  end if;
  if p_workspace is null then
    return coalesce((select jsonb_agg(to_jsonb(item)) from
      (select w.id,w.name from public.st_v2_workspaces w where w.owner=actor
        and sectalk_private.st_v2_role(w.id,actor)='owner' order by w.name,w.id limit 100) item),'[]');
  end if;
  if not exists(select 1 from public.st_v2_workspaces w where w.id=p_workspace and w.owner=actor
    and sectalk_private.st_v2_role(w.id,actor)='owner') then
    raise exception 'Workspace billing owner required' using errcode='42501';
  end if;
  select * into plan from sectalk_private.st_v7_workspace_entitlements(p_workspace);
  select coalesce(sum(e.amount) filter(where e.metric='ai_scans'),0),
    jsonb_build_object('recording_ms',coalesce(sum(e.amount) filter(where e.metric='recording_ms'),0),
      'transcription_samples',coalesce(sum(e.amount) filter(where e.metric='transcription_samples'),0),
      'storage_byte_hours',coalesce(sum(e.amount) filter(where e.metric='storage_byte_hours'),0))
  into scans,usage_totals from sectalk_private.st_v7_usage_events e where e.workspace=p_workspace and e.occurred_at>=span;
  select included_per_month into allowance from sectalk_private.st_v7_scan_allowances a
    where a.plan=plan.plan and a.plan_version=plan.version;
  select s.bytes into stored from sectalk_private.st_v7_workspace_storage() s where s.workspace=p_workspace;
  return usage_totals||jsonb_build_object('period_start',span,'plan',plan.plan,'plan_version',plan.version,
    'storage_bytes',coalesce(stored,0),'storage_quota_bytes',plan.storage_bytes,
    'ai_scans',scans,'ai_scan_allowance',allowance,'ai_scan_overage',
    case when allowance is not null then greatest(0,scans-allowance) end);
end $$;

revoke all on function sectalk_private.st_v7_write_usage(uuid,text,text,bigint,timestamptz),
  sectalk_private.st_v7_workspace_storage(),sectalk_private.st_v7_sample_workspace_storage(),
  public.st_v7_complete_metered_recording(uuid,uuid,text,bigint),public.st_v7_publish_metered_caption(uuid,uuid,text,uuid,text,integer),
  public.st_v7_meter_file_scan(text,uuid,uuid,uuid,text,text),public.st_v7_workspace_usage(uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_complete_metered_recording(uuid,uuid,text,bigint),
  public.st_v7_publish_metered_caption(uuid,uuid,text,uuid,text,integer),public.st_v7_meter_file_scan(text,uuid,uuid,uuid,text,text)
  to service_role;
grant execute on function public.st_v7_workspace_usage(uuid) to authenticated;
select cron.schedule('sectalk-v7-storage-meter','3 * * * *','select sectalk_private.st_v7_sample_workspace_storage()');
commit;
