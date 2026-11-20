begin;

alter table sectalk_private.st_v6_call_qos add column workspace_id uuid
  references public.st_v2_workspaces(id) on delete cascade;
alter table sectalk_private.st_v6_call_qos add constraint st_v6_call_qos_meeting_workspace
  check(workspace_id is null or mode='meeting');
create index st_v6_call_qos_workspace_day on sectalk_private.st_v6_call_qos(workspace_id,day,metric)
  where workspace_id is not null;

create or replace function public.st_v6_report_call_qos(
  p_mode text,p_resource uuid,p_device uuid,p_metric text,p_bucket text
) returns boolean language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  utc_day date:=(clock_timestamp() at time zone 'UTC')::date;
  key_bytes bytea;
  reporter bytea;
  event bytea;
  scope_workspace uuid;
begin
  if actor is null or p_resource is null or p_mode is null or p_metric is null or p_bucket is null or not (
    (p_metric='setup' and p_bucket in ('fast','moderate','slow','failed'))
    or (p_metric='relay' and p_bucket in ('relayed','non_relayed'))
    or (p_metric='recovery' and p_bucket in ('recovered','failed'))
    or (p_metric='join' and p_bucket in ('started','connected'))
    or (p_metric='ice_restart' and p_mode='direct' and p_bucket in ('not_requested','requested'))
    or (p_metric='mos' and p_bucket in ('below_2','2_to_3','3_to_4','4_or_more'))
  ) then return false; end if;

  if p_mode='direct' then
    if p_metric='ice_restart' and not exists (
      select 1 from public.st_calls c where c.id=p_resource and c.caller=actor
    ) then return false; end if;
    if (not sectalk_private.call_access(p_resource,actor) and not exists (
      select 1 from public.st_calls c where c.id=p_resource and actor in(c.caller,c.callee)
        and c.status='ended' and c.end_reason is null and c.expires_at>=now()-interval '1 minute'
        and sectalk_private.open_pair(c.caller,c.callee)
    )) or exists (
      select 1 from sectalk_private.st_v6_call_endpoints e
      where e.call_id=p_resource and e.actor_id=actor and (
        e.device_id is distinct from p_device or e.auth_session is distinct from auth.jwt()->>'session_id'
      )
    ) then return false; end if;
  elsif p_mode='meeting' then
    if p_device is not null or not public.st_v3_media_access(p_resource) then return false; end if;
    select m.workspace_id into scope_workspace from public.st_v3_meetings m where m.id=p_resource;
    if not found then return false; end if;
  else
    return false;
  end if;

  select secret into key_bytes from sectalk_private.st_v6_call_qos_key where singleton;
  reporter:=extensions.hmac(convert_to('reporter:'||utc_day||':'||actor,'UTF8'),key_bytes,'sha256');
  event:=extensions.hmac(convert_to('event:'||utc_day||':'||actor||':'||p_mode||':'||p_resource||':'||p_metric,'UTF8'),key_bytes,'sha256');
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(encode(reporter,'hex'),0));
  if p_metric in ('join','ice_restart') then
    update sectalk_private.st_v6_call_qos
      set bucket=p_bucket,workspace_id=coalesce(workspace_id,scope_workspace)
      where day=utc_day and event_key=event and (
        (metric='join' and bucket='started' and p_bucket='connected')
        or (metric='ice_restart' and bucket='not_requested' and p_bucket='requested')
      );
    if found then return true; end if;
  end if;
  if (select count(*) from sectalk_private.st_v6_call_qos where day=utc_day and reporter_key=reporter)>=24
    then return false; end if;
  insert into sectalk_private.st_v6_call_qos(day,event_key,reporter_key,mode,metric,bucket,workspace_id)
    values(utc_day,event,reporter,p_mode,p_metric,p_bucket,scope_workspace) on conflict do nothing;
  return found;
end $$;

create function public.st_v6_workspace_analytics(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare cutoff timestamptz:=date_trunc('day',now(),'UTC');
declare shared_activity jsonb;
declare quality jsonb;
declare posture jsonb;
begin
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Verified workspace analytics access is required' using errcode='42501';
  end if;
  with eligible as (
    select p.sender from public.st_v6_room_posts p join public.st_v6_rooms r on r.id=p.room_id
      where r.workspace_id=p_workspace and r.kind in ('public','announcement','broadcast')
        and r.classification in ('public','internal') and not r.archived and p.removed_at is null
        and p.created_at>=cutoff-interval '168 hours' and p.created_at<cutoff
    union all
    select p.sender from public.st_v2_posts p join public.st_v2_channels c on c.id=p.channel_id
      where c.workspace_id=p_workspace and c.visibility='workspace' and not c.archived
        and p.created_at>=cutoff-interval '168 hours' and p.created_at<cutoff
  ), measured as (
    select count(*) posts,count(distinct sender) contributors from eligible e
    join public.st_v2_members m on m.workspace_id=p_workspace and m.user_id=e.sender and m.suspended_at is null
    having count(distinct sender)>=5
  )
  select jsonb_build_object('posts',(posts/5)*5,'contributors',(contributors/5)*5) into shared_activity from measured;

  with qualified_days as (
    select day,metric,count(*) sampled,count(*) filter(where bucket in ('connected','relayed')) positive
    from sectalk_private.st_v6_call_qos
    where workspace_id=p_workspace and mode='meeting' and day>=(cutoff at time zone 'UTC')::date-7
      and day<(cutoff at time zone 'UTC')::date and metric in ('join','relay')
    group by day,metric
    having count(*)>=10 and count(distinct reporter_key)>=5
      and count(distinct reporter_key) filter(where bucket in ('connected','relayed')) not between 1 and 4
      and count(distinct reporter_key) filter(where bucket not in ('connected','relayed')) not between 1 and 4
  ), totals as (
    select metric,sum((sampled/10)*10) samples,floor(sum(positive)*10/sum(sampled))*10 rate
    from qualified_days group by metric
  )
  select coalesce(jsonb_object_agg(metric,jsonb_build_object('samples',samples,'percent',rate)),'{}'::jsonb)
    into quality from totals;

  select jsonb_build_object(
    'managed_rooms',count(*),'protected_rooms',count(*) filter(where r.classification in ('confidential','restricted')),
    'blocked_forwarding',count(*) filter(where r.classification in ('confidential','restricted') or not r.forwarding_allowed),
    'archived_rooms',count(*) filter(where r.archived)
  ) into posture from public.st_v6_rooms r
  where r.workspace_id=p_workspace and sectalk_private.st_v6_room_directory(r.id);

  return jsonb_build_object('period_start',cutoff-interval '168 hours','period_end',cutoff,
    'shared_activity',shared_activity,'meeting_quality',quality,'security_posture',posture);
end $$;
revoke all on function public.st_v6_workspace_analytics(uuid) from public,anon,authenticated;
grant execute on function public.st_v6_workspace_analytics(uuid) to authenticated;

commit;
