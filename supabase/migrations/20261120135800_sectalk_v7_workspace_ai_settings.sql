begin;

create table sectalk_private.st_v7_workspace_ai_policy (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  enabled boolean not null,
  processing_consent boolean not null,
  advisory_threshold integer not null check(advisory_threshold between 1 and 3),
  retention_days integer not null check(retention_days between 1 and 90),
  retention_floor timestamptz not null default '-infinity',
  epoch uuid not null default gen_random_uuid()
);
alter table sectalk_private.st_v7_workspace_ai_policy enable row level security;
revoke all on sectalk_private.st_v7_workspace_ai_policy from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_workspace_ai_state(p_workspace uuid)
returns table(enabled boolean,consent boolean,threshold integer,days integer,cutoff timestamptz,epoch uuid)
language sql stable set search_path='' as $$
  select coalesce(p.enabled,true),coalesce(p.processing_consent,true),coalesce(p.advisory_threshold,1),
    coalesce(p.retention_days,30),greatest(coalesce(p.retention_floor,'-infinity'),
      now()-make_interval(days=>coalesce(p.retention_days,30))),
    coalesce(p.epoch,'00000000-0000-0000-0000-000000000000'::uuid)
  from (select p_workspace as id) ws left join sectalk_private.st_v7_workspace_ai_policy p on p.workspace=ws.id
$$;

create function public.st_v7_workspace_ai_settings(p_workspace uuid,p_enabled boolean default null,
  p_processing_consent boolean default null,p_advisory_threshold integer default null,p_retention_days integer default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); member_role text; prior_cutoff timestamptz; state record;
begin
  member_role:=sectalk_private.st_v2_role(p_workspace,actor);
  if coalesce(member_role,'') not in ('owner','admin') or not coalesce(sectalk_private.st_v2_active(actor),false) then
    raise exception using errcode='42501',message='Workspace AI settings are unavailable';
  end if;
  if num_nonnulls(p_enabled,p_processing_consent,p_advisory_threshold,p_retention_days)<>0 then
    if member_role<>'owner' then raise exception using errcode='42501',message='Only the workspace owner can change AI settings'; end if;
    if num_nonnulls(p_enabled,p_processing_consent,p_advisory_threshold,p_retention_days)<>4
      or p_advisory_threshold not between 1 and 3 or p_retention_days not between 1 and 90 then
      raise exception using errcode='22023',message='Invalid workspace AI settings';
    end if;
    perform sectalk_private.limit_action('workspace_ai_settings',12);
    perform 1 from public.st_v2_workspaces where id=p_workspace for update;
    if not found or sectalk_private.st_v2_role(p_workspace,actor) is distinct from 'owner' then
      raise exception using errcode='42501',message='Workspace AI settings are unavailable';
    end if;
    select s.cutoff into prior_cutoff from sectalk_private.st_v7_workspace_ai_state(p_workspace) s;
    insert into sectalk_private.st_v7_workspace_ai_policy as current_policy
      (workspace,enabled,processing_consent,advisory_threshold,retention_days,retention_floor)
      values(p_workspace,p_enabled,p_processing_consent,p_advisory_threshold,p_retention_days,
        greatest(prior_cutoff,now()-make_interval(days=>p_retention_days)))
      on conflict(workspace) do update set enabled=excluded.enabled,processing_consent=excluded.processing_consent,
        advisory_threshold=excluded.advisory_threshold,retention_days=excluded.retention_days,
        retention_floor=excluded.retention_floor,epoch=gen_random_uuid()
      where (current_policy.enabled,current_policy.processing_consent,current_policy.advisory_threshold,current_policy.retention_days)
        is distinct from (excluded.enabled,excluded.processing_consent,excluded.advisory_threshold,excluded.retention_days);
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(p_workspace,actor,'workspace.ai_policy',p_workspace);
    end if;
  end if;
  select * into state from sectalk_private.st_v7_workspace_ai_state(p_workspace);
  return jsonb_build_object('owner',member_role='owner','enabled',state.enabled,'consent',state.consent,
    'threshold',state.threshold,'retentionDays',state.days);
end
$$;

alter table sectalk_private.st_v6_caption_consent add column ai_policy_epoch uuid;

create index st_v7_caption_retention_spoken on sectalk_private.st_v6_caption_line(spoken_at,meeting,sequence);
create function sectalk_private.st_v7_purge_ai_transcript(p_limit integer default 1000)
returns integer language plpgsql security definer set search_path='' as $$
declare purged integer;
begin
  with expired as (
    select l.meeting,l.sequence from sectalk_private.st_v6_caption_line l
    join public.st_v3_meetings m on m.id=l.meeting
    left join sectalk_private.st_v7_workspace_ai_policy p on p.workspace=m.workspace_id
    where l.spoken_at<now()-interval '1 day'
      and l.spoken_at<greatest(coalesce(p.retention_floor,'-infinity'),
        now()-make_interval(days=>coalesce(p.retention_days,30)))
    order by l.spoken_at,l.meeting,l.sequence limit least(2000,greatest(1,coalesce(p_limit,1000))) for update of l skip locked
  ) delete from sectalk_private.st_v6_caption_line l using expired x where (l.meeting,l.sequence)=(x.meeting,x.sequence);
  get diagnostics purged=row_count;
  return purged;
end
$$;
revoke all on function sectalk_private.st_v7_workspace_ai_state(uuid),sectalk_private.st_v7_purge_ai_transcript(integer),
  public.st_v7_workspace_ai_settings(uuid,boolean,boolean,integer,integer) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_workspace_ai_settings(uuid,boolean,boolean,integer,integer) to authenticated;
select cron.schedule('sectalk-v7-purge-ai-transcripts','*/5 * * * *','select sectalk_private.st_v7_purge_ai_transcript(1000)');

create or replace function public.st_v6_meeting_caption_command(
  p_meeting uuid,p_actor uuid,p_action text,p_sid text default null,
  p_language text default null,p_lease uuid default null,p_text text default null,p_after integer default 0
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  meeting_row public.st_v3_meetings;
  session sectalk_private.st_v6_caption_session;
  consent sectalk_private.st_v6_caption_consent;
  is_host boolean;
  admitted boolean;
  active boolean;
  allowed boolean;
  lines jsonb:='[]';
  speaker text;
  ai record;
  processing boolean;
begin
  if p_action='view' then
    select * into meeting_row from public.st_v3_meetings where id=p_meeting;
  else
    select * into meeting_row from public.st_v3_meetings where id=p_meeting for share;
  end if;
  if not found or not coalesce(sectalk_private.st_v2_active(p_actor),false)
    or not coalesce(sectalk_private.st_v3_meeting_visible(p_meeting,p_actor),false)
    or not coalesce(sectalk_private.open_pair(meeting_row.host_id,p_actor),false)
    or sectalk_private.st_v2_role(meeting_row.workspace_id,p_actor) is null then return null; end if;
  select * into ai from sectalk_private.st_v7_workspace_ai_state(meeting_row.workspace_id);
  processing:=ai.enabled and ai.consent;
  if not processing and p_action not in ('view','withdraw') then return null; end if;
  is_host:=sectalk_private.st_v3_is_host(p_meeting,p_actor);
  admitted:=meeting_row.status='live' and meeting_row.ends_at>now() and exists(
    select 1 from public.st_v3_attendance where meeting_id=p_meeting and user_id=p_actor and status='admitted'
  );
  if admitted and p_action<>'view' then
    perform 1 from public.st_v3_attendance where meeting_id=p_meeting and user_id=p_actor and status='admitted' for share;
    admitted:=found;
  end if;
  if p_action='view' then
    select * into session from sectalk_private.st_v6_caption_session where meeting=p_meeting;
  else
    select * into session from sectalk_private.st_v6_caption_session where meeting=p_meeting for update;
  end if;
  select * into consent from sectalk_private.st_v6_caption_consent where meeting=p_meeting and actor=p_actor;
  active:=processing and coalesce(not session.stopped and session.expires_at>now() and meeting_row.status='live' and meeting_row.ends_at>now(),false);
  allowed:=coalesce(consent.granted and p_sid=consent.participant_sid,false);

  if p_action='start' then
    if not (admitted and is_host) or p_sid is null or session.meeting is not null
      or p_language is null or p_language not in ('en','es','fr','de','hi') then return null; end if;
    insert into sectalk_private.st_v6_caption_session(meeting,source_language,expires_at)
      values(p_meeting,p_language,least(meeting_row.ends_at,now()+interval '2 hours')) on conflict do nothing;
    return jsonb_build_object('ok',true);
  elsif p_action='join' then
    if not (active and admitted) or p_sid is null then return null; end if;
    insert into sectalk_private.st_v6_caption_consent(meeting,actor,participant_sid)
      values(p_meeting,p_actor,p_sid) on conflict(meeting,actor) do update
      set granted=true,participant_sid=excluded.participant_sid,lease=null,ai_policy_epoch=null;
    return jsonb_build_object('ok',true);
  elsif p_action='withdraw' then
    if consent.actor is null then return null; end if;
    update sectalk_private.st_v6_caption_consent set granted=false,lease=null,ai_policy_epoch=null where meeting=p_meeting and actor=p_actor;
    delete from sectalk_private.st_v6_caption_line where meeting=p_meeting and actor=p_actor;
    return jsonb_build_object('ok',true);
  elsif p_action='stop' then
    if not (active and is_host and admitted) or p_sid is null then return null; end if;
    update sectalk_private.st_v6_caption_session set stopped=true where meeting=p_meeting;
    return jsonb_build_object('ok',true);
  elsif p_action='reserve' then
    if not (active and admitted and allowed) or session.line_count>=2400 or p_lease is null or
      consent.last_chunk_at>clock_timestamp()-interval '3500 milliseconds' then return null; end if;
    update sectalk_private.st_v6_caption_consent set last_chunk_at=clock_timestamp(),lease=p_lease,ai_policy_epoch=ai.epoch
      where meeting=p_meeting and actor=p_actor;
    return jsonb_build_object('language',session.source_language);
  elsif p_action='process' then
    if not (active and admitted and allowed) or p_lease is null or consent.lease is distinct from p_lease
      or consent.ai_policy_epoch is distinct from ai.epoch
      or consent.last_chunk_at<clock_timestamp()-interval '20 seconds' then return null; end if;
    return jsonb_build_object('language',session.source_language);
  elsif p_action='publish' then
    if not (active and admitted and allowed) or session.line_count>=2400 or p_lease is null
      or consent.lease is distinct from p_lease or consent.ai_policy_epoch is distinct from ai.epoch
      or consent.last_chunk_at<clock_timestamp()-interval '20 seconds' then return null; end if;
    update sectalk_private.st_v6_caption_consent set lease=null,ai_policy_epoch=null where meeting=p_meeting and actor=p_actor;
    if char_length(trim(p_text)) between 1 and 500 then
      select name into speaker from public.st_profiles where id=p_actor;
      if speaker is null then return null; end if;
      update sectalk_private.st_v6_caption_session set line_count=line_count+1 where meeting=p_meeting returning * into session;
      insert into sectalk_private.st_v6_caption_line(meeting,sequence,actor,speaker,line)
        values(p_meeting,session.line_count,p_actor,speaker,trim(p_text));
    end if;
    return jsonb_build_object('ok',true);
  elsif p_action<>'view' then
    return null;
  end if;

  if not admitted and not coalesce(consent.granted,false) then return null; end if;
  if processing and ((active and admitted and allowed) or (not active and coalesce(consent.granted,false))) then
    select coalesce(jsonb_agg(to_jsonb(row) order by row.sequence),'[]') into lines from (
      select l.sequence,l.speaker,l.line,l.spoken_at from sectalk_private.st_v6_caption_line l
      where l.meeting=p_meeting and l.sequence>greatest(0,p_after) and l.spoken_at>=ai.cutoff
        and sectalk_private.open_pair(p_actor,l.actor)
      order by case when active then -l.sequence else l.sequence end limit 100
    ) row;
  end if;
  return jsonb_build_object('workspaceEnabled',processing,'active',active,'host',is_host,'admitted',admitted,
    'language',session.source_language,'consented',coalesce(consent.granted,false),'sending',active and admitted and allowed,'lines',lines);
end
$$;

create or replace function public.st_v6_meeting_summary_command(p_meeting uuid,p_actor uuid,p_action text,p_enabled boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  meeting_row public.st_v3_meetings;
  owner boolean;
  policy boolean;
  eligible boolean;
  consented boolean;
  policy_epoch uuid;
  consent_epoch uuid;
  transcript_language text;
  source_rows jsonb;
  fingerprint text;
  ai record;
  processing boolean;
begin
  select * into meeting_row from public.st_v3_meetings where id=p_meeting;
  if not found or not coalesce(sectalk_private.st_v2_active(p_actor),false)
    or not coalesce(sectalk_private.st_v3_meeting_visible(p_meeting,p_actor),false)
    or not coalesce(sectalk_private.open_pair(meeting_row.host_id,p_actor),false)
    or sectalk_private.st_v2_role(meeting_row.workspace_id,p_actor) is null then return null; end if;
  select * into ai from sectalk_private.st_v7_workspace_ai_state(meeting_row.workspace_id);
  processing:=ai.enabled and ai.consent;
  if not processing and p_action in ('source','opt-in') then return null; end if;
  owner:=sectalk_private.st_v2_role(meeting_row.workspace_id,p_actor)='owner';
  select enabled,epoch into policy,policy_epoch from sectalk_private.st_v6_summary_policy where workspace=meeting_row.workspace_id;
  policy:=coalesce(policy,false);
  select source_language into transcript_language from sectalk_private.st_v6_caption_session where meeting=p_meeting;
  eligible:=(meeting_row.status='ended' or (meeting_row.status='live' and meeting_row.ends_at<=now())) and exists(
    select 1 from sectalk_private.st_v6_caption_consent where meeting=p_meeting and actor=p_actor and granted
  );
  select epoch into consent_epoch from sectalk_private.st_v6_summary_consent where meeting=p_meeting and actor=p_actor;
  consented:=found;

  if p_action='policy' then
    if not owner or p_enabled is null or (p_enabled and not processing) then return null; end if;
    insert into sectalk_private.st_v6_summary_policy(workspace,enabled) values(meeting_row.workspace_id,p_enabled)
      on conflict(workspace) do update set enabled=excluded.enabled,epoch=gen_random_uuid() returning epoch into policy_epoch;
    if not p_enabled then
      delete from sectalk_private.st_v6_summary_consent c using public.st_v3_meetings m
        where c.meeting=m.id and m.workspace_id=meeting_row.workspace_id;
      consented:=false;
    end if;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(meeting_row.workspace_id,p_actor,'workspace.summary_policy',meeting_row.workspace_id);
    policy:=p_enabled;
  elsif p_action='opt-in' then
    if not (policy and eligible) then return null; end if;
    perform 1 from sectalk_private.st_v6_summary_policy where workspace=meeting_row.workspace_id and enabled for share;
    if not found then return null; end if;
    perform 1 from sectalk_private.st_v6_caption_consent where meeting=p_meeting and actor=p_actor and granted for share;
    if not found then return null; end if;
    insert into sectalk_private.st_v6_summary_consent(meeting,actor) values(p_meeting,p_actor) on conflict do nothing;
    select epoch into consent_epoch from sectalk_private.st_v6_summary_consent where meeting=p_meeting and actor=p_actor;
    consented:=true;
  elsif p_action='withdraw' then
    delete from sectalk_private.st_v6_summary_consent where meeting=p_meeting and actor=p_actor;
    consented:=false;
  elsif p_action not in ('view','source') then
    return null;
  end if;

  policy:=policy and processing;
  if (p_action='source' and not (policy and eligible and consented)) or
    (not (owner or eligible or consented)) then return null; end if;

  if policy and eligible and consented then
    select md5(ai.epoch::text||':'||policy_epoch::text||':'||consent_epoch::text||':'||string_agg(l.sequence::text||':'||l.epoch::text,',' order by l.sequence)),
      case when p_action='source' then coalesce(jsonb_agg(jsonb_build_object('line',l.line,'speaker',l.speaker)
        order by l.sequence),'[]') end into fingerprint,source_rows
    from (
      select l.sequence,l.line,l.speaker,s.epoch from sectalk_private.st_v6_caption_line l
      join sectalk_private.st_v6_caption_consent c on c.meeting=l.meeting and c.actor=l.actor and c.granted
      join sectalk_private.st_v6_summary_consent s on s.meeting=l.meeting and s.actor=l.actor
      where l.meeting=p_meeting and l.spoken_at>=ai.cutoff and sectalk_private.st_v2_active(l.actor)
        and sectalk_private.open_pair(p_actor,l.actor) and sectalk_private.open_pair(meeting_row.host_id,l.actor)
        and sectalk_private.st_v2_role(meeting_row.workspace_id,l.actor) is not null
      order by l.sequence limit 160
    ) l;
  end if;
  return jsonb_build_object('workspaceEnabled',processing,'owner',owner,'policy',policy,'eligible',eligible,'consented',consented,'language',transcript_language,
    'revision',fingerprint,'source',source_rows);
end
$$;

create or replace function public.st_v6_room_thread_summary_command(p_room uuid,p_root uuid,p_actor uuid,p_action text,p_enabled boolean)
returns jsonb language plpgsql security definer set search_path='' as $$
declare room_row public.st_v6_rooms;
declare policy sectalk_private.st_v6_thread_summary_policy;
declare owner boolean;
declare consent_epoch uuid;
declare source_rows jsonb;
declare revision text;
declare ai record;
declare processing boolean;
begin
  if p_action is null or p_action not in ('view','source','policy','opt-in','withdraw') then return null; end if;
  select * into room_row from public.st_v6_rooms r where r.id=p_room
    and r.kind='public' and r.classification in ('public','internal') and not r.archived;
  if not found or coalesce(sectalk_private.st_v6_room_role(p_room,p_actor),'') not in ('owner','moderator','member')
    or not exists(select 1 from public.st_v6_room_posts p where p.room_id=p_room and p.id=p_root
      and p.parent_id is null and p.removed_at is null and not p.forwarded and p.kind='message'
      and sectalk_private.open_pair(p_actor,p.sender)) then return null; end if;
  select * into ai from sectalk_private.st_v7_workspace_ai_state(room_row.workspace_id);
  processing:=ai.enabled and ai.consent;
  if not processing and p_action in ('source','opt-in') then return null; end if;
  owner:=sectalk_private.st_v2_role(room_row.workspace_id,p_actor)='owner';
  select * into policy from sectalk_private.st_v6_thread_summary_policy where workspace=room_row.workspace_id;

  if p_action='policy' then
    if not owner or p_enabled is null or (p_enabled and not processing) then return null; end if;
    perform 1 from public.st_v2_workspaces where id=room_row.workspace_id for update;
    select * into policy from sectalk_private.st_v6_thread_summary_policy where workspace=room_row.workspace_id;
    if coalesce(policy.enabled,false) is distinct from p_enabled then
      insert into sectalk_private.st_v6_thread_summary_policy(workspace,enabled) values(room_row.workspace_id,p_enabled)
        on conflict(workspace) do update set enabled=excluded.enabled,epoch=gen_random_uuid() returning * into policy;
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(room_row.workspace_id,p_actor,'workspace.thread_summary_policy',room_row.workspace_id);
    end if;
  elsif p_action='opt-in' then
    select * into policy from sectalk_private.st_v6_thread_summary_policy where workspace=room_row.workspace_id and enabled for share;
    if not found then return null; end if;
    insert into sectalk_private.st_v6_thread_summary_consent(room,root,actor,policy_epoch)
      values(p_room,p_root,p_actor,policy.epoch)
      on conflict(room,root,actor) do update set policy_epoch=excluded.policy_epoch,epoch=gen_random_uuid()
      where st_v6_thread_summary_consent.policy_epoch is distinct from excluded.policy_epoch;
  elsif p_action='withdraw' then
    delete from sectalk_private.st_v6_thread_summary_consent where room=p_room and root=p_root and actor=p_actor;
  end if;

  if coalesce(policy.enabled,false) then
    select c.epoch into consent_epoch from sectalk_private.st_v6_thread_summary_consent c
      where c.room=p_room and c.root=p_root and c.actor=p_actor and c.policy_epoch=policy.epoch;
  end if;
  if p_action='source' and consent_epoch is null then return null; end if;
  if processing and consent_epoch is not null and p_action in ('view','source') then
    select coalesce(jsonb_agg(jsonb_build_object('id',source.id,'line',source.body,'speaker',source.name,'epoch',source.epoch)
      order by source.is_root desc,source.created_at,source.id),'[]'::jsonb) into source_rows
    from (
      select p.id,p.body,pr.name,c.epoch,p.created_at,p.id=p_root as is_root
      from public.st_v6_room_posts p
      join sectalk_private.st_v6_thread_summary_consent c on c.room=p.room_id and c.root=p_root and c.actor=p.sender
        and c.policy_epoch=policy.epoch
      join public.st_profiles pr on pr.id=p.sender
      where p.room_id=p_room and (p.id=p_root or p.parent_id=p_root)
        and p.removed_at is null and not p.forwarded and p.kind='message'
        and char_length(p.body) between 1 and 500 and btrim(p.body)<>''
        and sectalk_private.open_pair(p_actor,p.sender)
        and sectalk_private.st_v6_room_role(p_room,p.sender) in ('owner','moderator','member')
      order by is_root desc,p.created_at desc,p.id desc limit 60
    ) source;
    revision:=encode(sha256(convert_to(ai.epoch::text||':'||policy.epoch::text||':'||consent_epoch::text||':'||source_rows::text,'UTF8')),'hex');
  end if;
  return jsonb_build_object('workspaceEnabled',processing,'owner',owner,'policy',processing and coalesce(policy.enabled,false),
    'consented',consent_epoch is not null,'revision',revision,
    'source',case when p_action='source' then source_rows end);
end
$$;


commit;
