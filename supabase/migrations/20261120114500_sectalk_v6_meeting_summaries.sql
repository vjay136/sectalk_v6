begin;

create table sectalk_private.st_v6_summary_policy (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  enabled boolean not null,
  epoch uuid not null default gen_random_uuid()
);
create table sectalk_private.st_v6_summary_consent (
  meeting uuid not null,
  actor uuid not null,
  epoch uuid not null default gen_random_uuid(),
  primary key(meeting,actor),
  foreign key(meeting,actor) references sectalk_private.st_v6_caption_consent on delete cascade
);
alter table sectalk_private.st_v6_summary_policy enable row level security;
alter table sectalk_private.st_v6_summary_consent enable row level security;
revoke all on sectalk_private.st_v6_summary_policy,sectalk_private.st_v6_summary_consent from public,anon,authenticated;

create function public.st_v6_meeting_summary_command(p_meeting uuid,p_actor uuid,p_action text,p_enabled boolean default null)
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
begin
  select * into meeting_row from public.st_v3_meetings where id=p_meeting;
  if not found or not coalesce(sectalk_private.st_v2_active(p_actor),false)
    or not coalesce(sectalk_private.st_v3_meeting_visible(p_meeting,p_actor),false)
    or not coalesce(sectalk_private.open_pair(meeting_row.host_id,p_actor),false)
    or sectalk_private.st_v2_role(meeting_row.workspace_id,p_actor) is null then return null; end if;
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
    if not owner or p_enabled is null then return null; end if;
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

  if (p_action='source' and not (policy and eligible and consented)) or
    (not (owner or eligible or consented)) then return null; end if;

  if policy and eligible and consented then
    select md5(policy_epoch::text||':'||consent_epoch::text||':'||string_agg(l.sequence::text||':'||l.epoch::text,',' order by l.sequence)),
      case when p_action='source' then coalesce(jsonb_agg(jsonb_build_object('line',l.line,'speaker',l.speaker)
        order by l.sequence),'[]') end into fingerprint,source_rows
    from (
      select l.sequence,l.line,l.speaker,s.epoch from sectalk_private.st_v6_caption_line l
      join sectalk_private.st_v6_caption_consent c on c.meeting=l.meeting and c.actor=l.actor and c.granted
      join sectalk_private.st_v6_summary_consent s on s.meeting=l.meeting and s.actor=l.actor
      where l.meeting=p_meeting and sectalk_private.st_v2_active(l.actor)
        and sectalk_private.open_pair(p_actor,l.actor) and sectalk_private.open_pair(meeting_row.host_id,l.actor)
        and sectalk_private.st_v2_role(meeting_row.workspace_id,l.actor) is not null
      order by l.sequence limit 160
    ) l;
  end if;
  return jsonb_build_object('owner',owner,'policy',policy,'eligible',eligible,'consented',consented,'language',transcript_language,
    'revision',fingerprint,'source',source_rows);
end
$$;
revoke all on function public.st_v6_meeting_summary_command(uuid,uuid,text,boolean) from public,anon,authenticated;
grant execute on function public.st_v6_meeting_summary_command(uuid,uuid,text,boolean) to service_role;

commit;
