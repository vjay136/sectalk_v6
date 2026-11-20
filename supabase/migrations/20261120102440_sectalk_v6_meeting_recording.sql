begin;

insert into storage.buckets(id,name,public) values ('recordings','recordings',false)
on conflict (id) do update set public=false;

create table sectalk_private.st_v6_recording_policy (
  workspace_id uuid primary key references public.st_v2_workspaces on delete cascade,
  enabled boolean not null
);
create table sectalk_private.st_v6_recording (
  meeting_id uuid primary key references public.st_v3_meetings on delete cascade,
  id uuid not null unique,
  status text not null check (status in ('collecting','starting','recording','stopping','ready','discard','failed')),
  roster jsonb not null,
  capture jsonb,
  approvals jsonb not null default '{}',
  egress_id text,
  attempted_at timestamptz,
  requested_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v6_recording_policy enable row level security;
alter table sectalk_private.st_v6_recording enable row level security;
revoke all on sectalk_private.st_v6_recording_policy,sectalk_private.st_v6_recording from public,anon,authenticated;

create function public.st_v6_set_recording_policy(p_workspace uuid,p_enabled boolean)
returns void language plpgsql security definer set search_path='' as $$
begin
  if p_enabled is null or not sectalk_private.st_v2_active(auth.uid()) or
      sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner' then
    raise exception 'Workspace owner required' using errcode='42501';
  end if;
  insert into sectalk_private.st_v6_recording_policy values(p_workspace,p_enabled)
    on conflict(workspace_id) do update set enabled=excluded.enabled;
  if not p_enabled then
    update sectalk_private.st_v6_recording r set status='discard'
      where r.meeting_id in (select id from public.st_v3_meetings where workspace_id=p_workspace)
        and r.status in ('collecting','starting','recording','stopping');
  end if;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,auth.uid(),'workspace.recording_policy',p_workspace);
end
$$;
revoke all on function public.st_v6_set_recording_policy(uuid,boolean) from public,anon,authenticated;
grant execute on function public.st_v6_set_recording_policy(uuid,boolean) to authenticated;

create function public.st_v6_recording_command(
  p_meeting uuid, p_actor uuid, p_action text, p_recording uuid default null,
  p_roster jsonb default null, p_egress text default null, p_capture jsonb default null
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  meeting public.st_v3_meetings;
  rec sectalk_private.st_v6_recording;
  policy boolean;
  owner boolean;
  host boolean;
  attendee boolean;
  participant boolean;
begin
  select * into meeting from public.st_v3_meetings where id=p_meeting for update;
  if not found then return null; end if;
  select coalesce((select enabled from sectalk_private.st_v6_recording_policy where workspace_id=meeting.workspace_id),false) into policy;
  select * into rec from sectalk_private.st_v6_recording where meeting_id=p_meeting for update;
  host:=p_actor is not null and sectalk_private.st_v3_is_host(p_meeting,p_actor) and sectalk_private.st_v2_active(p_actor);
  owner:=p_actor is not null and coalesce(sectalk_private.st_v2_role(meeting.workspace_id,p_actor)='owner',false)
    and sectalk_private.st_v2_active(p_actor);
  attendee:=p_actor is not null and meeting.status='live' and meeting.ends_at>now()
    and sectalk_private.st_v3_is_host(p_meeting,meeting.host_id) and sectalk_private.st_v2_active(meeting.host_id)
    and sectalk_private.st_v2_active(p_actor) and sectalk_private.open_pair(meeting.host_id,p_actor)
    and sectalk_private.st_v2_role(meeting.workspace_id,p_actor) is not null
    and exists(select 1 from public.st_v3_attendance where meeting_id=p_meeting and user_id=p_actor and status='admitted');
  participant:=coalesce(rec.roster ? p_actor::text,false);

  if p_action in ('view','download') then
    if p_actor is null or not sectalk_private.st_v2_active(p_actor) or
      not sectalk_private.st_v3_meeting_visible(p_meeting,p_actor) then return null; end if;
    if p_action='download' and not (rec.status='ready' and participant and rec.approvals->>p_actor::text='true'
      and sectalk_private.open_pair(meeting.host_id,p_actor)) then return null; end if;
    if not coalesce(attendee or (participant and sectalk_private.open_pair(meeting.host_id,p_actor)),false) then
      rec:=null;
    end if;
  elsif p_action='request' then
    if not (host and attendee and policy) or p_recording is null or p_roster is null or jsonb_typeof(p_roster)<>'object'
      or not (p_roster ? p_actor::text) or (select count(*) from jsonb_object_keys(p_roster)) not between 1 and 12 then return null; end if;
    if rec.id is not null and rec.status<>'failed' and
      not (rec.status='collecting' and rec.requested_at<clock_timestamp()-interval '3 minutes') then return null; end if;
    if exists(select 1 from jsonb_each_text(p_roster) member
      where member.value='' or not exists(select 1 from public.st_v3_attendance
        where meeting_id=p_meeting and user_id::text=member.key and status='admitted')) then return null; end if;
    insert into sectalk_private.st_v6_recording(meeting_id,id,status,roster,capture)
      values(p_meeting,p_recording,'collecting',p_roster,p_capture)
      on conflict(meeting_id) do update set id=excluded.id,status='collecting',roster=excluded.roster,
        approvals='{}',capture=excluded.capture,egress_id=null,attempted_at=null,requested_at=clock_timestamp() returning * into rec;
  else
    if rec.id is null or (p_recording is not null and p_recording<>rec.id) then return null; end if;
    if p_action='accept' then
      if not (attendee and participant and policy) or rec.status<>'collecting' or p_roster is distinct from rec.roster or p_capture is distinct from rec.capture
        or rec.requested_at<clock_timestamp()-interval '3 minutes' then return null; end if;
      update sectalk_private.st_v6_recording set approvals=approvals||jsonb_build_object(p_actor::text,true)
        where meeting_id=p_meeting returning * into rec;
    elsif p_action='start' then
      if not (host and attendee and policy) or rec.status<>'collecting' or p_roster is distinct from rec.roster or p_capture is distinct from rec.capture
        or rec.requested_at<clock_timestamp()-interval '3 minutes' or rec.approvals<>(
          select jsonb_object_agg(key,true) from jsonb_object_keys(rec.roster) as key) then return null; end if;
      update sectalk_private.st_v6_recording set status='starting',attempted_at=clock_timestamp()
        where meeting_id=p_meeting returning * into rec;
    elsif p_action='withdraw' then
      if not participant or rec.status not in ('collecting','starting','recording','stopping') then return null; end if;
      update sectalk_private.st_v6_recording set status='discard',approvals=approvals-p_actor::text
        where meeting_id=p_meeting returning * into rec;
    elsif p_action='stop' then
      if not host or rec.status<>'recording' then return null; end if;
      update sectalk_private.st_v6_recording set status='stopping' where meeting_id=p_meeting returning * into rec;
    elsif p_action='invalidate' then
      if rec.status in ('collecting','starting','recording','stopping')
        and (not policy or meeting.status<>'live' or p_roster is distinct from rec.roster or p_capture is distinct from rec.capture
          or (rec.status='collecting' and rec.requested_at<clock_timestamp()-interval '3 minutes')
          or (rec.status='starting' and rec.attempted_at<clock_timestamp()-interval '30 seconds')) then
        update sectalk_private.st_v6_recording set status='discard' where meeting_id=p_meeting returning * into rec;
      end if;
    elsif p_action='internal' then
      null;
    elsif p_action='attach' then
      if rec.status not in ('starting','discard') or p_egress is null then return null; end if;
      update sectalk_private.st_v6_recording set status=case when status='starting' then 'recording' else status end,
        egress_id=p_egress where meeting_id=p_meeting returning * into rec;
    elsif p_action='complete' then
      if rec.status<>'stopping' or p_egress is distinct from rec.egress_id or not policy then return null; end if;
      update sectalk_private.st_v6_recording set status='ready' where meeting_id=p_meeting returning * into rec;
    elsif p_action='discard' then
      if rec.status in ('ready','failed') then return null; end if;
      update sectalk_private.st_v6_recording set status='discard' where meeting_id=p_meeting returning * into rec;
    elsif p_action='cleaned' then
      if rec.status<>'discard' or p_egress is distinct from rec.egress_id
        or (rec.egress_id is null and rec.attempted_at>clock_timestamp()-interval '30 seconds') then return null; end if;
      update sectalk_private.st_v6_recording set status='failed' where meeting_id=p_meeting returning * into rec;
    else
      return null;
    end if;
  end if;
  return jsonb_build_object('policy',policy,'owner',owner,'host',host,'attendee',attendee,
    'recording',case when rec.id is null then null else to_jsonb(rec) end);
end
$$;
revoke all on function public.st_v6_recording_command(uuid,uuid,text,uuid,jsonb,text,jsonb) from public,anon,authenticated;
grant execute on function public.st_v6_recording_command(uuid,uuid,text,uuid,jsonb,text,jsonb) to service_role;

commit;
