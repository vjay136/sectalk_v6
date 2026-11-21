begin;

create function public.st_v8_meeting_artifact_viewer()
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('actor',s.user_id,'session',s.id)
  from auth.sessions s where s.user_id=auth.uid() and s.id::text=auth.jwt()->>'session_id'
    and public.st_v7_current_session_valid() and sectalk_private.st_v2_active(s.user_id);
$$;

create function sectalk_private.st_v8_meeting_artifact_app_allowed(
  p_meeting uuid,p_actor uuid,p_session uuid,p_safety boolean
)
returns boolean language sql stable set search_path='' as $$
  select sectalk_private.st_v2_active(p_actor) and exists(
    select 1 from auth.sessions s where (s.id,s.user_id)=(p_session,p_actor)
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
  ) and exists(select 1 from public.st_v3_meetings m where m.id=p_meeting
    and (p_safety or not exists(select 1 from sectalk_private.st_v8_workspace_entry_sso policy
      where policy.workspace=m.workspace_id and not exists(
        select 1 from sectalk_private.st_v7_workspace_sso_sessions receipt
        join sectalk_private.st_v7_workspace_sso setup on setup.workspace=receipt.workspace
        where receipt.workspace=policy.workspace and (receipt.principal,receipt.session)=(p_actor,p_session)
          and (receipt.protocol,receipt.provider)=(policy.protocol,policy.provider)
          and (setup.protocol,setup.provider)=(policy.protocol,policy.provider)
          and sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol)=setup.provider
      ))));
$$;

-- Service workers use their original command. Only user-originated commands
-- can use the native actor/session handoff and the narrowly scoped safety path.
create function public.st_v8_app_recording_command(p_meeting uuid,p_actor uuid,p_session uuid,p_action text,
  p_recording uuid default null,p_roster jsonb default null,p_capture jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
begin
  if p_action is null or p_action not in ('view','download','request','accept','start','stop','withdraw')
    or sectalk_private.st_v8_meeting_artifact_app_allowed(p_meeting,p_actor,p_session,p_action in ('stop','withdraw')) is not true
  then return null; end if;
  return public.st_v6_recording_command(p_meeting,p_actor,p_action,p_recording,p_roster,null,p_capture);
end $$;

create function public.st_v8_app_meeting_summary_command(p_meeting uuid,p_actor uuid,p_session uuid,p_action text,
  p_enabled boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare result jsonb;
begin
  if p_action is null or p_action not in ('view','policy','opt-in','withdraw','source')
    or sectalk_private.st_v8_meeting_artifact_app_allowed(p_meeting,p_actor,p_session,p_action='withdraw') is not true
  then return null; end if;
  result:=public.st_v6_meeting_summary_command(p_meeting,p_actor,p_action,p_enabled);
  if result is not null and p_action='withdraw'
    and not sectalk_private.st_v8_meeting_artifact_app_allowed(p_meeting,p_actor,p_session,false)
  then return '{"withdrawn":true}'; end if;
  return result;
end $$;

create or replace function public.st_v6_set_recording_policy(p_workspace uuid,p_enabled boolean)
returns void language plpgsql security definer set search_path='' as $$
begin
  if p_enabled is null or not sectalk_private.st_v2_active(auth.uid()) or
      sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner' then
    raise exception 'Workspace owner required' using errcode='42501';
  end if;
  if p_enabled then
    perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
    if not found or sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner'
      or not sectalk_private.st_v8_entry_sso_allows(p_workspace) then
      raise exception 'Sign in through your workspace provider to enable recording' using errcode='42501';
    end if;
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

revoke all on function public.st_v8_meeting_artifact_viewer(),
  sectalk_private.st_v8_meeting_artifact_app_allowed(uuid,uuid,uuid,boolean),
  public.st_v8_app_recording_command(uuid,uuid,uuid,text,uuid,jsonb,jsonb),
  public.st_v8_app_meeting_summary_command(uuid,uuid,uuid,text,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_meeting_artifact_viewer() to authenticated;
grant execute on function public.st_v8_app_recording_command(uuid,uuid,uuid,text,uuid,jsonb,jsonb),
  public.st_v8_app_meeting_summary_command(uuid,uuid,uuid,text,boolean) to service_role;

commit;
