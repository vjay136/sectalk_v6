begin;

create function sectalk_private.st_v8_conversation_alert_providers(
  p_workspace uuid,p_room boolean,p_mode text,p_task boolean
) returns jsonb language sql stable set search_path='' as $$
  select coalesce(jsonb_agg(distinct jsonb_build_array(p.protocol,p.provider)),'[]')
  from (
    select protocol,provider from sectalk_private.st_v8_workspace_entry_sso where workspace=p_workspace
    union all select protocol,provider from sectalk_private.st_v8_workspace_planner_sso
      where workspace=p_workspace and p_room and p_task
    union all select protocol,provider from sectalk_private.st_v8_workspace_room_structure_sso
      where workspace=p_workspace and p_room
    union all select protocol,provider from sectalk_private.st_v8_workspace_channel_structure_sso
      where workspace=p_workspace and not p_room
    union all select protocol,provider from sectalk_private.st_v8_workspace_standard_room_sso
      where workspace=p_workspace and p_room and p_mode='standard'
    union all select protocol,provider from sectalk_private.st_v8_workspace_standard_channel_sso
      where workspace=p_workspace and not p_room and p_mode='standard'
    union all select protocol,provider from sectalk_private.st_v8_workspace_managed_content_sso
      where workspace=p_workspace and p_mode='managed'
  ) p;
$$;
revoke all on function sectalk_private.st_v8_conversation_alert_providers(uuid,boolean,text,boolean)
  from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v8_send_conversation_activity(
  p_room uuid,p_channel uuid,p_recipient uuid,p_event text,p_payload jsonb
) returns void language plpgsql set search_path='' as $$
declare
  space uuid;
  mode text;
  required_providers jsonb;
begin
  if num_nonnulls(p_room,p_channel)<>1 or p_recipient is null then return; end if;
  if p_room is not null then
    select r.workspace_id,r.encryption_mode into space,mode from public.st_v6_rooms r where r.id=p_room;
  else
    select c.workspace_id,c.encryption_mode into space,mode from public.st_v2_channels c where c.id=p_channel;
  end if;
  if space is null then return; end if;

  required_providers:=sectalk_private.st_v8_conversation_alert_providers(space,p_room is not null,mode,
    p_event='category_alert' and p_payload->>'kind' in ('task.due','task.completed'));

  if required_providers='[]'::jsonb then
    perform realtime.send(p_payload,p_event,'st:account:'||p_recipient,true);
    return;
  end if;

  perform realtime.send(p_payload,p_event,'st:workspace-session:'||p_recipient||':'||s.id,true)
  from sectalk_private.st_v7_workspace_sso_sessions receipt
  join sectalk_private.st_v7_workspace_sso setup on (setup.workspace,setup.protocol,setup.provider)=
    (receipt.workspace,receipt.protocol,receipt.provider)
  join auth.sessions s on (s.id,s.user_id)=(receipt.session,receipt.principal)
  where (receipt.workspace,receipt.principal)=(space,p_recipient)
    and required_providers=jsonb_build_array(jsonb_build_array(receipt.protocol,receipt.provider))
    and sectalk_private.st_v7_workspace_sso_provider(space,setup.domain,setup.protocol)=setup.provider
    and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp();
end $$;

create or replace function sectalk_private.st_v6_web_push_allowed(
  p_actor uuid,p_kind text,p_room uuid,p_chat uuid,p_call uuid
)
returns boolean language plpgsql stable set search_path='' as $$
declare category text; space uuid; mode text; quiet boolean;
begin
  if p_kind='security.account' then return true; end if;
  if not sectalk_private.st_v2_active(p_actor) then return false; end if;
  if p_kind in ('dm.message','call.incoming') then
    category:=split_part(p_kind,'.',1);
  else
    select a.category into category from sectalk_private.st_v6_alert_priority(p_kind) a;
  end if;
  if category is null then return false; end if;
  if p_call is not null and not exists(select 1 from public.st_calls c
    where c.id=p_call and c.chat_id=p_chat and c.callee=p_actor and c.status='ringing' and c.expires_at>now()) then
    return false;
  end if;
  if p_room is not null then
    select r.workspace_id,r.encryption_mode into space,mode from public.st_v6_rooms r
    where r.id=p_room and not r.archived and sectalk_private.st_v6_task_audience(r.id,null,p_actor);
    if not found then return false; end if;
    -- Providers receive no alert for rooms that require a current native workspace session.
    if sectalk_private.st_v8_conversation_alert_providers(space,true,mode,category='task')<>'[]'::jsonb then
      return false;
    end if;
    if category=any(sectalk_private.st_v6_mandatory_workspace_alerts(space)) then return true; end if;
    quiet:=sectalk_private.st_v6_room_alert_quiet(p_actor,p_room);
  elsif p_chat is not null then
    if not sectalk_private.st_v2_chat_write(p_chat,p_actor) then return false; end if;
    quiet:=sectalk_private.st_v6_quiet_for(p_actor,p_chat);
  else
    quiet:=sectalk_private.st_v6_quiet_for(p_actor,null);
  end if;
  return not quiet and sectalk_private.st_v6_notification_enabled(p_actor,category);
end
$$;

commit;
