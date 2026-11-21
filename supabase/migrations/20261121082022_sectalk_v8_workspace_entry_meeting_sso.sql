begin;

create or replace function sectalk_private.st_v8_schedule_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v8_entry_sso_allows(p_workspace) and not exists(select 1 from sectalk_private.st_v8_workspace_schedule_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;

create or replace function sectalk_private.st_v8_meeting_schedule_sso_allows(p_meeting uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce((select sectalk_private.st_v8_entry_sso_allows(m.workspace_id)
    and (m.room_id is not null or sectalk_private.st_v8_schedule_sso_allows(m.workspace_id))
    from public.st_v3_meetings m where m.id=p_meeting),false);
$$;

-- Standalone schedule settings keep their original room-call exception.
-- Entry, when enabled, also applies to room-call metadata and admission.
alter policy st_v8_schedule_sso on public.st_v3_meetings
  using(sectalk_private.st_v8_entry_sso_allows(workspace_id)
    and (room_id is not null or sectalk_private.st_v8_schedule_sso_allows(workspace_id)));

create or replace function public.st_v6_room_calls(p_room uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare target public.st_v6_rooms;
declare actor uuid:=auth.uid();
begin
  select * into target from public.st_v6_rooms r where r.id=p_room;
  if not found or not sectalk_private.st_v8_entry_sso_allows(target.workspace_id)
    or sectalk_private.st_v6_room_role(p_room,actor) is null or target.archived then return null; end if;
  return jsonb_build_object('can_start',not target.locked and
    sectalk_private.st_v6_room_call_may_host(p_room,target.workspace_id,actor),'calls',coalesce((
      select jsonb_agg(jsonb_build_object('id',m.id,'title',m.title,'starts_at',m.starts_at,
        'live',m.status='live' and m.ends_at>now(),
        'roster',case when m.status='live' and m.ends_at>now() then coalesce((
          select jsonb_agg(r.name order by r.host desc,r.name) from (
            select pr.name,a.user_id=m.host_id as host from public.st_v3_attendance a
            join public.st_profiles pr on pr.id=a.user_id where a.meeting_id=m.id and a.status='admitted'
              and sectalk_private.st_v3_meeting_visible(m.id,a.user_id) and sectalk_private.open_pair(actor,a.user_id)
            order by (a.user_id=m.host_id) desc,a.admitted_at,a.user_id limit 12
          ) r
        ),'[]'::jsonb) else '[]'::jsonb end,
        'your_status',(select a.status from public.st_v3_attendance a where a.meeting_id=m.id and a.user_id=actor))
        order by m.starts_at desc,m.id)
      from (select * from public.st_v3_meetings call where call.room_id=p_room and call.workspace_id=target.workspace_id
        and sectalk_private.st_v3_meeting_visible(call.id,actor) and sectalk_private.open_pair(actor,call.host_id)
        order by call.starts_at desc,call.id limit 20) m
    ),'[]'::jsonb));
end
$$;

create or replace function sectalk_private.st_v6_room_call_may_host(p_room uuid,p_workspace uuid,p_actor uuid)
returns boolean language sql stable set search_path='' as $$
  select (p_actor is distinct from auth.uid() or sectalk_private.st_v8_entry_sso_allows(p_workspace))
    and coalesce((case sectalk_private.st_v6_room_role_rule(p_room,p_actor,'start_call')
    when 'deny' then false
    when 'allow' then sectalk_private.st_v6_room_role(p_room,p_actor) in ('owner','moderator','member')
    else sectalk_private.st_v2_role(p_workspace,p_actor) in ('owner','admin')
      and sectalk_private.st_v6_room_role(p_room,p_actor) in ('owner','moderator')
  end),false)
$$;

create or replace function public.st_v8_workspace_member_media_allowed(p_meeting uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce((select case when not sectalk_private.st_v8_entry_sso_allows(m.workspace_id) then false
      when p.workspace is null then true
      else sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) end
    from public.st_v3_meetings m left join sectalk_private.st_v8_workspace_member_media_sso p on p.workspace=m.workspace_id
    where m.id=p_meeting and auth.uid() is not null
      and sectalk_private.st_v2_active(auth.uid())
      and sectalk_private.st_v3_meeting_visible(m.id,auth.uid())),false);
$$;

create or replace function public.st_v8_livekit_bound_admission(p_kind text,p_room uuid,p_actor uuid,p_generation integer,p_binding uuid)
returns boolean language sql stable security definer set search_path='' as $$
  with policy as (
    select workspace,protocol,provider from sectalk_private.st_v8_workspace_member_media_sso
    union all
    select workspace,protocol,provider from sectalk_private.st_v8_workspace_entry_sso
  )
  select coalesce(public.st_v8_livekit_signal_admission(p_kind,p_room,p_actor,p_generation),false)
    and case
      when p_kind in ('group','network') then p_binding is null
      when p_binding is not null then exists(
        select 1 from sectalk_private.st_v8_livekit_member_binding b
        join auth.sessions s on (s.id,s.user_id)=(b.native_session,b.actor)
        join public.st_v3_meetings m on m.id=b.meeting
        where (b.id,b.meeting,b.actor,b.kind)=(p_binding,p_room,p_actor,p_kind)
          and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
          and (p_kind<>'protected' or exists(select 1 from sectalk_private.st_v6_protected_meeting_endpoint d
            where (d.meeting,d.actor,d.session_id)=(b.meeting,b.actor,b.native_session::text) and d.verified))
          and not exists(select 1 from policy p
            where p.workspace=m.workspace_id and not exists(
              select 1 from sectalk_private.st_v7_workspace_sso_sessions r
              join sectalk_private.st_v7_workspace_sso c on c.workspace=r.workspace
              where (r.workspace,r.principal,r.session,r.protocol,r.provider)=(p.workspace,b.actor,b.native_session,p.protocol,p.provider)
                and (c.protocol,c.provider)=(p.protocol,p.provider)
                and sectalk_private.st_v7_workspace_sso_provider(c.workspace,c.domain,c.protocol)=c.provider)))
      when p_kind in ('managed','protected') then
        -- Pre-update credentials may finish reconnecting while the policy is open.
        -- Managed guest links are an independent authorized attendance path.
        not exists(select 1 from public.st_v3_meetings m
          join policy p on p.workspace=m.workspace_id where m.id=p_room)
        or (p_kind='managed' and exists(select 1 from sectalk_private.st_v6_guest_visit v
          join sectalk_private.st_v6_guest_link l on l.id=v.link and l.meeting=p_room
          join sectalk_private.st_v6_guest_policy g on g.meeting=l.meeting and g.enabled
          where v.id=p_actor and v.state='approved' and l.revoked_at is null and l.expires_at>statement_timestamp()))
      else false end;
$$;

create or replace function public.st_v3_meeting_state(p_meeting uuid,p_state text)
returns void language plpgsql security definer set search_path='' as $$
declare m public.st_v3_meetings; actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v3_meeting_state',20);
  select * into m from public.st_v3_meetings where id=p_meeting for update;
  if not found or not sectalk_private.st_v2_active(actor)
    or not coalesce((
      sectalk_private.st_v3_is_host(p_meeting,actor)
      or (p_state='ended' and m.host_id=actor and m.room_id is not null
        and not sectalk_private.st_v8_entry_sso_allows(m.workspace_id)
        and not exists(select 1 from public.st_v6_rooms r
          join sectalk_private.st_v8_workspace_standard_room_sso p on p.workspace=r.workspace_id
          where r.id=m.room_id and r.encryption_mode='standard'
            and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true)
        and ((sectalk_private.st_v2_role(m.workspace_id,actor) in ('owner','admin')
                and sectalk_private.st_v8_room_membership_role(m.room_id,actor) in ('owner','moderator'))
             or (m.room_host_grant is not null
                and m.room_host_grant=sectalk_private.st_v8_room_membership_role(m.room_id,actor))))
    ),false)
    then raise exception 'Meeting action unavailable'; end if;
  if p_state is null or p_state not in ('live','ended') then raise exception 'Invalid meeting state'; end if;
  if p_state='live' and not sectalk_private.st_v8_meeting_schedule_sso_allows(p_meeting) then
    raise exception 'Sign in through your workspace provider to open the meeting lobby' using errcode='42501';
  end if;
  if p_state=m.status then return; end if;
  if p_state='live' and (m.status<>'scheduled' or m.starts_at>now()+interval '15 minutes' or now()>=m.ends_at) then
    raise exception 'A meeting can start up to 15 minutes before it is scheduled'; end if;
  update public.st_v3_meetings set status=p_state where id=p_meeting;
  if p_state='live' then
    insert into public.st_v3_attendance(meeting_id,user_id,status,admitted_at) values(p_meeting,actor,'admitted',clock_timestamp())
      on conflict(meeting_id,user_id) do update set status='admitted',admitted_at=clock_timestamp(),left_at=null;
  else
    update public.st_v3_attendance set status='left',left_at=clock_timestamp() where meeting_id=p_meeting and status in ('admitted','waiting');
  end if;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(m.workspace_id,actor,'meeting.'||p_state,p_meeting);
end $$;

commit;
