begin;
create function public.st_v8_livekit_signal_admission(p_kind text,p_room uuid,p_actor uuid,p_generation integer)
returns boolean language sql stable security definer set search_path='' as $$
  select case p_kind
    when 'network' then p_room=p_actor and sectalk_private.st_v2_active(p_actor)
    when 'group' then exists(select 1 from sectalk_private.st_v6_group_call g
      join sectalk_private.st_v6_group_member a on a.call_id=g.id and a.actor=p_actor
      where g.id=p_room and not g.ended and g.expires_at>now() and a.state='joined'
        and sectalk_private.st_v2_active(a.actor) and sectalk_private.st_v2_active(g.owner)
        and sectalk_private.open_pair(g.owner,a.actor)
        and g.topology in ('promoting','sfu','demoting') and p_generation=
          case when g.topology='promoting' then g.promotion else g.sfu_generation end)
    when 'managed' then exists(select 1 from public.st_v3_meetings m where m.id=p_room
      and m.media_protection=0 and m.status='live' and m.ends_at>now()
      and sectalk_private.st_v3_is_host(m.id,m.host_id) and sectalk_private.st_v2_active(m.host_id)
      and (exists(select 1 from public.st_v3_attendance a where a.meeting_id=m.id and a.user_id=p_actor
          and a.status='admitted' and a.removed_at is null and sectalk_private.st_v2_active(a.user_id)
          and sectalk_private.st_v3_meeting_visible(m.id,a.user_id) and sectalk_private.open_pair(m.host_id,a.user_id))
        or exists(select 1 from sectalk_private.st_v6_guest_visit v
          join sectalk_private.st_v6_guest_link l on l.id=v.link and l.meeting=m.id
          join sectalk_private.st_v6_guest_policy g on g.meeting=m.id and g.enabled
          where v.id=p_actor and v.state='approved' and l.revoked_at is null and l.expires_at>now())))
    when 'protected' then exists(select 1 from public.st_v3_meetings m
      join public.st_v3_attendance a on a.meeting_id=m.id and a.user_id=p_actor
      join sectalk_private.st_v6_protected_meeting e on e.meeting=m.id
      join sectalk_private.st_v6_protected_meeting_endpoint d on d.meeting=m.id and d.actor=p_actor
      where m.id=p_room and m.status='live' and m.ends_at>now() and m.media_protection=1 and m.meeting_locked
        and sectalk_private.st_v3_is_host(m.id,m.host_id) and sectalk_private.st_v2_active(m.host_id)
        and a.status='admitted' and a.removed_at is null and sectalk_private.st_v2_active(a.user_id)
        and sectalk_private.st_v3_meeting_visible(m.id,a.user_id) and sectalk_private.open_pair(m.host_id,a.user_id)
        and not e.closed and p_actor=any(e.roster) and d.verified
        and e.roster=(select array_agg(attendant.user_id order by attendant.user_id) from public.st_v3_attendance attendant
          where attendant.meeting_id=m.id and attendant.status='admitted')
        and not exists(select 1 from unnest(e.roster) actor(id) where not sectalk_private.st_v2_active(actor.id)
          or sectalk_private.st_v2_role(m.workspace_id,actor.id) is null or not sectalk_private.open_pair(m.host_id,actor.id)))
    else false end;
$$;
revoke all on function public.st_v8_livekit_signal_admission(text,uuid,uuid,integer) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_livekit_signal_admission(text,uuid,uuid,integer) to service_role;
commit;
