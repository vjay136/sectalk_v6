begin;

-- LiveKit copies participant attributes into refreshed grants. The reference
-- is random and carries no native session ID or authentication credential.
create table sectalk_private.st_v8_livekit_member_binding (
  id uuid primary key default gen_random_uuid(),
  meeting uuid not null references public.st_v3_meetings on delete cascade,
  actor uuid not null references auth.users on delete cascade,
  native_session uuid not null references auth.sessions on delete cascade,
  kind text not null check(kind in ('managed','protected')),
  unique(meeting,actor,native_session,kind)
);
create index st_v8_livekit_member_binding_session on sectalk_private.st_v8_livekit_member_binding(native_session);
alter table sectalk_private.st_v8_livekit_member_binding enable row level security;
revoke all on sectalk_private.st_v8_livekit_member_binding from public,anon,authenticated,service_role;

create function public.st_v8_livekit_bind_member(p_meeting uuid,p_kind text)
returns uuid language plpgsql security definer set search_path='' as $$
declare
  actor_id uuid:=auth.uid(); bound_session uuid; binding_id uuid;
begin
  if not coalesce(public.st_v7_current_session_valid(),false)
    or p_kind is null or p_kind not in ('managed','protected')
    or not coalesce(public.st_v8_workspace_member_media_allowed(p_meeting),false)
    or not coalesce(public.st_v8_livekit_signal_admission(p_kind,p_meeting,actor_id,null),false)
  then return null; end if;
  bound_session:=(auth.jwt()->>'session_id')::uuid;
  if p_kind='protected' and not exists(select 1 from sectalk_private.st_v6_protected_meeting_endpoint d
    where (d.meeting,d.actor,d.session_id)=(p_meeting,actor_id,bound_session::text) and d.verified)
  then return null; end if;
  insert into sectalk_private.st_v8_livekit_member_binding(meeting,actor,native_session,kind)
    values(p_meeting,actor_id,bound_session,p_kind)
    on conflict(meeting,actor,native_session,kind) do nothing returning id into binding_id;
  if binding_id is null then
    select b.id into binding_id from sectalk_private.st_v8_livekit_member_binding b
      where (b.meeting,b.actor,b.native_session,b.kind)=(p_meeting,actor_id,bound_session,p_kind);
  end if;
  return binding_id;
end $$;

create function public.st_v8_livekit_bound_admission(p_kind text,p_room uuid,p_actor uuid,p_generation integer,p_binding uuid)
returns boolean language sql stable security definer set search_path='' as $$
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
          and not exists(select 1 from sectalk_private.st_v8_workspace_member_media_sso p
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
          join sectalk_private.st_v8_workspace_member_media_sso p on p.workspace=m.workspace_id where m.id=p_room)
        or (p_kind='managed' and exists(select 1 from sectalk_private.st_v6_guest_visit v
          join sectalk_private.st_v6_guest_link l on l.id=v.link and l.meeting=p_room
          join sectalk_private.st_v6_guest_policy g on g.meeting=l.meeting and g.enabled
          where v.id=p_actor and v.state='approved' and l.revoked_at is null and l.expires_at>statement_timestamp()))
      else false end;
$$;

revoke all on function public.st_v8_livekit_bind_member(uuid,text),
  public.st_v8_livekit_bound_admission(text,uuid,uuid,integer,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_livekit_bind_member(uuid,text) to authenticated;
grant execute on function public.st_v8_livekit_bound_admission(text,uuid,uuid,integer,uuid) to service_role;
notify pgrst,'reload schema';
commit;
