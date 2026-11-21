begin;

alter function public.st_v6_moderate_meeting(uuid,text,uuid,boolean) set schema sectalk_private;
revoke all on function sectalk_private.st_v6_moderate_meeting(uuid,text,uuid,boolean)
  from public,anon,authenticated,service_role;

create function public.st_v6_moderate_meeting(p_meeting uuid,p_action text,p_target uuid,p_enabled boolean)
returns uuid[] language plpgsql security definer set search_path='' as $$
begin
  -- Preserve the existing teardown path for a host after the provider disconnects.
  if p_action is distinct from 'end' then
    perform 1 from public.st_v3_meetings m join public.st_v2_workspaces w on w.id=m.workspace_id
      where m.id=p_meeting and sectalk_private.st_v2_role(w.id,auth.uid()) is not null
      for key share of w;
    if not found or not sectalk_private.st_v8_meeting_schedule_sso_allows(p_meeting) then
      raise exception 'Meeting moderation is unavailable' using errcode='42501';
    end if;
  end if;

  return sectalk_private.st_v6_moderate_meeting(p_meeting,p_action,p_target,p_enabled);
end $$;

revoke all on function public.st_v6_moderate_meeting(uuid,text,uuid,boolean)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_moderate_meeting(uuid,text,uuid,boolean) to authenticated;
notify pgrst,'reload schema';
commit;
