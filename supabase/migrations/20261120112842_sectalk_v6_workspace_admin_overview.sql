begin;

create function public.st_v6_workspace_admin_overview(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare workspace_owner uuid;
declare plan text;
declare seat_limit integer;
declare occupied integer;
declare enabled integer;
declare pending_invites integer;
declare expiring_links integer;
declare access_requests integer;
declare contributors integer;
declare since timestamptz:=now()-interval '168 hours';
begin
  if not coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    or sectalk_private.st_v2_active(auth.uid()) is not true
  then raise exception 'Workspace overview is unavailable' using errcode='42501'; end if;
  select w.owner into workspace_owner from public.st_v2_workspaces w where w.id=p_workspace;
  plan:=sectalk_private.st_v2_effective_plan(workspace_owner);
  seat_limit:=case plan when 'basic' then 12 when 'professional' then 30
    when 'business' then 100 when 'enterprise' then 500 else 5 end;
  select count(*),count(*) filter(where m.suspended_at is null) into occupied,enabled
  from public.st_v2_members m where m.workspace_id=p_workspace;

  select (select count(*) from public.st_v2_invites i where i.workspace_id=p_workspace and i.status='pending')
      + count(*),
    count(*) filter(where i.expires_at<=now()+interval '24 hours')
  into pending_invites,expiring_links
  from sectalk_private.st_v6_workspace_link_invites i
  where i.workspace_id=p_workspace and i.consumed_at is null and i.expires_at>now();
  select count(*) into access_requests
  from public.st_v6_room_entries e join public.st_v6_rooms r on r.id=e.room_id
  where r.workspace_id=p_workspace and not r.archived and e.kind='request' and e.expires_at>now()
    and sectalk_private.st_v6_room_role(r.id) in ('owner','moderator');

  if enabled>=5 then
    select count(*) into contributors from public.st_v2_members m
    where m.workspace_id=p_workspace and m.suspended_at is null and (
      exists(select 1 from public.st_v6_room_posts p join public.st_v6_rooms r on r.id=p.room_id
        where r.workspace_id=p_workspace and r.kind in ('public','announcement','broadcast')
          and not r.archived and p.sender=m.user_id and p.removed_at is null and p.created_at>=since)
      or exists(select 1 from public.st_v2_posts p join public.st_v2_channels c on c.id=p.channel_id
        where c.workspace_id=p_workspace and c.visibility='workspace' and not c.archived
          and p.sender=m.user_id and p.created_at>=since)
    );
    if contributors<3 then contributors:=null; end if;
  end if;
  return jsonb_build_object('plan',plan,'seat_limit',seat_limit,'occupied',occupied,'active',enabled,
    'pending_invites',pending_invites,'expiring_links',expiring_links,'access_requests',access_requests,
    'contributors',contributors,'activity_window_hours',168);
end $$;

revoke all on function public.st_v6_workspace_admin_overview(uuid) from public,anon,authenticated;
grant execute on function public.st_v6_workspace_admin_overview(uuid) to authenticated;

commit;
