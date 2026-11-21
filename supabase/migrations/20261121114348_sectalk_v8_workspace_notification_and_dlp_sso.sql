begin;

create or replace function sectalk_private.st_v6_workspace_notification_settings(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare p sectalk_private.st_v6_workspace_notification_policy;
begin
  if not sectalk_private.st_v2_active(auth.uid())
    or sectalk_private.st_v2_role(p_workspace,auth.uid()) is null
    or not sectalk_private.st_v8_entry_sso_allows(p_workspace) then
    raise exception 'Workspace notification policy unavailable' using errcode='42501';
  end if;
  select * into p from sectalk_private.st_v6_workspace_notification_policy where workspace_id=p_workspace;
  return jsonb_build_object('mandatory_categories',coalesce(p.mandatory_categories,'{}'),
    'max_quiet_minutes',p.max_quiet_minutes);
end
$$;

create or replace function public.st_v6_workspace_presence_policy(p_workspace uuid)
returns boolean language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_v2_active(auth.uid())
    or sectalk_private.st_v2_role(p_workspace,auth.uid()) is null
    or not sectalk_private.st_v8_entry_sso_allows(p_workspace) then
    raise exception 'Workspace presence policy unavailable' using errcode='42501';
  end if;
  return exists(select 1 from sectalk_private.st_v6_workspace_presence_policy where workspace_id=p_workspace);
end $$;

create or replace function public.st_v6_set_workspace_presence_policy(p_workspace uuid,p_required boolean)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_workspace_presence_policy',10);
  if not sectalk_private.st_v2_active(actor) or p_required is null
    or coalesce(sectalk_private.st_v2_role(p_workspace,actor),'') not in ('owner','admin') then
    raise exception 'Workspace presence policy unavailable' using errcode='42501';
  end if;
  perform 1 from public.st_v2_workspaces w where w.id=p_workspace for update;
  if not found or not sectalk_private.st_v2_active(actor)
    or coalesce(sectalk_private.st_v2_role(p_workspace,actor),'') not in ('owner','admin') then
    raise insufficient_privilege;
  end if;
  perform sectalk_private.st_v8_assert_workspace_policy_sso(p_workspace);
  if p_required then
    insert into sectalk_private.st_v6_workspace_presence_policy(workspace_id) values(p_workspace)
      on conflict do nothing;
  else
    delete from sectalk_private.st_v6_workspace_presence_policy where workspace_id=p_workspace;
  end if;
  if not found then return; end if;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor,case when p_required then 'workspace.presence_required'
      else 'workspace.presence_member_choice' end,p_workspace);
  perform realtime.send('{}'::jsonb,'presence','st:account:'||m.user_id,true)
    from public.st_v2_members m where m.workspace_id=p_workspace and m.suspended_at is null;
end $$;

create or replace function public.st_v7_workspace_dlp(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare access text:=sectalk_private.st_v6_holds_access(p_workspace);
begin
  if access='none' then raise exception 'Workspace data loss controls are unavailable' using errcode='42501'; end if;
  if not sectalk_private.st_v8_policy_admin_sso_allows(p_workspace) then return '{"access":"sso"}'::jsonb; end if;
  if access<>'verified' or not coalesce(sectalk_private.st_v7_admin_fresh(),false) then return jsonb_build_object('access','mfa'); end if;
  return jsonb_build_object('access','verified','revision',coalesce((select p.revision from sectalk_private.st_v7_workspace_dlp p
    where p.workspace_id=p_workspace),0),'rules',coalesce((select p.rules from sectalk_private.st_v7_workspace_dlp p
    where p.workspace_id=p_workspace),'{"pii":"allow","phi":"allow","payment_card":"allow","credential":"allow"}'::jsonb));
end $$;

notify pgrst,'reload schema';
commit;
