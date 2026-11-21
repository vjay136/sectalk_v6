begin;

create table sectalk_private.st_v8_workspace_channel_structure_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_channel_structure_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_channel_structure_sso from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_channel_structure_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_channel_structure_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_channel_structure_sso_allows(uuid) from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v8_channel_structure_sso_allows(uuid) to authenticated;

create function public.st_v8_workspace_channel_structure_requires_sso(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v2_active(auth.uid())
    and sectalk_private.st_v2_role(p_workspace,auth.uid()) is not null
    and not sectalk_private.st_v8_channel_structure_sso_allows(p_workspace);
$$;

create function public.st_v8_workspace_channel_structure_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_channel_structure_sso_policy',5);
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
      raise insufficient_privilege;
    end if;
    if p_require then
      select * into setup from sectalk_private.st_v7_workspace_sso c where c.workspace=p_workspace;
      if not found or sectalk_private.st_v7_workspace_sso_provider(p_workspace,setup.domain,setup.protocol)
        is distinct from setup.provider or not exists(
          select 1 from sectalk_private.st_v7_workspace_sso_sessions r join auth.sessions s on (s.id,s.user_id)=(r.session,r.principal)
          where r.workspace=p_workspace and (r.protocol,r.provider)=(setup.protocol,setup.provider)
            and sectalk_private.st_v2_active(r.principal) and sectalk_private.st_v2_role(p_workspace,r.principal) is not null
            and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
        ) then return '{"access":"verified","error":"verified_provider_session_required"}'; end if;
      insert into sectalk_private.st_v8_workspace_channel_structure_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_channel_structure_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.channel_structure_sso_required'
          else 'workspace.channel_structure_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_channel_structure_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_channel_structure_requires_sso(uuid),
  public.st_v8_workspace_channel_structure_policy(uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_channel_structure_requires_sso(uuid),
  public.st_v8_workspace_channel_structure_policy(uuid,boolean) to authenticated;

-- Keep current-caller channel structure separate from content, evidence and job capabilities.
create policy st_v8_channel_structure_sso on public.st_v2_channels as restrictive for select to authenticated
  using(sectalk_private.st_v8_channel_structure_sso_allows(workspace_id));

create or replace function public.st_v2_create_channel(p_workspace uuid,p_name text)
returns uuid language plpgsql security definer set search_path='' as $$
declare channel uuid;
begin
  perform sectalk_private.limit_action('v2_channel',10);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if not coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(auth.uid()) then raise exception 'Workspace action unavailable'; end if;
  if not sectalk_private.st_v8_channel_structure_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to create channels' using errcode='42501';
  end if;
  if (select count(*) from public.st_v2_channels where workspace_id=p_workspace)>=100 then raise exception 'Channel limit reached'; end if;
  insert into public.st_v2_channels(workspace_id,name) values(p_workspace,lower(btrim(p_name))) returning id into channel;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(p_workspace,auth.uid(),'channel.created',channel);
  return channel;
end $$;

create or replace function sectalk_private.st_v6_channel_details(p_channel uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare member_access boolean:=sectalk_private.st_v6_channel_content_access(p_channel,auth.uid());
  can_manage boolean:=sectalk_private.st_v6_channel_can_manage(p_channel,auth.uid());
  details jsonb;
begin
  details:=jsonb_build_object('can_read',member_access,'can_manage',can_manage);
  if (member_access or can_manage) and exists(select 1 from public.st_v2_channels c where c.id=p_channel
    and not sectalk_private.st_v8_channel_structure_sso_allows(c.workspace_id)) then
    return '{"can_read":false,"can_manage":false,"structure_sso_required":true}';
  end if;
  if member_access and not sectalk_private.st_v8_standard_channel_session_allowed(p_channel) then
    details:=details||'{"can_read":false,"sso_required":true}'::jsonb;
  end if;
  if not can_manage then return details; end if;
  return details||jsonb_build_object(
    'members',coalesce((select jsonb_agg(m.user_id order by m.user_id) from sectalk_private.st_v6_channel_members m
      where m.channel_id=p_channel),'[]'::jsonb),
    'audit',coalesce((select jsonb_agg(to_jsonb(a)-'channel_id' order by a.id desc) from (
      select * from sectalk_private.st_v6_channel_audit where channel_id=p_channel order by id desc limit 50) a),'[]'::jsonb));
end $$;

create or replace function sectalk_private.st_v6_manage_channel(p_channel uuid,p_action text,p_target uuid,p_visibility text)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); channel public.st_v2_channels; workspace uuid; audit_detail text;
begin
  if not sectalk_private.st_v6_channel_can_manage(p_channel,actor) then raise exception 'Channel management unavailable'; end if;
  perform sectalk_private.limit_action('v6_manage_channel',30);
  select workspace_id into workspace from public.st_v2_channels where id=p_channel;
  perform 1 from public.st_v2_workspaces w where w.id=workspace for share;
  if not found then raise exception 'Channel management unavailable'; end if;
  if not sectalk_private.st_v8_channel_structure_sso_allows(workspace) then
    raise exception 'Sign in through your workspace provider to manage channels' using errcode='42501';
  end if;
  if p_action in ('add_member','transfer_owner') then
    perform 1 from public.st_v2_members where workspace_id=workspace and user_id=p_target and suspended_at is null for share;
    if not found or not sectalk_private.st_v2_active(p_target) then raise exception 'Choose an active workspace member'; end if;
  end if;
  select * into channel from public.st_v2_channels where id=p_channel for update;
  if not found or channel.workspace_id is distinct from workspace or not sectalk_private.st_v6_channel_can_manage(p_channel,actor)
    or (channel.archived and p_action is distinct from 'restore' and p_action is distinct from 'archive') then
    raise exception 'Channel management unavailable';
  end if;
  if p_action in ('add_member','transfer_owner') and p_target=channel.owner then return; end if;
  case p_action
    when 'visibility' then
      if p_visibility is null or p_visibility not in ('workspace','private') then raise exception 'Choose a channel visibility'; end if;
      if channel.visibility=p_visibility then return; end if;
      update public.st_v2_channels set visibility=p_visibility where id=p_channel;
      audit_detail:=channel.visibility||' → '||p_visibility;
    when 'add_member' then
      insert into sectalk_private.st_v6_channel_members values(p_channel,p_target) on conflict do nothing;
      if not found then return; end if;
    when 'remove_member' then
      if p_target=channel.owner then raise exception 'Transfer ownership before removing the owner'; end if;
      delete from sectalk_private.st_v6_channel_members where channel_id=p_channel and user_id=p_target;
      if not found then return; end if;
    when 'transfer_owner' then
      if public.st_v7_sensitive_action_status('room_role')<>'verified' then
        raise exception 'Verify your current sign-in to transfer ownership' using errcode='42501';
      end if;
      update public.st_v2_channels set owner=p_target where id=p_channel;
      delete from sectalk_private.st_v6_channel_members where channel_id=p_channel and user_id=p_target;
      audit_detail:=channel.owner::text;
    when 'archive','restore' then
      if channel.archived=(p_action='archive') then return; end if;
      update public.st_v2_channels set archived=(p_action='archive') where id=p_channel;
    else raise exception 'Channel management unavailable';
  end case;
  insert into sectalk_private.st_v6_channel_audit(channel_id,actor,action,target,detail)
    values(p_channel,actor,p_action,case when p_action in ('add_member','remove_member','transfer_owner') then p_target end,audit_detail);
end $$;

commit;
