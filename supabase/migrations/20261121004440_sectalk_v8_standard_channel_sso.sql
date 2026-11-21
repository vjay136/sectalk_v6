begin;

create table sectalk_private.st_v8_workspace_standard_channel_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_standard_channel_sso enable row level security;
revoke all on sectalk_private.st_v8_workspace_standard_channel_sso from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_standard_channel_session_allowed(p_channel uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce((select sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is true
    from public.st_v2_channels c join sectalk_private.st_v8_workspace_standard_channel_sso p on p.workspace=c.workspace_id
    where c.id=p_channel and c.encryption_mode='standard'),true);
$$;
revoke all on function sectalk_private.st_v8_standard_channel_session_allowed(uuid) from public,anon,authenticated,service_role;

-- RLS and invoker Search pass the JWT's subject as u. The same receipt check
-- covers new reports. Internal actor checks under service-only credentials remain
-- an independent authorization path for preservation and reviewed exports.
create or replace function sectalk_private.st_v2_post_read(c uuid,s uuid,u uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v6_channel_content_access(c,u)
    and (u is distinct from auth.uid() or sectalk_private.st_v8_standard_channel_session_allowed(c))
    and not exists(select 1 from public.st_blocks where (actor,target) in ((u,s),(s,u)));
$$;

create or replace function sectalk_private.st_v2_post(p_channel uuid,p_id uuid,p_body text)
returns void language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); is_archived boolean; space uuid;
begin
  perform sectalk_private.limit_action('v2_post',60);
  select archived,workspace_id into is_archived,space from public.st_v2_channels where id=p_channel for update;
  if not found or is_archived or not sectalk_private.st_v6_channel_content_access(p_channel,me)
    then raise exception 'Channel unavailable'; end if;
  perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-standard-channel-sso:'||space::text,0));
  if not sectalk_private.st_v8_standard_channel_session_allowed(p_channel) then
    raise exception 'Workspace single sign-on is required for these channel messages' using errcode='42501';
  end if;
  if exists(select 1 from public.st_v2_posts where id=p_id and channel_id=p_channel and sender=me
    and (body=btrim(p_body) or sectalk_private.st_v7_dlp_is_retry('channel',p_channel,p_id,me,p_body))) then return; end if;
  insert into public.st_v2_posts(id,channel_id,sender,body) values(p_id,p_channel,me,btrim(p_body)) on conflict(id) do nothing;
  if not found then raise exception 'Message ID already in use'; end if;
end $$;

create or replace function sectalk_private.st_v6_channel_details(p_channel uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare member_access boolean:=sectalk_private.st_v6_channel_content_access(p_channel,auth.uid());
  can_manage boolean:=sectalk_private.st_v6_channel_can_manage(p_channel,auth.uid());
  details jsonb;
begin
  details:=jsonb_build_object('can_read',member_access,'can_manage',can_manage);
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

create function public.st_v8_workspace_standard_channel_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_standard_channel_sso_policy',5);
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
      raise insufficient_privilege;
    end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-standard-channel-sso:'||p_workspace::text,0));
    if p_require then
      select * into setup from sectalk_private.st_v7_workspace_sso c where c.workspace=p_workspace;
      if not found or sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol)
        is distinct from setup.provider or not exists(
          select 1 from sectalk_private.st_v7_workspace_sso_sessions r join auth.sessions s on s.id=r.session and s.user_id=r.principal
          where r.workspace=p_workspace and r.protocol=setup.protocol and r.provider=setup.provider
            and sectalk_private.st_v2_active(r.principal) and sectalk_private.st_v2_role(p_workspace,r.principal) is not null
            and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
        ) then return '{"access":"verified","error":"verified_provider_session_required"}'; end if;
      insert into sectalk_private.st_v8_workspace_standard_channel_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_standard_channel_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.standard_channel_sso_required'
          else 'workspace.standard_channel_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_standard_channel_sso p where p.workspace=p_workspace));
end $$;
revoke all on function public.st_v8_workspace_standard_channel_policy(uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_standard_channel_policy(uuid,boolean) to authenticated;

commit;
