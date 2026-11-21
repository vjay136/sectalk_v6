begin;

create table sectalk_private.st_v8_workspace_managed_content_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_managed_content_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_managed_content_sso from public,anon,authenticated,service_role;

-- Service operations use the actor and native session on the verified ticket.
create function sectalk_private.st_v8_managed_content_session_allowed(p_workspace uuid,p_actor uuid,p_session text)
returns boolean language sql stable set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_managed_content_sso p
    where p.workspace=p_workspace and not exists(
      select 1 from sectalk_private.st_v7_workspace_sso_sessions receipt
      join sectalk_private.st_v7_workspace_sso setup on setup.workspace=receipt.workspace
      join auth.sessions s on (s.id,s.user_id)=(receipt.session,receipt.principal)
      where receipt.workspace=p.workspace and receipt.principal=p_actor and receipt.session::text=p_session
        and (receipt.protocol,receipt.provider)=(p.protocol,p.provider)
        and (setup.protocol,setup.provider)=(p.protocol,p.provider)
        and sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol)=setup.provider
        and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
    ));
$$;

create function public.st_v8_workspace_managed_content_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_managed_content_sso_policy',5);
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
      insert into sectalk_private.st_v8_workspace_managed_content_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_managed_content_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.managed_content_sso_required'
          else 'workspace.managed_content_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_managed_content_sso p where p.workspace=p_workspace));
end $$;

-- Keep the existing per-mode entitlement, DLP, retry and posting checks behind
-- the browser entry points. Gate ticket issuance before any duplicate check.
alter function public.st_v8_managed_channel_ticket(uuid,text,uuid,text) set schema sectalk_private;
alter function public.st_v8_managed_room_ticket(uuid,uuid,text) set schema sectalk_private;
alter function public.st_v8_managed_room_work(uuid,uuid,text,jsonb) set schema sectalk_private;
revoke all on function sectalk_private.st_v8_managed_channel_ticket(uuid,text,uuid,text),
  sectalk_private.st_v8_managed_room_ticket(uuid,uuid,text),sectalk_private.st_v8_managed_room_work(uuid,uuid,text,jsonb)
  from public,anon,authenticated,service_role;

create function public.st_v8_managed_channel_ticket(p_channel uuid,p_purpose text,p_post uuid default null,p_body text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
begin
  if not sectalk_private.st_v8_managed_content_session_allowed(
    (select c.workspace_id from public.st_v2_channels c where c.id=p_channel and c.encryption_mode='managed'),auth.uid(),auth.jwt()->>'session_id') then
    raise exception 'Managed channel unavailable' using errcode='42501';
  end if;
  return sectalk_private.st_v8_managed_channel_ticket(p_channel,p_purpose,p_post,p_body);
end $$;

create function public.st_v8_managed_room_ticket(p_room uuid,p_post uuid default null,p_body text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
begin
  if not sectalk_private.st_v8_managed_content_session_allowed(
    (select r.workspace_id from public.st_v6_rooms r where r.id=p_room and r.encryption_mode='managed'),auth.uid(),auth.jwt()->>'session_id') then
    raise exception 'Managed room unavailable' using errcode='42501';
  end if;
  return sectalk_private.st_v8_managed_room_ticket(p_room,p_post,p_body);
end $$;

create or replace function public.st_v8_managed_channel_still_readable(p_channel uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select public.st_v7_current_session_valid() and public.st_v7_account_under_lockdown() is false
    and sectalk_private.st_v2_active(auth.uid()) and sectalk_private.st_v6_channel_content_access(p_channel,auth.uid())
    and exists(select 1 from public.st_v2_channels c where c.id=p_channel and c.encryption_mode='managed'
      and sectalk_private.st_v8_managed_content_session_allowed(c.workspace_id,auth.uid(),auth.jwt()->>'session_id'));
$$;

create or replace function public.st_v8_managed_room_readable(p_room uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce(public.st_v7_current_session_valid() and public.st_v7_account_under_lockdown() is false
    and public.st_v7_login_risk_status()='clear' and exists(select 1 from public.st_v6_rooms r where r.id=p_room
      and sectalk_private.st_v8_managed_room_allowed(r,auth.uid(),false)
      and sectalk_private.st_v8_managed_content_session_allowed(r.workspace_id,auth.uid(),auth.jwt()->>'session_id')),false);
$$;

create or replace function sectalk_private.st_v8_channel_ticket_live(t sectalk_private.st_v8_channel_key_tickets)
returns boolean language sql stable set search_path='' as $$
  select t.id is not null and t.expires_at>statement_timestamp()
    and sectalk_private.st_v2_active(t.actor)
    and sectalk_private.st_v6_channel_content_access(t.channel,t.actor)
    and exists(select 1 from auth.sessions s where s.id=t.native_session and s.user_id=t.actor
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp())
    and exists(select 1 from public.st_v2_channels c where c.id=t.channel and c.encryption_mode='managed'
      and sectalk_private.st_v8_managed_content_session_allowed(c.workspace_id,t.actor,t.native_session::text));
$$;

create or replace function sectalk_private.st_v8_managed_report_live(t sectalk_private.st_v8_managed_report_tickets)
returns boolean language sql stable set search_path='' as $$
  select t.id is not null and t.expires_at>statement_timestamp() and sectalk_private.st_v2_active(t.actor)
    and not exists (select 1 from sectalk_private.st_v7_account_lockdowns l where l.user_id=t.actor and l.released_at is null)
    and exists(select 1 from auth.sessions s where s.id=t.native_session and s.user_id=t.actor
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp())
    and exists(select 1 from public.st_v2_channels c where c.id=t.channel and c.encryption_mode='managed'
      and sectalk_private.st_v8_managed_content_session_allowed(c.workspace_id,t.actor,t.native_session::text));
$$;

create function public.st_v8_managed_room_work(p_ticket uuid,p_actor uuid,p_action text,p_data jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare ticket_session uuid; workspace_id uuid;
begin
  select t.native_session,r.workspace_id into ticket_session,workspace_id
    from sectalk_private.st_v8_managed_room_tickets t join public.st_v6_rooms r on r.id=t.room
    where t.id=p_ticket and t.actor=p_actor and r.encryption_mode='managed';
  if not found or not sectalk_private.st_v8_managed_content_session_allowed(workspace_id,p_actor,ticket_session::text) then
    return null;
  end if;
  return sectalk_private.st_v8_managed_room_work(p_ticket,p_actor,p_action,p_data);
end $$;

revoke all on function sectalk_private.st_v8_managed_content_session_allowed(uuid,uuid,text),
  public.st_v8_workspace_managed_content_policy(uuid,boolean),
  public.st_v8_managed_channel_ticket(uuid,text,uuid,text),public.st_v8_managed_room_ticket(uuid,uuid,text),
  public.st_v8_managed_room_work(uuid,uuid,text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_managed_content_policy(uuid,boolean),
  public.st_v8_managed_channel_ticket(uuid,text,uuid,text),public.st_v8_managed_room_ticket(uuid,uuid,text) to authenticated;
grant execute on function public.st_v8_managed_room_work(uuid,uuid,text,jsonb) to service_role;
commit;
