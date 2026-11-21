begin;

create table sectalk_private.st_v8_workspace_file_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_file_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_file_sso from public,anon,authenticated,service_role;

-- The authenticated RPCs use the current native session for the file scope.
create function sectalk_private.st_v8_file_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_file_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_file_sso_allows(uuid) from public,anon,authenticated,service_role;

create function public.st_v8_workspace_file_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_file_sso_policy',5);
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
      insert into sectalk_private.st_v8_workspace_file_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_file_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.file_sso_required'
          else 'workspace.file_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_file_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_file_policy(uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_file_policy(uuid,boolean) to authenticated;

create function sectalk_private.st_v8_scoped_file_workspace(p_scope_type text,p_scope uuid)
returns uuid language sql stable set search_path='' as $$
  select case p_scope_type when 'workspace' then p_scope when 'room' then
    (select r.workspace_id from public.st_v6_rooms r where r.id=p_scope) end;
$$;
revoke all on function sectalk_private.st_v8_scoped_file_workspace(text,uuid) from public,anon,authenticated,service_role;

create function public.st_v8_scoped_file_context(p_scope_type text,p_scope uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid(); workspace uuid; native_session uuid;
begin
  workspace:=sectalk_private.st_v8_scoped_file_workspace(p_scope_type,p_scope);
  if workspace is null or not coalesce(public.st_v7_current_session_valid(),false)
    or public.st_v7_account_under_lockdown() or public.st_v7_login_risk_status()<>'clear'
    or sectalk_private.st_v2_active(actor) is not true
    or (p_scope_type='workspace' and sectalk_private.st_v2_role(workspace,actor) is null)
    or (p_scope_type='room' and sectalk_private.st_v6_room_role(p_scope,actor) is null) then
    return '{"access":"unavailable"}';
  end if;
  if not sectalk_private.st_v8_file_sso_allows(workspace) then return '{"access":"sso_required"}'; end if;
  select s.id into native_session from auth.sessions s where s.id::text=auth.jwt()->>'session_id' and s.user_id=actor;
  if native_session is null then return '{"access":"unavailable"}'; end if;
  return jsonb_build_object('access','allowed','session',native_session);
end $$;
revoke all on function public.st_v8_scoped_file_context(text,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_scoped_file_context(text,uuid) to authenticated;

-- Repeat the native session and receipt checks at each storage command,
-- including the final server-side check before returning bytes.
create function public.st_v8_scoped_file_command(p_scope_type text,p_scope uuid,p_actor uuid,p_session uuid,
  p_action text,p_id uuid,p_name text,p_bytes integer,p_hash text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare workspace_key uuid:=sectalk_private.st_v8_scoped_file_workspace(p_scope_type,p_scope);
begin
  if workspace_key is null or not exists(
    select 1 from auth.sessions s where (s.id,s.user_id)=(p_session,p_actor)
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
  ) then return null; end if;
  if exists(select 1 from sectalk_private.st_v8_workspace_file_sso policy where policy.workspace=workspace_key
    and not exists(
      select 1 from sectalk_private.st_v7_workspace_sso_sessions receipt
      join sectalk_private.st_v7_workspace_sso setup on setup.workspace=receipt.workspace
      where receipt.workspace=policy.workspace and receipt.principal=p_actor and receipt.session=p_session
        and (receipt.protocol,receipt.provider)=(policy.protocol,policy.provider)
        and (setup.protocol,setup.provider)=(policy.protocol,policy.provider)
        and sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol)=setup.provider
    )) then return null; end if;
  if p_scope_type='room' then
    return public.st_v6_room_file_command(p_scope,p_actor,p_action,p_id,p_name,p_bytes,p_hash);
  elsif p_action in ('view','download','share') then
    return public.st_v6_record_workspace_file_access(p_scope,p_id,p_actor,p_action);
  end if;
  return public.st_v6_workspace_file_command(p_scope,p_actor,p_action,p_id,p_name,p_bytes,p_hash);
end $$;
revoke all on function public.st_v8_scoped_file_command(text,uuid,uuid,uuid,text,uuid,text,integer,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_scoped_file_command(text,uuid,uuid,uuid,text,uuid,text,integer,text) to service_role;

create or replace function public.st_v7_explain_file_egress(p_scope_type text,p_scope uuid,p_file uuid,p_operation text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare baseline jsonb;
begin
  if not sectalk_private.st_v8_file_sso_allows(sectalk_private.st_v8_scoped_file_workspace(p_scope_type,p_scope)) then
    return '{"allowed":false,"reasons":["access_unavailable"]}';
  end if;
  baseline:=public.st_v7_builtin_file_egress(p_scope_type,p_scope,p_file,p_operation);
  if baseline->>'allowed'='true' and p_scope_type='workspace'
    and sectalk_private.st_v2_role(p_scope,auth.uid())='member'
    and exists(select 1 from sectalk_private.st_v7_file_custom_role_required f where (f.workspace,f.file)=(p_scope,p_file))
    and not coalesce(('file.'||p_operation)=any(sectalk_private.st_v7_custom_scope_access(p_scope,'file',p_file)),false) then
    return jsonb_build_object('allowed',false,'reasons',jsonb_build_array('custom_role_required'));
  end if;
  return baseline;
end
$$;

create or replace function sectalk_private.st_v6_can_read_workspace_file_history(p_workspace uuid,p_uploader uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce(sectalk_private.st_v2_active(auth.uid()),false) and
    sectalk_private.st_v2_role(p_workspace,auth.uid()) is not null and
    sectalk_private.st_v8_file_sso_allows(p_workspace) and
    (p_uploader=auth.uid() or (sectalk_private.st_v6_holds_access(p_workspace)='verified' and exists(
      select 1 from sectalk_private.st_v6_workspace_file_history_policy p where p.workspace=p_workspace and p.enabled
    )))
$$;

commit;
