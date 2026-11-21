begin;

create table sectalk_private.st_v8_workspace_organization_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_organization_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_organization_sso from public,anon,authenticated,service_role;

-- Organization settings use the interactive native session. Provider recovery,
-- independent residency review, and existing background delivery keep their roles.
create function sectalk_private.st_v8_organization_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_organization_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_organization_sso_allows(uuid) from public,anon,authenticated,service_role;

create function public.st_v8_workspace_organization_requires_sso(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v2_active(auth.uid())
    and coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    and not sectalk_private.st_v8_organization_sso_allows(p_workspace);
$$;

create function public.st_v8_workspace_organization_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_organization_sso_policy',5);
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
      insert into sectalk_private.st_v8_workspace_organization_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_organization_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.organization_sso_required'
          else 'workspace.organization_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_organization_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_organization_policy(uuid,boolean),
  public.st_v8_workspace_organization_requires_sso(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_organization_policy(uuid,boolean),
  public.st_v8_workspace_organization_requires_sso(uuid) to authenticated;

create or replace function public.st_v7_org_settings(p_workspace uuid,p_action text default 'read',p_name text default null,
  p_accent text default null,p_days integer default null,p_region text default null,p_domain text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare ws public.st_v2_workspaces; owner_id uuid:=auth.uid(); dom text; proof sectalk_private.st_v7_org_domains; updated boolean;
begin
  if not public.st_v7_current_session_valid() or public.st_v7_account_under_lockdown()
    or public.st_v7_login_risk_status() is distinct from 'clear' or not sectalk_private.st_v2_active(owner_id) then
    raise exception using errcode='42501',message='Organization settings unavailable';
  end if;
  if p_action in ('read','save') then
    select * into ws from public.st_v2_workspaces where id=p_workspace and owner=owner_id;
  else
    select * into ws from public.st_v2_workspaces where id=p_workspace and owner=owner_id for update;
  end if;
  if not found then raise exception using errcode='42501',message='Organization settings unavailable'; end if;
  if not sectalk_private.st_v8_organization_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to manage organization settings' using errcode='42501';
  end if;
  if p_action is distinct from 'read' then
    if public.st_v7_sensitive_action_status('room_role') is distinct from 'verified' then
      raise exception using errcode='42501',message='Verify your current sign-in to change organization settings';
    end if;
    perform sectalk_private.limit_action('v7_org_settings',12);
  end if;
  if p_action='save' then
    if nullif(btrim(p_name),'') is null or char_length(btrim(p_name))>64 or p_name~'[[:cntrl:]]'
      or p_accent is null or p_accent not in ('blue','teal','violet','amber')
      or p_days is null or p_days not between 7 and 3650 or p_region is null or p_region not in ('none','us','eu','apac') then
      raise exception using errcode='22023',message='Enter valid branding, retention and region settings';
    end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
    update public.st_v2_workspaces set name=btrim(p_name),brand_accent=p_accent
      where id=p_workspace and owner=owner_id returning * into ws;
    if not found then raise exception using errcode='42501',message='Organization settings unavailable'; end if;
    if not sectalk_private.st_v8_organization_sso_allows(p_workspace) then
      raise exception 'Sign in through your workspace provider to manage organization settings' using errcode='42501';
    end if;
    insert into sectalk_private.st_v7_org_preferences values(p_workspace,p_region)
      on conflict(workspace) do update set requested_region=excluded.requested_region;
    insert into sectalk_private.st_v6_room_retention_policy values(p_workspace,p_days)
      on conflict(workspace_id) do update set retention_days=excluded.retention_days
      where st_v6_room_retention_policy.retention_days<>excluded.retention_days;
    updated:=found;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event)
      values(p_workspace,owner_id,'workspace.organization_settings_changed');
    if updated then insert into public.st_v2_workspace_audit(workspace_id,actor,event)
      values(p_workspace,owner_id,'workspace.room_retention_changed'); end if;
  elsif p_action in ('domain.start','domain.remove','domain.proof') then
    dom:=lower(btrim(p_domain));
    if dom is null or length(dom)>225 or dom !~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$'
      or dom~'\.(local|localhost|internal|onion|test|example)$' then
      raise exception using errcode='22023',message='Enter a DNS domain without a URL, path or port';
    end if;
    if p_action='domain.start' then
      if (select count(*) from sectalk_private.st_v7_org_domains where workspace=p_workspace)>=10
        and not exists(select 1 from sectalk_private.st_v7_org_domains where workspace=p_workspace and domain=dom) then
        raise exception using errcode='22023',message='This organization already has ten domain entries';
      end if;
      insert into sectalk_private.st_v7_org_domains(workspace,domain) values(p_workspace,dom)
        on conflict(workspace,domain) do update set challenge=excluded.challenge,expires_at=excluded.expires_at
        where st_v7_org_domains.verified_at is null and st_v7_org_domains.expires_at<=now();
    elsif p_action='domain.remove' then
      delete from sectalk_private.st_v7_org_domains where workspace=p_workspace and domain=dom;
      if found then insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,owner_id,'workspace.domain_removed'); end if;
    else
      select * into proof from sectalk_private.st_v7_org_domains where workspace=p_workspace and domain=dom
        and verified_at is null and expires_at>now();
      if not found then raise exception using errcode='22023',message='Start or renew the domain challenge'; end if;
      return jsonb_build_object('challenge',proof.challenge,'domain',proof.domain,'owner',owner_id,'session',auth.jwt()->>'session_id');
    end if;
  elsif p_action is distinct from 'read' then
    raise exception using errcode='22023',message='Invalid organization action';
  end if;
  return jsonb_build_object('name',ws.name,'accent',ws.brand_accent,'retentionDays',sectalk_private.st_v6_room_retention_days(p_workspace),
    'region',coalesce((select requested_region from sectalk_private.st_v7_org_preferences where workspace=p_workspace),'none'),
    'domains',coalesce((select jsonb_agg(jsonb_build_object('domain',domain,
      'challenge',case when verified_at is null then challenge end,'expiresAt',expires_at,'verifiedAt',verified_at) order by domain)
      from sectalk_private.st_v7_org_domains where workspace=p_workspace),'[]'));
end
$$;

create or replace function public.st_v7_finish_org_domain(p_workspace uuid,p_challenge uuid,p_owner uuid,p_session uuid)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  perform 1 from public.st_v2_workspaces where id=p_workspace and owner=p_owner for update;
  if not found or not sectalk_private.st_v2_active(p_owner)
    or not exists(select 1 from auth.sessions where id=p_session and user_id=p_owner
      and sectalk_private.st_v7_session_deadline(created_at,refreshed_at,not_after)>statement_timestamp()) then
    return false;
  end if;
  if exists(select 1 from sectalk_private.st_v8_workspace_organization_sso policy where policy.workspace=p_workspace
    and not exists(
      select 1 from sectalk_private.st_v7_workspace_sso_sessions receipt
      join sectalk_private.st_v7_workspace_sso setup on setup.workspace=receipt.workspace
      where receipt.workspace=policy.workspace and receipt.principal=p_owner and receipt.session=p_session
        and (receipt.protocol,receipt.provider)=(policy.protocol,policy.provider)
        and (setup.protocol,setup.provider)=(policy.protocol,policy.provider)
        and sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol)=setup.provider
    )) then return false; end if;
  update sectalk_private.st_v7_org_domains set verified_at=clock_timestamp()
    where workspace=p_workspace and challenge=p_challenge and verified_at is null and expires_at>now();
  if not found then return false; end if;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(p_workspace,p_owner,'workspace.domain_verified');
  return true;
exception when unique_violation then return false;
end
$$;

create or replace function public.st_v8_workspace_residency(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare entitled boolean; current_request jsonb;
begin
  if not sectalk_private.st_v8_residency_owner(p_workspace) then
    raise exception 'Workspace residency unavailable' using errcode='42501'; end if;
  if not sectalk_private.st_v8_organization_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to manage organization settings' using errcode='42501';
  end if;
  entitled:=coalesce((sectalk_private.st_v7_workspace_entitlements(p_workspace)).plan='enterprise',false);
  select jsonb_build_object('id',r.id,'region',c.region,'label',c.label,'requestedAt',r.requested_at,
    'state',case when c.retired_at is not null or a.workspace is null then 'unavailable'
      when not entitled then 'paused'
      when c.environment='deployment' then
        case when q.verified_at>statement_timestamp()-interval '1 day'
          and exists(select 1 from sectalk_private.st_v8_residency_provider_scope(r.id,q.reviewer))
          then 'provider_target_verified'
          when q.verified_at is not null then 'needs_verification'
          else 'pending_verification' end
      when r.observed_at is not null and (r.observed_at<statement_timestamp()-interval '1 day'
        or r.observation_nonce is distinct from i.installation_nonce) then 'needs_verification'
      when r.reviewed_at is not null then 'fixture_target_verified'
      when r.observed_at is not null then 'independent_review_required' else 'pending_verification' end)
  into current_request from sectalk_private.st_v8_residency_requests r
  join sectalk_private.st_v8_residency_cells c on c.id=r.cell
  left join sectalk_private.st_v8_residency_cell_authorizations a on (a.workspace,a.cell)=(r.workspace,r.cell)
  left join sectalk_private.st_v8_residency_installation i on i.cell=r.cell
  left join sectalk_private.st_v8_residency_provider_checks q on q.request=r.id
  where r.workspace=p_workspace and r.withdrawn_at is null;
  return jsonb_build_object('eligible',entitled,'request',current_request,
    'cells',case when entitled then coalesce((select jsonb_agg(to_jsonb(x)) from (
      select c.id,c.region,c.label,c.environment from sectalk_private.st_v8_residency_cells c
      join sectalk_private.st_v8_residency_cell_authorizations a on a.cell=c.id
      where a.workspace=p_workspace and c.retired_at is null order by c.region,c.label,c.id limit 30
    ) x),'[]'::jsonb) else '[]'::jsonb end);
end $$;

create or replace function public.st_v8_workspace_residency_change(p_workspace uuid,p_cell uuid default null)
returns uuid language plpgsql security definer set search_path='' as $$
declare current_request sectalk_private.st_v8_residency_requests; receipt uuid; actor uuid:=auth.uid();
begin
  perform 1 from public.st_v2_workspaces where id=p_workspace and owner=actor for no key update;
  if not found or not sectalk_private.st_v8_residency_owner(p_workspace)
    or public.st_v7_sensitive_action_status('room_role') is distinct from 'verified' then
    raise exception 'Verified workspace owner required' using errcode='42501'; end if;
  if not sectalk_private.st_v8_organization_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to manage organization settings' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v8_workspace_residency',8);
  select * into current_request from sectalk_private.st_v8_residency_requests
    where workspace=p_workspace and withdrawn_at is null for update;
  if p_cell is null then
    if current_request.id is not null then
      update sectalk_private.st_v8_residency_requests set withdrawn_at=statement_timestamp() where id=current_request.id;
      insert into sectalk_private.st_v8_residency_audit(request,workspace,cell,actor,action)
        values(current_request.id,p_workspace,current_request.cell,actor,'withdrawn');
    end if;
    return current_request.id;
  end if;
  if (sectalk_private.st_v7_workspace_entitlements(p_workspace)).plan is distinct from 'enterprise'
    or not exists(select 1 from sectalk_private.st_v8_residency_cell_authorizations a
      join sectalk_private.st_v8_residency_cells c on a.cell=c.id
      where (a.workspace,a.cell)=(p_workspace,p_cell) and c.retired_at is null) then
    raise exception 'This dedicated target is unavailable' using errcode='42501'; end if;
  if current_request.cell=p_cell then return current_request.id; end if;
  if current_request.id is not null then
    raise exception 'Withdraw the current request before selecting a different target' using errcode='22023'; end if;
  insert into sectalk_private.st_v8_residency_requests(workspace,cell,requester)
    values(p_workspace,p_cell,actor) returning id into receipt;
  insert into sectalk_private.st_v8_residency_audit(request,workspace,cell,actor,action)
    values(receipt,p_workspace,p_cell,actor,'requested');
  return receipt;
end $$;

create or replace function public.st_v7_workspace_email_template(p_workspace uuid,p_action text default 'read',
  p_subject text default null,p_body text default null,p_version integer default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare ws public.st_v2_workspaces; actor uuid:=auth.uid(); active_version integer; selected_version integer;
begin
  if not public.st_v7_current_session_valid() or public.st_v7_account_under_lockdown()
    or public.st_v7_login_risk_status() is distinct from 'clear' or not sectalk_private.st_v2_active(actor) then
    raise exception using errcode='42501',message='Workspace email settings unavailable';
  end if;
  if p_action='delivery' then
    if coalesce(sectalk_private.st_v2_role(p_workspace,actor),'') not in ('owner','admin') then
      raise exception using errcode='42501',message='Workspace email settings unavailable';
    end if;
    select * into ws from public.st_v2_workspaces where id=p_workspace;
  elsif p_action='read' then
    select * into ws from public.st_v2_workspaces where id=p_workspace and owner=actor;
  else
    select * into ws from public.st_v2_workspaces where id=p_workspace and owner=actor for no key update;
  end if;
  if not found then raise exception using errcode='42501',message='Workspace email settings unavailable'; end if;

  if p_action is distinct from 'delivery' and not sectalk_private.st_v8_organization_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to manage organization settings' using errcode='42501';
  end if;

  if p_action not in ('read','delivery') then
    if public.st_v7_sensitive_action_status('room_role') is distinct from 'verified' then
      raise exception using errcode='42501',message='Verify your current sign-in to change email templates';
    end if;
    perform sectalk_private.limit_action('v7_workspace_email_template',10);
    if p_action='publish' then
      if p_subject is null or char_length(btrim(p_subject)) not between 1 and 100 or p_subject~'[[:cntrl:]]'
        or p_body is null or char_length(btrim(p_body)) not between 1 and 1500 or translate(p_body,E'\n\t','')~'[[:cntrl:]]'
        or (replace(p_subject,'{{organization}}','')||replace(p_body,'{{organization}}',''))~'[{}<>]'
        or p_subject~*'(https?://|www\.|mailto:)' or p_body~*'(https?://|www\.|mailto:)' then
        raise exception using errcode='22023',message='Use plain text and the organization variable. The invitation link is included automatically.';
      end if;
      select coalesce(max(version),0)+1 into selected_version
        from sectalk_private.st_v7_workspace_email_versions where workspace=p_workspace;
      if selected_version>100 then raise exception using errcode='22023',message='This workspace has reached 100 published versions'; end if;
      insert into sectalk_private.st_v7_workspace_email_versions(workspace,version,subject,body)
        values(p_workspace,selected_version,btrim(p_subject),btrim(p_body));
    elsif p_action='activate' then
      selected_version:=p_version;
      if selected_version is null or (selected_version<>0 and not exists(select 1
        from sectalk_private.st_v7_workspace_email_versions where workspace=p_workspace and version=selected_version)) then
        raise exception using errcode='22023',message='Choose an available template version';
      end if;
    else
      raise exception using errcode='22023',message='Invalid email template action';
    end if;
    if selected_version=0 then
      delete from sectalk_private.st_v7_workspace_email_active where workspace=p_workspace;
    else
      insert into sectalk_private.st_v7_workspace_email_active values(p_workspace,selected_version)
        on conflict(workspace) do update set version=excluded.version;
    end if;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(p_workspace,actor,
      case when p_action='publish' then 'workspace.email_template_published' else 'workspace.email_template_restored' end);
  end if;

  select version into active_version from sectalk_private.st_v7_workspace_email_active where workspace=p_workspace;
  if p_action='delivery' then
    return jsonb_build_object('organization',ws.name,'template',(select jsonb_build_object('subject',subject,'body',body)
      from sectalk_private.st_v7_workspace_email_versions where workspace=p_workspace and version=active_version));
  end if;
  return jsonb_build_object('organization',ws.name,'active',coalesce(active_version,0),'versions',
    coalesce((select jsonb_agg(jsonb_build_object('version',version,'subject',subject,'body',body,'createdAt',created_at) order by version desc)
      from sectalk_private.st_v7_workspace_email_versions where workspace=p_workspace),'[]'));
end
$$;

create or replace function public.st_v6_room_retention_policy(p_workspace uuid,p_days integer default null)
returns integer language plpgsql security definer set search_path='' as $$
begin
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Verify workspace governance access' using errcode='42501';
  end if;
  if not sectalk_private.st_v8_organization_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to manage organization settings' using errcode='42501';
  end if;
  if p_days is null then return sectalk_private.st_v6_room_retention_days(p_workspace); end if;
  if p_days not between 7 and 3650 then raise exception 'Use a retention period from 7 to 3650 days'; end if;
  perform sectalk_private.limit_action('v6_room_retention',10);
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Workspace governance is unavailable' using errcode='42501';
  end if;
  if not sectalk_private.st_v8_organization_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to manage organization settings' using errcode='42501';
  end if;
  insert into sectalk_private.st_v6_room_retention_policy(workspace_id,retention_days) values(p_workspace,p_days)
    on conflict(workspace_id) do update set retention_days=excluded.retention_days
    where st_v6_room_retention_policy.retention_days is distinct from excluded.retention_days;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event)
      values(p_workspace,auth.uid(),'workspace.room_retention_changed');
  end if;
  return p_days;
end $$;

commit;
