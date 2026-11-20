begin;
create table sectalk_private.st_v7_oidc_domain_approvals (
  domain text primary key,
  identifier text not null unique check(identifier~'^custom:[a-z0-9-]{1,48}$')
);
create table sectalk_private.st_v7_workspace_sso (
  workspace uuid primary key references public.st_v2_workspaces(id) on delete cascade,
  domain text not null,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null,
  jit boolean not null default false,
  foreign key(workspace,domain) references sectalk_private.st_v7_org_domains(workspace,domain) on delete cascade
);
create table sectalk_private.st_v7_workspace_sso_attempts (
  digest text primary key check(digest~'^[0-9a-f]{64}$'),
  challenge text not null check(challenge~'^[A-Za-z0-9_-]{43}$'),
  workspace uuid not null references sectalk_private.st_v7_workspace_sso(workspace) on delete cascade,
  protocol text not null,
  provider text not null,
  domain text not null,
  expires_at timestamptz not null default clock_timestamp()+interval '10 minutes',
  claimed_by uuid references auth.users(id) on delete cascade
);
create index st_v7_workspace_sso_attempts_workspace on sectalk_private.st_v7_workspace_sso_attempts(workspace,expires_at);
create table sectalk_private.st_v7_sso_departures (
  workspace uuid not null references public.st_v2_workspaces(id) on delete cascade,
  principal uuid not null references auth.users(id) on delete cascade,
  primary key(workspace,principal)
);
alter table sectalk_private.st_v7_sso_departures enable row level security;
revoke all on sectalk_private.st_v7_sso_departures from public,anon,authenticated,service_role;
create function sectalk_private.st_v7_record_sso_departure()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if exists(select 1 from sectalk_private.st_v7_workspace_sso s where s.workspace=old.workspace_id)
    and exists(select 1 from public.st_v2_workspaces w where w.id=old.workspace_id)
    and exists(select 1 from auth.users u where u.id=old.user_id) then
    insert into sectalk_private.st_v7_sso_departures values(old.workspace_id,old.user_id) on conflict do nothing;
  end if;
  return null;
end
$$;
create trigger st_v7_sso_departure after delete on public.st_v2_members
  for each row execute function sectalk_private.st_v7_record_sso_departure();
revoke all on function sectalk_private.st_v7_record_sso_departure() from public,anon,authenticated,service_role;

create table sectalk_private.st_v7_workspace_sso_sessions (
  session uuid not null references auth.sessions(id) on delete cascade,
  workspace uuid not null references sectalk_private.st_v7_workspace_sso(workspace) on delete cascade,
  principal uuid not null references auth.users(id) on delete cascade,
  protocol text not null,
  provider text not null,
  established_at timestamptz not null default clock_timestamp(),
  primary key(workspace,session)
);
alter table sectalk_private.st_v7_oidc_domain_approvals enable row level security;
alter table sectalk_private.st_v7_workspace_sso enable row level security;
alter table sectalk_private.st_v7_workspace_sso_attempts enable row level security;
alter table sectalk_private.st_v7_workspace_sso_sessions enable row level security;
revoke all on sectalk_private.st_v7_oidc_domain_approvals,sectalk_private.st_v7_workspace_sso,
  sectalk_private.st_v7_workspace_sso_attempts,sectalk_private.st_v7_workspace_sso_sessions from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_workspace_sso_provider(p_workspace uuid,p_domain text,p_protocol text)
returns text language sql stable set search_path='' as $$
  select case p_protocol
    when 'saml' then (select s.id::text from auth.sso_domains d join auth.sso_providers s on s.id=d.sso_provider_id
      join auth.saml_providers p on p.sso_provider_id=s.id where lower(d.domain)=p_domain and s.disabled is not true limit 1)
    when 'oidc' then (select p.identifier from sectalk_private.st_v7_oidc_domain_approvals a
      join auth.custom_oauth_providers p on p.identifier=a.identifier
      where a.domain=p_domain and p.enabled and p.provider_type='oidc' and p.email_optional is not true limit 1)
    end
  from sectalk_private.st_v7_org_domains d where d.workspace=p_workspace and d.domain=p_domain and d.verified_at is not null
    and coalesce((sectalk_private.st_v7_workspace_entitlements(p_workspace)).plan='enterprise',false);
$$;

create function public.st_v7_workspace_sso_settings(p_workspace uuid,p_action text default 'read',p_domain text default null,
  p_protocol text default null,p_jit boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); configured_provider text; current_setup jsonb;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if not coalesce((sectalk_private.st_v7_workspace_entitlements(p_workspace)).plan='enterprise',false) then
    return jsonb_build_object('access','upgrade');
  end if;
  if p_action<>'read' then
    perform sectalk_private.limit_action('v7_workspace_sso_settings',10);
    perform 1 from public.st_v2_workspaces where id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
      raise exception using errcode='42501',message='Fresh workspace owner verification required';
    end if;
    if p_action='save' then
      configured_provider:=sectalk_private.st_v7_workspace_sso_provider(p_workspace,p_domain,p_protocol);
      if configured_provider is null or p_jit is null then
        raise exception using errcode='22023',message='This verified domain has no approved native provider of that type';
      end if;
      if exists(select 1 from sectalk_private.st_v7_workspace_sso s where s.workspace=p_workspace
        and (s.domain,s.protocol,s.provider) is distinct from (p_domain,p_protocol,configured_provider)) then
        delete from sectalk_private.st_v7_workspace_sso where workspace=p_workspace;
      end if;
      insert into sectalk_private.st_v7_workspace_sso values(p_workspace,p_domain,p_protocol,configured_provider,p_jit)
        on conflict(workspace) do update set jit=excluded.jit;
    elsif p_action='remove' then
      delete from sectalk_private.st_v7_workspace_sso where workspace=p_workspace;
    else raise exception using errcode='22023',message='Choose a supported organization sign-in operation'; end if;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,auth.uid(),'workspace.sso_'||p_action,p_workspace);
  end if;
  select jsonb_build_object('domain',s.domain,'protocol',s.protocol,'jit',s.jit,
    'available',sectalk_private.st_v7_workspace_sso_provider(s.workspace,s.domain,s.protocol)=s.provider)
    into current_setup from sectalk_private.st_v7_workspace_sso s where s.workspace=p_workspace;
  return jsonb_build_object('access','verified','setup',current_setup);
end
$$;

create function public.st_v7_workspace_sso_begin(p_domain text,p_digest text,p_challenge text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare setup sectalk_private.st_v7_workspace_sso;
begin
  select * into setup from sectalk_private.st_v7_workspace_sso s where s.domain=p_domain
    and sectalk_private.st_v7_workspace_sso_provider(s.workspace,s.domain,s.protocol)=s.provider;
  if not found then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended('workspace-sso:'||setup.workspace::text,0));
  delete from sectalk_private.st_v7_workspace_sso_attempts where workspace=setup.workspace and expires_at<=clock_timestamp();
  if (select count(*) from sectalk_private.st_v7_workspace_sso_attempts a where a.workspace=setup.workspace)>=40 then return null; end if;
  insert into sectalk_private.st_v7_workspace_sso_attempts(digest,challenge,workspace,protocol,provider,domain)
    values(p_digest,p_challenge,setup.workspace,setup.protocol,setup.provider,setup.domain);
  return jsonb_build_object('protocol',setup.protocol,'provider',setup.provider);
end
$$;

create function public.st_v7_workspace_sso_claim(p_digest text,p_code text,p_challenge text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare flow auth.flow_state; attempt sectalk_private.st_v7_workspace_sso_attempts;
begin
  select * into attempt from sectalk_private.st_v7_workspace_sso_attempts a where a.digest=p_digest
    and a.challenge=p_challenge and a.claimed_by is null and a.expires_at>clock_timestamp() for update;
  if not found or sectalk_private.st_v7_workspace_sso_provider(attempt.workspace,attempt.domain,attempt.protocol)
    is distinct from attempt.provider then return null; end if;
  select * into flow from auth.flow_state f where f.auth_code=p_code and f.code_challenge=attempt.challenge
    and f.code_challenge_method::text='s256' and f.user_id is not null
    -- Native SAML fills the principal in the ACS without stamping auth_code_issued_at.
    and (case when attempt.protocol='saml' then coalesce(f.auth_code_issued_at,f.created_at)
      else f.auth_code_issued_at end)>clock_timestamp()-interval '10 minutes';
  if not found then return null; end if;
  if attempt.protocol='oidc' and (flow.authentication_method<>'oauth' or flow.provider_type is distinct from attempt.provider)
    or attempt.protocol='saml' and (flow.authentication_method<>'sso/saml' or not exists(select 1
      from auth.identities i where i.user_id=flow.user_id and i.provider='sso:'||attempt.provider)) then return null; end if;
  update sectalk_private.st_v7_workspace_sso_attempts set claimed_by=flow.user_id where digest=attempt.digest;
  return jsonb_build_object('principal',flow.user_id,'protocol',attempt.protocol,'provider',attempt.provider);
end
$$;

create function public.st_v7_workspace_sso_finish(p_digest text,p_actor uuid,p_session uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare attempt sectalk_private.st_v7_workspace_sso_attempts; setup sectalk_private.st_v7_workspace_sso;
  verified_email text; native_provider text; member_role text; initial_profile boolean;
begin
  select * into attempt from sectalk_private.st_v7_workspace_sso_attempts a where a.digest=p_digest and a.claimed_by=p_actor;
  if not found then return null; end if;
  perform 1 from public.st_v2_workspaces where id=attempt.workspace for update;
  if not found then return null; end if;
  select * into attempt from sectalk_private.st_v7_workspace_sso_attempts a where a.digest=p_digest and a.claimed_by=p_actor
    and a.expires_at>clock_timestamp() for update;
  if not found then return null; end if;
  delete from sectalk_private.st_v7_workspace_sso_attempts where digest=p_digest;
  select * into setup from sectalk_private.st_v7_workspace_sso s where s.workspace=attempt.workspace and s.domain=attempt.domain
    and s.protocol=attempt.protocol and s.provider=attempt.provider;
  if not found or sectalk_private.st_v7_workspace_sso_provider(attempt.workspace,attempt.domain,attempt.protocol)
    is distinct from attempt.provider then return null; end if;
  native_provider:=case setup.protocol when 'saml' then 'sso:'||setup.provider else setup.provider end;
  select lower(u.email) into verified_email from auth.users u where u.id=p_actor and u.email_confirmed_at is not null
    and exists(select 1 from auth.identities i where i.user_id=u.id and i.provider=native_provider and lower(i.email)=lower(u.email)
      and (setup.protocol='saml' or i.identity_data->>'email_verified'='true'));
  if verified_email is null or split_part(verified_email,'@',2) is distinct from setup.domain
    or not exists(select 1 from auth.sessions s join auth.mfa_amr_claims a on a.session_id=s.id
      where s.id=p_session and s.user_id=p_actor and s.created_at>=attempt.expires_at-interval '10 minutes'
        and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
        and a.authentication_method=case setup.protocol when 'saml' then 'sso/saml' else 'oauth' end) then return null; end if;
  perform 1 from public.st_v2_workspaces where id=setup.workspace for update;
  if not found then return null; end if;
  if sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol) is distinct from setup.provider
    or not exists(select 1 from sectalk_private.st_v7_workspace_sso c where c.workspace=setup.workspace
      and (c.domain,c.protocol,c.provider,c.jit)=(setup.domain,setup.protocol,setup.provider,setup.jit)) then return null; end if;
  select m.role into member_role from public.st_v2_members m where m.workspace_id=setup.workspace and m.user_id=p_actor;
  if member_role is not null and sectalk_private.st_v2_role(setup.workspace,p_actor) is null then return null; end if;
  if member_role is null then
    if not setup.jit or exists(select 1 from sectalk_private.st_v7_sso_departures d where d.workspace=setup.workspace and d.principal=p_actor)
      or exists(select 1 from public.st_v2_members m join auth.users u on u.id=m.user_id
        where m.workspace_id=setup.workspace and lower(u.email)=verified_email and u.id<>p_actor)
      or (select count(*) from public.st_v2_members m where m.workspace_id=setup.workspace)>=coalesce((sectalk_private.st_v7_workspace_entitlements(setup.workspace)).seat_limit,0) then return null; end if;
    select not exists(select 1 from public.st_profiles p where p.id=p_actor) into initial_profile;
    if initial_profile then
      insert into public.st_profiles(id,handle,name) values(p_actor,'sso_'||left(replace(p_actor::text,'-',''),20),'Workspace member')
        on conflict(id) do nothing;
    end if;
    if not sectalk_private.st_v2_active(p_actor) then return null; end if;
    insert into public.st_v2_members(workspace_id,user_id,role) values(setup.workspace,p_actor,'member');
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(setup.workspace,p_actor,'workspace.sso_jit',p_actor);
  elsif not sectalk_private.st_v2_active(p_actor) then return null; end if;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(p_session,setup.workspace,p_actor,setup.protocol,setup.provider) on conflict do nothing;
  return jsonb_build_object('workspace',setup.workspace);
end
$$;

create function public.st_v7_workspace_uses_sso(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select public.st_v7_current_session_valid() and exists(select 1
    from sectalk_private.st_v7_workspace_sso_sessions s join sectalk_private.st_v7_workspace_sso c on c.workspace=s.workspace
    where s.workspace=p_workspace and s.principal=auth.uid() and s.session::text=auth.jwt()->>'session_id'
      and s.protocol=c.protocol and s.provider=c.provider
      and sectalk_private.st_v7_workspace_sso_provider(c.workspace,c.domain,c.protocol)=s.provider);
$$;

revoke all on function sectalk_private.st_v7_workspace_sso_provider(uuid,text,text),
  public.st_v7_workspace_sso_settings(uuid,text,text,text,boolean),public.st_v7_workspace_sso_begin(text,text,text),
  public.st_v7_workspace_sso_claim(text,text,text),public.st_v7_workspace_sso_finish(text,uuid,uuid),
  public.st_v7_workspace_uses_sso(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_workspace_sso_settings(uuid,text,text,text,boolean),
  public.st_v7_workspace_uses_sso(uuid) to authenticated;
grant execute on function public.st_v7_workspace_sso_begin(text,text,text),public.st_v7_workspace_sso_claim(text,text,text),
  public.st_v7_workspace_sso_finish(text,uuid,uuid) to service_role;
commit;
