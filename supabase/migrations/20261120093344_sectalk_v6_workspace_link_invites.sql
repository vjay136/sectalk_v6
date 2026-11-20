begin;

create table sectalk_private.st_v6_workspace_link_policy (
  workspace_id uuid primary key references public.st_v2_workspaces on delete cascade,
  domains text[] not null
);
create table sectalk_private.st_v6_workspace_link_invites (
  token_hash bytea primary key check(octet_length(token_hash)=32),
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  issued_by uuid not null references auth.users on delete cascade,
  email text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz
);
create index st_v6_workspace_link_invites_workspace on sectalk_private.st_v6_workspace_link_invites(workspace_id,expires_at);
alter table sectalk_private.st_v6_workspace_link_policy enable row level security;
alter table sectalk_private.st_v6_workspace_link_invites enable row level security;
revoke all on sectalk_private.st_v6_workspace_link_policy,sectalk_private.st_v6_workspace_link_invites
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_link_domain_allowed(p_workspace uuid,p_email text)
returns boolean language sql stable set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v6_workspace_link_policy p
    where p.workspace_id=p_workspace and cardinality(p.domains)>0 and not(split_part(p_email,'@',2)=any(p.domains)))
$$;

create function sectalk_private.st_v6_manage_link_invites(p_workspace uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    and sectalk_private.st_v2_active(auth.uid())
$$;

create function sectalk_private.st_v6_workspace_link_policy_get(p_workspace uuid)
returns text[] language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_v6_manage_link_invites(p_workspace) then
    raise exception 'Invitation settings unavailable' using errcode='42501';
  end if;
  return coalesce((select domains from sectalk_private.st_v6_workspace_link_policy where workspace_id=p_workspace),'{}');
end
$$;

create function sectalk_private.st_v6_workspace_link_policy_set(p_workspace uuid,p_domains text[])
returns void language plpgsql security definer set search_path='' as $$
declare normalized text[];
begin
  if not sectalk_private.st_v6_manage_link_invites(p_workspace) then
    raise exception 'Invitation settings unavailable' using errcode='42501';
  end if;
  if p_domains is null or cardinality(p_domains)>10
    or exists(select 1 from unnest(p_domains) d where d is null or length(d)>253
      or lower(btrim(d)) !~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:[.][a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$')
  then raise exception 'Enter up to ten valid email domains'; end if;
  perform sectalk_private.limit_action('v6_invite_link_policy',15);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if not sectalk_private.st_v6_manage_link_invites(p_workspace) then
    raise exception 'Invitation settings unavailable' using errcode='42501';
  end if;
  normalized:=array(select distinct lower(btrim(d)) from unnest(p_domains) d order by lower(btrim(d)));
  insert into sectalk_private.st_v6_workspace_link_policy(workspace_id,domains) values(p_workspace,normalized)
  on conflict(workspace_id) do update set domains=excluded.domains
    where st_v6_workspace_link_policy.domains is distinct from excluded.domains;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event)
    values(p_workspace,auth.uid(),'workspace.link_policy_changed');
  end if;
end
$$;

create function sectalk_private.st_v6_workspace_link_create(p_workspace uuid,p_email text,p_hours integer)
returns jsonb language plpgsql security definer set search_path='' as $$
declare target_email text:=lower(btrim(p_email));
declare token text;
declare expiry timestamptz;
begin
  if not sectalk_private.st_v6_manage_link_invites(p_workspace) then
    raise exception 'Invitations unavailable' using errcode='42501';
  end if;
  if target_email is null or length(target_email)>254 or target_email!~'^[^[:space:]@]+@[^[:space:]@]+[.][^[:space:]@]+$'
    or p_hours is null or p_hours not between 1 and 168 then raise exception 'Enter a valid email and expiry'; end if;
  perform sectalk_private.limit_action('v6_invite_link_create',20);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if not sectalk_private.st_v6_manage_link_invites(p_workspace) then
    raise exception 'Invitations unavailable' using errcode='42501';
  end if;
  if not sectalk_private.st_v6_link_domain_allowed(p_workspace,target_email)
  then raise exception 'Email domain is outside the workspace invitation policy'; end if;
  token:=encode(extensions.gen_random_bytes(24),'hex');
  expiry:=clock_timestamp()+make_interval(hours=>p_hours);
  insert into sectalk_private.st_v6_workspace_link_invites(token_hash,workspace_id,issued_by,email,expires_at)
    values(sha256(convert_to(token,'UTF8')),p_workspace,auth.uid(),target_email,expiry);
  insert into public.st_v2_workspace_audit(workspace_id,actor,event)
    values(p_workspace,auth.uid(),'workspace.link_invited');
  return jsonb_build_object('token',token,'expires_at',expiry);
end
$$;

create function sectalk_private.st_v6_workspace_link_accept(p_token text)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare token_digest bytea;
declare invitation sectalk_private.st_v6_workspace_link_invites;
declare workspace uuid;
declare owner_id uuid;
declare verified_email text;
declare cap integer;
begin
  if not sectalk_private.st_v2_active(actor) or p_token is null or p_token!~'^[0-9a-f]{48}$'
  then raise exception 'Invitation unavailable'; end if;
  perform sectalk_private.limit_action('v6_invite_link_accept',15);
  token_digest:=sha256(convert_to(p_token,'UTF8'));
  select workspace_id into workspace from sectalk_private.st_v6_workspace_link_invites where token_hash=token_digest;
  select owner into owner_id from public.st_v2_workspaces where id=workspace for update;
  if not found then raise exception 'Invitation unavailable'; end if;
  select * into invitation from sectalk_private.st_v6_workspace_link_invites where token_hash=token_digest for update;
  select lower(u.email) into verified_email from auth.users u where u.id=actor and u.email_confirmed_at is not null;
  if not found or verified_email is distinct from invitation.email or invitation.consumed_at is not null
    or invitation.expires_at<=clock_timestamp()
    or not coalesce(sectalk_private.st_v2_role(workspace,invitation.issued_by) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(invitation.issued_by)
    or not sectalk_private.st_v6_link_domain_allowed(workspace,verified_email)
    or not sectalk_private.open_pair(actor,invitation.issued_by)
  then raise exception 'Invitation unavailable'; end if;
  if exists(select 1 from public.st_v2_members where workspace_id=workspace and user_id=actor)
    then raise exception 'Invitation unavailable'; end if;
  cap:=case sectalk_private.st_v2_effective_plan(owner_id)
    when 'basic' then 12 when 'professional' then 30 when 'business' then 100 when 'enterprise' then 500 else 5 end;
  if (select count(*) from public.st_v2_members where workspace_id=workspace)>=cap
    then raise exception 'Workspace has no available seats'; end if;
  insert into public.st_v2_members(workspace_id,user_id) values(workspace,actor);
  update sectalk_private.st_v6_workspace_link_invites set consumed_at=clock_timestamp() where token_hash=token_digest;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(workspace,actor,'workspace.link_joined',actor);
  return workspace;
end
$$;

create function public.st_v6_workspace_link_policy_get(p_workspace uuid)
returns text[] language sql stable set search_path='' return sectalk_private.st_v6_workspace_link_policy_get(p_workspace);
create function public.st_v6_workspace_link_policy_set(p_workspace uuid,p_domains text[])
returns void language sql set search_path='' return sectalk_private.st_v6_workspace_link_policy_set(p_workspace,p_domains);
create function public.st_v6_workspace_link_create(p_workspace uuid,p_email text,p_hours integer)
returns jsonb language sql set search_path='' return sectalk_private.st_v6_workspace_link_create(p_workspace,p_email,p_hours);
create function public.st_v6_workspace_link_accept(p_token text)
returns uuid language sql set search_path='' return sectalk_private.st_v6_workspace_link_accept(p_token);

revoke all on function sectalk_private.st_v6_link_domain_allowed(uuid,text),sectalk_private.st_v6_manage_link_invites(uuid),
  sectalk_private.st_v6_workspace_link_policy_get(uuid),sectalk_private.st_v6_workspace_link_policy_set(uuid,text[]),
  sectalk_private.st_v6_workspace_link_create(uuid,text,integer),sectalk_private.st_v6_workspace_link_accept(text),
  public.st_v6_workspace_link_policy_get(uuid),public.st_v6_workspace_link_policy_set(uuid,text[]),
  public.st_v6_workspace_link_create(uuid,text,integer),public.st_v6_workspace_link_accept(text)
  from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v6_workspace_link_policy_get(uuid),sectalk_private.st_v6_workspace_link_policy_set(uuid,text[]),
  sectalk_private.st_v6_workspace_link_create(uuid,text,integer),sectalk_private.st_v6_workspace_link_accept(text),
  public.st_v6_workspace_link_policy_get(uuid),public.st_v6_workspace_link_policy_set(uuid,text[]),
  public.st_v6_workspace_link_create(uuid,text,integer),public.st_v6_workspace_link_accept(text) to authenticated;

commit;
