begin;
alter table public.st_v2_workspaces add column brand_accent text not null default 'blue'
  check(brand_accent in ('blue','teal','violet','amber'));

create table sectalk_private.st_v7_org_preferences (
  workspace uuid primary key references public.st_v2_workspaces(id) on delete cascade,
  requested_region text not null check(requested_region in ('none','us','eu','apac'))
);
create table sectalk_private.st_v7_org_domains (
  workspace uuid not null references public.st_v2_workspaces(id) on delete cascade,
  domain text not null,
  challenge uuid not null unique default gen_random_uuid(),
  expires_at timestamptz not null default (now()+interval '48 hours'),
  verified_at timestamptz,
  primary key(workspace,domain)
);
create unique index st_v7_org_verified_domain on sectalk_private.st_v7_org_domains(domain) where verified_at is not null;
alter table sectalk_private.st_v7_org_preferences enable row level security;
alter table sectalk_private.st_v7_org_domains enable row level security;
revoke all on sectalk_private.st_v7_org_preferences,sectalk_private.st_v7_org_domains from public,anon,authenticated,service_role;

create function public.st_v7_org_settings(p_workspace uuid,p_action text default 'read',p_name text default null,
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

create function public.st_v7_finish_org_domain(p_workspace uuid,p_challenge uuid,p_owner uuid,p_session uuid)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  perform 1 from public.st_v2_workspaces where id=p_workspace and owner=p_owner for update;
  if not found or not sectalk_private.st_v2_active(p_owner)
    or not exists(select 1 from auth.sessions where id=p_session and user_id=p_owner
      and sectalk_private.st_v7_session_deadline(created_at,refreshed_at,not_after)>statement_timestamp()) then
    return false;
  end if;
  update sectalk_private.st_v7_org_domains set verified_at=clock_timestamp()
    where workspace=p_workspace and challenge=p_challenge and verified_at is null and expires_at>now();
  if not found then return false; end if;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(p_workspace,p_owner,'workspace.domain_verified');
  return true;
exception when unique_violation then return false;
end
$$;
revoke all on function public.st_v7_org_settings(uuid,text,text,text,integer,text,text),
  public.st_v7_finish_org_domain(uuid,uuid,uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_org_settings(uuid,text,text,text,integer,text,text) to authenticated;
grant execute on function public.st_v7_finish_org_domain(uuid,uuid,uuid,uuid) to service_role;
commit;
