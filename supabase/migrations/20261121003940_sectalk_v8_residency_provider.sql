begin;

create table sectalk_private.st_v8_residency_provider_bindings (
  cell uuid primary key references sectalk_private.st_v8_residency_cells(id) on delete restrict,
  provider_region text not null check(provider_region~'^(us|eu|ap)-[a-z]+-[1-9][0-9]?$'),
  organization_slug text not null check(organization_slug~'^[A-Za-z0-9_-]{1,80}$')
);
create trigger st_v8_residency_provider_binding_immutable before update or delete on sectalk_private.st_v8_residency_provider_bindings
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create table sectalk_private.st_v8_residency_provider_checks (
  request uuid primary key references sectalk_private.st_v8_residency_requests(id) on delete cascade,
  ticket uuid not null unique,
  reviewer uuid not null,
  session_id uuid not null,
  started_at timestamptz not null,
  verified_at timestamptz
);
alter table sectalk_private.st_v8_residency_provider_bindings enable row level security;
alter table sectalk_private.st_v8_residency_provider_checks enable row level security;
revoke all on sectalk_private.st_v8_residency_provider_bindings,sectalk_private.st_v8_residency_provider_checks
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_residency_provider_scope(p_request uuid,p_actor uuid)
returns table(cell uuid,project text,region text,organization text,workspace uuid)
language sql stable security definer set search_path='' as $$
  select c.id,c.project_reference,b.provider_region,b.organization_slug,r.workspace
  from sectalk_private.st_v8_residency_requests r
  join public.st_v2_workspaces w on w.id=r.workspace and w.owner=r.requester and w.owner<>p_actor
  join sectalk_private.st_v8_residency_verifiers v on (v.workspace,v.actor)=(r.workspace,p_actor)
  join sectalk_private.st_v8_residency_cells c on c.id=r.cell and c.environment='deployment' and c.retired_at is null
  join sectalk_private.st_v8_residency_cell_authorizations a on (a.workspace,a.cell)=(r.workspace,r.cell)
  join sectalk_private.st_v8_residency_provider_bindings b on b.cell=c.id
  where r.id=p_request and r.withdrawn_at is null and r.requester<>p_actor
    and (sectalk_private.st_v7_workspace_entitlements(r.workspace)).plan='enterprise'
    and sectalk_private.st_v2_active(p_actor) and c.project_reference~'^[a-z]{20}$'
    and split_part(b.provider_region,'-',1)=case when c.region='apac' then 'ap' else c.region end;
$$;

create function public.st_v8_begin_residency_provider_check(p_request uuid)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); receipt uuid:=gen_random_uuid();
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false) or not sectalk_private.st_v7_admin_fresh()
    or not exists(select 1 from sectalk_private.st_v8_residency_provider_scope(p_request,actor_id)) then
    raise exception 'Provider review is unavailable for this session' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v8_residency_provider',5);
  insert into sectalk_private.st_v8_residency_provider_checks as q(request,ticket,reviewer,session_id,started_at)
    values(p_request,receipt,actor_id,(auth.jwt()->>'session_id')::uuid,clock_timestamp())
  on conflict(request) do update set ticket=excluded.ticket,reviewer=excluded.reviewer,session_id=excluded.session_id,
    started_at=excluded.started_at,verified_at=null
    where q.verified_at is not null or q.started_at<statement_timestamp()-interval '45 seconds';
  if not found then return null; end if;
  return receipt;
end $$;

create function sectalk_private.st_v8_residency_provider_check_live(p_check sectalk_private.st_v8_residency_provider_checks)
returns boolean language sql stable set search_path='' as $$
  select p_check.verified_at is null and p_check.started_at>statement_timestamp()-interval '45 seconds'
    and exists(select 1 from auth.sessions s join auth.mfa_factors f on f.id=s.factor_id and f.user_id=s.user_id
      join auth.mfa_amr_claims a on a.session_id=s.id and a.authentication_method='totp'
      where (s.id,s.user_id)=(p_check.session_id,p_check.reviewer) and s.aal='aal2'
        and f.status='verified' and f.factor_type='totp' and a.updated_at>statement_timestamp()-interval '5 minutes'
        and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp())
    and not exists(select 1 from sectalk_private.st_v7_account_lockdowns l where l.user_id=p_check.reviewer and l.released_at is null);
$$;

create function public.st_v8_residency_provider_target(p_ticket uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('cell',s.cell,'project',s.project,'region',s.region,'organization',s.organization)
  from sectalk_private.st_v8_residency_provider_checks q
  cross join lateral sectalk_private.st_v8_residency_provider_scope(q.request,q.reviewer) s
  where q.ticket=p_ticket and sectalk_private.st_v8_residency_provider_check_live(q);
$$;

create function public.st_v8_finish_residency_provider_check(p_ticket uuid,p_cell uuid,p_project text,p_region text,p_organization text)
returns boolean language plpgsql security definer set search_path='' as $$
declare c sectalk_private.st_v8_residency_provider_checks; target record;
begin
  select * into c from sectalk_private.st_v8_residency_provider_checks where ticket=p_ticket for update;
  if not found or sectalk_private.st_v8_residency_provider_check_live(c) is not true then return false; end if;
  select * into target from sectalk_private.st_v8_residency_provider_scope(c.request,c.reviewer) q
    where (q.cell,q.project,q.region,q.organization)=(p_cell,p_project,p_region,p_organization);
  if not found then return false; end if;
  update sectalk_private.st_v8_residency_provider_checks set verified_at=clock_timestamp() where ticket=p_ticket;
  insert into sectalk_private.st_v8_residency_audit(request,workspace,cell,actor,action)
    values(c.request,target.workspace,target.cell,c.reviewer,'reviewed');
  return true;
end $$;

-- Installed in the independently provisioned target. The probe credential has
-- no storage, schema, or account access and can only perform this existence check.
create function public.st_v8_residency_target_ready(p_cell uuid,p_project text,p_installation_nonce uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v8_residency_installation i
    join sectalk_private.st_v8_residency_cells c on c.id=i.cell
    where i.cell=p_cell and i.installation_nonce=p_installation_nonce and c.project_reference=p_project
      and c.environment='deployment' and c.retired_at is null
      and exists(select 1 from storage.buckets b where b.id='sectalk-exports' and not b.public));
$$;

revoke all on function sectalk_private.st_v8_residency_provider_scope(uuid,uuid),
  sectalk_private.st_v8_residency_provider_check_live(sectalk_private.st_v8_residency_provider_checks),
  public.st_v8_begin_residency_provider_check(uuid),public.st_v8_residency_provider_target(uuid),
  public.st_v8_finish_residency_provider_check(uuid,uuid,text,text,text),
  public.st_v8_residency_target_ready(uuid,text,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_begin_residency_provider_check(uuid) to authenticated;
grant execute on function public.st_v8_residency_provider_target(uuid),
  public.st_v8_finish_residency_provider_check(uuid,uuid,text,text,text) to service_role;
grant execute on function public.st_v8_residency_target_ready(uuid,text,uuid) to anon,authenticated;
create or replace function public.st_v8_workspace_residency(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare entitled boolean; current_request jsonb;
begin
  if not sectalk_private.st_v8_residency_owner(p_workspace) then
    raise exception 'Workspace residency unavailable' using errcode='42501'; end if;
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

notify pgrst,'reload schema';
commit;
