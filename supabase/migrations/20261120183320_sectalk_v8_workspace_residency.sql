begin;

create table sectalk_private.st_v8_residency_cells (
  id uuid primary key,
  region text not null check(region in ('us','eu','apac')),
  project_reference text not null unique check(project_reference~'^[a-z0-9][a-z0-9-]{2,63}$'),
  label text not null check(char_length(label) between 3 and 80 and label!~'[[:cntrl:]]'),
  environment text not null check(environment in ('fixture','deployment')),
  retired_at timestamptz
);
create trigger st_v8_residency_cell_identity_immutable before update on sectalk_private.st_v8_residency_cells
  for each row when ((old.id,old.region,old.project_reference,old.environment)
    is distinct from (new.id,new.region,new.project_reference,new.environment))
  execute function sectalk_private.st_v7_immutable_threat_audit();
create table sectalk_private.st_v8_residency_cell_authorizations (
  workspace uuid not null references public.st_v2_workspaces(id) on delete cascade,
  cell uuid not null references sectalk_private.st_v8_residency_cells(id) on delete cascade,
  primary key(workspace,cell)
);
-- This installation marker is provisioned on a project using separate deployment credentials.
create table sectalk_private.st_v8_residency_installation (
  singleton boolean primary key default true check(singleton),
  cell uuid not null unique references sectalk_private.st_v8_residency_cells(id),
  installation_nonce uuid not null unique
);
create table sectalk_private.st_v8_residency_verifiers (
  workspace uuid not null references public.st_v2_workspaces(id) on delete cascade,
  actor uuid not null references auth.users(id) on delete cascade,
  primary key(workspace,actor)
);
create table sectalk_private.st_v8_residency_requests (
  id uuid primary key default gen_random_uuid(),
  workspace uuid not null references public.st_v2_workspaces(id) on delete cascade,
  cell uuid not null references sectalk_private.st_v8_residency_cells(id),
  requester uuid not null,
  requested_at timestamptz not null default statement_timestamp(),
  observed_at timestamptz,
  observation_nonce uuid,
  reviewed_by uuid,
  reviewed_at timestamptz,
  withdrawn_at timestamptz,
  check((observed_at is null)=(observation_nonce is null)),
  check((reviewed_at is null)=(reviewed_by is null)),
  check(reviewed_by is null or (reviewed_by<>requester and observed_at is not null))
);
create unique index st_v8_residency_open_request on sectalk_private.st_v8_residency_requests(workspace) where withdrawn_at is null;
create table sectalk_private.st_v8_residency_audit (
  id bigint generated always as identity primary key,
  request uuid not null,
  workspace uuid not null,
  cell uuid not null,
  actor uuid,
  action text not null check(action in ('requested','observed','reviewed','withdrawn')),
  occurred_at timestamptz not null default statement_timestamp()
);
create trigger st_v8_residency_audit_immutable before update or delete on sectalk_private.st_v8_residency_audit
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

alter table sectalk_private.st_v8_residency_cells enable row level security;
alter table sectalk_private.st_v8_residency_cell_authorizations enable row level security;
alter table sectalk_private.st_v8_residency_installation enable row level security;
alter table sectalk_private.st_v8_residency_verifiers enable row level security;
alter table sectalk_private.st_v8_residency_requests enable row level security;
alter table sectalk_private.st_v8_residency_audit enable row level security;
revoke all on sectalk_private.st_v8_residency_cells,sectalk_private.st_v8_residency_cell_authorizations,
  sectalk_private.st_v8_residency_installation,sectalk_private.st_v8_residency_verifiers,
  sectalk_private.st_v8_residency_requests,sectalk_private.st_v8_residency_audit from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_residency_owner(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    and exists(select 1 from public.st_v2_workspaces w where w.id=p_workspace and w.owner=auth.uid()
      and sectalk_private.st_v2_role(p_workspace,auth.uid())='owner');
$$;

create function public.st_v8_workspace_residency(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare entitled boolean; current_request jsonb;
begin
  if not sectalk_private.st_v8_residency_owner(p_workspace) then
    raise exception 'Workspace residency unavailable' using errcode='42501'; end if;
  entitled:=coalesce((sectalk_private.st_v7_workspace_entitlements(p_workspace)).plan='enterprise',false);
  select jsonb_build_object('id',r.id,'region',c.region,'label',c.label,'requestedAt',r.requested_at,
    'state',case when c.retired_at is not null or a.workspace is null then 'unavailable'
      when not entitled then 'paused'
      when c.environment='deployment' then 'pending_verification'
      when r.observed_at is not null and (r.observed_at<statement_timestamp()-interval '1 day'
        or r.observation_nonce is distinct from i.installation_nonce) then 'needs_verification'
      when r.reviewed_at is not null then 'fixture_target_verified'
      when r.observed_at is not null then 'independent_review_required' else 'pending_verification' end)
  into current_request from sectalk_private.st_v8_residency_requests r
  join sectalk_private.st_v8_residency_cells c on c.id=r.cell
  left join sectalk_private.st_v8_residency_cell_authorizations a on (a.workspace,a.cell)=(r.workspace,r.cell)
  left join sectalk_private.st_v8_residency_installation i on i.cell=r.cell
  where r.workspace=p_workspace and r.withdrawn_at is null;
  return jsonb_build_object('eligible',entitled,'request',current_request,
    'cells',case when entitled then coalesce((select jsonb_agg(to_jsonb(x)) from (
      select c.id,c.region,c.label,c.environment from sectalk_private.st_v8_residency_cells c
      join sectalk_private.st_v8_residency_cell_authorizations a on a.cell=c.id
      where a.workspace=p_workspace and c.retired_at is null order by c.region,c.label,c.id limit 30
    ) x),'[]'::jsonb) else '[]'::jsonb end);
end $$;

create function public.st_v8_workspace_residency_change(p_workspace uuid,p_cell uuid default null)
returns uuid language plpgsql security definer set search_path='' as $$
declare current_request sectalk_private.st_v8_residency_requests; receipt uuid; actor uuid:=auth.uid();
begin
  perform 1 from public.st_v2_workspaces where id=p_workspace and owner=actor for no key update;
  if not found or not sectalk_private.st_v8_residency_owner(p_workspace)
    or public.st_v7_sensitive_action_status('room_role') is distinct from 'verified' then
    raise exception 'Verified workspace owner required' using errcode='42501'; end if;
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

-- A deployment probe must execute against the real target project. The local
-- fixture can demonstrate that handshake, never verifying hosted geography or cutover.
create function public.st_v8_observe_residency_fixture(p_request uuid,p_project text,p_installation_nonce uuid)
returns boolean language plpgsql security definer set search_path='' as $$
declare target sectalk_private.st_v8_residency_requests;
begin
  select r.* into target from sectalk_private.st_v8_residency_requests r
  join sectalk_private.st_v8_residency_cells c on c.id=r.cell and c.environment='fixture' and c.retired_at is null
  join sectalk_private.st_v8_residency_installation i on i.cell=c.id
  join sectalk_private.st_v8_residency_cell_authorizations a on (a.workspace,a.cell)=(r.workspace,r.cell)
  join public.st_v2_workspaces w on w.id=r.workspace
  where r.id=p_request and r.withdrawn_at is null and c.project_reference=p_project
    and i.installation_nonce=p_installation_nonce
    and (sectalk_private.st_v7_workspace_entitlements(r.workspace)).plan='enterprise'
    and exists(select 1 from storage.buckets where id='sectalk-exports' and public=false)
    and exists(select 1 from storage.objects o where o.bucket_id='sectalk-exports'
      and o.name='residency-fixture/'||r.id::text and o.created_at>=r.requested_at
      and o.metadata->>'mimetype'='application/json')
  for update of r;
  if target.id is null then return false; end if;
  if target.observation_nonce=p_installation_nonce and target.observed_at>=statement_timestamp()-interval '1 day' then return true; end if;
  update sectalk_private.st_v8_residency_requests
    set observed_at=statement_timestamp(),observation_nonce=p_installation_nonce,reviewed_at=null,reviewed_by=null where id=target.id;
  insert into sectalk_private.st_v8_residency_audit(request,workspace,cell,action)
    values(target.id,target.workspace,target.cell,'observed');
  return true;
end $$;

create function public.st_v8_review_residency_fixture(p_request uuid)
returns boolean language plpgsql security definer set search_path='' as $$
declare target sectalk_private.st_v8_residency_requests; reviewer_id uuid:=auth.uid();
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false) or not sectalk_private.st_v7_admin_fresh() then
    raise exception 'Verified independent residency reviewer required' using errcode='42501'; end if;
  select r.* into target from sectalk_private.st_v8_residency_requests r
    join sectalk_private.st_v8_residency_installation i on i.cell=r.cell and i.installation_nonce=r.observation_nonce
    join sectalk_private.st_v8_residency_cells c on c.id=r.cell and c.retired_at is null and c.environment='fixture'
    join sectalk_private.st_v8_residency_cell_authorizations a on (a.workspace,a.cell)=(r.workspace,r.cell)
    join sectalk_private.st_v8_residency_verifiers v on v.workspace=r.workspace and v.actor=reviewer_id
    join public.st_v2_workspaces w on w.id=r.workspace and w.owner<>reviewer_id
    where r.id=p_request and r.requester<>reviewer_id and r.withdrawn_at is null
      and r.observed_at>=statement_timestamp()-interval '1 day'
      and (sectalk_private.st_v7_workspace_entitlements(r.workspace)).plan='enterprise'
    for update of r;
  if target.id is null then return false; end if;
  if target.reviewed_at is not null then return true; end if;
  perform sectalk_private.limit_action('v8_residency_review',20);
  update sectalk_private.st_v8_residency_requests set reviewed_at=statement_timestamp(),reviewed_by=reviewer_id where id=target.id;
  insert into sectalk_private.st_v8_residency_audit(request,workspace,cell,actor,action)
    values(target.id,target.workspace,target.cell,reviewer_id,'reviewed');
  return true;
end $$;

revoke all on function sectalk_private.st_v8_residency_owner(uuid),public.st_v8_workspace_residency(uuid),
  public.st_v8_workspace_residency_change(uuid,uuid),public.st_v8_observe_residency_fixture(uuid,text,uuid),
  public.st_v8_review_residency_fixture(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_residency(uuid),public.st_v8_workspace_residency_change(uuid,uuid),
  public.st_v8_review_residency_fixture(uuid) to authenticated;
grant execute on function public.st_v8_observe_residency_fixture(uuid,text,uuid) to service_role;
notify pgrst,'reload schema';
commit;
