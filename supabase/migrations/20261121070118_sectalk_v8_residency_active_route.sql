begin;

create table sectalk_private.st_v8_residency_active_routes (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  request uuid not null references sectalk_private.st_v8_residency_requests,
  approval uuid not null,
  handoff uuid not null,
  source_project text not null,
  destination_project text not null,
  environment text not null check (environment in ('fixture','deployment')),
  proof_sha256 bytea not null check (octet_length(proof_sha256)=32),
  destination_activated_at timestamptz not null,
  published_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v8_residency_active_routes enable row level security;
revoke all on sectalk_private.st_v8_residency_active_routes from public,anon,authenticated,service_role;

create function public.st_v8_residency_active_route(p_workspace uuid,p_action text default 'status',
  p_approval uuid default null,p_confirmation text default null,p_proof jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor_id uuid:=auth.uid();
  member_role text;
  owner_allowed boolean;
  request_id uuid;
  installed sectalk_private.st_v8_residency_active_routes;
  scope record;
  wire text;
  claims jsonb;
  key_bytes bytea;
  proof_hash bytea;
  activation timestamptz;
  expires bigint;
  now_epoch bigint;
  route_active boolean;
begin
  if actor_id is null or p_workspace is null or p_action is null or p_action not in ('status','issue','publish')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false) then raise insufficient_privilege; end if;
  member_role:=sectalk_private.st_v2_role(p_workspace,actor_id);
  owner_allowed:=coalesce(member_role='owner'
    and sectalk_private.st_v8_offboarding_role(p_workspace,actor_id)='owner'
    and sectalk_private.st_v8_organization_sso_allows(p_workspace),false);
  if p_action<>'status' then
    if not owner_allowed or p_approval is null or p_confirmation is distinct from p_workspace::text
      or not coalesce(sectalk_private.st_v7_admin_fresh(),false) then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces w where (w.id,w.owner)=(p_workspace,actor_id) for share;
    if not found then raise insufficient_privilege; end if;
  elsif member_role is null and not exists(select 1 from sectalk_private.st_v8_residency_verifiers v
    where (v.workspace,v.actor)=(p_workspace,actor_id) and sectalk_private.st_v2_active(v.actor)) then
    raise insufficient_privilege;
  end if;

  select * into installed from sectalk_private.st_v8_residency_active_routes a where a.workspace=p_workspace;
  if found then
    if member_role is null then return '{"status":"unavailable"}'::jsonb; end if;
    route_active:=exists(
      select 1 from sectalk_private.st_v8_residency_write_handoffs f
      join sectalk_private.st_v8_residency_requests r on (r.workspace,r.id)=(f.workspace,installed.request)
      join sectalk_private.st_v8_residency_cells c on c.id=r.cell and c.retired_at is null
      join sectalk_private.st_v8_residency_cell_authorizations a on (a.workspace,a.cell)=(r.workspace,r.cell)
      where (f.workspace,f.approval,f.handoff,f.phase,f.source_project,f.destination_project,c.project_reference,c.environment)=
        (installed.workspace,installed.approval,installed.handoff,'held',installed.source_project,
          installed.destination_project,installed.destination_project,installed.environment)
        and r.withdrawn_at is null);
    if p_action<>'status' and (p_action<>'publish' or not route_active or p_approval is distinct from installed.approval
      or p_proof is null or octet_length(p_proof::text)>2400
      or extensions.digest(p_proof::text,'sha256') is distinct from installed.proof_sha256) then
      raise exception 'The published route already has a different approval or proof, or is unavailable.' using errcode='PT409';
    end if;
    if not route_active then return '{"status":"unavailable"}'::jsonb; end if;
    return jsonb_build_object('status','active','project',installed.destination_project,'fixture',installed.environment='fixture');
  end if;
  if not owner_allowed then return '{"status":"inactive"}'::jsonb; end if;

  select f.approval,f.handoff,f.source_project,f.destination_project,f.changed_at,
      a.side,a.environment,a.manifest_sha256,a.plan_sha256,a.recovery_sha256,
      least(a.expires_at,h.expires_at,statement_timestamp()+interval '5 minutes') expiry,h.vault_id
    into scope from sectalk_private.st_v8_residency_write_handoffs f
    join sectalk_private.st_v8_residency_activation_admissions a on (a.workspace,a.approval,a.handoff)=(f.workspace,f.approval,f.handoff)
    join sectalk_private.st_v8_residency_history_links h on
      (h.workspace,h.approval,h.side,h.source_project,h.destination_project)=(f.workspace,f.approval,a.side,f.source_project,f.destination_project)
    where f.workspace=p_workspace and (p_approval is null or f.approval=p_approval)
      and least(a.expires_at,h.expires_at)>statement_timestamp()
      and ((a.side='source' and f.phase='held') or (a.side='destination' and f.phase='activated' and exists(
        select 1 from sectalk_private.st_v8_residency_workspace_claims c
        join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
        join sectalk_private.st_v8_residency_cells t on t.id=c.cell and t.retired_at is null
        where (c.workspace,c.approval,c.source_project,c.owner_id,c.manifest_sha256)=
          (p_workspace,f.approval,f.source_project,actor_id,a.manifest_sha256)
          and c.claimed_at is not null and (t.project_reference,t.environment)=(f.destination_project,a.environment))));
  if not found then
    if p_action='status' then return '{"status":"inactive"}'::jsonb; end if;
    raise insufficient_privilege;
  end if;
  if scope.side='source' then
    select r.id into request_id from sectalk_private.st_v8_residency_requests r
    join sectalk_private.st_v8_residency_cells t on t.id=r.cell and t.retired_at is null
    join sectalk_private.st_v8_residency_cell_authorizations a on (a.workspace,a.cell)=(r.workspace,r.cell)
    where r.workspace=p_workspace and r.requester=actor_id and r.withdrawn_at is null
      and (t.project_reference,t.environment)=(scope.destination_project,scope.environment)
      for share of r,t,a;
    if not found then
      if p_action='status' then return '{"status":"inactive"}'::jsonb; end if;
      raise insufficient_privilege;
    end if;
  end if;
  if p_action='status' then return jsonb_build_object('status','ready','side',scope.side,'approval',scope.approval); end if;
  if (p_action='issue') is distinct from (scope.side='destination') then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_residency_active_route',10);
  select decode(v.decrypted_secret,'hex') into key_bytes from vault.decrypted_secrets v
    where v.id=scope.vault_id and v.decrypted_secret~'^[0-9a-f]{64}$';
  if not found then raise insufficient_privilege; end if;

  if p_action='issue' then
    wire:=jsonb_build_object('format','sectalk-active-residency-route-v1','workspace',p_workspace,'approval',p_approval,
      'handoff',scope.handoff,'source',scope.source_project,'destination',scope.destination_project,'environment',scope.environment,
      'manifest',scope.manifest_sha256,'plan',scope.plan_sha256,'recovery',scope.recovery_sha256,
      'activated',scope.changed_at,'expires',floor(extract(epoch from scope.expiry)))::text;
    return jsonb_build_object('proof',jsonb_build_object('payload',wire,
      'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),key_bytes,'sha256'),'hex')));
  end if;

  if not coalesce(jsonb_typeof(p_proof)='object' and octet_length(p_proof::text)<=2400,false)
    or not coalesce(p_proof->>'signature'~'^[0-9a-f]{64}$' and octet_length(p_proof->>'payload') between 80 and 1900,false)
    then raise insufficient_privilege; end if;
  wire:=p_proof->>'payload';
  if extensions.hmac(extensions.hmac(convert_to(wire,'UTF8'),key_bytes,'sha256'),key_bytes,'sha256')
    <>extensions.hmac(decode(p_proof->>'signature','hex'),key_bytes,'sha256') then raise insufficient_privilege; end if;
  claims:=wire::jsonb;
  now_epoch:=floor(extract(epoch from clock_timestamp()));
  expires:=(claims->>'expires')::bigint;
  activation:=(claims->>'activated')::timestamptz;
  if (claims->>'format',claims->>'workspace',claims->>'approval',claims->>'handoff',claims->>'source',claims->>'destination',
        claims->>'environment',claims->>'manifest',claims->>'plan',claims->>'recovery')
    is distinct from ('sectalk-active-residency-route-v1',p_workspace::text,p_approval::text,scope.handoff::text,
      scope.source_project,scope.destination_project,scope.environment,scope.manifest_sha256,scope.plan_sha256,scope.recovery_sha256)
    or activation is null or activation<scope.changed_at-interval '3 seconds' or activation>clock_timestamp()+interval '3 seconds'
    or expires is null or expires<=now_epoch or expires>now_epoch+303 then raise insufficient_privilege; end if;
  if (public.st_v8_workspace_residency(p_workspace)#>>'{request,state}') is distinct from
    (case when scope.environment='deployment' then 'provider_target_verified' else 'fixture_target_verified' end) then
    raise exception 'The destination verification is no longer current.' using errcode='PT409'; end if;

  proof_hash:=extensions.digest(p_proof::text,'sha256');
  insert into sectalk_private.st_v8_residency_active_routes
    (workspace,request,approval,handoff,source_project,destination_project,environment,proof_sha256,destination_activated_at)
    values(p_workspace,request_id,p_approval,scope.handoff,scope.source_project,scope.destination_project,
      scope.environment,proof_hash,activation);
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor_id,'workspace.residency_active_route_published',scope.handoff);
  return jsonb_build_object('status','active','project',scope.destination_project,'fixture',scope.environment='fixture');
end $$;

revoke all on function public.st_v8_residency_active_route(uuid,text,uuid,text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_active_route(uuid,text,uuid,text,jsonb) to authenticated;
notify pgrst,'reload schema';
commit;
