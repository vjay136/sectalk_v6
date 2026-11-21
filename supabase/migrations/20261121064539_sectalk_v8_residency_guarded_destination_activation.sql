begin;

alter table sectalk_private.st_v8_residency_write_handoffs drop constraint st_v8_residency_write_handoffs_phase_check;
alter table sectalk_private.st_v8_residency_write_handoffs add constraint st_v8_residency_write_handoffs_phase_check
  check (phase in ('standby','cancelled','held','restored','activated'));

create function sectalk_private.st_v8_residency_active_destination_immutable()
returns trigger language plpgsql set search_path='' as $$
begin
  raise exception 'The destination is active. Standby cancellation is unavailable after activation.' using errcode='PT409';
end $$;
revoke all on function sectalk_private.st_v8_residency_active_destination_immutable() from public,anon,authenticated,service_role;
create trigger st_v8_residency_active_destination_immutable before update of phase on sectalk_private.st_v8_residency_write_handoffs
  for each row when (old.phase='activated' and new.phase is distinct from old.phase)
  execute function sectalk_private.st_v8_residency_active_destination_immutable();

-- Installation operators admit the exact, independently reviewed plan and recovery evidence on each project.
create table sectalk_private.st_v8_residency_activation_admissions (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  approval uuid not null,
  handoff uuid not null,
  side text not null check (side in ('source','destination')),
  environment text not null check (environment in ('fixture','deployment')),
  manifest_sha256 text not null check (manifest_sha256~'^[0-9a-f]{64}$'),
  plan_sha256 text not null check (plan_sha256~'^[0-9a-f]{64}$'),
  recovery_sha256 text not null check (recovery_sha256~'^[0-9a-f]{64}$'),
  expires_at timestamptz not null
);
alter table sectalk_private.st_v8_residency_activation_admissions enable row level security;
revoke all on sectalk_private.st_v8_residency_activation_admissions from public,anon,authenticated,service_role;

create function public.st_v8_residency_cutover(p_workspace uuid,p_action text default 'status',
  p_approval uuid default null,p_confirmation text default null,p_proof jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); scope record; review record; coverage jsonb; comparison jsonb; wire text; claims jsonb;
  key_bytes bytea; mac bytea; now_epoch bigint; expires bigint;
begin
  if p_workspace is null or p_action is null or p_action not in ('status','issue','activate')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or sectalk_private.st_v8_offboarding_role(p_workspace,actor) is distinct from 'owner'
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if p_approval is null or p_confirmation is distinct from p_workspace::text
      or not coalesce(sectalk_private.st_v7_admin_fresh(),false) then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces w where (w.id,w.owner)=(p_workspace,actor) for share;
    if not found then raise insufficient_privilege; end if;
  end if;

  select f.approval,f.handoff,f.source_project,f.destination_project,f.phase,f.changed_at,
      a.side,a.environment,a.manifest_sha256,a.plan_sha256,a.recovery_sha256,h.vault_id,v.decrypted_secret secret,
      least(a.expires_at,h.expires_at,statement_timestamp()+interval '5 minutes') expiry
    into scope from sectalk_private.st_v8_residency_write_handoffs f
    join sectalk_private.st_v8_residency_activation_admissions a on (a.workspace,a.approval,a.handoff)=(f.workspace,f.approval,f.handoff)
    join sectalk_private.st_v8_residency_history_links h on
      (h.workspace,h.approval,h.side,h.source_project,h.destination_project)=(f.workspace,f.approval,a.side,f.source_project,f.destination_project)
    join vault.decrypted_secrets v on v.id=h.vault_id
    where f.workspace=p_workspace and (p_approval is null or f.approval=p_approval)
      and least(a.expires_at,h.expires_at)>statement_timestamp() and v.decrypted_secret~'^[0-9a-f]{64}$'
      and ((a.side='source' and f.phase='held' and exists(
        select 1 from sectalk_private.st_v8_residency_requests r
        join sectalk_private.st_v8_residency_cells t on t.id=r.cell and t.retired_at is null
        where r.workspace=p_workspace and r.requester=actor and r.withdrawn_at is null
          and (t.project_reference,t.environment)=(f.destination_project,a.environment)
        )) or (a.side='destination' and f.phase='standby' and exists(
        select 1 from sectalk_private.st_v8_residency_workspace_claims c
        join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
        join sectalk_private.st_v8_residency_cells t on t.id=c.cell and t.retired_at is null
        where (c.workspace,c.approval,c.source_project,c.owner_id,c.manifest_sha256)=
          (p_workspace,f.approval,f.source_project,actor,a.manifest_sha256) and c.claimed_at is not null
          and c.expires_at>statement_timestamp() and (t.project_reference,t.environment)=(f.destination_project,a.environment)
        )));
  if not found then
    if p_action='status' then return '{"admitted":false}'::jsonb; end if;
    raise insufficient_privilege;
  end if;
  if p_action='status' then return jsonb_build_object('admitted',true,'side',scope.side,'approval',scope.approval); end if;
  if (p_action='issue') is distinct from (scope.side='source') then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_residency_cutover',10);
  key_bytes:=decode(scope.secret,'hex');

  if p_action='issue' then
    if (public.st_v8_workspace_residency(p_workspace)#>>'{request,state}') is distinct from
      (case when scope.environment='deployment' then 'provider_target_verified' else 'fixture_target_verified' end) then
      raise exception 'The destination verification is no longer current.' using errcode='PT409'; end if;
    select c.record_count,c.expires_at,r.id,r.counts,r.checked_at,r.reviewed_at,r.expires_at as receipt_expiry
      into review from sectalk_private.st_v8_content_exports c
      join lateral (
        select x.* from sectalk_private.st_v8_residency_comparison_receipts x
        where (x.workspace,x.approval,x.manifest_sha256,x.destination,x.vault_id,x.reviewed_by)=
          (p_workspace,c.id,scope.manifest_sha256,scope.destination_project,scope.vault_id,c.reviewer)
        order by x.checked_at desc,x.reviewed_at desc limit 1
      ) r on true
      where (c.id,c.workspace,c.requester,c.manifest_sha256)=(scope.approval,p_workspace,actor,scope.manifest_sha256)
        and c.withdrawn_at is null and c.approved_at is not null and c.expires_at>statement_timestamp()
        and sectalk_private.st_v8_offboarding_role(p_workspace,c.reviewer)='reviewer';
    if not found or review.record_count<1 or (review.counts->>'matched')::integer is distinct from review.record_count
      or review.checked_at<scope.changed_at or review.reviewed_at<scope.changed_at
      or review.receipt_expiry<=statement_timestamp() then
      raise exception 'The held source needs a current independent comparison with every approved record matched.' using errcode='PT409'; end if;
    coverage:=public.st_v8_residency_source_coverage(p_workspace,p_approval);
    if (coverage->>'approvedRecords')::integer is distinct from review.record_count or
      exists(select 1 from jsonb_array_elements(coverage->'families') f where
        (f->>'capped')::boolean is distinct from false or (f->>'unapproved')::integer<>0 or (f->>'drifted')::integer<>0)
      then raise exception 'Source coverage changed or includes unapproved records.' using errcode='PT409'; end if;
    wire:=jsonb_build_object('format','sectalk-guarded-activation-v1','workspace',p_workspace,'approval',p_approval,
      'handoff',scope.handoff,'source',scope.source_project,'destination',scope.destination_project,'environment',scope.environment,
      'manifest',scope.manifest_sha256,'plan',scope.plan_sha256,'recovery',scope.recovery_sha256,'review',review.id,
      'records',review.record_count,'expires',floor(extract(epoch from least(scope.expiry,review.expires_at,review.receipt_expiry))))::text;
    return jsonb_build_object('proof',jsonb_build_object('payload',wire,
      'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),key_bytes,'sha256'),'hex')));
  end if;

  if not coalesce(jsonb_typeof(p_proof)='object' and octet_length(p_proof::text)<=2400,false)
    or not coalesce(p_proof->>'signature'~'^[0-9a-f]{64}$' and octet_length(p_proof->>'payload') between 80 and 1900,false)
    then raise insufficient_privilege; end if;
  wire:=p_proof->>'payload';
  mac:=extensions.hmac(convert_to(wire,'UTF8'),key_bytes,'sha256');
  if extensions.hmac(mac,key_bytes,'sha256')<>extensions.hmac(decode(p_proof->>'signature','hex'),key_bytes,'sha256')
    then raise insufficient_privilege; end if;
  claims:=wire::jsonb;
  now_epoch:=floor(extract(epoch from clock_timestamp()));
  expires:=(claims->>'expires')::bigint;
  if (claims->>'format',claims->>'workspace',claims->>'approval',claims->>'handoff',claims->>'source',claims->>'destination',
        claims->>'environment',claims->>'manifest',claims->>'plan',claims->>'recovery')
    is distinct from ('sectalk-guarded-activation-v1',p_workspace::text,p_approval::text,scope.handoff::text,
      scope.source_project,scope.destination_project,scope.environment,scope.manifest_sha256,scope.plan_sha256,scope.recovery_sha256)
    or expires is null or expires<=now_epoch or expires>now_epoch+303 then raise insufficient_privilege; end if;
  comparison:=public.st_v8_residency_compare_destination(p_workspace,p_approval);
  if not coalesce((comparison->>'approvalCurrent')::boolean,false)
    or comparison->>'manifestSha256' is distinct from scope.manifest_sha256
    or (claims->>'records')::integer is distinct from jsonb_array_length(comparison->'records')
    or exists(select 1 from jsonb_array_elements(comparison->'records') r where r->>'status' is distinct from 'matched') then
    raise exception 'Every approved record must still match before activation.' using errcode='PT409'; end if;
  update sectalk_private.st_v8_residency_write_handoffs set phase='activated',changed_at=clock_timestamp()
    where (workspace,approval,handoff,phase)=(p_workspace,p_approval,scope.handoff,'standby');
  if not found then raise insufficient_privilege; end if;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor,'workspace.residency_destination_activated',scope.handoff);
  return jsonb_build_object('phase','activated','handoff',scope.handoff);
end $$;

revoke all on function public.st_v8_residency_cutover(uuid,text,uuid,text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_cutover(uuid,text,uuid,text,jsonb) to authenticated;

notify pgrst,'reload schema';
commit;
