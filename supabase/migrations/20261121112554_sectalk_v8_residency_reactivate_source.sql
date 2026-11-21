begin;

create table sectalk_private.st_v8_residency_source_reactivations (
  handoff uuid primary key,
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  destination_receipt uuid not null unique,
  source_evidence uuid not null,
  source_digest text not null check (source_digest~'^[0-9a-f]{64}$'),
  proof_digest text not null check (proof_digest~'^[0-9a-f]{64}$'),
  actor uuid not null,
  reopened_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v8_residency_source_reactivations enable row level security;
revoke all on sectalk_private.st_v8_residency_source_reactivations from public,anon,authenticated,service_role;

create function public.st_v8_residency_reactivate_source(p_workspace uuid,p_action text default 'status',
  p_confirmation text default null,p_packet jsonb default null) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor_id uuid:=auth.uid();
  transfer sectalk_private.st_v8_residency_write_handoffs;
  manifest sectalk_private.st_v8_residency_rollback_manifests;
  admission sectalk_private.st_v8_residency_rollback_manifest_admissions;
  reactivation sectalk_private.st_v8_residency_source_reactivations;
  evidence jsonb;
  current_evidence jsonb;
  wire text;
  claim jsonb;
  packet_digest text;
  signing_key bytea;
  expiry bigint;
  now_epoch bigint;
begin
  if p_workspace is null or not coalesce(p_action in ('status','reopen'),false)
    or sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'owner'
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    then raise insufficient_privilege; end if;
  if p_action='reopen' then
    if p_confirmation is distinct from p_workspace::text
      or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
      or not coalesce(jsonb_typeof(p_packet)='object' and octet_length(p_packet::text)<=3072
        and p_packet-array['payload','signature']='{}'::jsonb and jsonb_typeof(p_packet->'payload')='string'
        and p_packet->>'signature'~'^[0-9a-f]{64}$',false) then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces w where (w.id,w.owner)=(p_workspace,actor_id) for share;
    if not found then raise insufficient_privilege; end if;
    packet_digest:=encode(sha256(convert_to(p_packet::text,'UTF8')),'hex');
  end if;

  select f.* into transfer from sectalk_private.st_v8_residency_write_handoffs f where f.workspace=p_workspace;
  select r.* into reactivation from sectalk_private.st_v8_residency_source_reactivations r
    where (r.workspace,r.handoff)=(p_workspace,transfer.handoff);
  if transfer.phase='restored' and reactivation.handoff is not null then
    if p_action='reopen' and (reactivation.proof_digest,reactivation.actor) is distinct from (packet_digest,actor_id)
      then raise exception 'This source already reopened with a different receipt.' using errcode='PT409'; end if;
    return jsonb_build_object('state','reopened','receipt',reactivation.destination_receipt,'reopenedAt',reactivation.reopened_at);
  end if;
  if sectalk_private.st_v8_residency_rollback_side(p_workspace) is distinct from 'source' then
    if p_action='status' then return '{"state":"inactive"}'::jsonb; end if;
    raise insufficient_privilege;
  end if;

  if p_action='reopen' then
    perform sectalk_private.limit_action('v8_residency_reactivate_source',12);
    select m.* into manifest from sectalk_private.st_v8_residency_rollback_manifests m
      where (m.workspace,m.handoff)=(p_workspace,transfer.handoff);
    if not found then raise insufficient_privilege; end if;
    select a.* into admission from sectalk_private.st_v8_residency_rollback_manifest_admissions a
      where (a.handoff,a.plan_sha256)=(manifest.handoff,manifest.plan_sha256) and a.expires_at>clock_timestamp();
    if not found then raise insufficient_privilege; end if;
    select decode(v.decrypted_secret,'hex') into signing_key from vault.decrypted_secrets v
      where v.id=admission.vault_id and v.decrypted_secret~'^[0-9a-f]{64}$';
    if not found then raise insufficient_privilege; end if;
    wire:=p_packet->>'payload';
    if extensions.hmac(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),signing_key,'sha256')
      <>extensions.hmac(decode(p_packet->>'signature','hex'),signing_key,'sha256') then raise insufficient_privilege; end if;
    claim:=wire::jsonb;
    if (claim->>'format',claim->>'workspace',claim->>'handoff',claim->>'approval',claim->>'source',claim->>'destination',
        claim->>'review',claim->>'digest',claim->>'plan') is distinct from
      ('sectalk-residency-retired-destination-v1',p_workspace::text,transfer.handoff::text,transfer.approval::text,
        transfer.source_project,transfer.destination_project,manifest.review::text,manifest.review_sha256,manifest.plan_sha256)
      or not coalesce(claim->>'expires'~'^[0-9]{1,12}$'
        and claim->>'receipt'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$',false) then raise insufficient_privilege; end if;
    expiry:=(claim->>'expires')::bigint;
    now_epoch:=floor(extract(epoch from clock_timestamp()));
    if expiry<=now_epoch or expiry>least(now_epoch+300,floor(extract(epoch from admission.expires_at)))
      then raise insufficient_privilege; end if;

    -- Freeze native rows that permit local safety or moderation changes during the recovery window.
    perform 1 from public.st_v2_items i join jsonb_array_elements(manifest.changes) e on (e->>'id')::uuid=i.id
      where i.workspace_id=p_workspace and e->>'kind'='workspace_task' order by i.id for share of i;
    perform 1 from public.st_v2_channels c where c.workspace_id=p_workspace and (exists(
      select 1 from jsonb_array_elements(manifest.changes) e where (e->>'kind',(e->>'id')::uuid)=('channel',c.id)) or exists(
      select 1 from public.st_v2_posts p join jsonb_array_elements(manifest.changes) e on (e->>'id')::uuid=p.id
      where p.channel_id=c.id and e->>'kind'='channel_message')) order by c.id for share of c;
    perform 1 from public.st_v2_posts p join jsonb_array_elements(manifest.changes) e on (e->>'id')::uuid=p.id
      join public.st_v2_channels c on c.id=p.channel_id and c.workspace_id=p_workspace
      where e->>'kind'='channel_message' order by p.id for share of p;
  end if;

  evidence:=public.st_v8_residency_source_evidence(p_workspace);
  if p_action='status' then
    return jsonb_build_object('state',case when evidence->>'coverage'='reviewed' then 'ready' else 'review_required' end);
  end if;
  if evidence->>'coverage' is distinct from 'reviewed' then
    raise exception 'A current independent source sign-off is required.' using errcode='PT409'; end if;
  -- Reuse the sign-off transaction's file locks and exact current-coverage check.
  current_evidence:=public.st_v8_residency_source_evidence(p_workspace,'capture',p_workspace::text,
    (evidence->>'evidenceId')::uuid,evidence->>'evidenceDigest');
  if (current_evidence->>'coverage',current_evidence->>'evidenceId') is distinct from ('reviewed',evidence->>'evidenceId')
    or expiry<=floor(extract(epoch from clock_timestamp())) then
    raise exception 'The source sign-off or destination proof is no longer current.' using errcode='PT409'; end if;

  insert into sectalk_private.st_v8_residency_source_reactivations(handoff,workspace,destination_receipt,source_evidence,
    source_digest,proof_digest,actor) values(transfer.handoff,p_workspace,(claim->>'receipt')::uuid,(evidence->>'evidenceId')::uuid,
      evidence->>'evidenceDigest',packet_digest,actor_id) returning * into reactivation;
  update sectalk_private.st_v8_residency_write_handoffs f set phase='restored',changed_at=reactivation.reopened_at
    where (f.workspace,f.handoff,f.phase)=(p_workspace,transfer.handoff,'held');
  if not found then raise insufficient_privilege; end if;
  update sectalk_private.st_v8_residency_source_pauses p set resumed_at=reactivation.reopened_at
    from sectalk_private.st_v8_residency_requests r join sectalk_private.st_v8_residency_cells c on c.id=r.cell
    where (p.workspace,p.request)=(r.workspace,r.id) and p.workspace=p_workspace and p.resumed_at is null
      and p.started_at<=transfer.changed_at and c.project_reference=transfer.destination_project;
  delete from sectalk_private.st_v8_residency_rollback_holds h
    where (h.workspace,h.approval,h.handoff,h.side)=(p_workspace,transfer.approval,transfer.handoff,'source');
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor_id,'workspace.residency_rollback_source_reopened',reactivation.destination_receipt);
  return jsonb_build_object('state','reopened','receipt',reactivation.destination_receipt,'reopenedAt',reactivation.reopened_at);
end $$;

revoke all on function public.st_v8_residency_reactivate_source(uuid,text,text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_reactivate_source(uuid,text,text,jsonb) to authenticated;
notify pgrst,'reload schema';
commit;
