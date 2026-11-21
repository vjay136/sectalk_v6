begin;

create table sectalk_private.st_v8_residency_retired_destinations (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  receipt uuid not null unique default gen_random_uuid(),
  handoff uuid not null,
  approval uuid not null,
  source_project text not null,
  destination_project text not null,
  review uuid not null,
  review_sha256 text not null check (review_sha256~'^[0-9a-f]{64}$'),
  plan_sha256 text not null check (plan_sha256~'^[0-9a-f]{64}$'),
  owner uuid not null,
  reviewer uuid not null,
  retired_at timestamptz not null default clock_timestamp(),
  check (owner<>reviewer and source_project<>destination_project)
);
alter table sectalk_private.st_v8_residency_retired_destinations enable row level security;
revoke all on sectalk_private.st_v8_residency_retired_destinations from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v8_residency_rollback_side(p_workspace uuid)
returns text language sql stable set search_path='' as $$
  select case when exists(select 1 from sectalk_private.st_v8_residency_retired_destinations d where d.workspace=p_workspace)
    then 'destination' else (
      select x.side from sectalk_private.st_v8_residency_rollback_holds x
      join sectalk_private.st_v8_residency_write_handoffs f using(workspace,approval,handoff)
      where x.workspace=p_workspace
        and ((x.side='source' and f.phase='held') or (x.side='destination' and f.phase='activated'))
    ) end
$$;

create function public.st_v8_residency_retire_destination(p_workspace uuid,p_action text default 'status',
  p_confirmation text default null) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor_id uuid:=auth.uid();
  transfer sectalk_private.st_v8_residency_write_handoffs;
  admission sectalk_private.st_v8_residency_rollback_manifest_admissions;
  retired sectalk_private.st_v8_residency_retired_destinations;
  reviewed sectalk_private.st_v8_residency_rollback_reviews;
  current_review jsonb;
  signing_key bytea;
  wire text;
begin
  if p_workspace is null or not coalesce(p_action in ('status','issue'),false)
    or sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'owner'
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    then raise insufficient_privilege; end if;
  if p_action='issue' then
    if p_confirmation is distinct from p_workspace::text or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
      then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces w where (w.id,w.owner)=(p_workspace,actor_id) for share;
    if not found then raise insufficient_privilege; end if;
    perform sectalk_private.limit_action('v8_residency_retire_destination',12);
  end if;

  select f.* into transfer from sectalk_private.st_v8_residency_write_handoffs f
    join sectalk_private.st_v8_residency_rollback_holds h using(workspace,approval,handoff)
    where f.workspace=p_workspace and f.phase='activated' and h.side='destination';
  if not found then
    if p_action='status' then return '{"state":"inactive"}'::jsonb; end if;
    raise insufficient_privilege;
  end if;
  select d.* into retired from sectalk_private.st_v8_residency_retired_destinations d where d.workspace=p_workspace;
  current_review:=public.st_v8_residency_rollback_reconcile(p_workspace);
  if current_review->>'state' is distinct from 'reviewed' then
    if p_action='status' then return jsonb_build_object('state','review_required','retired',retired.receipt is not null); end if;
    raise exception 'A current, independent destination review is required.' using errcode='PT409';
  end if;
  select q.* into reviewed from sectalk_private.st_v8_residency_rollback_reviews q
    where (q.handoff,q.id,q.digest,q.requester)=(transfer.handoff,(current_review->>'id')::uuid,current_review->>'digest',actor_id)
      and q.reviewed_at is not null and q.reviewer<>actor_id
      and sectalk_private.st_v8_offboarding_role(p_workspace,q.reviewer)='reviewer';
  if not found then raise insufficient_privilege; end if;
  select a.* into admission from sectalk_private.st_v8_residency_rollback_manifest_admissions a
    where a.handoff=transfer.handoff and a.expires_at>statement_timestamp();
  if not found then
    if p_action='status' then return jsonb_build_object('state','admission_required','retired',retired.receipt is not null); end if;
    raise insufficient_privilege;
  end if;
  if retired.receipt is not null and (retired.handoff,retired.approval,retired.source_project,retired.destination_project,
      retired.review,retired.review_sha256,retired.plan_sha256,retired.owner,retired.reviewer)
    is distinct from (transfer.handoff,transfer.approval,transfer.source_project,transfer.destination_project,
      reviewed.id,reviewed.digest,admission.plan_sha256,actor_id,reviewed.reviewer) then
    if p_action='status' then return '{"state":"review_changed","retired":true}'::jsonb; end if;
    raise exception 'The destination review differs from the retired handoff.' using errcode='PT409';
  end if;
  if p_action='status' then return jsonb_build_object('state',case when retired.receipt is null then 'ready' else 'retired' end,
    'receipt',retired.receipt,'review',reviewed.id,'digest',reviewed.digest); end if;

  perform 1 from sectalk_private.st_v8_offboarding_reviewers r
    join public.st_v2_members m on (m.workspace_id,m.user_id)=(r.workspace,r.actor)
    where (r.workspace,r.actor)=(p_workspace,reviewed.reviewer) and m.role='admin' and m.suspended_at is null for share of r,m;
  if not found then raise insufficient_privilege; end if;
  select decode(v.decrypted_secret,'hex') into signing_key from vault.decrypted_secrets v
    where v.id=admission.vault_id and v.decrypted_secret~'^[0-9a-f]{64}$';
  if not found then raise insufficient_privilege; end if;
  if retired.receipt is null then
    insert into sectalk_private.st_v8_residency_retired_destinations(workspace,handoff,approval,source_project,destination_project,
      review,review_sha256,plan_sha256,owner,reviewer)
      values(p_workspace,transfer.handoff,transfer.approval,transfer.source_project,transfer.destination_project,
        reviewed.id,reviewed.digest,admission.plan_sha256,actor_id,reviewed.reviewer) returning * into retired;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor_id,'workspace.residency_rollback_destination_retired',retired.receipt);
  end if;
  wire:=jsonb_build_object('format','sectalk-residency-retired-destination-v1','workspace',p_workspace,
    'handoff',retired.handoff,'approval',retired.approval,'source',retired.source_project,'destination',retired.destination_project,
    'review',retired.review,'digest',retired.review_sha256,'plan',retired.plan_sha256,'receipt',retired.receipt,
    'expires',floor(extract(epoch from least(admission.expires_at,statement_timestamp()+interval '5 minutes'))))::text;
  return jsonb_build_object('state','retired','receipt',retired.receipt,'review',retired.review,'digest',retired.review_sha256,
    'packet',jsonb_build_object('payload',wire,'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),'hex')));
end $$;

revoke all on function public.st_v8_residency_retire_destination(uuid,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_retire_destination(uuid,text,text) to authenticated;
notify pgrst,'reload schema';
commit;
