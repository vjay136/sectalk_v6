begin;

create table sectalk_private.st_v8_residency_comparison_receipts (
  id uuid primary key default gen_random_uuid(),
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  approval uuid not null,
  manifest_sha256 text not null,
  destination text not null,
  vault_id uuid not null,
  digest text not null unique,
  counts jsonb not null,
  checked_at timestamptz not null,
  expires_at timestamptz not null,
  reviewed_by uuid not null,
  reviewed_at timestamptz not null default clock_timestamp()
);
create index st_v8_residency_receipts_latest on sectalk_private.st_v8_residency_comparison_receipts
  (workspace,approval,reviewed_at desc);
alter table sectalk_private.st_v8_residency_comparison_receipts enable row level security;
revoke all on sectalk_private.st_v8_residency_comparison_receipts from public,anon,authenticated,service_role;

create function public.st_v8_residency_issue_comparison_receipt(p_workspace uuid,p_approval uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare evidence jsonb; link record; counts jsonb; wire text; observed bigint; valid_until bigint;
begin
  evidence:=public.st_v8_residency_compare_destination(p_workspace,p_approval);
  if not coalesce((evidence->>'approvalCurrent')::boolean,false) then raise insufficient_privilege; end if;
  select h.source_project,h.destination_project,v.decrypted_secret as secret,
    least(h.expires_at,c.expires_at,a.expires_at,statement_timestamp()+interval '5 minutes') as expiry
    into link from sectalk_private.st_v8_residency_history_links h
    join vault.decrypted_secrets v on v.id=h.vault_id
    join sectalk_private.st_v8_residency_workspace_claims c on (c.workspace,c.approval,c.source_project)=(h.workspace,h.approval,h.source_project)
    join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
    join sectalk_private.st_v8_residency_cells t on (t.id,t.project_reference)=(c.cell,h.destination_project) and t.retired_at is null
    join sectalk_private.st_v8_residency_content_admissions a on (a.cell,a.workspace,a.source_project,a.approval)=
      (c.cell,c.workspace,c.source_project,c.approval)
    where (h.workspace,h.approval,h.side)=(p_workspace,p_approval,'destination') and c.claimed_at is not null
      and c.owner_id=auth.uid() and c.manifest_sha256=a.manifest_sha256 and c.manifest_sha256=evidence->>'manifestSha256'
      and h.expires_at>statement_timestamp() and v.decrypted_secret~'^[0-9a-f]{64}$';
  if not found or link.expiry<=clock_timestamp() then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_residency_comparison_receipt_issue',10);
  select jsonb_object_agg(state,total) into counts from (
    select s.state,count(r) total from unnest(array['matched','missing','changed','check_bytes','unsupported']) s(state)
    left join jsonb_array_elements(evidence->'records') r on r->>'status'=s.state group by s.state
  ) result;
  observed:=floor(extract(epoch from (evidence->>'checkedAt')::timestamptz));
  valid_until:=floor(extract(epoch from link.expiry));
  wire:=jsonb_build_object('format','sectalk-destination-comparison-v1','workspace',p_workspace,'approval',p_approval,
    'manifest',evidence->>'manifestSha256','source',link.source_project,'destination',link.destination_project,
    'counts',counts,'checked',observed,'expires',valid_until)::text;
  return jsonb_build_object('payload',wire,
    'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),decode(link.secret,'hex'),'sha256'),'hex'));
end $$;

create function public.st_v8_residency_review_comparison_receipt(p_workspace uuid,p_approval uuid,p_proof jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); link record; wire text; signature text; supplied_sig bytea; expected_sig bytea; key bytea;
  claims jsonb; counts jsonb; checked bigint; valid_until bigint; now_epoch bigint; record_count integer; saved uuid;
  receipt sectalk_private.st_v8_residency_comparison_receipts;
begin
  if p_workspace is null or p_approval is null or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
      or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    then raise insufficient_privilege; end if;
  select c.requester,c.reviewer,c.manifest_sha256,h.source_project,h.destination_project,h.vault_id,
    least(c.expires_at,h.expires_at) expiry,v.decrypted_secret as secret
    into link from sectalk_private.st_v8_content_exports c
    join sectalk_private.st_v8_residency_history_links h on (h.workspace,h.approval,h.side)=(c.workspace,c.id,'source')
    join vault.decrypted_secrets v on v.id=h.vault_id
    where (c.workspace,c.id)=(p_workspace,p_approval) and c.approved_at is not null and c.withdrawn_at is null
      and least(c.expires_at,h.expires_at)>statement_timestamp() and v.decrypted_secret~'^[0-9a-f]{64}$'
      and actor_id in (c.requester,c.reviewer)
      and sectalk_private.st_v8_offboarding_role(c.workspace,c.requester)='owner'
      and sectalk_private.st_v8_offboarding_role(c.workspace,c.reviewer)='reviewer'
    for share of c,h;
  if not found then raise insufficient_privilege; end if;

  if p_proof is not null then
    if actor_id is distinct from link.reviewer or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
      or not coalesce(jsonb_typeof(p_proof)='object' and octet_length(p_proof::text)<=2048,false)
      then raise insufficient_privilege; end if;
    wire:=p_proof->>'payload'; signature:=p_proof->>'signature';
    if not coalesce(signature~'^[0-9a-f]{64}$' and octet_length(wire) between 40 and 1400,false)
      or p_proof-array['payload','signature']<>'{}'::jsonb then raise insufficient_privilege; end if;
    perform sectalk_private.limit_action('v8_residency_comparison_receipt_review',12);
    key:=decode(link.secret,'hex'); supplied_sig:=decode(signature,'hex');
    expected_sig:=extensions.hmac(convert_to(wire,'UTF8'),key,'sha256');
    if extensions.hmac(expected_sig,key,'sha256')<>extensions.hmac(supplied_sig,key,'sha256')
      then raise insufficient_privilege; end if;
    claims:=wire::jsonb;
    if (claims->>'format',claims->>'workspace',claims->>'approval',claims->>'manifest',claims->>'source',claims->>'destination')
      is distinct from ('sectalk-destination-comparison-v1',p_workspace::text,p_approval::text,link.manifest_sha256,
        link.source_project,link.destination_project) then raise insufficient_privilege; end if;
    checked:=(claims->>'checked')::bigint; valid_until:=(claims->>'expires')::bigint;
    now_epoch:=floor(extract(epoch from clock_timestamp()));
    if checked is null or valid_until is null or checked>now_epoch+3 or checked<now_epoch-300
      or valid_until<=now_epoch or valid_until>checked+300 or valid_until>floor(extract(epoch from link.expiry))
      then raise insufficient_privilege; end if;
    counts:=claims->'counts';
    if jsonb_typeof(counts) is distinct from 'object' or not (counts ?& array['matched','missing','changed','check_bytes','unsupported'])
      or counts-array['matched','missing','changed','check_bytes','unsupported']<>'{}'::jsonb
      or exists(select 1 from jsonb_each(counts) v where jsonb_typeof(v.value)<>'number' or v.value::text!~'^[0-9]{1,3}$')
      then raise insufficient_privilege; end if;
    select count(*) into record_count from sectalk_private.st_v8_content_export_entries e where e.export_id=p_approval;
    if record_count<1 or record_count>500 or (select sum(v.value::integer) from jsonb_each(counts) v)<>record_count
      then raise insufficient_privilege; end if;

    insert into sectalk_private.st_v8_residency_comparison_receipts(workspace,approval,manifest_sha256,destination,vault_id,
      digest,counts,checked_at,expires_at,reviewed_by) values(p_workspace,p_approval,link.manifest_sha256,link.destination_project,
        link.vault_id,encode(sha256(convert_to(wire,'UTF8')),'hex'),counts,to_timestamp(checked),to_timestamp(valid_until),actor_id)
      on conflict(digest) do nothing returning id into saved;
    if saved is not null then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(p_workspace,actor_id,'workspace.residency_comparison_reviewed',saved);
    end if;
  end if;

  select * into receipt from sectalk_private.st_v8_residency_comparison_receipts r
    where (r.workspace,r.approval,r.manifest_sha256,r.destination,r.vault_id,r.reviewed_by)=
      (p_workspace,p_approval,link.manifest_sha256,link.destination_project,link.vault_id,link.reviewer)
    order by r.checked_at desc,r.reviewed_at desc limit 1;
  return jsonb_build_object('role',case when actor_id=link.reviewer then 'reviewer' else 'owner' end,
    'receipt',case when receipt.id is not null then jsonb_build_object('id',receipt.id,'counts',receipt.counts,
      'checkedAt',receipt.checked_at,'reviewedAt',receipt.reviewed_at,'expiresAt',receipt.expires_at) end);
end $$;

revoke all on function public.st_v8_residency_issue_comparison_receipt(uuid,uuid),
  public.st_v8_residency_review_comparison_receipt(uuid,uuid,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_issue_comparison_receipt(uuid,uuid),
  public.st_v8_residency_review_comparison_receipt(uuid,uuid,jsonb) to authenticated;
notify pgrst,'reload schema';
commit;
