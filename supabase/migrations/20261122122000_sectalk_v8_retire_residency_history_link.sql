begin;

create table sectalk_private.st_v8_residency_history_link_retirements (
  workspace uuid not null,
  approval uuid not null,
  side text not null check (side in ('source','destination')),
  link_expires_at timestamptz not null,
  vault_row_removed boolean not null,
  reference text not null check (char_length(reference) between 8 and 160),
  retired_by name not null default current_user,
  retired_at timestamptz not null default clock_timestamp(),
  primary key(workspace,approval,side)
);
alter table sectalk_private.st_v8_residency_history_link_retirements enable row level security;
revoke all on sectalk_private.st_v8_residency_history_link_retirements from public,anon,authenticated,service_role;
create trigger st_v8_residency_history_link_retirements_immutable before update or delete
  on sectalk_private.st_v8_residency_history_link_retirements
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

create or replace function sectalk_private.st_v8_guard_residency_history_link()
returns trigger language plpgsql security invoker set search_path='' as $$
declare workspace_id uuid;
begin
  if current_setting('transaction_isolation') not in ('read committed','read uncommitted') then
    raise exception 'Regional history link changes require a fresh database snapshot.' using errcode='25000';
  end if;
  if tg_op='UPDATE' and (new.workspace,new.approval,new.side) is distinct from (old.workspace,old.approval,old.side) then
    raise exception 'A regional history link cannot change its identity.' using errcode='23514';
  end if;
  workspace_id:=case when tg_op='DELETE' then old.workspace else new.workspace end;
  -- Native root removal holds the same workspace lock through its last census and receipt.
  if not pg_try_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||workspace_id::text,0)) then
    raise exception 'Workspace preservation or offboarding is in progress. Retry the link change.' using errcode='55P03';
  end if;
  if tg_op='DELETE' then return old; end if;
  if exists(select 1 from sectalk_private.st_v8_offboarding_native_root_receipts r where r.workspace=workspace_id) then
    raise exception 'The workspace has an existing native removal receipt.' using errcode='PT409';
  end if;
  if exists(select 1 from sectalk_private.st_v8_residency_history_link_retirements r
    where (r.workspace,r.approval,r.side)=(new.workspace,new.approval,new.side)) then
    raise exception 'The regional history link has already been retired.' using errcode='PT409';
  end if;
  return new;
end $$;

create function sectalk_private.st_v8_retire_residency_history_link(
  p_workspace uuid,p_approval uuid,p_side text,p_vault uuid,p_reference text
) returns timestamptz language plpgsql security invoker set search_path='' as $$
declare link sectalk_private.st_v8_residency_history_links; removed boolean; retired timestamptz;
begin
  if p_workspace is null or p_approval is null or p_vault is null
    or (p_side in ('source','destination')) is not true
    or (char_length(btrim(p_reference)) between 8 and 160) is not true then
    raise exception 'Specify the exact workspace, approval, side and Vault record with an operational reference.' using errcode='22023';
  end if;
  if not pg_try_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0))
    or not pg_try_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0)) then
    raise exception 'Workspace preservation or transfer is in progress. Retry link retirement.' using errcode='55P03';
  end if;
  select r.retired_at into retired from sectalk_private.st_v8_residency_history_link_retirements r
    where (r.workspace,r.approval,r.side)=(p_workspace,p_approval,p_side);
  if found then return retired; end if;
  select * into link from sectalk_private.st_v8_residency_history_links h
    where (h.workspace,h.approval,h.side,h.vault_id)=(p_workspace,p_approval,p_side,p_vault) for update nowait;
  if not found or link.expires_at>clock_timestamp() or sectalk_private.st_v8_offboarding_holds(p_workspace)
    or exists(select 1 from sectalk_private.st_v8_residency_write_handoffs h
      where (h.workspace,h.approval)=(p_workspace,p_approval) and h.phase not in ('cancelled','restored')) then
    raise exception 'Link retirement requires the exact expired link without a hold or active handoff.' using errcode='PT409';
  end if;
  -- Serialize the reference check with comparison and rollback admissions on this installation.
  lock table sectalk_private.st_v8_residency_comparison_receipts,
    sectalk_private.st_v8_residency_rollback_manifest_admissions,
    sectalk_private.st_v8_content_exports,sectalk_private.st_v8_residency_content_admissions in share mode nowait;
  if exists(select 1 from sectalk_private.st_v8_content_exports c
    where (c.workspace,c.id)=(p_workspace,p_approval) and c.approved_at is not null
      and c.withdrawn_at is null and c.expires_at>clock_timestamp())
    or exists(select 1 from sectalk_private.st_v8_residency_content_admissions a
      where (a.workspace,a.approval,a.source_project)=(p_workspace,p_approval,link.source_project)
        and a.expires_at>clock_timestamp()) then
    raise exception 'An active export or destination admission still references the link.' using errcode='PT409';
  end if;
  if exists(select 1 from sectalk_private.st_v8_residency_comparison_receipts r where r.vault_id=p_vault)
    or exists(select 1 from sectalk_private.st_v8_residency_rollback_manifest_admissions r where r.vault_id=p_vault) then
    raise exception 'The Vault record is referenced by separate comparison or rollback evidence.' using errcode='PT409';
  end if;
  delete from vault.secrets v where v.id=p_vault;
  removed:=found;
  delete from sectalk_private.st_v8_residency_history_links h
    where (h.workspace,h.approval,h.side)=(p_workspace,p_approval,p_side);
  insert into sectalk_private.st_v8_residency_history_link_retirements
    (workspace,approval,side,link_expires_at,vault_row_removed,reference)
    values(p_workspace,p_approval,p_side,link.expires_at,removed,btrim(p_reference))
    returning retired_at into retired;
  return retired;
end $$;
revoke all on function sectalk_private.st_v8_retire_residency_history_link(uuid,uuid,text,uuid,text)
  from public,anon,authenticated,service_role;

commit;
