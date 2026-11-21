begin;

create table sectalk_private.st_v8_offboarding_root_rehearsal_receipts (
  reconciliation uuid primary key references sectalk_private.st_v8_offboarding_reconciliations(id),
  recorded_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v8_offboarding_root_rehearsal_receipts enable row level security;
revoke all on sectalk_private.st_v8_offboarding_root_rehearsal_receipts from public,anon,authenticated,service_role;
create trigger st_v8_offboarding_root_rehearsal_receipts_immutable before update or delete
  on sectalk_private.st_v8_offboarding_root_rehearsal_receipts
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

create or replace function sectalk_private.st_v8_run_offboarding_root_rehearsal(
  p_workspace uuid,p_confirmation text,p_reconciliation uuid,p_sha256 text
) returns jsonb language plpgsql security definer set search_path='' set lock_timeout='1s' as $$
declare
  r sectalk_private.st_v8_offboarding_requests;
  outcome jsonb;
  recorded timestamptz;
begin
  if auth.uid() is null or p_workspace is null or p_reconciliation is null
    or (p_sha256~'^[a-f0-9]{64}$') is not true then raise insufficient_privilege; end if;
  if p_confirmation is null then
    r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
    if not sectalk_private.st_v8_audit_sso_allows(p_workspace)
      or not sectalk_private.st_v8_compliance_sso_allows(p_workspace) then raise insufficient_privilege; end if;
    select receipt.recorded_at into recorded from sectalk_private.st_v8_offboarding_root_rehearsal_receipts receipt
    join sectalk_private.st_v8_offboarding_reconciliations plan on plan.id=receipt.reconciliation
    join sectalk_private.st_v8_offboarding_reconciliation_receipts review on review.reconciliation=plan.id
    where (plan.workspace,plan.request_id,plan.id,plan.sha256,plan.owner_id,review.reviewer)=
      (r.workspace,r.id,p_reconciliation,p_sha256,r.requester,r.reviewer)
      and plan.reviewer_id=r.reviewer;
    if not found then return null; end if;
    return jsonb_build_object('workspace',p_workspace,'reconciliation',p_reconciliation,'recordedAt',recorded,'rolledBack',true);
  end if;

  if sectalk_private.st_v8_offboarding_role(p_workspace,auth.uid()) is distinct from 'owner'
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false) then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_offboarding_root_rehearsal',4);
  outcome:=sectalk_private.st_v8_offboarding_root_rehearse(p_workspace,p_confirmation,p_reconciliation,p_sha256);
  insert into sectalk_private.st_v8_offboarding_root_rehearsal_receipts(reconciliation) values(p_reconciliation)
    on conflict(reconciliation) do nothing;
  select recorded_at into strict recorded from sectalk_private.st_v8_offboarding_root_rehearsal_receipts
    where reconciliation=p_reconciliation;
  return outcome||jsonb_build_object('recordedAt',recorded);
end $$;

commit;
