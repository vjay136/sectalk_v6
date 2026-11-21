begin;

create table sectalk_private.st_v8_offboarding_native_root_approvals (
  reconciliation uuid primary key references sectalk_private.st_v8_offboarding_root_rehearsal_receipts(reconciliation),
  reviewer uuid not null,
  approved_at timestamptz not null default clock_timestamp()
);
create table sectalk_private.st_v8_offboarding_native_root_receipts (
  reconciliation uuid primary key references sectalk_private.st_v8_offboarding_native_root_approvals(reconciliation),
  workspace uuid not null unique,
  removed_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v8_offboarding_native_root_approvals enable row level security;
alter table sectalk_private.st_v8_offboarding_native_root_receipts enable row level security;
revoke all on sectalk_private.st_v8_offboarding_native_root_approvals,
  sectalk_private.st_v8_offboarding_native_root_receipts from public,anon,authenticated,service_role;
create trigger st_v8_offboarding_native_root_approvals_immutable before update or delete
  on sectalk_private.st_v8_offboarding_native_root_approvals
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_offboarding_native_root_receipts_immutable before update or delete
  on sectalk_private.st_v8_offboarding_native_root_receipts
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

-- A reconciliation confirms evidence. This separate decision authorizes only native root removal.
create function sectalk_private.st_v8_approve_offboarding_native_root(
  p_workspace uuid,p_confirmation text,p_reconciliation uuid,p_sha256 text
) returns timestamptz language plpgsql set search_path='' set lock_timeout='1s' as $$
declare
  r sectalk_private.st_v8_offboarding_requests;
  current_plan jsonb;
  approved timestamptz;
begin
  if auth.uid() is null or p_workspace is null or p_confirmation is distinct from p_workspace::text
    or p_reconciliation is null or (p_sha256~'^[a-f0-9]{64}$') is not true then raise insufficient_privilege; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if auth.uid() is distinct from r.reviewer or not sectalk_private.st_v8_audit_sso_allows(p_workspace)
    or not sectalk_private.st_v8_compliance_sso_allows(p_workspace)
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
  current_plan:=public.st_v8_offboarding_reconciliation(p_workspace);
  if (current_plan->>'current')::boolean is not true or current_plan->>'reviewedAt' is null
    or (current_plan->>'plan',current_plan->>'sha256') is distinct from (p_reconciliation::text,p_sha256)
    or not exists(select 1 from sectalk_private.st_v8_offboarding_root_rehearsal_receipts a
      where a.reconciliation=p_reconciliation) then
    raise exception 'Approve the exact current plan after a successful rehearsal' using errcode='PT409';
  end if;
  insert into sectalk_private.st_v8_offboarding_native_root_approvals(reconciliation,reviewer)
    values(p_reconciliation,r.reviewer) on conflict(reconciliation) do nothing;
  select a.approved_at into strict approved from sectalk_private.st_v8_offboarding_native_root_approvals a
    where (a.reconciliation,a.reviewer)=(p_reconciliation,r.reviewer);
  return approved;
end $$;

create function sectalk_private.st_v8_offboarding_root_mutation(
  p_workspace uuid,p_confirmation text,p_reconciliation uuid,p_sha256 text,p_commit boolean
) returns jsonb language plpgsql set search_path='' set timezone='UTC' set datestyle='ISO, YMD' set lock_timeout='1s' as $$
declare
  actor uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests; c sectalk_private.st_v7_compliance_cases;
  general public.st_v2_channels; member public.st_v2_members; grant_row sectalk_private.st_v8_offboarding_reviewers;
  reviewed jsonb; workflow jsonb; audit_custody jsonb; summary jsonb; native_rows jsonb; root_effects jsonb;
  captured_audit text; count_removed integer; executed boolean:=false; removed timestamptz;
begin
  if actor is null or p_workspace is null or p_confirmation is distinct from p_workspace::text
    or p_reconciliation is null or (p_sha256~'^[a-f0-9]{64}$') is not true or p_commit is null
    then raise insufficient_privilege; end if;
  if p_commit then
    if not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
      or not coalesce(sectalk_private.st_v7_admin_fresh(),false) then raise insufficient_privilege; end if;
    select receipt.removed_at into removed from sectalk_private.st_v8_offboarding_native_root_receipts receipt
    join sectalk_private.st_v8_offboarding_reconciliations plan on (plan.id,plan.workspace)=(receipt.reconciliation,receipt.workspace)
    where (receipt.workspace,receipt.reconciliation,plan.owner_id,plan.sha256)=(p_workspace,p_reconciliation,actor,p_sha256);
    if found then
      return jsonb_build_object('scope','bounded-native-root','workspace',p_workspace,'reconciliation',p_reconciliation,
        'nativeRecordRemoved',true,'removedAt',removed,'providerBytes','unverified','backupErasure','unverified');
    end if;
  end if;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if actor is distinct from r.requester then raise insufficient_privilege; end if;
  lock table public.st_v2_workspaces,public.st_v2_members,public.st_v2_channels,sectalk_private.st_v8_offboarding_reviewers
    in row exclusive mode nowait;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform 1 from public.st_v2_workspaces w where (w.id,w.owner)=(p_workspace,actor) for update nowait;
  if not found then raise insufficient_privilege; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-member-retirement:'||p_workspace::text,0));
  perform 1 from sectalk_private.st_v8_offboarding_requests x where x.id=r.id for update nowait;
  select * into grant_row from sectalk_private.st_v8_offboarding_reviewers x
    where (x.workspace,x.actor)=(p_workspace,r.reviewer) for update nowait;
  perform 1 from public.st_v2_members x where x.workspace_id=p_workspace and x.user_id in (r.requester,r.reviewer)
    order by x.user_id for update nowait;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  select * into c from sectalk_private.st_v7_compliance_cases x where (x.id,x.workspace_id)=(r.case_id,r.workspace) for update nowait;
  if actor is distinct from r.requester or grant_row.actor is null or c.id is null
    or not sectalk_private.st_v8_audit_sso_allows(p_workspace) or not sectalk_private.st_v8_compliance_sso_allows(p_workspace)
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
  perform 1 from auth.sessions n join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
    join auth.mfa_amr_claims a on a.session_id=n.id and a.authentication_method='totp'
    where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',actor) and n.aal='aal2'
      and f.status='verified' and f.factor_type='totp' and a.updated_at>clock_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp() for share of n,f,a;
  if not found then raise insufficient_privilege; end if;
  select * into general from public.st_v2_channels x
    where (x.workspace_id,x.name,x.owner,x.visibility,x.encryption_mode,x.archived)=(p_workspace,'general',actor,'workspace','standard',false)
    for update nowait;
  reviewed:=public.st_v8_offboarding_reconciliation(p_workspace);
  workflow:=public.st_v8_offboarding_workflow_custody(p_workspace);
  audit_custody:=public.st_v8_offboarding_workspace_audit_custody(p_workspace);
  if (reviewed->>'current')::boolean is not true or reviewed->>'reviewedAt' is null
    or (reviewed->>'plan',reviewed->>'sha256') is distinct from (p_reconciliation::text,p_sha256)
    or (workflow->>'current')::boolean is not true or (workflow->>'linked')::boolean is distinct from false
    or (audit_custody->>'current')::boolean is not true or (audit_custody->>'linked')::boolean is distinct from false
    or r.live_workspace is not null or c.live_workspace is not null then
    raise exception 'Exact current native custody and independent reconciliation are required' using errcode='PT409';
  end if;
  if p_commit and not exists(select 1 from sectalk_private.st_v8_offboarding_native_root_approvals a
    where (a.reconciliation,a.reviewer)=(p_reconciliation,r.reviewer)) then
    raise exception 'Independent approval for native root removal is required' using errcode='PT409';
  end if;
  captured_audit:=audit_custody->>'auditSha256';
  summary:=reviewed->'summary';
  native_rows:=summary->'nativeRows';
  root_effects:=summary#>'{workspaceRootDependencies,deleteActions}';
  if root_effects is distinct from '{"cascade":4,"restrict":0,"setNull":0,"setDefault":0}'::jsonb
    or summary#>>'{workspaceRootDependencies,unclassifiedConstraints}' is distinct from '0'
    or summary#>>'{workspaceRootDependencies,unsupportedConstraints}' is distinct from '0'
    or native_rows->>'workspace' is distinct from '1' or native_rows->>'members' is distinct from '2'
    or native_rows->>'channels' is distinct from '1' or general.id is null
    or exists(select 1 from jsonb_each_text(native_rows-'workspace'-'members'-'channels') q where q.value::bigint<>0)
    or exists(select 1 from jsonb_each_text(summary->'storageMetadata') q where q.value::bigint<>0)
    or exists(select 1 from (values
      ('public.st_v2_members'::regclass,'workspace_id'),('public.st_v2_channels'::regclass,'workspace_id'),
      ('sectalk_private.st_v8_offboarding_reviewers'::regclass,'workspace')) z(relation,column_name)
      where (select count(*) from pg_constraint f
        join pg_attribute a on (a.attrelid,a.attnum)=(f.conrelid,f.conkey[1])
        join pg_attribute b on (b.attrelid,b.attnum)=(f.confrelid,f.confkey[1])
        where f.contype='f' and f.confdeltype='c' and f.convalidated and cardinality(f.conkey)=1
          and (f.conrelid,f.confrelid,a.attname,b.attname)=(z.relation,'public.st_v2_workspaces'::regclass,z.column_name,'id'))<>1)
    or sectalk_private.st_v8_offboarding_root_child_has_references('public.st_v2_channels',to_jsonb(general))
    or sectalk_private.st_v8_offboarding_root_child_has_references('sectalk_private.st_v8_offboarding_reviewers',to_jsonb(grant_row))
    then raise exception 'Workspace root rehearsal only supports the two approvers and the empty default channel' using errcode='PT409';
  end if;
  for member in select * from public.st_v2_members m where m.workspace_id=p_workspace loop
    if member.suspended_at is not null or (member.user_id,member.role) not in ((r.requester,'owner'),(r.reviewer,'admin'))
      or sectalk_private.st_v8_offboarding_root_child_has_references('public.st_v2_members',to_jsonb(member)) then
      raise exception 'The final approver roster has an unsupported dependency' using errcode='PT409';
    end if;
  end loop;
  -- Audit the actual DELETE hooks on this bounded cohort. The listed hooks
  -- use native SQL changes or transactional notifications, including the
  -- membership hint and queued (rather than synchronous) webhook delivery.
  if current_setting('session_replication_role')<>'origin' or exists (
    with expected(relation,name,handler,flags) as (values
      ('public.st_v2_workspaces'::regclass,'st_v6_workspace_hold_guard','sectalk_private.st_v6_guard_held_workspace_scope()'::regprocedure,11),
      ('public.st_v2_channels','st_v6_channel_delete_hold_guard','sectalk_private.st_v6_guard_held_workspace_scope()',11),
      ('public.st_v2_members','st_v6_channel_workspace_departure','sectalk_private.st_v6_channel_workspace_departure()',9),
      ('public.st_v2_members','st_v6_invalidate_member_count','sectalk_private.st_v6_invalidate_member_count()',29),
      ('public.st_v2_members','st_v6_webhook_roster','sectalk_private.st_v6_emit_webhook_event()',29),
      ('public.st_v2_members','st_v6_workspace_membership_hint','sectalk_private.st_v6_workspace_membership_hint()',29),
      ('public.st_v2_members','st_v7_managed_account_lifecycle','sectalk_private.st_v7_end_invalid_managed_relationships()',25),
      ('public.st_v2_members','st_v7_sso_departure','sectalk_private.st_v7_record_sso_departure()',9),
      ('public.st_v2_members','st_v8_offboarding_guard_staged_roster_delete','sectalk_private.st_v8_offboarding_guard_suspended_membership()',11),
      ('public.st_v2_members','st_v8_scim_member_departure','sectalk_private.st_v8_scim_record_departure()',9)
    ), actual as (
      select t.tgrelid as relation,t.tgname::text as name,t.tgfoid as handler,t.tgtype::integer as flags,t.tgenabled
      from pg_trigger t where (t.tgtype::integer&8)=8 and t.tgrelid in (
        'public.st_v2_workspaces'::regclass,'public.st_v2_channels'::regclass,
        'public.st_v2_members'::regclass,'sectalk_private.st_v8_offboarding_reviewers'::regclass) and not t.tgisinternal
    ) select 1 from expected e full join actual a
      on (a.relation,a.name,a.handler,a.flags)=(e.relation,e.name,e.handler,e.flags)
      where e.relation is null or a.tgenabled is distinct from 'O'
  ) or exists(
    select 1 from pg_rewrite p where p.ev_type='4' and p.ev_class in (
      'public.st_v2_workspaces'::regclass,'public.st_v2_channels'::regclass,
      'public.st_v2_members'::regclass,'sectalk_private.st_v8_offboarding_reviewers'::regclass)
  ) then raise exception 'Workspace root rehearsal encountered an unreviewed delete hook' using errcode='PT409'; end if;
  begin
    insert into sectalk_private.st_v8_offboarding_root_rehearsal_roster(workspace,request_id,member_id,transaction_id,membership)
      select p_workspace,r.id,m.user_id,pg_current_xact_id(),to_jsonb(m)
      from public.st_v2_members m where m.workspace_id=p_workspace;
    delete from public.st_v2_workspaces w where w.id=p_workspace;
    get diagnostics count_removed=row_count;
    if count_removed<>1 or exists(select 1 from public.st_v2_members m where m.workspace_id=p_workspace)
      or exists(select 1 from public.st_v2_channels x where x.workspace_id=p_workspace)
      or exists(select 1 from sectalk_private.st_v8_offboarding_reviewers x where x.workspace=p_workspace)
      or not exists(select 1 from sectalk_private.st_v8_offboarding_requests x where x.id=r.id and to_jsonb(x)=to_jsonb(r))
      or not exists(select 1 from sectalk_private.st_v7_compliance_cases x where x.id=c.id and to_jsonb(x)=to_jsonb(c))
      or not exists(select 1 from sectalk_private.st_v8_offboarding_audit_custody_manifest(p_workspace) x
        where x.valid and x.sha256=captured_audit) then
      raise exception 'Root rehearsal did not preserve exact audit and workflow custody' using errcode='PT409';
    end if;
    if p_commit then
      delete from sectalk_private.st_v8_offboarding_root_rehearsal_roster permit
        where (permit.workspace,permit.request_id,permit.transaction_id)=(p_workspace,r.id,pg_current_xact_id());
      get diagnostics count_removed=row_count;
      if count_removed<>2 then raise exception 'Native root removal did not consume its exact roster scope' using errcode='PT409'; end if;
      insert into sectalk_private.st_v8_offboarding_native_root_receipts(reconciliation,workspace)
        values(p_reconciliation,p_workspace) returning removed_at into removed;
      return jsonb_build_object('scope','bounded-native-root','workspace',p_workspace,'reconciliation',p_reconciliation,
        'nativeRecordRemoved',true,'removedAt',removed,'providerBytes','unverified','backupErasure','unverified');
    end if;
    executed:=true;
    raise exception 'Rollback verified workspace root rehearsal' using errcode='PT439';
  exception when sqlstate 'PT439' then
    if not executed or sqlerrm<>'Rollback verified workspace root rehearsal' then raise; end if;
  end;
  if not exists(select 1 from public.st_v2_workspaces w where w.id=p_workspace)
    or (select count(*) from public.st_v2_members m where m.workspace_id=p_workspace)<>2
    or not exists(select 1 from public.st_v2_channels x where x.id=general.id)
    or not exists(select 1 from sectalk_private.st_v8_offboarding_reviewers x where (x.workspace,x.actor)=(p_workspace,r.reviewer))
    or exists(select 1 from sectalk_private.st_v8_offboarding_root_rehearsal_roster x where x.workspace=p_workspace)
    then raise exception 'Root rehearsal did not restore the live scope' using errcode='PT409'; end if;
  return jsonb_build_object('scope','bounded-native-root','workspace',p_workspace,'reconciliation',p_reconciliation,
    'deletedInsideRollback',true,'rolledBack',true,'providerBytes','unverified','backupErasure','unverified');
end $$;

create or replace function sectalk_private.st_v8_offboarding_root_rehearse(
  p_workspace uuid,p_confirmation text,p_reconciliation uuid,p_sha256 text
) returns jsonb language sql set search_path=''
  begin atomic
    select sectalk_private.st_v8_offboarding_root_mutation(p_workspace,p_confirmation,p_reconciliation,p_sha256,false);
  end;

-- The production action remains private pending provider and backup verification.
revoke all on function sectalk_private.st_v8_offboarding_root_mutation(uuid,text,uuid,text,boolean),
  sectalk_private.st_v8_approve_offboarding_native_root(uuid,text,uuid,text) from public,anon,authenticated,service_role;

commit;
