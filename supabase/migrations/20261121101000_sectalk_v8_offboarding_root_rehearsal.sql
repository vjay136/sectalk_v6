begin;

-- These authorizations exist exclusively inside the rolled-back executor
-- subtransaction. Application and service roles cannot issue or consume them.
create table sectalk_private.st_v8_offboarding_root_rehearsal_roster (
  workspace uuid not null,
  request_id uuid not null,
  member_id uuid not null,
  transaction_id xid8 not null,
  membership jsonb not null,
  primary key(workspace,member_id,transaction_id)
);
alter table sectalk_private.st_v8_offboarding_root_rehearsal_roster enable row level security;
revoke all on sectalk_private.st_v8_offboarding_root_rehearsal_roster from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v8_offboarding_guard_suspended_membership()
returns trigger language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
begin
  if tg_op='DELETE' then
    if exists(select 1 from sectalk_private.st_v8_offboarding_requests r
      where r.workspace=old.workspace_id and r.state='read_only'
        and not exists(select 1 from sectalk_private.st_v8_offboarding_retired_suspended_member t
          join sectalk_private.st_v8_offboarding_suspended_member_plans p on p.id=t.plan
          where (t.workspace,t.member_id,p.request_id)=(old.workspace_id,old.user_id,r.id)
            and t.custody->'membership'=to_jsonb(old))
        and not exists(select 1 from sectalk_private.st_v8_offboarding_root_rehearsal_roster x
          where (x.workspace,x.request_id,x.member_id,x.transaction_id,x.membership)=
            (old.workspace_id,r.id,old.user_id,pg_current_xact_id_if_assigned(),to_jsonb(old)))) then
      raise exception 'Reviewed roster custody is required during workspace offboarding' using errcode='PT423';
    end if;
    return old;
  end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-member-retirement:'||new.workspace_id::text,0));
  if exists(select 1 from sectalk_private.st_v8_offboarding_retired_suspended_member t
    where (t.workspace,t.member_id)=(new.workspace_id,new.user_id)) then
    raise exception 'This workspace membership is permanently retired' using errcode='PT409';
  end if;
  return new;
end $$;

-- Never infer emptiness from the root FK count. Check incoming foreign keys
-- of each allowed direct child, including composite and non-cascade keys.
create function sectalk_private.st_v8_offboarding_root_child_has_references(p_parent regclass,p_row jsonb)
returns boolean language plpgsql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare reference record; present boolean;
begin
  for reference in
    select f.conrelid::regclass as relation,f.convalidated,n.relkind,k.join_clause
    from pg_constraint f join pg_class n on n.oid=f.conrelid
    cross join lateral (
      select string_agg(format('c.%I=r.%I',source.attname,parent.attname),' and ' order by cols.position) as join_clause
      from unnest(f.conkey,f.confkey) with ordinality cols(source_column,parent_column,position)
      join pg_attribute source on (source.attrelid,source.attnum)=(f.conrelid,cols.source_column)
      join pg_attribute parent on (parent.attrelid,parent.attnum)=(f.confrelid,cols.parent_column)
    ) k
    where f.contype='f' and f.confrelid=p_parent and f.conparentid=0
  loop
    if not reference.convalidated or reference.relkind not in ('r','p') or reference.join_clause is null then
      return true;
    end if;
    execute format('select exists(select 1 from %s c join %s r on %s where to_jsonb(r)=$1)',
      reference.relation,p_parent,reference.join_clause) into present using p_row;
    if present then return true; end if;
  end loop;
  return false;
end $$;

create function sectalk_private.st_v8_offboarding_root_rehearse(
  p_workspace uuid,p_confirmation text,p_reconciliation uuid,p_sha256 text
) returns jsonb language plpgsql set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  actor uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests; c sectalk_private.st_v7_compliance_cases;
  general public.st_v2_channels; member public.st_v2_members; grant_row sectalk_private.st_v8_offboarding_reviewers;
  reviewed jsonb; workflow jsonb; audit_custody jsonb; summary jsonb; native_rows jsonb; root_effects jsonb;
  captured_audit text; count_removed integer; executed boolean:=false;
begin
  if p_workspace is null or p_confirmation is distinct from p_workspace::text
    or p_reconciliation is null or (p_sha256~'^[a-f0-9]{64}$') is not true then raise insufficient_privilege; end if;
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

revoke all on function sectalk_private.st_v8_offboarding_root_child_has_references(regclass,jsonb),
  sectalk_private.st_v8_offboarding_root_rehearse(uuid,text,uuid,text) from public,anon,authenticated,service_role;
commit;
