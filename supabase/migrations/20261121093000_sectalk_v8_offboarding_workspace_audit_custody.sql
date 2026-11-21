begin;

-- Preserve original audit rows and hashes under a retained tenant identifier.
-- A live link continues to block deleting the workspace until it is reviewed.
create table sectalk_private.st_v8_workspace_audit_custody (
  workspace uuid primary key,
  live_workspace uuid unique references public.st_v2_workspaces(id) on delete restrict,
  check(live_workspace is null or live_workspace=workspace)
);
alter table sectalk_private.st_v8_workspace_audit_custody enable row level security;

lock table public.st_v2_workspaces,public.st_v2_workspace_audit in share row exclusive mode;
insert into sectalk_private.st_v8_workspace_audit_custody(workspace,live_workspace)
  select distinct a.workspace_id,a.workspace_id from public.st_v2_workspace_audit a;
alter table public.st_v2_workspace_audit
  add constraint st_v8_workspace_audit_custody_fkey foreign key(workspace_id)
    references sectalk_private.st_v8_workspace_audit_custody(workspace) on delete restrict,
  drop constraint st_v2_workspace_audit_workspace_id_fkey;

create function sectalk_private.st_v8_workspace_audit_custody_write()
returns trigger language plpgsql security definer set search_path='' as $$
declare w uuid:=case when tg_op='DELETE' then old.workspace_id else new.workspace_id end;
begin
  if tg_op='UPDATE' and old.workspace_id is distinct from new.workspace_id then
    raise exception 'Original workspace audit attribution is immutable' using errcode='PT409';
  end if;
  perform 1 from public.st_v2_workspaces a where a.id=w for key share;
  if not found then raise exception 'Retained workspace audit is immutable' using errcode='PT409'; end if;
  -- A mutation after review restores the root restriction in the same transaction.
  if not exists(select 1 from sectalk_private.st_v8_workspace_audit_custody a where (a.workspace,a.live_workspace)=(w,w)) then
    insert into sectalk_private.st_v8_workspace_audit_custody as c(workspace,live_workspace)
      values(w,w) on conflict(workspace) do update set live_workspace=excluded.live_workspace
      where c.live_workspace is null;
  end if;
  if tg_op='DELETE' then return old; end if;
  return new;
end $$;
create trigger st_v8_workspace_audit_custody_write before insert or update or delete on public.st_v2_workspace_audit
  for each row execute function sectalk_private.st_v8_workspace_audit_custody_write();

create function sectalk_private.st_v8_workspace_audit_reserved_identity()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if tg_op='UPDATE' and new.id=old.id then return new; end if;
  if exists(select 1 from sectalk_private.st_v8_workspace_audit_custody a where a.workspace=new.id) then
    raise exception 'This workspace identifier is reserved by retained audit' using errcode='PT409';
  end if;
  return new;
end $$;
create trigger st_v8_workspace_audit_reserved_identity before insert or update of id on public.st_v2_workspaces
  for each row execute function sectalk_private.st_v8_workspace_audit_reserved_identity();

create table sectalk_private.st_v8_offboarding_audit_custody_plans (
  id uuid primary key default gen_random_uuid(),
  capture_order bigint generated always as identity unique,
  workspace uuid not null references sectalk_private.st_v8_workspace_audit_custody(workspace),
  request_id uuid not null,
  owner_id uuid not null,
  reviewer_id uuid not null check(owner_id<>reviewer_id),
  event_count integer not null check(event_count between 1 and 10000),
  audit_sha256 text not null check(audit_sha256~'^[a-f0-9]{64}$'),
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  captured_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null
);
create index st_v8_offboarding_audit_custody_latest
  on sectalk_private.st_v8_offboarding_audit_custody_plans(workspace,request_id,capture_order desc);
create table sectalk_private.st_v8_offboarding_audit_custody_decisions (
  plan uuid not null references sectalk_private.st_v8_offboarding_audit_custody_plans(id),
  action text not null check(action in ('approved','detached')),
  actor uuid not null,
  happened_at timestamptz not null default clock_timestamp(),
  primary key(plan,action)
);
create trigger st_v8_offboarding_audit_custody_plans_immutable before update or delete
  on sectalk_private.st_v8_offboarding_audit_custody_plans
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_offboarding_audit_custody_decisions_immutable before update or delete
  on sectalk_private.st_v8_offboarding_audit_custody_decisions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_audit_custody_plans enable row level security;
alter table sectalk_private.st_v8_offboarding_audit_custody_decisions enable row level security;
revoke all on sectalk_private.st_v8_workspace_audit_custody,sectalk_private.st_v8_offboarding_audit_custody_plans,
  sectalk_private.st_v8_offboarding_audit_custody_decisions from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_offboarding_audit_custody_manifest(p_workspace uuid)
returns table(event_count integer,valid boolean,sha256 text) language sql stable
set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  with audit as materialized (
    select a.id,sectalk_private.st_v6_audit_row_hash(to_jsonb(a)) as row_hash
      from public.st_v2_workspace_audit a where a.workspace_id=p_workspace
      order by a.created_at desc,a.id desc limit 10001
  ), proofs as (
    select a.*,p.entry_no,p.entry_hash,p.row_hash=a.row_hash and p.operation<>'DELETE' as matches
    from audit a left join lateral (
      select x.entry_no,x.entry_hash,x.row_hash,x.operation
        from sectalk_private.st_v6_audit_chain x where (x.source,x.source_id)=('public.st_v2_workspace_audit',a.id)
        order by x.entry_no desc limit 1
    ) p on true
  )
  select count(*)::integer,coalesce(bool_and(coalesce(p.matches,false)),false) and count(*)<=10000,
    case when count(*) between 1 and 10000 then encode(sha256(convert_to(jsonb_agg(
      jsonb_build_array(p.id,encode(p.row_hash,'hex'),p.entry_no,encode(p.entry_hash,'hex')) order by p.id)::text,'UTF8')),'hex') end
  from proofs p
$$;

create function public.st_v8_offboarding_workspace_audit_custody(
  p_workspace uuid,p_action text default 'status',p_confirmation text default null,
  p_plan uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  actor uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_audit_custody_plans; manifest record; custody_link uuid;
  linked boolean; held boolean; current_review boolean; digest text; approved_at timestamptz; detached_at timestamptz;
  inventory_until timestamptz; inventory_sha text;
begin
  if p_workspace is null or p_action is null or p_action not in ('status','capture','approve','detach') then raise insufficient_privilege; end if;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if not sectalk_private.st_v8_audit_sso_allows(p_workspace) then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if p_confirmation is distinct from p_workspace::text or actor is distinct from
      (case when p_action='approve' then r.reviewer else r.requester end) then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
    perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces where id=p_workspace for update nowait;
    perform 1 from sectalk_private.st_v8_offboarding_requests x where (x.id,x.workspace)=(r.id,p_workspace) for update;
    perform 1 from sectalk_private.st_v8_offboarding_reviewers x where (x.workspace,x.actor)=(p_workspace,r.reviewer) for share;
    perform 1 from public.st_v2_members x where x.workspace_id=p_workspace and x.user_id in (r.requester,r.reviewer)
      order by x.user_id for share;
    r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
    if not sectalk_private.st_v8_audit_sso_allows(p_workspace) or actor is distinct from
      (case when p_action='approve' then r.reviewer else r.requester end)
      or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
    perform 1 from auth.sessions n
      join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
      join auth.mfa_amr_claims a on a.session_id=n.id and a.authentication_method='totp'
      where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',actor) and n.aal='aal2'
        and f.status='verified' and f.factor_type='totp' and a.updated_at>clock_timestamp()-interval '5 minutes'
        and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp()
      for share of n,f,a;
    if not found then raise insufficient_privilege; end if;
    perform 1 from sectalk_private.st_v7_compliance_cases c where (c.id,c.workspace_id)=(r.case_id,p_workspace) for share;
  end if;
  perform sectalk_private.limit_action('v8_offboarding_workspace_audit_custody',30);
  held:=sectalk_private.st_v8_offboarding_holds(p_workspace);
  select a.live_workspace into custody_link from sectalk_private.st_v8_workspace_audit_custody a where a.workspace=p_workspace;
  linked:=custody_link is not null;
  select * into manifest from sectalk_private.st_v8_offboarding_audit_custody_manifest(p_workspace);
  select c.expires_at,c.manifest_sha256 into inventory_until,inventory_sha from sectalk_private.st_v7_compliance_cases c
    where (c.id,c.workspace_id,c.requester,c.reviewer)=(r.case_id,p_workspace,r.requester,r.reviewer)
      and c.state='approved' and c.expires_at>clock_timestamp() and c.manifest_sha256~'^[a-f0-9]{64}$'
      and c.ticket is null and exists(select 1 from sectalk_private.st_v7_compliance_audit a
        where (a.case_id,a.workspace_id,a.actor,a.action)=(c.id,p_workspace,r.requester,'downloaded'));
  if p_action<>'status' and (inventory_sha is null or not manifest.valid
    or exists(select 1 from sectalk_private.st_v7_compliance_cases c where c.workspace_id=p_workspace and c.id<>r.case_id
      and c.state in ('pending','approved') and c.expires_at>clock_timestamp())
    or exists(select 1 from sectalk_private.st_v7_evidence_operations x
      join sectalk_private.st_v7_compliance_cases c on c.id=x.case_id where c.workspace_id=p_workspace and x.expires_at>clock_timestamp())) then
    raise exception 'Live inventory and verifiable bounded original audit are required' using errcode='PT409';
  end if;
  digest:=encode(sha256(convert_to(jsonb_build_array('sectalk-workspace-audit-custody-v1',
    p_workspace,r.id,r.requester,r.reviewer,r.snapshot_sha256,inventory_sha,manifest.event_count,manifest.sha256)::text,'UTF8')),'hex');
  select x.* into plan from sectalk_private.st_v8_offboarding_audit_custody_plans x
    where (x.workspace,x.request_id,x.owner_id,x.reviewer_id)=(p_workspace,r.id,r.requester,r.reviewer)
    order by x.capture_order desc limit 1;
  current_review:=coalesce(not held and manifest.valid and inventory_sha is not null and plan.sha256=digest
    and plan.expires_at>clock_timestamp(),false);
  if p_action='capture' then
    if not linked or p_plan is not null or p_sha256 is not null then
      raise exception 'Capture the current live audit link' using errcode='PT409';
    end if;
    if not current_review then
      insert into sectalk_private.st_v8_offboarding_audit_custody_plans(workspace,request_id,owner_id,reviewer_id,
        event_count,audit_sha256,sha256,expires_at)
        values(p_workspace,r.id,r.requester,r.reviewer,manifest.event_count,manifest.sha256,digest,
          least(inventory_until,clock_timestamp()+interval '30 minutes')) returning * into plan;
      current_review:=true;
    end if;
  end if;
  select d.happened_at into approved_at from sectalk_private.st_v8_offboarding_audit_custody_decisions d
    where (d.plan,d.action,d.actor)=(plan.id,'approved',r.reviewer);
  select d.happened_at into detached_at from sectalk_private.st_v8_offboarding_audit_custody_decisions d
    where (d.plan,d.action,d.actor)=(plan.id,'detached',r.requester);
  if p_action in ('approve','detach') then
    if not current_review or p_plan is null or p_plan is distinct from plan.id or p_sha256 is distinct from plan.sha256 then
      raise exception 'Confirm the latest exact audit custody plan' using errcode='PT409';
    end if;
    if p_action='approve' then
      if not linked then raise exception 'The live audit link is absent' using errcode='PT409'; end if;
      insert into sectalk_private.st_v8_offboarding_audit_custody_decisions(plan,action,actor)
        values(plan.id,'approved',actor) on conflict do nothing;
      select d.happened_at into approved_at from sectalk_private.st_v8_offboarding_audit_custody_decisions d
        where (d.plan,d.action,d.actor)=(plan.id,'approved',r.reviewer);
    elsif approved_at is null then
      raise insufficient_privilege;
    elsif linked then
      if detached_at is not null then raise exception 'Capture a new audit custody plan' using errcode='PT409'; end if;
      update sectalk_private.st_v8_workspace_audit_custody a set live_workspace=null
        where (a.workspace,a.live_workspace)=(p_workspace,p_workspace);
      if not found then raise exception 'The live audit link changed' using errcode='PT409'; end if;
      insert into sectalk_private.st_v8_offboarding_audit_custody_decisions(plan,action,actor)
        values(plan.id,'detached',actor) returning happened_at into detached_at;
      linked:=false;
    end if;
  end if;
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'auditSha256',manifest.sha256,'eventCount',manifest.event_count,
    'verified',manifest.valid,'held',held,'linked',linked,'current',current_review,'approvedAt',approved_at,
    'detachedAt',detached_at,'expiresAt',plan.expires_at);
end $$;

revoke all on function sectalk_private.st_v8_workspace_audit_custody_write(),
  sectalk_private.st_v8_workspace_audit_reserved_identity(),sectalk_private.st_v8_offboarding_audit_custody_manifest(uuid),
  public.st_v8_offboarding_workspace_audit_custody(uuid,text,text,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_workspace_audit_custody(uuid,text,text,uuid,text) to authenticated;
create or replace function sectalk_private.st_v8_offboarding_workspace_root_snapshot(p_workspace uuid)
returns jsonb language plpgsql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  dependency record; exposure text; affected bigint; row_digest text; audit record;
  impact jsonb:='{"cascade":0,"restrict":0,"setNull":0,"setDefault":0}';
  groups jsonb:='{"content":0,"access":0,"preservation":0,"billing":0,"integrations":0,"policies":0,"operations":0,"unclassified":0}';
  fingerprints jsonb:='[]'; scan_incomplete integer:=0; unknown integer:=0; bounded_count integer:=0;
begin
  for dependency in
    select n.nspname,c.relname,f.conname,a.attname,f.confdeltype,f.convalidated,f.condeferrable,f.condeferred,
      cardinality(f.conkey)=1 and cardinality(f.confkey)=1 and t.attname='id'
        and c.relkind in ('r','p') as supported,
      case (n.nspname||'.'||c.relname)
        when 'public.st_v2_channels' then 'content'
        when 'public.st_v6_rooms' then 'content'
        when 'public.st_v2_items' then 'content'
        when 'public.st_v3_meetings' then 'content'
        else
          case
            when n.nspname='public' and c.relname=any(array['st_v2_members','st_v2_invites','st_v6_workspace_groups'])
              then 'access'
            when n.nspname='public' and c.relname='st_v2_workspace_audit' then 'preservation'
            when n.nspname='public' and c.relname=any(array['st_v6_workspace_policy','st_v6_workspace_reaction_policy'])
              then 'policies'
            when n.nspname='public' and c.relname='st_v3_notifications' then 'operations'
            when n.nspname='sectalk_private' and c.relname=any(array[
              'st_v6_workspace_link_invites','st_v7_managed_accounts','st_v7_org_domains','st_v7_school_classes',
              'st_v7_sso_departures','st_v7_workspace_sso','st_v7_custom_role_heads','st_v8_workspace_audit_sso',
              'st_v8_workspace_billing_sso','st_v8_workspace_channel_structure_sso','st_v8_workspace_custom_role_admin_sso',
              'st_v8_workspace_directory_sso','st_v8_workspace_entry_sso','st_v8_workspace_file_sso','st_v8_workspace_groups_sso',
              'st_v8_workspace_integration_admin_sso','st_v8_workspace_invitation_admin_sso','st_v8_workspace_legal_hold_sso',
              'st_v8_workspace_managed_content_sso','st_v8_workspace_member_media_sso','st_v8_workspace_organization_sso','st_v8_workspace_compliance_sso',
              'st_v8_workspace_planner_sso','st_v8_workspace_policy_admin_sso','st_v8_workspace_room_structure_sso',
              'st_v8_workspace_schedule_sso','st_v8_workspace_standard_channel_sso','st_v8_workspace_standard_room_sso'
            ]) then 'access'
            when n.nspname='sectalk_private' and c.relname=any(array[
              'st_v6_break_glass_requests','st_v6_workspace_holds','st_v6_workspace_policy_versions',
              'st_v6_workspace_retired_file_ids','st_v7_compliance_cases','st_v7_dlp_acknowledgements',
              'st_v7_dlp_delivery_receipts','st_v7_policy_snapshots','st_v7_profile_rule_history','st_v7_siem_batches',
              'st_v7_soc_response_grants','st_v7_tenant_destroy_reviewers','st_v7_workspace_email_versions',
              'st_v8_content_exports','st_v8_offboarding_requests','st_v8_offboarding_reviewers','st_v8_workspace_audit_custody'
            ]) then 'preservation'
            when n.nspname='sectalk_private' and c.relname=any(array[
              'st_v7_usage_events','st_v7_workspace_trials','st_v8_enterprise_billing_operators',
              'st_v8_enterprise_orders','st_v8_workspace_seat_changes','st_v8_workspace_seats'
            ]) then 'billing'
            when n.nspname='sectalk_private' and c.relname=any(array[
              'st_v6_integration_keys','st_v6_webhooks','st_v8_scim_keys','st_v8_scim_users',
              'st_v8_residency_cell_authorizations','st_v8_residency_requests','st_v8_residency_routing_rehearsals',
              'st_v8_residency_source_pauses','st_v8_residency_verifiers','st_v8_residency_active_routes',
              'st_v8_residency_route_revocations','st_v8_residency_rollback_holds',
              'st_v8_residency_activation_admissions','st_v8_residency_channel_history','st_v8_residency_channel_imports',
              'st_v8_residency_comparison_receipts','st_v8_residency_file_verifications','st_v8_residency_room_history',
              'st_v8_residency_room_imports','st_v8_residency_task_imports','st_v8_residency_write_handoffs'
            ]) then 'integrations'
            when n.nspname='sectalk_private' and c.relname=any(array[
              'st_v6_recording_policy','st_v6_room_retention_policy','st_v6_summary_policy','st_v6_tenant_feature_pauses',
              'st_v6_thread_summary_policy','st_v6_workspace_file_history_policy','st_v6_workspace_link_policy',
              'st_v6_workspace_notification_policy','st_v6_workspace_presence_policy','st_v7_file_egress_policies',
              'st_v7_org_preferences','st_v7_profile_rule_evaluation','st_v7_profile_rule_workspace','st_v7_workspace_ai_policy',
              'st_v7_workspace_dlp','st_v7_workspace_email_active','st_v8_channel_encryption_policy',
              'st_v8_room_encryption_policy','st_v8_tenant_rotation_schedules','workspace_read_receipt_policy'
            ]) then 'policies'
            when n.nspname='sectalk_private' and c.relname=any(array[
              'st_v6_call_qos','st_v6_emergency_notices','st_v6_tenant_metadata_cache'
            ]) then 'operations'
            else 'unclassified'
          end
      end as category
    from pg_constraint f
    join pg_class c on c.oid=f.conrelid
    join pg_namespace n on n.oid=c.relnamespace
    join pg_attribute a on a.attrelid=c.oid and a.attnum=f.conkey[1]
    join pg_attribute t on t.attrelid=f.confrelid and t.attnum=f.confkey[1]
    where f.contype='f' and f.confrelid='public.st_v2_workspaces'::regclass and f.conparentid=0
    order by n.nspname,c.relname,f.conname
  loop
    exposure:=case dependency.confdeltype
      when 'c' then 'cascade' when 'a' then 'restrict' when 'r' then 'restrict'
      when 'n' then 'setNull' when 'd' then 'setDefault' end;
    if dependency.category='unclassified' then unknown:=unknown+1; end if;
    affected:=0;
    row_digest:=null;
    if not coalesce(dependency.supported,false) or exposure is null then
      scan_incomplete:=scan_incomplete+1;
    else
      execute format(
        'select count(*),encode(sha256(convert_to(coalesce(string_agg(row_sha,'''' order by row_sha),''''),''UTF8'')),''hex'')
         from (select encode(sha256(convert_to(to_jsonb(x)::text,''UTF8'')),''hex'') as row_sha
               from %I.%I x where x.%I=$1 order by row_sha limit 501) scoped',
         dependency.nspname,dependency.relname,dependency.attname)
        into affected,row_digest using p_workspace;
      groups:=jsonb_set(groups,array[dependency.category],to_jsonb((groups->>dependency.category)::bigint+affected));
      impact:=jsonb_set(impact,array[exposure],to_jsonb((impact->>exposure)::bigint+affected));
      if affected>500 then bounded_count:=bounded_count+1; end if;
    end if;
    fingerprints:=fingerprints||jsonb_build_array(jsonb_build_array(dependency.nspname,dependency.relname,
      dependency.conname,dependency.attname,dependency.confdeltype,dependency.convalidated,dependency.condeferrable,
      dependency.condeferred,dependency.category,affected,row_digest));
  end loop;
  select * into audit from sectalk_private.st_v8_offboarding_audit_custody_manifest(p_workspace);
  if audit.event_count>10000 then bounded_count:=bounded_count+1;
  elsif audit.event_count>0 and not audit.valid then scan_incomplete:=scan_incomplete+1; end if;
  fingerprints:=fingerprints||jsonb_build_array(jsonb_build_array('preserved-workspace-audit',
    audit.event_count,audit.valid,audit.sha256));
  return jsonb_build_object(
    'summary',jsonb_build_object('categories',groups,'deleteActions',impact,
      'unsupportedConstraints',scan_incomplete,'unclassifiedConstraints',unknown,'overflowFamilies',bounded_count,
      'directReferencesClear',scan_incomplete=0 and unknown=0 and bounded_count=0
        and not exists(select 1 from jsonb_each_text(impact) q where q.value::bigint>0)),
    'revision',encode(sha256(convert_to(fingerprints::text,'UTF8')),'hex'));
end $$;

notify pgrst,'reload schema';
commit;
