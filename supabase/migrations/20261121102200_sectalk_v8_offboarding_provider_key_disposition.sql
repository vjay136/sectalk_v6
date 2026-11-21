begin;

create table sectalk_private.st_v8_offboarding_byok_plans (
  id uuid primary key default gen_random_uuid(),
  capture_order bigint generated always as identity unique,
  workspace uuid not null,
  request_id uuid not null references sectalk_private.st_v8_offboarding_requests(id),
  source_review uuid not null references sectalk_private.st_v8_offboarding_reconciliations(id),
  owner_id uuid not null,
  reviewer_id uuid not null check(reviewer_id<>owner_id),
  versions integer not null check(versions between 1 and 64),
  evidence_sha256 text not null check(evidence_sha256~'^[a-f0-9]{64}$'),
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  expires_at timestamptz not null
);
create index st_v8_offboarding_byok_latest on sectalk_private.st_v8_offboarding_byok_plans(request_id,capture_order desc);
create table sectalk_private.st_v8_offboarding_byok_decisions (
  plan uuid not null references sectalk_private.st_v8_offboarding_byok_plans(id),
  action text not null check(action in ('approved','retired')),
  actor uuid not null,
  happened_at timestamptz not null default clock_timestamp(),
  primary key(plan,action)
);
create table sectalk_private.st_v8_offboarding_retired_provider_pins (
  pin_sha256 text primary key check(pin_sha256~'^[a-f0-9]{64}$'),
  plan uuid not null references sectalk_private.st_v8_offboarding_byok_plans(id),
  version integer not null check(version>0),
  marker_sha256 text not null check(marker_sha256~'^[a-f0-9]{64}$'),
  receipt_sha256 text not null check(receipt_sha256~'^[a-f0-9]{64}$'),
  unique(plan,version)
);
alter table sectalk_private.st_v8_offboarding_byok_plans enable row level security;
alter table sectalk_private.st_v8_offboarding_byok_decisions enable row level security;
alter table sectalk_private.st_v8_offboarding_retired_provider_pins enable row level security;
revoke all on sectalk_private.st_v8_offboarding_byok_plans,sectalk_private.st_v8_offboarding_byok_decisions,
  sectalk_private.st_v8_offboarding_retired_provider_pins from public,anon,authenticated,service_role;
create trigger st_v8_offboarding_byok_plans_immutable before update or delete on sectalk_private.st_v8_offboarding_byok_plans
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_offboarding_byok_decisions_immutable before update or delete on sectalk_private.st_v8_offboarding_byok_decisions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_offboarding_provider_pins_immutable before update or delete on sectalk_private.st_v8_offboarding_retired_provider_pins
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

create function sectalk_private.st_v8_offboarding_provider_pin_digest(p_pin text)
returns text language sql immutable strict set search_path='' as $$
  select encode(sha256(convert_to('sectalk-retired-provider-pin-v1:'||p_pin,'UTF8')),'hex')
$$;

-- Keep a permanent unique reservation at registration. The unique constraint
-- also prevents concurrent reuse under a previously opened MVCC snapshot.
create table sectalk_private.st_v8_offboarding_provider_pin_registry (
  pin_sha256 text primary key check(pin_sha256~'^[a-f0-9]{64}$'),
  workspace uuid not null,
  version integer not null
);
alter table sectalk_private.st_v8_offboarding_provider_pin_registry enable row level security;
revoke all on sectalk_private.st_v8_offboarding_provider_pin_registry from public,anon,authenticated,service_role;
create trigger st_v8_offboarding_provider_pin_registry_immutable before update or delete on sectalk_private.st_v8_offboarding_provider_pin_registry
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
lock table sectalk_private.st_v7_tenant_key_versions in share row exclusive mode;
insert into sectalk_private.st_v8_offboarding_provider_pin_registry(pin_sha256,workspace,version)
  select sectalk_private.st_v8_offboarding_provider_pin_digest(substr(k.wrapped,13,43)),k.workspace,k.version
  from sectalk_private.st_v7_tenant_key_versions k where k.custody='byok'
    and k.wrapped~'^external_v2_[A-Za-z0-9_-]{43}_[A-Za-z0-9_-]{43}$';

create function sectalk_private.st_v8_offboarding_guard_provider_pin()
returns trigger language plpgsql security definer set search_path='' as $$
declare digest text;
begin
  if new.custody='byok' and new.wrapped~'^external_v2_[A-Za-z0-9_-]{43}_[A-Za-z0-9_-]{43}$' then
    digest:=sectalk_private.st_v8_offboarding_provider_pin_digest(substr(new.wrapped,13,43));
    if tg_op='UPDATE' and (old.workspace,old.version,old.custody,substr(old.wrapped,13,43))
      =(new.workspace,new.version,new.custody,substr(new.wrapped,13,43)) then return new; end if;
    insert into sectalk_private.st_v8_offboarding_provider_pin_registry(pin_sha256,workspace,version)
      values(digest,new.workspace,new.version) on conflict do nothing;
    if not found then
      raise exception 'Previously registered provider key cannot be reused' using errcode='PT409';
    end if;
  end if;
  return new;
end $$;
create trigger st_v8_offboarding_guard_provider_pin before insert or update of workspace,version,custody,wrapped
  on sectalk_private.st_v7_tenant_key_versions
  for each row execute function sectalk_private.st_v8_offboarding_guard_provider_pin();

create function sectalk_private.st_v8_offboarding_provider_key_scope(r sectalk_private.st_v8_offboarding_requests)
returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  with state as materialized (
    select * from sectalk_private.st_v7_tenant_key_state k where k.workspace=r.workspace
  ), versions as materialized (
    select * from sectalk_private.st_v7_tenant_key_versions k where k.workspace=r.workspace order by k.version limit 65
  ), evidence as materialized (
    select e.*,encode(sha256(convert_to(to_jsonb(e)::text,'UTF8')),'hex') as digest
    from sectalk_private.st_v8_provider_erasure_receipts e where (e.request,e.workspace)=(r.id,r.workspace)
    order by e.version limit 65
  ), coverage as (
    select count(*)::integer as n,min(k.version) as first_version,max(k.version) as last_version,
      count(e.version)::integer as matched,
      coalesce(bool_and(k.custody='byok' and k.wrapped~'^external_v2_[A-Za-z0-9_-]{43}_[A-Za-z0-9_-]{43}$'
        and (select count(*) from sectalk_private.st_v7_tenant_key_audit a where (a.workspace,a.version)=(r.workspace,k.version)
          and a.event in ('provisioned','rotated','scheduled_rotation'))=1),false) as pinned,
      coalesce(jsonb_agg(jsonb_build_array(k.version,encode(sha256(convert_to(to_jsonb(k)::text,'UTF8')),'hex'),
        e.digest) order by k.version),'[]') as fingerprints
    from versions k left join evidence e on e.version=k.version and e.actor=r.reviewer
      and e.provider_pin=substr(k.wrapped,13,43) and e.provider_event_time>=r.staged_at
      and e.provider_event_time<=clock_timestamp()
  ), retired as (
    select p.id,p.sha256,p.versions
    from sectalk_private.st_v8_offboarding_byok_plans p
    join sectalk_private.st_v8_offboarding_byok_decisions d on (d.plan,d.action,d.actor)=(p.id,'retired',r.requester)
    join sectalk_private.st_v8_offboarding_byok_decisions a on (a.plan,a.action,a.actor)=(p.id,'approved',r.reviewer)
    join state s on s.destroyed_at=d.happened_at and s.current_version=p.versions
    where (p.workspace,p.request_id,p.owner_id,p.reviewer_id)=(r.workspace,r.id,r.requester,r.reviewer)
      and (select count(*) from evidence)=p.versions and (select count(*) from sectalk_private.st_v8_offboarding_retired_provider_pins x
        join evidence e on (e.version,e.digest)=(x.version,x.receipt_sha256)
          and x.pin_sha256=sectalk_private.st_v8_offboarding_provider_pin_digest(e.provider_pin)
        join sectalk_private.st_v8_offboarding_provider_pin_registry pin
          on (pin.pin_sha256,pin.workspace,pin.version)=(x.pin_sha256,r.workspace,x.version)
        where x.plan=p.id)=p.versions
  ), summary as (
    select c.n,c.matched,s.current_version,
      case when t.id is not null and c.n=0 then 'native-markers-retired'
        when c.n=0 and s.workspace is null
          and not exists(select 1 from sectalk_private.st_v7_tenant_key_audit a where a.workspace=r.workspace)
          and not exists(select 1 from evidence) then 'no-recorded-key-history'
        when s.destroyed_at is null and c.n between 1 and 64 and c.n=s.current_version
          and (c.first_version,c.last_version)=(1,s.current_version) and c.pinned and c.matched=c.n
          and c.n=(select count(*) from evidence)
          and c.n=(select count(*) from sectalk_private.st_v7_tenant_key_audit a where a.workspace=r.workspace
            and a.event in ('provisioned','rotated','scheduled_rotation')) then 'exact-provider-key-evidence'
        else 'unresolved-key-history' end as state_name,
      t.id as retirement,t.sha256 as retirement_sha,t.versions as retired_versions,c.fingerprints
    from coverage c left join state s on true left join retired t on true
  )
  select jsonb_build_object('state',x.state_name,'versions',x.n,'matched',x.matched,
    'retiredVersions',coalesce(x.retired_versions,0),'receipt',x.retirement,'receiptSha256',x.retirement_sha,
    'sha256',encode(sha256(convert_to(jsonb_build_array('sectalk-native-provider-key-scope-v1',r.workspace,r.id,
      x.current_version,x.state_name,x.fingerprints,x.retirement,x.retirement_sha)::text,'UTF8')),'hex'))
  from summary x
$$;

-- Consume provider-key scope in the exact root digest. Storage and recovery
-- remain separately unverified by the existing reconciliation response.
create or replace function sectalk_private.st_v8_offboarding_reconcile_workspace_root(r sectalk_private.st_v8_offboarding_requests)
returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  with base as materialized (select sectalk_private.st_v8_offboarding_reconcile_archives(r) as snapshot),
    root as materialized (select sectalk_private.st_v8_offboarding_workspace_root_snapshot(r.workspace) as snapshot),
    provider as materialized (select sectalk_private.st_v8_offboarding_provider_key_scope(r) as snapshot)
  select jsonb_build_object('summary',(base.snapshot->'summary')||jsonb_build_object(
    'workspaceRootDependencies',root.snapshot->'summary',
    'providerKeyDisposition',provider.snapshot-'sha256',
    'overflow',(base.snapshot#>'{summary,overflow}')||case when (root.snapshot#>>'{summary,overflowFamilies}')::integer>0
      then '["workspaceRootReferences"]'::jsonb else '[]'::jsonb end),
    'revision',encode(sha256(convert_to(jsonb_build_array('sectalk-workspace-root-reconciliation-v2',
      base.snapshot->>'revision',root.snapshot->>'revision',provider.snapshot->>'sha256')::text,'UTF8')),'hex'))
  from base cross join root cross join provider;
$$;

create function public.st_v8_offboarding_provider_key_retirement(
  p_workspace uuid,p_action text default 'status',p_confirmation text default null,
  p_plan uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  actor uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_byok_plans; reviewed jsonb; scope jsonb; digest text;
  approved_at timestamptz; retired_at timestamptz; removed integer; current_review boolean;
begin
  if p_workspace is null or p_action is null or p_action not in ('status','capture','approve','retire')
    then raise insufficient_privilege; end if;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if not sectalk_private.st_v8_audit_sso_allows(p_workspace)
    or not sectalk_private.st_v8_compliance_sso_allows(p_workspace) then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if p_confirmation is distinct from p_workspace::text or actor is distinct from
      (case when p_action='approve' then r.reviewer else r.requester end) then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
    perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for update nowait;
    perform 1 from sectalk_private.st_v8_offboarding_requests x where x.id=r.id for share nowait;
    perform 1 from sectalk_private.st_v8_offboarding_reviewers x where (x.workspace,x.actor)=(p_workspace,r.reviewer) for share;
    perform 1 from sectalk_private.st_v7_tenant_destroy_reviewers d where (d.workspace,d.actor)=(p_workspace,r.reviewer) for share;
    perform 1 from public.st_v2_members x where x.workspace_id=p_workspace and x.user_id in (r.requester,r.reviewer)
      order by x.user_id for share;
    r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
    if actor is distinct from (case when p_action='approve' then r.reviewer else r.requester end)
      or not sectalk_private.st_v8_provider_erasure_reviewer(r,r.reviewer)
      or not sectalk_private.st_v8_audit_sso_allows(p_workspace) or not sectalk_private.st_v8_compliance_sso_allows(p_workspace)
      then raise insufficient_privilege; end if;
    perform 1 from auth.sessions n join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
      join auth.mfa_amr_claims a on a.session_id=n.id and a.authentication_method='totp'
      where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',actor) and n.aal='aal2'
        and f.status='verified' and f.factor_type='totp' and a.updated_at>clock_timestamp()-interval '5 minutes'
        and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp() for share of n,f,a;
    if not found then raise insufficient_privilege; end if;
    perform 1 from sectalk_private.st_v7_tenant_key_state x where x.workspace=p_workspace for update nowait;
    perform 1 from sectalk_private.st_v7_tenant_key_versions x where x.workspace=p_workspace order by x.version limit 65 for update nowait;
    if p_action='retire' then
      lock table sectalk_private.st_v7_artifact_envelopes,sectalk_private.st_v8_managed_room_evidence,
        sectalk_private.st_v7_tenant_rotation_tickets,sectalk_private.st_v8_provider_erasure_tickets,
        sectalk_private.st_v7_evidence_operations in share mode nowait;
    end if;
  end if;
  perform sectalk_private.limit_action('v8_offboarding_provider_key_retirement',20);
  scope:=sectalk_private.st_v8_offboarding_provider_key_scope(r);
  select x.* into plan from sectalk_private.st_v8_offboarding_byok_plans x
    where (x.workspace,x.request_id,x.owner_id,x.reviewer_id)=(p_workspace,r.id,r.requester,r.reviewer)
    order by x.capture_order desc limit 1;
  select d.happened_at into approved_at from sectalk_private.st_v8_offboarding_byok_decisions d
    where (d.plan,d.action,d.actor)=(plan.id,'approved',r.reviewer);
  select d.happened_at into retired_at from sectalk_private.st_v8_offboarding_byok_decisions d
    where (d.plan,d.action,d.actor)=(plan.id,'retired',r.requester);
  if scope->>'state'='native-markers-retired' then
    if p_action<>'status' and (p_action<>'retire' or (p_plan,p_sha256) is distinct from (plan.id,plan.sha256)) then
      raise exception 'Use the existing exact provider-key retirement receipt' using errcode='PT409'; end if;
  end if;
  if p_action='status' or scope->>'state'='native-markers-retired' then
    return scope||jsonb_build_object('plan',plan.id,'planSha256',plan.sha256,'approvedAt',approved_at,'retiredAt',retired_at,
      'held',sectalk_private.st_v8_offboarding_holds(p_workspace),'backupErasure','unverified','providerBytes','unverified');
  end if;
  reviewed:=public.st_v8_offboarding_reconciliation(p_workspace);
  if scope->>'state' is distinct from 'exact-provider-key-evidence'
    or (reviewed->>'current')::boolean is not true or reviewed->>'reviewedAt' is null
    or exists(select 1 from sectalk_private.st_v7_artifact_envelopes x where x.workspace=p_workspace)
    or exists(select 1 from sectalk_private.st_v8_managed_room_evidence x where x.workspace=p_workspace)
    or exists(select 1 from sectalk_private.st_v7_tenant_rotation_tickets x where x.workspace=p_workspace and x.expires_at>clock_timestamp())
    or exists(select 1 from sectalk_private.st_v8_provider_erasure_tickets x where x.workspace=p_workspace and x.expires_at>clock_timestamp())
    or exists(select 1 from sectalk_private.st_v7_tenant_key_destroy x where x.workspace=p_workspace and x.result is null)
    or exists(select 1 from sectalk_private.st_v8_tenant_rotation_schedules x where x.workspace=p_workspace)
    or exists(select 1 from sectalk_private.st_v7_compliance_cases x where x.workspace_id=p_workspace and x.ticket_until>clock_timestamp())
    or exists(select 1 from sectalk_private.st_v7_evidence_operations x
      join sectalk_private.st_v7_compliance_cases c on c.id=x.case_id where c.workspace_id=p_workspace and x.expires_at>clock_timestamp())
    or exists(select 1 from sectalk_private.st_v7_tenant_key_versions k where k.workspace=p_workspace
      and sectalk_private.st_v8_offboarding_root_child_has_references('sectalk_private.st_v7_tenant_key_versions',to_jsonb(k)))
    then raise exception 'Exact reviewed provider-key history and clear live evidence dependencies are required' using errcode='PT409'; end if;
  digest:=encode(sha256(convert_to(jsonb_build_array('sectalk-native-provider-key-retirement-v1',p_workspace,r.id,r.requester,
    r.reviewer,scope->>'sha256',reviewed->>'plan',reviewed->>'sha256')::text,'UTF8')),'hex');
  current_review:=coalesce(plan.sha256=digest and plan.expires_at>clock_timestamp(),false);
  if p_action='capture' then
    if p_plan is not null or p_sha256 is not null then raise exception 'Capture the current provider-key history' using errcode='PT409'; end if;
    if not current_review then
      insert into sectalk_private.st_v8_offboarding_byok_plans(workspace,request_id,source_review,owner_id,reviewer_id,versions,evidence_sha256,sha256,expires_at)
        values(p_workspace,r.id,(reviewed->>'plan')::uuid,r.requester,r.reviewer,(scope->>'versions')::integer,scope->>'sha256',digest,
          least((reviewed->>'expiresAt')::timestamptz,clock_timestamp()+interval '30 minutes')) returning * into plan;
    end if;
  elsif not current_review or p_plan is null or (p_plan,p_sha256) is distinct from (plan.id,plan.sha256) then
    raise exception 'Confirm the latest exact provider-key retirement digest' using errcode='PT409';
  end if;
  if p_action='approve' then
    insert into sectalk_private.st_v8_offboarding_byok_decisions(plan,action,actor)
      values(plan.id,'approved',actor) on conflict do nothing;
  end if;
  select d.happened_at into approved_at from sectalk_private.st_v8_offboarding_byok_decisions d
    where (d.plan,d.action,d.actor)=(plan.id,'approved',r.reviewer);
  if p_action='retire' then
    if approved_at is null then raise insufficient_privilege; end if;
    insert into sectalk_private.st_v8_offboarding_retired_provider_pins(pin_sha256,plan,version,marker_sha256,receipt_sha256)
      select sectalk_private.st_v8_offboarding_provider_pin_digest(e.provider_pin),plan.id,k.version,
        encode(sha256(convert_to(to_jsonb(k)::text,'UTF8')),'hex'),encode(sha256(convert_to(to_jsonb(e)::text,'UTF8')),'hex')
      from sectalk_private.st_v7_tenant_key_versions k join sectalk_private.st_v8_provider_erasure_receipts e
        on (e.request,e.workspace,e.version)=(r.id,k.workspace,k.version) where k.workspace=p_workspace;
    delete from sectalk_private.st_v7_tenant_key_versions k where k.workspace=p_workspace;
    get diagnostics removed=row_count;
    if removed<>plan.versions then raise exception 'The reviewed provider-key version set changed' using errcode='PT409'; end if;
    insert into sectalk_private.st_v8_offboarding_byok_decisions(plan,action,actor)
      values(plan.id,'retired',actor) returning happened_at into retired_at;
    update sectalk_private.st_v7_tenant_key_state s set destroyed_at=retired_at where s.workspace=p_workspace and s.destroyed_at is null;
    if not found then raise exception 'The original tenant key state changed' using errcode='PT409'; end if;
    insert into sectalk_private.st_v7_tenant_key_audit(workspace,actor,event,version,reason)
      values(p_workspace,actor,'destroyed',plan.versions,'Retired native markers after independently verified provider-key deletion.');
    scope:=sectalk_private.st_v8_offboarding_provider_key_scope(r);
    if scope->>'state' is distinct from 'native-markers-retired' then
      raise exception 'Retired key disposition could not be verified' using errcode='PT409'; end if;
  end if;
  return scope||jsonb_build_object('plan',plan.id,'planSha256',plan.sha256,'approvedAt',approved_at,'retiredAt',retired_at,'held',false,
    'backupErasure','unverified','providerBytes','unverified');
end $$;

revoke all on function sectalk_private.st_v8_offboarding_provider_pin_digest(text),
  sectalk_private.st_v8_offboarding_guard_provider_pin(),
  sectalk_private.st_v8_offboarding_provider_key_scope(sectalk_private.st_v8_offboarding_requests),
  public.st_v8_offboarding_provider_key_retirement(uuid,text,text,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_provider_key_retirement(uuid,text,text,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
