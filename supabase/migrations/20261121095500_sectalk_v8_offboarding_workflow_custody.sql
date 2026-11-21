begin;

-- Keep the existing root cascades for ordinary workspaces. The reviewed staged
-- request and its exact inventory case can retain their native identities.
alter table sectalk_private.st_v8_offboarding_requests add column live_workspace uuid;
alter table sectalk_private.st_v7_compliance_cases add column live_workspace uuid;
update sectalk_private.st_v8_offboarding_requests set live_workspace=workspace;
update sectalk_private.st_v7_compliance_cases set live_workspace=workspace_id;
alter table sectalk_private.st_v8_offboarding_requests
  add constraint st_v8_offboarding_requests_live_workspace_fkey foreign key(live_workspace)
    references public.st_v2_workspaces(id) on delete cascade,
  add check(live_workspace is null or live_workspace=workspace),
  drop constraint st_v8_offboarding_requests_workspace_fkey;
alter table sectalk_private.st_v7_compliance_cases
  add constraint st_v7_compliance_cases_live_workspace_fkey foreign key(live_workspace)
    references public.st_v2_workspaces(id) on delete cascade,
  add check(live_workspace is null or live_workspace=workspace_id),
  drop constraint st_v7_compliance_cases_workspace_id_fkey;
create index st_v8_offboarding_requests_live_workspace on sectalk_private.st_v8_offboarding_requests(live_workspace)
  where live_workspace is not null;
create index st_v7_compliance_cases_live_workspace on sectalk_private.st_v7_compliance_cases(live_workspace)
  where live_workspace is not null;

create table sectalk_private.st_v8_offboarding_workflow_custody_plans (
  id uuid primary key default gen_random_uuid(),
  capture_order bigint generated always as identity unique,
  workspace uuid not null,
  request_id uuid not null references sectalk_private.st_v8_offboarding_requests(id),
  case_id uuid not null references sectalk_private.st_v7_compliance_cases(id),
  reconciliation uuid not null references sectalk_private.st_v8_offboarding_reconciliations(id),
  audit_plan uuid not null references sectalk_private.st_v8_offboarding_audit_custody_plans(id),
  owner_id uuid not null,
  reviewer_id uuid not null check(owner_id<>reviewer_id),
  request_sha256 text not null check(request_sha256~'^[a-f0-9]{64}$'),
  inventory_sha256 text not null check(inventory_sha256~'^[a-f0-9]{64}$'),
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  captured_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null
);
create index st_v8_offboarding_workflow_custody_latest
  on sectalk_private.st_v8_offboarding_workflow_custody_plans(request_id,capture_order desc);
create table sectalk_private.st_v8_offboarding_workflow_custody_decisions (
  plan uuid not null references sectalk_private.st_v8_offboarding_workflow_custody_plans(id),
  action text not null check(action in ('approved','detached')),
  actor uuid not null,
  execution_xid xid8 not null default pg_current_xact_id(),
  happened_at timestamptz not null default clock_timestamp(),
  primary key(plan,action)
);
alter table sectalk_private.st_v8_offboarding_workflow_custody_plans enable row level security;
alter table sectalk_private.st_v8_offboarding_workflow_custody_decisions enable row level security;
revoke all on sectalk_private.st_v8_offboarding_workflow_custody_plans,
  sectalk_private.st_v8_offboarding_workflow_custody_decisions from public,anon,authenticated,service_role;
create trigger st_v8_offboarding_workflow_custody_plans_immutable before update or delete
  on sectalk_private.st_v8_offboarding_workflow_custody_plans
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_offboarding_workflow_custody_decisions_immutable before update or delete
  on sectalk_private.st_v8_offboarding_workflow_custody_decisions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

create function sectalk_private.st_v8_offboarding_workflow_row_digest(p_row jsonb)
returns text language sql immutable strict set search_path='' as $$
  select encode(sha256(convert_to((p_row-'live_workspace')::text,'UTF8')),'hex')
$$;

create function sectalk_private.st_v8_offboarding_workflow_custody_guard()
returns trigger language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  workspace_key uuid:=((case when tg_op='DELETE' then to_jsonb(old) else to_jsonb(new) end)->>tg_argv[0])::uuid;
  old_sha text;
  is_request boolean:=tg_argv[0]='workspace';
begin
  if tg_op='INSERT' then
    new.live_workspace:=workspace_key;
    return new;
  end if;
  if tg_op='DELETE' then
    if old.live_workspace is null then raise exception 'Reviewed offboarding evidence is retained' using errcode='PT409'; end if;
    return old;
  end if;
  if workspace_key is distinct from (to_jsonb(old)->>tg_argv[0])::uuid or new.id is distinct from old.id then
    raise exception 'Original offboarding workflow attribution is immutable' using errcode='PT409';
  end if;
  old_sha:=sectalk_private.st_v8_offboarding_workflow_row_digest(to_jsonb(old));
  if old.live_workspace is null and (to_jsonb(old)-'live_workspace') is distinct from (to_jsonb(new)-'live_workspace') then
    -- A live change restores its own dependency. After root removal the FK
    -- prevents any further mutation of the retained source row.
    new.live_workspace:=workspace_key;
  elsif old.live_workspace is not null and new.live_workspace is null then
    if (to_jsonb(old)-'live_workspace') is distinct from (to_jsonb(new)-'live_workspace')
      or not exists(select 1 from sectalk_private.st_v8_offboarding_workflow_custody_plans p
        join sectalk_private.st_v8_offboarding_workflow_custody_decisions a
          on (a.plan,a.action,a.actor)=(p.id,'approved',p.reviewer_id)
        join sectalk_private.st_v8_offboarding_workflow_custody_decisions d
          on (d.plan,d.action,d.actor)=(p.id,'detached',p.owner_id)
        where p.workspace=workspace_key and p.expires_at>clock_timestamp() and d.execution_xid=pg_current_xact_id()
          and p.owner_id=auth.uid()
          and case when is_request then (p.request_id,p.request_sha256)=(old.id,old_sha)
            else (p.case_id,p.inventory_sha256)=(old.id,old_sha) end) then
      raise exception 'Current independently reviewed workflow custody is required' using errcode='PT423';
    end if;
  end if;
  return new;
end $$;
create trigger st_v8_offboarding_workflow_request_custody before insert or update or delete
  on sectalk_private.st_v8_offboarding_requests
  for each row execute function sectalk_private.st_v8_offboarding_workflow_custody_guard('workspace');
create trigger st_v8_offboarding_workflow_case_custody before insert or update or delete
  on sectalk_private.st_v7_compliance_cases
  for each row execute function sectalk_private.st_v8_offboarding_workflow_custody_guard('workspace_id');

create function public.st_v8_offboarding_workflow_custody(
  p_workspace uuid,p_action text default 'status',p_confirmation text default null,
  p_plan uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  actor uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests; c sectalk_private.st_v7_compliance_cases;
  plan sectalk_private.st_v8_offboarding_workflow_custody_plans;
  reconciliation jsonb; audit_custody jsonb; request_sha text; case_sha text; digest text;
  held boolean; linked boolean; authorized boolean; matching boolean;
  approved_at timestamptz; detached_at timestamptz;
begin
  if p_workspace is null or p_action is null or p_action not in ('status','capture','approve','detach')
    then raise insufficient_privilege; end if;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if not sectalk_private.st_v8_audit_sso_allows(p_workspace)
    or not sectalk_private.st_v8_compliance_sso_allows(p_workspace) then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if p_confirmation is distinct from p_workspace::text or actor is distinct from
      (case when p_action='approve' then r.reviewer else r.requester end) then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
    perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces where id=p_workspace for update nowait;
    perform 1 from sectalk_private.st_v8_offboarding_requests x where (x.id,x.workspace)=(r.id,p_workspace) for update nowait;
    perform 1 from sectalk_private.st_v8_offboarding_reviewers x where (x.workspace,x.actor)=(p_workspace,r.reviewer) for share;
    perform 1 from public.st_v2_members m where m.workspace_id=p_workspace and m.user_id in (r.requester,r.reviewer)
      order by m.user_id for share;
    r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
    if not sectalk_private.st_v8_audit_sso_allows(p_workspace) or not sectalk_private.st_v8_compliance_sso_allows(p_workspace)
      or actor is distinct from (case when p_action='approve' then r.reviewer else r.requester end)
      or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
    perform 1 from auth.sessions n
      join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
      join auth.mfa_amr_claims a on a.session_id=n.id and a.authentication_method='totp'
      where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',actor) and n.aal='aal2'
        and f.status='verified' and f.factor_type='totp' and a.updated_at>clock_timestamp()-interval '5 minutes'
        and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp()
      for share of n,f,a;
    if not found then raise insufficient_privilege; end if;
    perform 1 from sectalk_private.st_v7_compliance_cases x where x.id=r.case_id for update nowait;
  end if;
  perform sectalk_private.limit_action('v8_offboarding_workflow_custody',20);
  select * into c from sectalk_private.st_v7_compliance_cases x
    where (x.id,x.workspace_id,x.requester,x.reviewer)=(r.case_id,p_workspace,r.requester,r.reviewer);
  if c.id is null then raise insufficient_privilege; end if;
  linked:=r.live_workspace is not null or c.live_workspace is not null;
  held:=sectalk_private.st_v8_offboarding_holds(p_workspace);
  request_sha:=sectalk_private.st_v8_offboarding_workflow_row_digest(to_jsonb(r));
  case_sha:=sectalk_private.st_v8_offboarding_workflow_row_digest(to_jsonb(c));
  select p.* into plan from sectalk_private.st_v8_offboarding_workflow_custody_plans p
    where (p.workspace,p.request_id,p.case_id,p.owner_id,p.reviewer_id)=(p_workspace,r.id,c.id,r.requester,r.reviewer)
    order by p.capture_order desc limit 1;
  select d.happened_at into detached_at from sectalk_private.st_v8_offboarding_workflow_custody_decisions d
    where (d.plan,d.action,d.actor)=(plan.id,'detached',r.requester);
  select d.happened_at into approved_at from sectalk_private.st_v8_offboarding_workflow_custody_decisions d
    where (d.plan,d.action,d.actor)=(plan.id,'approved',r.reviewer);
  audit_custody:=public.st_v8_offboarding_workspace_audit_custody(p_workspace);
  if not linked and detached_at is not null and request_sha=plan.request_sha256 and case_sha=plan.inventory_sha256 then
    if p_action<>'status' and (p_action<>'detach' or (p_plan,p_sha256) is distinct from (plan.id,plan.sha256)) then
      raise exception 'Confirm the existing exact workflow custody receipt' using errcode='PT409';
    end if;
    return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'requestSha256',request_sha,'inventorySha256',case_sha,
      'current',not held and (audit_custody->>'current')::boolean and not (audit_custody->>'linked')::boolean
        and (audit_custody->>'plan')::uuid=plan.audit_plan,'ready',false,
      'held',held,'linked',false,'approvedAt',approved_at,'detachedAt',detached_at);
  end if;
  reconciliation:=public.st_v8_offboarding_reconciliation(p_workspace);
  authorized:=coalesce(not held and (audit_custody->>'current')::boolean and not (audit_custody->>'linked')::boolean
    and audit_custody->>'detachedAt' is not null and (reconciliation->>'current')::boolean
    and reconciliation->>'reviewedAt' is not null and c.state='approved' and c.ticket is null
    and c.expires_at>clock_timestamp() and c.manifest_sha256~'^[a-f0-9]{64}$'
    and exists(select 1 from sectalk_private.st_v7_compliance_audit a
      where (a.case_id,a.workspace_id,a.actor,a.action)=(c.id,p_workspace,r.requester,'downloaded'))
    and not exists(select 1 from sectalk_private.st_v7_evidence_operations x
      join sectalk_private.st_v7_compliance_cases q on q.id=x.case_id where q.workspace_id=p_workspace
      and x.expires_at>clock_timestamp()),false);
  if p_action<>'status' and (not linked or not authorized) then
    raise exception 'A current independent audit custody and source review are required' using errcode='PT409';
  end if;
  digest:=encode(sha256(convert_to(jsonb_build_array('sectalk-offboarding-workflow-custody-v1',p_workspace,r.id,c.id,
    r.requester,r.reviewer,request_sha,case_sha,audit_custody->>'plan',audit_custody->>'sha256',
    reconciliation->>'plan',reconciliation->>'sha256')::text,'UTF8')),'hex');
  matching:=coalesce(authorized and plan.sha256=digest and plan.expires_at>clock_timestamp(),false);
  if p_action='capture' then
    if p_plan is not null or p_sha256 is not null then raise exception 'Capture the current custody scope' using errcode='PT409'; end if;
    if not matching then
      insert into sectalk_private.st_v8_offboarding_workflow_custody_plans(workspace,request_id,case_id,reconciliation,audit_plan,
        owner_id,reviewer_id,request_sha256,inventory_sha256,sha256,expires_at)
        values(p_workspace,r.id,c.id,(reconciliation->>'plan')::uuid,(audit_custody->>'plan')::uuid,r.requester,r.reviewer,
          request_sha,case_sha,digest,least(c.expires_at,(reconciliation->>'expiresAt')::timestamptz,
          (audit_custody->>'expiresAt')::timestamptz,clock_timestamp()+interval '30 minutes')) returning * into plan;
      matching:=true;
      approved_at:=null;
      detached_at:=null;
    end if;
  elsif p_action in ('approve','detach') then
    if not matching or p_plan is null or (p_plan,p_sha256) is distinct from (plan.id,plan.sha256) then
      raise exception 'Confirm the latest exact workflow custody plan' using errcode='PT409'; end if;
    if p_action='approve' then
      insert into sectalk_private.st_v8_offboarding_workflow_custody_decisions(plan,action,actor)
        values(plan.id,'approved',actor) on conflict do nothing;
      select d.happened_at into approved_at from sectalk_private.st_v8_offboarding_workflow_custody_decisions d
        where (d.plan,d.action,d.actor)=(plan.id,'approved',r.reviewer);
    else
      if approved_at is null or detached_at is not null then raise insufficient_privilege; end if;
      insert into sectalk_private.st_v8_offboarding_workflow_custody_decisions(plan,action,actor)
        values(plan.id,'detached',actor) returning happened_at into detached_at;
      update sectalk_private.st_v8_offboarding_requests x set live_workspace=null where x.id=r.id and x.live_workspace=p_workspace;
      update sectalk_private.st_v7_compliance_cases x set live_workspace=null where x.id=c.id and x.live_workspace=p_workspace;
      linked:=false;
      authorized:=false;
    end if;
  end if;
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'requestSha256',request_sha,'inventorySha256',case_sha,
    'current',matching,'ready',authorized,'held',held,'linked',linked,'approvedAt',approved_at,'detachedAt',detached_at);
end $$;

revoke all on function sectalk_private.st_v8_offboarding_workflow_row_digest(jsonb),
  sectalk_private.st_v8_offboarding_workflow_custody_guard(),
  public.st_v8_offboarding_workflow_custody(uuid,text,text,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_workflow_custody(uuid,text,text,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
