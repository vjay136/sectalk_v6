begin;

create table sectalk_private.st_v8_offboarding_webhook_copies (
  request_id uuid not null,
  endpoint uuid not null,
  owner_id uuid not null,
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  issued_at timestamptz not null default clock_timestamp(),
  primary key(request_id,endpoint,sha256)
);
create table sectalk_private.st_v8_offboarding_webhook_plans (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null,
  workspace uuid not null,
  endpoint uuid not null,
  endpoint_label text not null,
  owner_id uuid not null,
  reviewer_id uuid not null check(reviewer_id<>owner_id),
  copy_sha256 text not null check(copy_sha256~'^[a-f0-9]{64}$'),
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  unique(request_id,endpoint,sha256)
);
create table sectalk_private.st_v8_offboarding_webhook_decisions (
  plan uuid not null references sectalk_private.st_v8_offboarding_webhook_plans,
  action text not null check(action in ('approved','removed')),
  actor uuid not null,
  happened_at timestamptz not null default clock_timestamp(),
  primary key(plan,action)
);
create table sectalk_private.st_v8_offboarding_retired_webhook (
  plan uuid primary key references sectalk_private.st_v8_offboarding_webhook_plans,
  endpoint uuid not null unique,
  custody jsonb not null,
  sha256 text not null check(sha256=encode(sha256(convert_to(custody::text,'UTF8')),'hex')),
  check((custody#>>'{endpoint,id}')::uuid=endpoint)
);
create trigger st_v8_webhook_copy_immutable before update or delete on sectalk_private.st_v8_offboarding_webhook_copies
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_webhook_plan_immutable before update or delete on sectalk_private.st_v8_offboarding_webhook_plans
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_webhook_decision_immutable before update or delete on sectalk_private.st_v8_offboarding_webhook_decisions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_retired_webhook_immutable before update or delete on sectalk_private.st_v8_offboarding_retired_webhook
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_webhook_copies enable row level security;
alter table sectalk_private.st_v8_offboarding_webhook_plans enable row level security;
alter table sectalk_private.st_v8_offboarding_webhook_decisions enable row level security;
alter table sectalk_private.st_v8_offboarding_retired_webhook enable row level security;
revoke all on sectalk_private.st_v8_offboarding_webhook_copies,sectalk_private.st_v8_offboarding_webhook_plans,
  sectalk_private.st_v8_offboarding_webhook_decisions,sectalk_private.st_v8_offboarding_retired_webhook
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_prevent_retired_webhook_reuse()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform pg_advisory_xact_lock(hashtextextended('sectalk-webhook-id:'||new.id::text,0));
  if exists(select 1 from sectalk_private.st_v8_offboarding_retired_webhook x where x.endpoint=new.id) then
    raise exception 'This webhook identifier is permanently retired' using errcode='PT409';
  end if;
  return new;
end $$;
create trigger st_v8_prevent_retired_webhook_reuse before insert or update of id on sectalk_private.st_v6_webhooks
  for each row execute function sectalk_private.st_v8_prevent_retired_webhook_reuse();
create function sectalk_private.st_v8_offboarding_webhook_source(
  r sectalk_private.st_v8_offboarding_requests,p_endpoint uuid
) returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  select jsonb_build_object(
    'endpoint',jsonb_build_object('id',k.id,'workspace',k.workspace_id,'label',k.label,
      'owner',k.owner,'topics',k.topics,'createdAt',k.created_at,'revokedAt',k.revoked_at),
    'shutdownAt',(r.integration_shutdown->>'at')::timestamptz,
    'revocation',case when k.revoked_at=(r.integration_shutdown->>'at')::timestamptz then 'offboarding' else 'owner' end,
    'workspaceAudit',a.events)
  from sectalk_private.st_v6_webhooks k
  cross join lateral (
    select jsonb_agg(to_jsonb(j) order by j.id) as events,
      count(*) filter(where j.event='integration.webhook_created') as created_count,
      count(*) filter(where j.event='integration.webhook_revoked') as revoked_count,
      coalesce(bool_and(j.actor=r.requester and j.event in ('integration.webhook_created','integration.webhook_revoked')
        and exists(select 1 from sectalk_private.st_v6_audit_chain c
          where (c.source,c.source_id,c.operation,c.row_hash)=
            ('public.st_v2_workspace_audit',j.id,'INSERT',sectalk_private.st_v6_audit_row_hash(to_jsonb(j))))
        and not exists(select 1 from sectalk_private.st_v6_audit_chain c where
          (c.source,c.source_id)=('public.st_v2_workspace_audit',j.id) and c.operation<>'INSERT')),false) as original
    from public.st_v2_workspace_audit j where (j.workspace_id,j.target)=(r.workspace,k.id)
  ) a
  where (k.workspace_id,k.id,k.owner)=(r.workspace,p_endpoint,r.requester)
    and k.revoked_at>=k.created_at and k.revoked_at<=(r.integration_shutdown->>'at')::timestamptz
    and a.created_count=1 and a.original
    and a.revoked_count=case when k.revoked_at=(r.integration_shutdown->>'at')::timestamptz then 0 else 1 end
    and not exists(select 1 from sectalk_private.st_v6_webhook_jobs q where q.endpoint_id=k.id)
    and not exists(select 1 from pg_constraint f
      where f.contype='f' and f.confrelid='sectalk_private.st_v6_webhooks'::regclass
        and not (f.conrelid='sectalk_private.st_v6_webhook_jobs'::regclass and cardinality(f.conkey)=1
          and f.conkey[1]=(select attnum from pg_attribute where attrelid=f.conrelid and attname='endpoint_id')))
$$;
create function public.st_v8_offboarding_webhook_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
begin
  if not sectalk_private.st_v8_integration_admin_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace) then raise insufficient_privilege; end if;
  return jsonb_build_object('held',sectalk_private.st_v8_offboarding_holds(p_workspace),
    'endpoints',case when auth.uid()=r.requester then coalesce((select jsonb_agg(to_jsonb(x) order by x.name,x.id) from (
      select c.id,c.label as name,exists(select 1 from sectalk_private.st_v8_offboarding_webhook_copies a
        where (a.request_id,a.endpoint,a.owner_id,a.sha256)=(r.id,c.id,r.requester,
          encode(sha256(convert_to(s.source::text,'UTF8')),'hex'))) as copied
      from sectalk_private.st_v6_webhooks c cross join lateral (select sectalk_private.st_v8_offboarding_webhook_source(r,c.id)
        as source offset 0) s
      where c.workspace_id=p_workspace and c.revoked_at is not null and s.source is not null order by c.label,c.id limit 100
    ) x),'[]') else '[]'::jsonb end,
    'plans',coalesce((select jsonb_agg(to_jsonb(p) order by p."createdAt" desc,p.plan) from (
      select x.id as plan,x.endpoint,x.endpoint_label as name,x.sha256,x.copy_sha256 as "copySha256",
        x.created_at as "createdAt",d.happened_at as "approvedAt",z.happened_at as "deletedAt"
      from sectalk_private.st_v8_offboarding_webhook_plans x
      left join sectalk_private.st_v8_offboarding_webhook_decisions d on (d.plan,d.action)=(x.id,'approved')
      left join sectalk_private.st_v8_offboarding_webhook_decisions z on (z.plan,z.action)=(x.id,'removed')
      where (x.request_id,x.workspace)=(r.id,p_workspace) and (x.expires_at>statement_timestamp() or z.happened_at is not null)
      order by x.created_at desc,x.id limit 50
    ) p),'[]'));
end $$;

create function public.st_v8_offboarding_webhook(
  p_workspace uuid,p_endpoint uuid,p_action text,p_confirmation text,p_plan uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  caller uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_webhook_plans;
  source jsonb; live_endpoint sectalk_private.st_v6_webhooks; metadata_sha text; endpoint_sha text; fingerprint text;
  inventory_until timestamptz; approved_at timestamptz; deleted_at timestamptz;
begin
  if p_workspace is null or p_endpoint is null or p_action is null or p_action not in ('copy','capture','approve','delete')
    or p_confirmation is distinct from p_workspace::text then raise insufficient_privilege; end if;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if not sectalk_private.st_v8_integration_admin_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace)
    or caller is distinct from (case when p_action='approve' then r.reviewer else r.requester end) then raise insufficient_privilege; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform 1 from public.st_v2_workspaces w where w.id=p_workspace for no key update;
  select x.* into r from sectalk_private.st_v8_offboarding_requests x
    where x.workspace=p_workspace and x.state='read_only' and x.integration_shutdown is not null for update;
  perform 1 from sectalk_private.st_v8_offboarding_reviewers x where (x.workspace,x.actor)=(p_workspace,r.reviewer) for share;
  if not found then raise insufficient_privilege; end if;
  perform 1 from public.st_v2_members x where x.workspace_id=p_workspace and x.user_id in (r.requester,r.reviewer)
    order by x.user_id for share;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if not sectalk_private.st_v8_integration_admin_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace)
    or caller is distinct from (case when p_action='approve' then r.reviewer else r.requester end)
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_offboarding_webhook',12);

  if p_action in ('approve','delete') then
    select p.* into plan from sectalk_private.st_v8_offboarding_webhook_plans p
      where (p.id,p.workspace,p.request_id,p.endpoint,p.sha256)=(p_plan,p_workspace,r.id,p_endpoint,p_sha256);
    if plan.id is null then raise exception 'Confirm the exact webhook retirement digest' using errcode='PT409'; end if;
    select x.happened_at into approved_at from sectalk_private.st_v8_offboarding_webhook_decisions x
      where (x.plan,x.action,x.actor)=(plan.id,'approved',r.reviewer);
    select x.happened_at into deleted_at from sectalk_private.st_v8_offboarding_webhook_decisions x
      where (x.plan,x.action,x.actor)=(plan.id,'removed',r.requester);
    if deleted_at is not null then
      return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'approvedAt',approved_at,'deletedAt',deleted_at);
    end if;
  end if;

  select c.expires_at into inventory_until from sectalk_private.st_v7_compliance_cases c
    where (c.id,c.workspace_id,c.requester,c.reviewer)=(r.case_id,p_workspace,r.requester,r.reviewer)
      and c.state='approved' and c.expires_at>clock_timestamp() and c.manifest_sha256~'^[a-f0-9]{64}$' and c.ticket is null for share;
  if inventory_until is null or not exists(select 1 from sectalk_private.st_v7_compliance_audit a
    where (a.case_id,a.workspace_id,a.actor,a.action)=(r.case_id,p_workspace,r.requester,'downloaded'))
    or exists(select 1 from sectalk_private.st_v7_compliance_cases c where c.workspace_id=p_workspace and c.id<>r.case_id
      and c.state in ('pending','approved') and c.expires_at>clock_timestamp())
    or exists(select 1 from sectalk_private.st_v7_evidence_operations o
      join sectalk_private.st_v7_compliance_cases c on c.id=o.case_id where c.workspace_id=p_workspace and o.expires_at>clock_timestamp())
    then raise exception 'Live inventory and clear evidence retention are required' using errcode='PT409'; end if;
  if p_action='delete' then
    perform pg_advisory_xact_lock(hashtextextended('sectalk-webhook-id:'||p_endpoint::text,0));
  end if;
  select k.* into live_endpoint from sectalk_private.st_v6_webhooks k where (k.workspace_id,k.id)=(p_workspace,p_endpoint) for update nowait;
  if not found then raise insufficient_privilege; end if;
  perform 1 from public.st_v2_workspace_audit a where (a.workspace_id,a.target)=(p_workspace,p_endpoint) order by a.id limit 3 for share nowait;
  source:=sectalk_private.st_v8_offboarding_webhook_source(r,p_endpoint);
  if source is null then raise exception 'The revoked webhook or its retained evidence is ineligible' using errcode='PT409'; end if;
  metadata_sha:=encode(sha256(convert_to(source::text,'UTF8')),'hex');
  endpoint_sha:=encode(sha256(convert_to(to_jsonb(live_endpoint)::text,'UTF8')),'hex');
  perform 1 from auth.sessions n join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
    join auth.mfa_amr_claims a on a.session_id=n.id and a.authentication_method='totp'
    where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',caller) and n.aal='aal2' and f.status='verified' and f.factor_type='totp'
      and a.updated_at>clock_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp() for share of n,f,a;
  if not found or inventory_until<=clock_timestamp() then raise insufficient_privilege; end if;

  if p_action='copy' then
    insert into sectalk_private.st_v8_offboarding_webhook_copies(request_id,endpoint,owner_id,sha256)
      values(r.id,p_endpoint,caller,metadata_sha) on conflict do nothing;
    return jsonb_build_object('format','sectalk-offboarding-webhook-retirement-copy-v1','endpoint',p_endpoint,
      'sha256',metadata_sha,'json',source::text);
  end if;
  if not exists(select 1 from sectalk_private.st_v8_offboarding_webhook_copies a
    where (a.request_id,a.endpoint,a.owner_id,a.sha256)=(r.id,p_endpoint,r.requester,metadata_sha)) then
    raise exception 'Download the exact approved endpoint copy first' using errcode='PT409'; end if;
  fingerprint:=encode(sha256(convert_to(jsonb_build_array('sectalk-offboarding-webhook-retirement-v1',p_workspace,r.id,
    r.snapshot_sha256,p_endpoint,metadata_sha,endpoint_sha)::text,'UTF8')),'hex');
  if p_action='capture' then
    insert into sectalk_private.st_v8_offboarding_webhook_plans(request_id,workspace,endpoint,endpoint_label,
      owner_id,reviewer_id,copy_sha256,sha256,expires_at)
      values(r.id,p_workspace,p_endpoint,source#>>'{endpoint,label}',r.requester,r.reviewer,metadata_sha,fingerprint,inventory_until)
      on conflict do nothing;
    select x.* into strict plan from sectalk_private.st_v8_offboarding_webhook_plans x
      where (x.request_id,x.workspace,x.endpoint,x.sha256)=(r.id,p_workspace,p_endpoint,fingerprint);
  elsif plan.sha256 is distinct from fingerprint or plan.expires_at<=clock_timestamp() then
    raise exception 'The exact endpoint approval changed or expired' using errcode='PT409';
  elsif p_action='approve' and approved_at is null then
    insert into sectalk_private.st_v8_offboarding_webhook_decisions(plan,action,actor)
      values(plan.id,'approved',caller) returning happened_at into approved_at;
  elsif p_action='delete' then
    if approved_at is null then raise insufficient_privilege; end if;
    insert into sectalk_private.st_v8_offboarding_retired_webhook(plan,endpoint,custody,sha256)
      values(plan.id,p_endpoint,source,metadata_sha);
    delete from sectalk_private.st_v6_webhooks c where (c.workspace_id,c.id)=(p_workspace,p_endpoint);
    if not found then raise exception 'The exact endpoint could not be removed' using errcode='PT409'; end if;
    insert into sectalk_private.st_v8_offboarding_webhook_decisions(plan,action,actor)
      values(plan.id,'removed',caller) returning happened_at into deleted_at;
  end if;
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'approvedAt',approved_at,'deletedAt',deleted_at);
end $$;

revoke all on function sectalk_private.st_v8_prevent_retired_webhook_reuse(),
  sectalk_private.st_v8_offboarding_webhook_source(sectalk_private.st_v8_offboarding_requests,uuid),
  public.st_v8_offboarding_webhook_status(uuid),public.st_v8_offboarding_webhook(uuid,uuid,text,text,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_webhook_status(uuid),
  public.st_v8_offboarding_webhook(uuid,uuid,text,text,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
