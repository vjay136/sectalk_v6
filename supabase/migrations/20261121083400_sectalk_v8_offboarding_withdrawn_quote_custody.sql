begin;

create table sectalk_private.st_v8_offboarding_withdrawn_quote_copies (
  request_id uuid not null,
  order_id uuid not null,
  owner_id uuid not null,
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  issued_at timestamptz not null default clock_timestamp(),
  primary key(request_id,order_id,sha256)
);
create table sectalk_private.st_v8_offboarding_withdrawn_quote_plans (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null,
  workspace uuid not null,
  order_id uuid not null,
  order_label text not null,
  owner_id uuid not null,
  reviewer_id uuid not null check(reviewer_id<>owner_id),
  copy_sha256 text not null check(copy_sha256~'^[a-f0-9]{64}$'),
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  unique(request_id,order_id,sha256)
);
create table sectalk_private.st_v8_offboarding_withdrawn_quote_decisions (
  plan uuid not null references sectalk_private.st_v8_offboarding_withdrawn_quote_plans,
  action text not null check(action in ('approved','detached')),
  actor uuid not null,
  happened_at timestamptz not null default clock_timestamp(),
  primary key(plan,action)
);
create table sectalk_private.st_v8_offboarding_retired_withdrawn_quote (
  plan uuid primary key references sectalk_private.st_v8_offboarding_withdrawn_quote_plans,
  order_id uuid not null unique,
  workspace uuid not null,
  workspace_owner uuid not null,
  workspace_created_at timestamptz not null,
  custody jsonb not null,
  sha256 text not null check(sha256=encode(sha256(convert_to(custody::text,'UTF8')),'hex')),
  check((custody#>>'{order,id}')::uuid=order_id),
  check((custody#>>'{order,workspace}')::uuid=workspace)
);
create trigger st_v8_withdrawn_quote_copy_immutable before update or delete on sectalk_private.st_v8_offboarding_withdrawn_quote_copies
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_withdrawn_quote_plan_immutable before update or delete on sectalk_private.st_v8_offboarding_withdrawn_quote_plans
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_withdrawn_quote_decision_immutable before update or delete on sectalk_private.st_v8_offboarding_withdrawn_quote_decisions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_retired_withdrawn_quote_immutable before update or delete on sectalk_private.st_v8_offboarding_retired_withdrawn_quote
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_withdrawn_quote_copies enable row level security;
alter table sectalk_private.st_v8_offboarding_withdrawn_quote_plans enable row level security;
alter table sectalk_private.st_v8_offboarding_withdrawn_quote_decisions enable row level security;
alter table sectalk_private.st_v8_offboarding_retired_withdrawn_quote enable row level security;
revoke all on sectalk_private.st_v8_offboarding_withdrawn_quote_copies,sectalk_private.st_v8_offboarding_withdrawn_quote_plans,
  sectalk_private.st_v8_offboarding_withdrawn_quote_decisions,sectalk_private.st_v8_offboarding_retired_withdrawn_quote
  from public,anon,authenticated,service_role;

-- Preserve original commercial attribution. Only the reviewed current-root link can be released.
alter table sectalk_private.st_v8_enterprise_orders add column live_workspace uuid;
update sectalk_private.st_v8_enterprise_orders set live_workspace=workspace;
alter table sectalk_private.st_v8_enterprise_orders
  add constraint st_v8_enterprise_orders_live_workspace_fkey foreign key(live_workspace)
    references public.st_v2_workspaces(id) on delete restrict,
  add constraint st_v8_enterprise_orders_live_workspace_matches check(live_workspace is null or live_workspace=workspace);
create index st_v8_enterprise_orders_live_workspace on sectalk_private.st_v8_enterprise_orders(live_workspace)
  where live_workspace is not null;
alter table sectalk_private.st_v8_enterprise_orders drop constraint st_v8_enterprise_orders_workspace_fkey;

create function sectalk_private.st_v8_enterprise_quote_custody_guard()
returns trigger language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
begin
  if tg_op='INSERT' then
    new.live_workspace:=new.workspace;
    return new;
  end if;
  if old.live_workspace is null then
    raise exception 'Retained enterprise quote is immutable' using errcode='PT409';
  end if;
  if tg_op='DELETE' then return old; end if;
  if new.workspace is distinct from old.workspace or new.id is distinct from old.id then
    raise exception 'Original enterprise order attribution is immutable' using errcode='PT409';
  end if;
  if new.live_workspace is distinct from old.live_workspace and (new.live_workspace is not null
    or (to_jsonb(new)-'live_workspace') is distinct from (to_jsonb(old)-'live_workspace')
    or not exists(select 1 from sectalk_private.st_v8_offboarding_retired_withdrawn_quote q
      where (q.order_id,q.workspace)=(old.id,old.workspace)
        and q.custody->'order'=(to_jsonb(old)-'live_workspace'))) then
    raise exception 'A reviewed exact quote custody receipt is required' using errcode='PT409';
  end if;
  return new;
end $$;
create trigger st_v8_enterprise_quote_custody_guard before insert or update or delete on sectalk_private.st_v8_enterprise_orders
  for each row execute function sectalk_private.st_v8_enterprise_quote_custody_guard();

create function sectalk_private.st_v8_enterprise_retained_event_guard()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform 1 from sectalk_private.st_v8_enterprise_orders o
    where (o.id,o.workspace)=(new.order_id,new.workspace) and o.live_workspace is not null for share;
  if not found then raise exception 'Retained or unavailable enterprise quote rejects new events' using errcode='PT409'; end if;
  return new;
end $$;
create trigger st_v8_enterprise_retained_event_guard before insert on sectalk_private.st_v8_enterprise_order_events
  for each row execute function sectalk_private.st_v8_enterprise_retained_event_guard();

create function sectalk_private.st_v8_offboarding_withdrawn_quote_source(
  r sectalk_private.st_v8_offboarding_requests,p_order uuid
) returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  select jsonb_build_object('order',to_jsonb(o)-'live_workspace','billingEvents',events.rows)
  from sectalk_private.st_v8_enterprise_orders o
  cross join lateral (
    select count(*) as total,jsonb_agg(to_jsonb(e) order by e.id) as rows,
      min(e.id) filter(where e.action='quote' and e.actor=o.quoted_by and e.note is null) as quoted,
      min(e.id) filter(where e.action='withdraw' and char_length(e.note) between 12 and 300) as withdrawn,
      bool_and(e.workspace=o.workspace) as same_workspace
    from sectalk_private.st_v8_enterprise_order_events e where e.order_id=o.id
  ) events
  where (o.live_workspace,o.workspace,o.id)=(r.workspace,r.workspace,p_order)
    and o.state='withdrawn' and o.accepted_by is null and o.po is null and o.invoice_number is null
    and o.due_on is null and o.payment_reference is null
    and events.total=2 and events.quoted<events.withdrawn and events.same_workspace
$$;
create function public.st_v8_offboarding_withdrawn_quote_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
begin
  if not sectalk_private.st_v8_billing_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace)
    or (auth.uid()=r.reviewer and not exists(select 1 from sectalk_private.st_v8_enterprise_billing_operators x
      where (x.workspace,x.actor)=(p_workspace,r.reviewer))) then raise insufficient_privilege; end if;
  return jsonb_build_object('held',sectalk_private.st_v8_offboarding_holds(p_workspace),
    'orders',case when auth.uid()=r.requester then coalesce((select jsonb_agg(to_jsonb(x) order by x.name,x.id) from (
      select c.id,c.reference as name,exists(select 1 from sectalk_private.st_v8_offboarding_withdrawn_quote_copies a
        where (a.request_id,a.order_id,a.owner_id,a.sha256)=(r.id,c.id,r.requester,
          encode(sha256(convert_to(s.source::text,'UTF8')),'hex'))) as copied
      from sectalk_private.st_v8_enterprise_orders c cross join lateral (select sectalk_private.st_v8_offboarding_withdrawn_quote_source(r,c.id)
        as source offset 0) s
      where c.live_workspace=p_workspace and c.state='withdrawn' and s.source is not null order by c.reference,c.id limit 100
    ) x),'[]') else '[]'::jsonb end,
    'plans',coalesce((select jsonb_agg(to_jsonb(p) order by p."createdAt" desc,p.plan) from (
      select x.id as plan,x.order_id as "order",x.order_label as name,x.sha256,x.copy_sha256 as "copySha256",
        x.created_at as "createdAt",d.happened_at as "approvedAt",z.happened_at as "detachedAt"
      from sectalk_private.st_v8_offboarding_withdrawn_quote_plans x
      left join sectalk_private.st_v8_offboarding_withdrawn_quote_decisions d on (d.plan,d.action)=(x.id,'approved')
      left join sectalk_private.st_v8_offboarding_withdrawn_quote_decisions z on (z.plan,z.action)=(x.id,'detached')
      where (x.request_id,x.workspace)=(r.id,p_workspace) and (x.expires_at>statement_timestamp() or z.happened_at is not null)
      order by x.created_at desc,x.id limit 50
    ) p),'[]'));
end $$;

create function public.st_v8_offboarding_withdrawn_quote(
  p_workspace uuid,p_order uuid,p_action text,p_confirmation text,p_plan uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  caller uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_withdrawn_quote_plans;
  source jsonb; metadata_sha text; fingerprint text; root_created timestamptz;
  inventory_until timestamptz; approved_at timestamptz; detached_at timestamptz;
begin
  if p_workspace is null or p_order is null or p_action is null or p_action not in ('copy','capture','approve','detach')
    or p_confirmation is distinct from p_workspace::text then raise insufficient_privilege; end if;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if not sectalk_private.st_v8_billing_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace)
    or caller is distinct from (case when p_action='approve' then r.reviewer else r.requester end) then raise insufficient_privilege; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  select w.created_at into root_created from public.st_v2_workspaces w where w.id=p_workspace for update;
  select x.* into r from sectalk_private.st_v8_offboarding_requests x
    where x.workspace=p_workspace and x.state='read_only' and x.integration_shutdown is not null for update;
  perform 1 from sectalk_private.st_v8_offboarding_reviewers x where (x.workspace,x.actor)=(p_workspace,r.reviewer) for share;
  if not found then raise insufficient_privilege; end if;
  perform 1 from sectalk_private.st_v8_enterprise_billing_operators x
    where (x.workspace,x.actor)=(p_workspace,r.reviewer) for share;
  if not found then raise exception 'The independent reviewer requires commercial billing authorization' using errcode='42501'; end if;
  perform 1 from public.st_v2_members x where x.workspace_id=p_workspace and x.user_id in (r.requester,r.reviewer)
    order by x.user_id for share;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if not sectalk_private.st_v8_billing_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace)
    or caller is distinct from (case when p_action='approve' then r.reviewer else r.requester end)
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_offboarding_withdrawn_quote',12);

  if p_action in ('approve','detach') then
    select p.* into plan from sectalk_private.st_v8_offboarding_withdrawn_quote_plans p
      where (p.id,p.workspace,p.request_id,p.order_id,p.sha256)=(p_plan,p_workspace,r.id,p_order,p_sha256);
    if plan.id is null then raise exception 'Confirm the exact withdrawn quote detachment digest' using errcode='PT409'; end if;
    select x.happened_at into approved_at from sectalk_private.st_v8_offboarding_withdrawn_quote_decisions x
      where (x.plan,x.action,x.actor)=(plan.id,'approved',r.reviewer);
    select x.happened_at into detached_at from sectalk_private.st_v8_offboarding_withdrawn_quote_decisions x
      where (x.plan,x.action,x.actor)=(plan.id,'detached',r.requester);
    if detached_at is not null then
      return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'approvedAt',approved_at,'detachedAt',detached_at);
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
  perform 1 from sectalk_private.st_v8_enterprise_orders k where (k.live_workspace,k.id)=(p_workspace,p_order) for update nowait;
  if not found then raise insufficient_privilege; end if;
  perform 1 from sectalk_private.st_v8_enterprise_order_events e where e.order_id=p_order order by e.id limit 3 for share nowait;
  source:=sectalk_private.st_v8_offboarding_withdrawn_quote_source(r,p_order);
  if source is null then raise exception 'Only a withdrawn, never-accepted quote with original billing events can be retained' using errcode='PT409'; end if;
  metadata_sha:=encode(sha256(convert_to(source::text,'UTF8')),'hex');
  perform 1 from auth.sessions n join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
    join auth.mfa_amr_claims a on a.session_id=n.id and a.authentication_method='totp'
    where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',caller) and n.aal='aal2' and f.status='verified' and f.factor_type='totp'
      and a.updated_at>clock_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp() for share of n,f,a;
  if not found or inventory_until<=clock_timestamp() then raise insufficient_privilege; end if;

  if p_action='copy' then
    insert into sectalk_private.st_v8_offboarding_withdrawn_quote_copies(request_id,order_id,owner_id,sha256)
      values(r.id,p_order,caller,metadata_sha) on conflict do nothing;
    return jsonb_build_object('format','sectalk-offboarding-withdrawn-quote-detachment-copy-v1','order',p_order,
      'sha256',metadata_sha,'json',source::text);
  end if;
  if not exists(select 1 from sectalk_private.st_v8_offboarding_withdrawn_quote_copies a
    where (a.request_id,a.order_id,a.owner_id,a.sha256)=(r.id,p_order,r.requester,metadata_sha)) then
    raise exception 'Download the exact quote copy first' using errcode='PT409'; end if;
  fingerprint:=encode(sha256(convert_to(jsonb_build_array('sectalk-offboarding-withdrawn-quote-detachment-v1',p_workspace,r.id,
    r.snapshot_sha256,p_order,metadata_sha)::text,'UTF8')),'hex');
  if p_action='capture' then
    insert into sectalk_private.st_v8_offboarding_withdrawn_quote_plans(request_id,workspace,order_id,order_label,
      owner_id,reviewer_id,copy_sha256,sha256,expires_at)
      values(r.id,p_workspace,p_order,source#>>'{order,reference}',r.requester,r.reviewer,metadata_sha,fingerprint,inventory_until)
      on conflict do nothing;
    select x.* into strict plan from sectalk_private.st_v8_offboarding_withdrawn_quote_plans x
      where (x.request_id,x.workspace,x.order_id,x.sha256)=(r.id,p_workspace,p_order,fingerprint);
  elsif plan.sha256 is distinct from fingerprint or plan.expires_at<=clock_timestamp() then
    raise exception 'The exact quote approval changed or expired' using errcode='PT409';
  elsif p_action='approve' and approved_at is null then
    insert into sectalk_private.st_v8_offboarding_withdrawn_quote_decisions(plan,action,actor)
      values(plan.id,'approved',caller) returning happened_at into approved_at;
  elsif p_action='detach' then
    if approved_at is null then raise insufficient_privilege; end if;
    insert into sectalk_private.st_v8_offboarding_retired_withdrawn_quote(plan,order_id,workspace,workspace_owner,workspace_created_at,custody,sha256)
      values(plan.id,p_order,p_workspace,r.requester,root_created,source,metadata_sha);
    update sectalk_private.st_v8_enterprise_orders c set live_workspace=null where (c.live_workspace,c.id)=(p_workspace,p_order);
    if not found then raise exception 'The exact withdrawn quote could not be detached' using errcode='PT409'; end if;
    insert into sectalk_private.st_v8_offboarding_withdrawn_quote_decisions(plan,action,actor)
      values(plan.id,'detached',caller) returning happened_at into detached_at;
  end if;
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'approvedAt',approved_at,'detachedAt',detached_at);
end $$;

revoke all on function sectalk_private.st_v8_enterprise_quote_custody_guard(),sectalk_private.st_v8_enterprise_retained_event_guard(),
  sectalk_private.st_v8_offboarding_withdrawn_quote_source(sectalk_private.st_v8_offboarding_requests,uuid),
  public.st_v8_offboarding_withdrawn_quote_status(uuid),public.st_v8_offboarding_withdrawn_quote(uuid,uuid,text,text,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_withdrawn_quote_status(uuid),
  public.st_v8_offboarding_withdrawn_quote(uuid,uuid,text,text,uuid,text) to authenticated;
create or replace function public.st_v8_enterprise_billing_view(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare roles text[]:=sectalk_private.st_v8_enterprise_billing_roles(p_workspace); enterprise boolean;
begin
  if cardinality(roles)=0 then raise exception 'Enterprise billing access unavailable' using errcode='42501'; end if;
  enterprise:=coalesce((sectalk_private.st_v7_workspace_entitlements(p_workspace)).plan='enterprise',false);
  if public.st_v7_sensitive_action_status('billing') is distinct from 'verified' then
    return jsonb_build_object('access','mfa','eligible',enterprise);
  end if;
  return jsonb_build_object('access','verified','eligible',enterprise,'roles',roles,'orders',
    coalesce((select jsonb_agg(to_jsonb(q)-'live_workspace'-'quoted_by'-'accepted_by'-'workspace'-'payment_reference') from (
      select o.* from sectalk_private.st_v8_enterprise_orders o where o.workspace=p_workspace and (o.live_workspace=p_workspace or exists(
        select 1 from sectalk_private.st_v8_offboarding_retired_withdrawn_quote q join public.st_v2_workspaces w on w.id=q.workspace
        where (q.order_id,q.workspace,q.workspace_owner,q.workspace_created_at)=(o.id,o.workspace,w.owner,w.created_at)))
      order by o.created_at desc,o.id limit 100
    ) q),'[]'::jsonb));
end $$;

notify pgrst,'reload schema';
commit;
