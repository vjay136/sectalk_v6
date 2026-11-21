begin;

create table sectalk_private.st_v8_offboarding_archived_group_copies (
  request_id uuid not null,
  group_id uuid not null,
  owner_id uuid not null,
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  issued_at timestamptz not null default clock_timestamp(),
  primary key(request_id,group_id,sha256)
);
create table sectalk_private.st_v8_offboarding_archived_group_plans (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null,
  workspace uuid not null,
  group_id uuid not null,
  group_label text not null,
  owner_id uuid not null,
  reviewer_id uuid not null check(reviewer_id<>owner_id),
  copy_sha256 text not null check(copy_sha256~'^[a-f0-9]{64}$'),
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  unique(request_id,group_id,sha256)
);
create table sectalk_private.st_v8_offboarding_archived_group_decisions (
  plan uuid not null references sectalk_private.st_v8_offboarding_archived_group_plans,
  action text not null check(action in ('approved','removed')),
  actor uuid not null,
  happened_at timestamptz not null default clock_timestamp(),
  primary key(plan,action)
);
create table sectalk_private.st_v8_offboarding_retired_archived_group (
  plan uuid primary key references sectalk_private.st_v8_offboarding_archived_group_plans,
  group_id uuid not null,
  workspace uuid not null,
  kind text not null,
  group_name text not null,
  unique(workspace,group_id),
  custody jsonb not null,
  sha256 text not null check(sha256=encode(sha256(convert_to(custody::text,'UTF8')),'hex')),
  check((custody#>>'{group,id}')::uuid=group_id),
  check((custody#>>'{group,workspace_id}')::uuid=workspace),
  check(custody#>>'{group,name}'=group_name and custody#>>'{group,kind}'=kind)
);
create unique index st_v8_retired_group_names on sectalk_private.st_v8_offboarding_retired_archived_group(workspace,kind,lower(group_name));

create trigger st_v8_archived_group_copy_immutable before update or delete on sectalk_private.st_v8_offboarding_archived_group_copies
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_archived_group_plan_immutable before update or delete on sectalk_private.st_v8_offboarding_archived_group_plans
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_archived_group_decision_immutable before update or delete on sectalk_private.st_v8_offboarding_archived_group_decisions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_retired_archived_group_immutable before update or delete on sectalk_private.st_v8_offboarding_retired_archived_group
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_archived_group_copies enable row level security;
alter table sectalk_private.st_v8_offboarding_archived_group_plans enable row level security;
alter table sectalk_private.st_v8_offboarding_archived_group_decisions enable row level security;
alter table sectalk_private.st_v8_offboarding_retired_archived_group enable row level security;
revoke all on sectalk_private.st_v8_offboarding_archived_group_copies,sectalk_private.st_v8_offboarding_archived_group_plans,
  sectalk_private.st_v8_offboarding_archived_group_decisions,sectalk_private.st_v8_offboarding_retired_archived_group
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_prevent_retired_archived_group_reuse()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-group-retirement:'||new.workspace_id::text,0));
  if exists(select 1 from sectalk_private.st_v8_offboarding_retired_archived_group x where x.workspace=new.workspace_id
    and (x.group_id=new.id or (x.kind,lower(x.group_name))=(new.kind,lower(new.name)))) then
    raise exception 'This workspace group identifier or name is permanently retired' using errcode='PT409';
  end if;
  return new;
end $$;
create trigger st_v8_prevent_retired_archived_group_reuse before insert or update of workspace_id,id,kind,name on public.st_v6_workspace_groups
  for each row execute function sectalk_private.st_v8_prevent_retired_archived_group_reuse();

create function sectalk_private.st_v8_offboarding_archived_group_source(
  r sectalk_private.st_v8_offboarding_requests,p_group uuid
) returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  select jsonb_build_object('group',to_jsonb(g),'workspaceAudit',a.events)
  from public.st_v6_workspace_groups g
  cross join lateral (
    select jsonb_agg(to_jsonb(j) order by j.id) as events,
      count(*) filter(where j.event='group.created') as created_count,
      count(*) filter(where j.event='group.archive') as archived_count,
      min(j.id) filter(where j.event='group.created') as created_id,
      min(j.id) filter(where j.event='group.archive') as archived_id,
      coalesce(bool_and(j.actor=r.requester and j.event in ('group.created','group.archive')
        and exists(select 1 from sectalk_private.st_v6_audit_chain c
          where (c.source,c.source_id,c.operation,c.row_hash)=
            ('public.st_v2_workspace_audit',j.id,'INSERT',sectalk_private.st_v6_audit_row_hash(to_jsonb(j))))
        and not exists(select 1 from sectalk_private.st_v6_audit_chain c where
          (c.source,c.source_id)=('public.st_v2_workspace_audit',j.id) and c.operation<>'INSERT')),false) as original
    from public.st_v2_workspace_audit j where (j.workspace_id,j.target)=(r.workspace,g.id)
  ) a
  where (g.workspace_id,g.id)=(r.workspace,p_group) and g.archived_at is not null
    and a.created_count=1 and a.archived_count=1 and a.created_id<a.archived_id and a.original
    and not exists(select 1 from public.st_v6_workspace_group_members x where (x.workspace_id,x.group_id)=(r.workspace,g.id))
    and not exists(select 1 from sectalk_private.st_v8_scim_groups x where (x.workspace,x.id)=(r.workspace,g.id))
    and not exists(select 1 from sectalk_private.st_v7_school_classes x where (x.workspace,x.id)=(r.workspace,g.id))
    and not exists(select 1 from sectalk_private.st_v7_custom_role_versions x
      where (x.workspace,x.scope_type,x.target)=(r.workspace,'group',g.id))
    and not exists(select 1 from pg_constraint f
      cross join lateral (
        select array_agg(att.attname::text order by k.position) as columns
        from unnest(f.conkey) with ordinality k(attnum,position)
        join pg_attribute att on (att.attrelid,att.attnum)=(f.conrelid,k.attnum)
      ) dependent
      cross join lateral (
        select array_agg(att.attname::text order by k.position) as columns
        from unnest(f.confkey) with ordinality k(attnum,position)
        join pg_attribute att on (att.attrelid,att.attnum)=(f.confrelid,k.attnum)
      ) referenced
      where f.contype='f' and f.confrelid='public.st_v6_workspace_groups'::regclass
        and (referenced.columns is distinct from array['workspace_id','id'] or not coalesce((
          (f.conrelid='public.st_v6_workspace_group_members'::regclass and dependent.columns=array['workspace_id','group_id'])
          or (f.conrelid in ('sectalk_private.st_v8_scim_groups'::regclass,'sectalk_private.st_v7_school_classes'::regclass)
            and dependent.columns=array['workspace','id'])),false)))
$$;
create function public.st_v8_offboarding_archived_group_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
begin
  if not sectalk_private.st_v8_groups_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace) then raise insufficient_privilege; end if;
  return jsonb_build_object('held',sectalk_private.st_v8_offboarding_holds(p_workspace),
    'groups',case when auth.uid()=r.requester then coalesce((select jsonb_agg(to_jsonb(x) order by x.name,x.id) from (
      select c.id,c.name,exists(select 1 from sectalk_private.st_v8_offboarding_archived_group_copies a
        where (a.request_id,a.group_id,a.owner_id,a.sha256)=(r.id,c.id,r.requester,
          encode(sha256(convert_to(s.source::text,'UTF8')),'hex'))) as copied
      from public.st_v6_workspace_groups c cross join lateral (select sectalk_private.st_v8_offboarding_archived_group_source(r,c.id)
        as source offset 0) s
      where c.workspace_id=p_workspace and c.archived_at is not null and s.source is not null order by c.name,c.id limit 100
    ) x),'[]') else '[]'::jsonb end,
    'plans',coalesce((select jsonb_agg(to_jsonb(p) order by p."createdAt" desc,p.plan) from (
      select x.id as plan,x.group_id as "group",x.group_label as name,x.sha256,x.copy_sha256 as "copySha256",
        x.created_at as "createdAt",d.happened_at as "approvedAt",z.happened_at as "deletedAt"
      from sectalk_private.st_v8_offboarding_archived_group_plans x
      left join sectalk_private.st_v8_offboarding_archived_group_decisions d on (d.plan,d.action)=(x.id,'approved')
      left join sectalk_private.st_v8_offboarding_archived_group_decisions z on (z.plan,z.action)=(x.id,'removed')
      where (x.request_id,x.workspace)=(r.id,p_workspace) and (x.expires_at>statement_timestamp() or z.happened_at is not null)
      order by x.created_at desc,x.id limit 50
    ) p),'[]'));
end $$;

create function public.st_v8_offboarding_archived_group(
  p_workspace uuid,p_group uuid,p_action text,p_confirmation text,p_plan uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  caller uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_archived_group_plans;
  source jsonb; live_group public.st_v6_workspace_groups; metadata_sha text; fingerprint text;
  inventory_until timestamptz; approved_at timestamptz; deleted_at timestamptz;
begin
  if p_workspace is null or p_group is null or p_action is null or p_action not in ('copy','capture','approve','delete')
    or p_confirmation is distinct from p_workspace::text then raise insufficient_privilege; end if;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if not sectalk_private.st_v8_groups_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace)
    or caller is distinct from (case when p_action='approve' then r.reviewer else r.requester end) then raise insufficient_privilege; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform 1 from public.st_v2_workspaces w where w.id=p_workspace for update;
  select x.* into r from sectalk_private.st_v8_offboarding_requests x
    where x.workspace=p_workspace and x.state='read_only' and x.integration_shutdown is not null for update;
  perform 1 from sectalk_private.st_v8_offboarding_reviewers x where (x.workspace,x.actor)=(p_workspace,r.reviewer) for share;
  if not found then raise insufficient_privilege; end if;
  perform 1 from public.st_v2_members x where x.workspace_id=p_workspace and x.user_id in (r.requester,r.reviewer)
    order by x.user_id for share;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if not sectalk_private.st_v8_groups_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace)
    or caller is distinct from (case when p_action='approve' then r.reviewer else r.requester end)
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_offboarding_archived_group',12);

  if p_action in ('approve','delete') then
    select p.* into plan from sectalk_private.st_v8_offboarding_archived_group_plans p
      where (p.id,p.workspace,p.request_id,p.group_id,p.sha256)=(p_plan,p_workspace,r.id,p_group,p_sha256);
    if plan.id is null then raise exception 'Confirm the exact group removal digest' using errcode='PT409'; end if;
    select x.happened_at into approved_at from sectalk_private.st_v8_offboarding_archived_group_decisions x
      where (x.plan,x.action,x.actor)=(plan.id,'approved',r.reviewer);
    select x.happened_at into deleted_at from sectalk_private.st_v8_offboarding_archived_group_decisions x
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
    perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-group-retirement:'||p_workspace::text,0));
  end if;
  select k.* into live_group from public.st_v6_workspace_groups k where (k.workspace_id,k.id)=(p_workspace,p_group) for update nowait;
  if not found then raise insufficient_privilege; end if;
  perform 1 from public.st_v2_workspace_audit a where (a.workspace_id,a.target)=(p_workspace,p_group) order by a.id limit 3 for share nowait;
  source:=sectalk_private.st_v8_offboarding_archived_group_source(r,p_group);
  if source is null then raise exception 'The archived group or its original audit and access records are ineligible' using errcode='PT409'; end if;
  metadata_sha:=encode(sha256(convert_to(source::text,'UTF8')),'hex');
  perform 1 from auth.sessions n join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
    join auth.mfa_amr_claims a on a.session_id=n.id and a.authentication_method='totp'
    where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',caller) and n.aal='aal2' and f.status='verified' and f.factor_type='totp'
      and a.updated_at>clock_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp() for share of n,f,a;
  if not found or inventory_until<=clock_timestamp() then raise insufficient_privilege; end if;

  if p_action='copy' then
    insert into sectalk_private.st_v8_offboarding_archived_group_copies(request_id,group_id,owner_id,sha256)
      values(r.id,p_group,caller,metadata_sha) on conflict do nothing;
    return jsonb_build_object('format','sectalk-offboarding-archived-group-removal-copy-v1','group',p_group,
      'sha256',metadata_sha,'json',source::text);
  end if;
  if not exists(select 1 from sectalk_private.st_v8_offboarding_archived_group_copies a
    where (a.request_id,a.group_id,a.owner_id,a.sha256)=(r.id,p_group,r.requester,metadata_sha)) then
    raise exception 'Download the exact approved group_id copy first' using errcode='PT409'; end if;
  fingerprint:=encode(sha256(convert_to(jsonb_build_array('sectalk-offboarding-archived-group-removal-v1',p_workspace,r.id,
    r.snapshot_sha256,p_group,metadata_sha)::text,'UTF8')),'hex');
  if p_action='capture' then
    insert into sectalk_private.st_v8_offboarding_archived_group_plans(request_id,workspace,group_id,group_label,
      owner_id,reviewer_id,copy_sha256,sha256,expires_at)
      values(r.id,p_workspace,p_group,source#>>'{group,name}',r.requester,r.reviewer,metadata_sha,fingerprint,inventory_until)
      on conflict do nothing;
    select x.* into strict plan from sectalk_private.st_v8_offboarding_archived_group_plans x
      where (x.request_id,x.workspace,x.group_id,x.sha256)=(r.id,p_workspace,p_group,fingerprint);
  elsif plan.sha256 is distinct from fingerprint or plan.expires_at<=clock_timestamp() then
    raise exception 'The exact group_id approval changed or expired' using errcode='PT409';
  elsif p_action='approve' and approved_at is null then
    insert into sectalk_private.st_v8_offboarding_archived_group_decisions(plan,action,actor)
      values(plan.id,'approved',caller) returning happened_at into approved_at;
  elsif p_action='delete' then
    if approved_at is null then raise insufficient_privilege; end if;
    insert into sectalk_private.st_v8_offboarding_retired_archived_group(plan,group_id,workspace,kind,group_name,custody,sha256)
      values(plan.id,p_group,p_workspace,live_group.kind,live_group.name,source,metadata_sha);
    delete from public.st_v6_workspace_groups c where (c.workspace_id,c.id)=(p_workspace,p_group);
    if not found then raise exception 'The exact group_id could not be removed' using errcode='PT409'; end if;
    insert into sectalk_private.st_v8_offboarding_archived_group_decisions(plan,action,actor)
      values(plan.id,'removed',caller) returning happened_at into deleted_at;
  end if;
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'approvedAt',approved_at,'deletedAt',deleted_at);
end $$;

revoke all on function sectalk_private.st_v8_prevent_retired_archived_group_reuse(),
  sectalk_private.st_v8_offboarding_archived_group_source(sectalk_private.st_v8_offboarding_requests,uuid),
  public.st_v8_offboarding_archived_group_status(uuid),public.st_v8_offboarding_archived_group(uuid,uuid,text,text,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_archived_group_status(uuid),
  public.st_v8_offboarding_archived_group(uuid,uuid,text,text,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
