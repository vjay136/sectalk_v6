begin;

alter table sectalk_private.st_v6_workspace_link_invites add column retirement_id uuid not null default gen_random_uuid() unique;


create table sectalk_private.st_v8_offboarding_expired_link_copies (
  request_id uuid not null,
  link uuid not null,
  owner_id uuid not null,
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  issued_at timestamptz not null default clock_timestamp(),
  primary key(request_id,link,sha256)
);
create table sectalk_private.st_v8_offboarding_expired_link_plans (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null,
  workspace uuid not null,
  link uuid not null,
  link_label text not null,
  owner_id uuid not null,
  reviewer_id uuid not null check(reviewer_id<>owner_id),
  copy_sha256 text not null check(copy_sha256~'^[a-f0-9]{64}$'),
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  unique(request_id,link,sha256)
);
create table sectalk_private.st_v8_offboarding_expired_link_decisions (
  plan uuid not null references sectalk_private.st_v8_offboarding_expired_link_plans,
  action text not null check(action in ('approved','removed')),
  actor uuid not null,
  happened_at timestamptz not null default clock_timestamp(),
  primary key(plan,action)
);
create table sectalk_private.st_v8_offboarding_retired_expired_link (
  plan uuid primary key references sectalk_private.st_v8_offboarding_expired_link_plans,
  link uuid not null unique,
  verifier_guard bytea not null unique check(octet_length(verifier_guard)=32),
  custody jsonb not null,
  sha256 text not null check(sha256=encode(sha256(convert_to(custody::text,'UTF8')),'hex')),
  check((custody#>>'{link,id}')::uuid=link)
);
create trigger st_v8_expired_link_copy_immutable before update or delete on sectalk_private.st_v8_offboarding_expired_link_copies
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_expired_link_plan_immutable before update or delete on sectalk_private.st_v8_offboarding_expired_link_plans
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_expired_link_decision_immutable before update or delete on sectalk_private.st_v8_offboarding_expired_link_decisions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_retired_expired_link_immutable before update or delete on sectalk_private.st_v8_offboarding_retired_expired_link
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_expired_link_copies enable row level security;
alter table sectalk_private.st_v8_offboarding_expired_link_plans enable row level security;
alter table sectalk_private.st_v8_offboarding_expired_link_decisions enable row level security;
alter table sectalk_private.st_v8_offboarding_retired_expired_link enable row level security;
revoke all on sectalk_private.st_v8_offboarding_expired_link_copies,sectalk_private.st_v8_offboarding_expired_link_plans,
  sectalk_private.st_v8_offboarding_expired_link_decisions,sectalk_private.st_v8_offboarding_retired_expired_link
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_retired_expired_link_guard(p_verifier bytea)
returns bytea language sql immutable set search_path='' as $$
  select sha256(convert_to('sectalk-offboarding-retired-invitation-link-v1','UTF8')||p_verifier);
$$;

create function sectalk_private.st_v8_prevent_retired_expired_link_reuse()
returns trigger language plpgsql security definer set search_path='' as $$
declare guard bytea:=sectalk_private.st_v8_retired_expired_link_guard(new.token_hash);
begin
  perform pg_advisory_xact_lock(hashtextextended('sectalk-invite-link-id:'||new.retirement_id::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-invite-link-guard:'||encode(guard,'hex'),0));
  if exists(select 1 from sectalk_private.st_v8_offboarding_retired_expired_link x where x.link=new.retirement_id or x.verifier_guard=guard) then
    raise exception 'This invitation link is permanently retired' using errcode='PT409';
  end if;
  return new;
end $$;
create trigger st_v8_prevent_retired_expired_link_reuse before insert or update of retirement_id,token_hash on sectalk_private.st_v6_workspace_link_invites
  for each row execute function sectalk_private.st_v8_prevent_retired_expired_link_reuse();

create function sectalk_private.st_v8_offboarding_expired_link_source(
  r sectalk_private.st_v8_offboarding_requests,p_link uuid
) returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  select jsonb_build_object('link',jsonb_build_object('id',i.retirement_id,'workspace',i.workspace_id,
    'issuer',i.issued_by,'expiresAt',i.expires_at,'state','expired-unused'))
  from sectalk_private.st_v6_workspace_link_invites i
  where (i.workspace_id,i.retirement_id,i.issued_by)=(r.workspace,p_link,r.requester)
    and i.consumed_at is null and i.expires_at<=statement_timestamp()
    and not exists(select 1 from pg_constraint f where f.contype='f'
      and f.confrelid='sectalk_private.st_v6_workspace_link_invites'::regclass)
$$;
create function public.st_v8_offboarding_expired_link_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
begin
  if not sectalk_private.st_v8_invitation_admin_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace) then raise insufficient_privilege; end if;
  return jsonb_build_object('held',sectalk_private.st_v8_offboarding_holds(p_workspace),
    'links',case when auth.uid()=r.requester then coalesce((select jsonb_agg(to_jsonb(x) order by x.name,x.id) from (
      select c.retirement_id as id,'Expired '||to_char(c.expires_at at time zone 'UTC','YYYY-MM-DD HH24:MI')||' UTC' as name,exists(select 1 from sectalk_private.st_v8_offboarding_expired_link_copies a
        where (a.request_id,a.link,a.owner_id,a.sha256)=(r.id,c.retirement_id,r.requester,
          encode(sha256(convert_to(s.source::text,'UTF8')),'hex'))) as copied
      from sectalk_private.st_v6_workspace_link_invites c cross join lateral (select sectalk_private.st_v8_offboarding_expired_link_source(r,c.retirement_id)
        as source offset 0) s
      where c.workspace_id=p_workspace and c.consumed_at is null and c.expires_at<=statement_timestamp() and s.source is not null order by c.expires_at,c.retirement_id limit 100
    ) x),'[]') else '[]'::jsonb end,
    'plans',coalesce((select jsonb_agg(to_jsonb(p) order by p."createdAt" desc,p.plan) from (
      select x.id as plan,x.link,x.link_label as name,x.sha256,x.copy_sha256 as "copySha256",
        x.created_at as "createdAt",d.happened_at as "approvedAt",z.happened_at as "deletedAt"
      from sectalk_private.st_v8_offboarding_expired_link_plans x
      left join sectalk_private.st_v8_offboarding_expired_link_decisions d on (d.plan,d.action)=(x.id,'approved')
      left join sectalk_private.st_v8_offboarding_expired_link_decisions z on (z.plan,z.action)=(x.id,'removed')
      where (x.request_id,x.workspace)=(r.id,p_workspace) and (x.expires_at>statement_timestamp() or z.happened_at is not null)
      order by x.created_at desc,x.id limit 50
    ) p),'[]'));
end $$;

create function public.st_v8_offboarding_expired_link(
  p_workspace uuid,p_link uuid,p_action text,p_confirmation text,p_plan uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  caller uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_expired_link_plans;
  source jsonb; live_link sectalk_private.st_v6_workspace_link_invites; metadata_sha text; guard bytea; link_sha text; fingerprint text;
  inventory_until timestamptz; approved_at timestamptz; deleted_at timestamptz;
begin
  if p_workspace is null or p_link is null or p_action is null or p_action not in ('copy','capture','approve','delete')
    or p_confirmation is distinct from p_workspace::text then raise insufficient_privilege; end if;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if not sectalk_private.st_v8_invitation_admin_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace)
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
  if not sectalk_private.st_v8_invitation_admin_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace)
    or caller is distinct from (case when p_action='approve' then r.reviewer else r.requester end)
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_offboarding_expired_link',12);

  if p_action in ('approve','delete') then
    select p.* into plan from sectalk_private.st_v8_offboarding_expired_link_plans p
      where (p.id,p.workspace,p.request_id,p.link,p.sha256)=(p_plan,p_workspace,r.id,p_link,p_sha256);
    if plan.id is null then raise exception 'Confirm the exact invitation link retirement digest' using errcode='PT409'; end if;
    select x.happened_at into approved_at from sectalk_private.st_v8_offboarding_expired_link_decisions x
      where (x.plan,x.action,x.actor)=(plan.id,'approved',r.reviewer);
    select x.happened_at into deleted_at from sectalk_private.st_v8_offboarding_expired_link_decisions x
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
    perform pg_advisory_xact_lock(hashtextextended('sectalk-invite-link-id:'||p_link::text,0));
  end if;
  select k.* into live_link from sectalk_private.st_v6_workspace_link_invites k where (k.workspace_id,k.retirement_id)=(p_workspace,p_link) for update nowait;
  if not found then raise insufficient_privilege; end if;
  guard:=sectalk_private.st_v8_retired_expired_link_guard(live_link.token_hash);
  if p_action='delete' then
    perform pg_advisory_xact_lock(hashtextextended('sectalk-invite-link-guard:'||encode(guard,'hex'),0));
  end if;
  source:=sectalk_private.st_v8_offboarding_expired_link_source(r,p_link);
  if source is null then raise exception 'Only expired invitation links with no use or dependent evidence can be retired' using errcode='PT409'; end if;
  metadata_sha:=encode(sha256(convert_to(source::text,'UTF8')),'hex');
  link_sha:=encode(sha256(convert_to(to_jsonb(live_link)::text,'UTF8')),'hex');
  perform 1 from auth.sessions n join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
    join auth.mfa_amr_claims a on a.session_id=n.id and a.authentication_method='totp'
    where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',caller) and n.aal='aal2' and f.status='verified' and f.factor_type='totp'
      and a.updated_at>clock_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp() for share of n,f,a;
  if not found or inventory_until<=clock_timestamp() then raise insufficient_privilege; end if;

  if p_action='copy' then
    insert into sectalk_private.st_v8_offboarding_expired_link_copies(request_id,link,owner_id,sha256)
      values(r.id,p_link,caller,metadata_sha) on conflict do nothing;
    return jsonb_build_object('format','sectalk-offboarding-invitation-link-retirement-copy-v1','link',p_link,
      'sha256',metadata_sha,'json',source::text);
  end if;
  if not exists(select 1 from sectalk_private.st_v8_offboarding_expired_link_copies a
    where (a.request_id,a.link,a.owner_id,a.sha256)=(r.id,p_link,r.requester,metadata_sha)) then
    raise exception 'Download the exact approved link copy first' using errcode='PT409'; end if;
  fingerprint:=encode(sha256(convert_to(jsonb_build_array('sectalk-offboarding-invitation-link-retirement-v1',p_workspace,r.id,
    r.snapshot_sha256,p_link,metadata_sha,link_sha)::text,'UTF8')),'hex');
  if p_action='capture' then
    insert into sectalk_private.st_v8_offboarding_expired_link_plans(request_id,workspace,link,link_label,
      owner_id,reviewer_id,copy_sha256,sha256,expires_at)
      values(r.id,p_workspace,p_link,'Expired '||to_char(live_link.expires_at at time zone 'UTC','YYYY-MM-DD HH24:MI')||' UTC',r.requester,r.reviewer,metadata_sha,fingerprint,inventory_until)
      on conflict do nothing;
    select x.* into strict plan from sectalk_private.st_v8_offboarding_expired_link_plans x
      where (x.request_id,x.workspace,x.link,x.sha256)=(r.id,p_workspace,p_link,fingerprint);
  elsif plan.sha256 is distinct from fingerprint or plan.expires_at<=clock_timestamp() then
    raise exception 'The exact link approval changed or expired' using errcode='PT409';
  elsif p_action='approve' and approved_at is null then
    insert into sectalk_private.st_v8_offboarding_expired_link_decisions(plan,action,actor)
      values(plan.id,'approved',caller) returning happened_at into approved_at;
  elsif p_action='delete' then
    if approved_at is null then raise insufficient_privilege; end if;
    insert into sectalk_private.st_v8_offboarding_retired_expired_link(plan,link,verifier_guard,custody,sha256)
      values(plan.id,p_link,guard,source,metadata_sha);
    delete from sectalk_private.st_v6_workspace_link_invites c where (c.workspace_id,c.retirement_id)=(p_workspace,p_link);
    if not found then raise exception 'The exact link could not be removed' using errcode='PT409'; end if;
    insert into sectalk_private.st_v8_offboarding_expired_link_decisions(plan,action,actor)
      values(plan.id,'removed',caller) returning happened_at into deleted_at;
  end if;
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'approvedAt',approved_at,'deletedAt',deleted_at);
end $$;

revoke all on function sectalk_private.st_v8_retired_expired_link_guard(bytea),sectalk_private.st_v8_prevent_retired_expired_link_reuse(),
  sectalk_private.st_v8_offboarding_expired_link_source(sectalk_private.st_v8_offboarding_requests,uuid),
  public.st_v8_offboarding_expired_link_status(uuid),public.st_v8_offboarding_expired_link(uuid,uuid,text,text,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_expired_link_status(uuid),
  public.st_v8_offboarding_expired_link(uuid,uuid,text,text,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
