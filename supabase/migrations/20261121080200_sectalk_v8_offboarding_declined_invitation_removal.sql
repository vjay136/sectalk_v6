begin;

create table sectalk_private.st_v8_offboarding_declined_invite_copies (
  request_id uuid not null,
  invitation uuid not null,
  owner_id uuid not null,
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  issued_at timestamptz not null default clock_timestamp(),
  primary key(request_id,invitation,sha256)
);
create table sectalk_private.st_v8_offboarding_declined_invite_plans (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null,
  workspace uuid not null,
  invitation uuid not null,
  invitation_label text not null,
  owner_id uuid not null,
  reviewer_id uuid not null check(reviewer_id<>owner_id),
  copy_sha256 text not null check(copy_sha256~'^[a-f0-9]{64}$'),
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  unique(request_id,invitation,sha256)
);
create table sectalk_private.st_v8_offboarding_declined_invite_decisions (
  plan uuid not null references sectalk_private.st_v8_offboarding_declined_invite_plans,
  action text not null check(action in ('approved','removed')),
  actor uuid not null,
  happened_at timestamptz not null default clock_timestamp(),
  primary key(plan,action)
);
create table sectalk_private.st_v8_offboarding_retired_declined_invite (
  plan uuid primary key references sectalk_private.st_v8_offboarding_declined_invite_plans,
  invitation uuid not null unique,
  workspace uuid not null,
  invitee uuid not null,
  unique(workspace,invitee),
  custody jsonb not null,
  sha256 text not null check(sha256=encode(sha256(convert_to(custody::text,'UTF8')),'hex')),
  check((custody#>>'{invitation,id}')::uuid=invitation),
  check((custody#>>'{invitation,workspace}')::uuid=workspace),
  check((custody#>>'{invitation,recipient}')::uuid=invitee)
);
create trigger st_v8_declined_invite_copy_immutable before update or delete on sectalk_private.st_v8_offboarding_declined_invite_copies
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_declined_invite_plan_immutable before update or delete on sectalk_private.st_v8_offboarding_declined_invite_plans
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_declined_invite_decision_immutable before update or delete on sectalk_private.st_v8_offboarding_declined_invite_decisions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_retired_declined_invite_immutable before update or delete on sectalk_private.st_v8_offboarding_retired_declined_invite
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_declined_invite_copies enable row level security;
alter table sectalk_private.st_v8_offboarding_declined_invite_plans enable row level security;
alter table sectalk_private.st_v8_offboarding_declined_invite_decisions enable row level security;
alter table sectalk_private.st_v8_offboarding_retired_declined_invite enable row level security;
revoke all on sectalk_private.st_v8_offboarding_declined_invite_copies,sectalk_private.st_v8_offboarding_declined_invite_plans,
  sectalk_private.st_v8_offboarding_declined_invite_decisions,sectalk_private.st_v8_offboarding_retired_declined_invite
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_block_retired_invitation_reissue()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-invitation-id:'||new.id::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-invitee:'||new.workspace_id::text||':'||new.invitee::text,0));
  if exists(select 1 from sectalk_private.st_v8_offboarding_retired_declined_invite x
    where x.invitation=new.id or (x.workspace,x.invitee)=(new.workspace_id,new.invitee)) then
    -- Match the existing invitation creation contract when this recipient already declined.
    if tg_op='INSERT' then return null; end if;
    raise exception 'This workspace invitation is permanently retired' using errcode='PT409';
  end if;
  return new;
end $$;
create trigger st_v8_block_retired_invitation_reissue before insert or update of id,workspace_id,invitee on public.st_v2_invites
  for each row execute function sectalk_private.st_v8_block_retired_invitation_reissue();

create function sectalk_private.st_v8_offboarding_declined_invite_source(
  r sectalk_private.st_v8_offboarding_requests,p_invitation uuid
) returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  select jsonb_build_object(
    'invitation',jsonb_build_object('id',i.id,'workspace',i.workspace_id,'recipient',i.invitee,
      'sender',i.created_by,'createdAt',i.created_at,'status',i.status),
    'workspaceAudit',to_jsonb(a))
  from public.st_v2_invites i
  join public.st_v2_workspace_audit a on (a.workspace_id,a.target,a.actor,a.event,a.created_at)=
    (i.workspace_id,i.invitee,i.created_by,'member.invited',i.created_at)
  where (i.workspace_id,i.id,i.created_by)=(r.workspace,p_invitation,r.requester)
    and i.status='declined' and i.invitee not in (r.requester,r.reviewer)
    and not exists(select 1 from public.st_v2_workspace_audit j
      where (j.workspace_id,j.target)=(i.workspace_id,i.invitee) and j.id<>a.id)
    and exists(select 1 from sectalk_private.st_v6_audit_chain c where
      (c.source,c.source_id,c.operation,c.row_hash)=
        ('public.st_v2_workspace_audit',a.id,'INSERT',sectalk_private.st_v6_audit_row_hash(to_jsonb(a))))
    and not exists(select 1 from sectalk_private.st_v6_audit_chain c where
      (c.source,c.source_id)=('public.st_v2_workspace_audit',a.id) and c.operation<>'INSERT')
    and not exists(select 1 from public.st_v2_members m where (m.workspace_id,m.user_id)=(i.workspace_id,i.invitee))
    and not exists(select 1 from sectalk_private.st_v8_scim_users s where (s.workspace,s.principal)=(i.workspace_id,i.invitee))
    and not exists(select 1 from sectalk_private.st_v7_sso_departures s where (s.workspace,s.principal)=(i.workspace_id,i.invitee))
    and not exists(select 1 from sectalk_private.st_v7_managed_accounts m where m.workspace=i.workspace_id
      and i.invitee in (m.supervisor,m.participant))
    and not exists(select 1 from public.st_v6_rooms r0 where r0.workspace_id=i.workspace_id
      and (exists(select 1 from public.st_v6_room_members m where (m.room_id,m.user_id)=(r0.id,i.invitee))
        or exists(select 1 from public.st_v6_room_entries m where (m.room_id,m.user_id)=(r0.id,i.invitee))))
    and not exists(select 1 from pg_constraint f where f.contype='f' and f.confrelid='public.st_v2_invites'::regclass)
$$;
create function public.st_v8_offboarding_declined_invite_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
begin
  if not sectalk_private.st_v8_invitation_admin_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace) then raise insufficient_privilege; end if;
  return jsonb_build_object('held',sectalk_private.st_v8_offboarding_holds(p_workspace),
    'invitations',case when auth.uid()=r.requester then coalesce((select jsonb_agg(to_jsonb(x) order by x.name,x.id) from (
      select c.id,'Invitation sent '||to_char(c.created_at at time zone 'UTC','YYYY-MM-DD') as name,exists(select 1 from sectalk_private.st_v8_offboarding_declined_invite_copies a
        where (a.request_id,a.invitation,a.owner_id,a.sha256)=(r.id,c.id,r.requester,
          encode(sha256(convert_to(s.source::text,'UTF8')),'hex'))) as copied
      from public.st_v2_invites c cross join lateral (select sectalk_private.st_v8_offboarding_declined_invite_source(r,c.id)
        as source offset 0) s
      where c.workspace_id=p_workspace and c.status='declined' and s.source is not null order by c.created_at desc,c.id limit 100
    ) x),'[]') else '[]'::jsonb end,
    'plans',coalesce((select jsonb_agg(to_jsonb(p) order by p."createdAt" desc,p.plan) from (
      select x.id as plan,x.invitation,x.invitation_label as name,x.sha256,x.copy_sha256 as "copySha256",
        x.created_at as "createdAt",d.happened_at as "approvedAt",z.happened_at as "deletedAt"
      from sectalk_private.st_v8_offboarding_declined_invite_plans x
      left join sectalk_private.st_v8_offboarding_declined_invite_decisions d on (d.plan,d.action)=(x.id,'approved')
      left join sectalk_private.st_v8_offboarding_declined_invite_decisions z on (z.plan,z.action)=(x.id,'removed')
      where (x.request_id,x.workspace)=(r.id,p_workspace) and (x.expires_at>statement_timestamp() or z.happened_at is not null)
      order by x.created_at desc,x.id limit 50
    ) p),'[]'));
end $$;

create function public.st_v8_offboarding_declined_invite(
  p_workspace uuid,p_invitation uuid,p_action text,p_confirmation text,p_plan uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  caller uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_declined_invite_plans;
  source jsonb; live_invite public.st_v2_invites; metadata_sha text; invitation_sha text; fingerprint text;
  inventory_until timestamptz; approved_at timestamptz; deleted_at timestamptz;
begin
  if p_workspace is null or p_invitation is null or p_action is null or p_action not in ('copy','capture','approve','delete')
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
  perform sectalk_private.limit_action('v8_offboarding_declined_invite',12);

  if p_action in ('approve','delete') then
    select p.* into plan from sectalk_private.st_v8_offboarding_declined_invite_plans p
      where (p.id,p.workspace,p.request_id,p.invitation,p.sha256)=(p_plan,p_workspace,r.id,p_invitation,p_sha256);
    if plan.id is null then raise exception 'Confirm the exact declined invitation removal digest' using errcode='PT409'; end if;
    select x.happened_at into approved_at from sectalk_private.st_v8_offboarding_declined_invite_decisions x
      where (x.plan,x.action,x.actor)=(plan.id,'approved',r.reviewer);
    select x.happened_at into deleted_at from sectalk_private.st_v8_offboarding_declined_invite_decisions x
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
    perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-invitation-id:'||p_invitation::text,0));
  end if;
  select k.* into live_invite from public.st_v2_invites k where (k.workspace_id,k.id)=(p_workspace,p_invitation) for update nowait;
  if not found then raise insufficient_privilege; end if;
  if p_action='delete' then
    perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-invitee:'||p_workspace::text||':'||live_invite.invitee::text,0));
  end if;
  perform 1 from public.st_v2_workspace_audit a
    where (a.workspace_id,a.target)=(p_workspace,live_invite.invitee) order by a.id limit 2 for share nowait;
  source:=sectalk_private.st_v8_offboarding_declined_invite_source(r,p_invitation);
  if source is null then raise exception 'The declined invitation or its retained evidence is ineligible' using errcode='PT409'; end if;
  metadata_sha:=encode(sha256(convert_to(source::text,'UTF8')),'hex');
  invitation_sha:=encode(sha256(convert_to(to_jsonb(live_invite)::text,'UTF8')),'hex');
  perform 1 from auth.sessions n join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
    join auth.mfa_amr_claims a on a.session_id=n.id and a.authentication_method='totp'
    where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',caller) and n.aal='aal2' and f.status='verified' and f.factor_type='totp'
      and a.updated_at>clock_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp() for share of n,f,a;
  if not found or inventory_until<=clock_timestamp() then raise insufficient_privilege; end if;

  if p_action='copy' then
    insert into sectalk_private.st_v8_offboarding_declined_invite_copies(request_id,invitation,owner_id,sha256)
      values(r.id,p_invitation,caller,metadata_sha) on conflict do nothing;
    return jsonb_build_object('format','sectalk-offboarding-declined-invitation-removal-copy-v1','invitation',p_invitation,
      'sha256',metadata_sha,'json',source::text);
  end if;
  if not exists(select 1 from sectalk_private.st_v8_offboarding_declined_invite_copies a
    where (a.request_id,a.invitation,a.owner_id,a.sha256)=(r.id,p_invitation,r.requester,metadata_sha)) then
    raise exception 'Download the exact approved invitation copy first' using errcode='PT409'; end if;
  fingerprint:=encode(sha256(convert_to(jsonb_build_array('sectalk-offboarding-declined-invitation-removal-v1',p_workspace,r.id,
    r.snapshot_sha256,p_invitation,metadata_sha,invitation_sha)::text,'UTF8')),'hex');
  if p_action='capture' then
    insert into sectalk_private.st_v8_offboarding_declined_invite_plans(request_id,workspace,invitation,invitation_label,
      owner_id,reviewer_id,copy_sha256,sha256,expires_at)
      values(r.id,p_workspace,p_invitation,'Invitation sent '||to_char(live_invite.created_at at time zone 'UTC','YYYY-MM-DD'),r.requester,r.reviewer,metadata_sha,fingerprint,inventory_until)
      on conflict do nothing;
    select x.* into strict plan from sectalk_private.st_v8_offboarding_declined_invite_plans x
      where (x.request_id,x.workspace,x.invitation,x.sha256)=(r.id,p_workspace,p_invitation,fingerprint);
  elsif plan.sha256 is distinct from fingerprint or plan.expires_at<=clock_timestamp() then
    raise exception 'The exact invitation approval changed or expired' using errcode='PT409';
  elsif p_action='approve' and approved_at is null then
    insert into sectalk_private.st_v8_offboarding_declined_invite_decisions(plan,action,actor)
      values(plan.id,'approved',caller) returning happened_at into approved_at;
  elsif p_action='delete' then
    if approved_at is null then raise insufficient_privilege; end if;
    if sectalk_private.st_v8_offboarding_declined_invite_source(r,p_invitation) is distinct from source then
      raise exception 'The invitation or its roster evidence changed' using errcode='PT409';
    end if;
    insert into sectalk_private.st_v8_offboarding_retired_declined_invite(plan,invitation,workspace,invitee,custody,sha256)
      values(plan.id,p_invitation,p_workspace,live_invite.invitee,source,metadata_sha);
    delete from public.st_v2_invites c where (c.workspace_id,c.id)=(p_workspace,p_invitation);
    if not found then raise exception 'The exact invitation could not be removed' using errcode='PT409'; end if;
    insert into sectalk_private.st_v8_offboarding_declined_invite_decisions(plan,action,actor)
      values(plan.id,'removed',caller) returning happened_at into deleted_at;
  end if;
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'approvedAt',approved_at,'deletedAt',deleted_at);
end $$;

revoke all on function sectalk_private.st_v8_block_retired_invitation_reissue(),
  sectalk_private.st_v8_offboarding_declined_invite_source(sectalk_private.st_v8_offboarding_requests,uuid),
  public.st_v8_offboarding_declined_invite_status(uuid),public.st_v8_offboarding_declined_invite(uuid,uuid,text,text,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_declined_invite_status(uuid),
  public.st_v8_offboarding_declined_invite(uuid,uuid,text,text,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
