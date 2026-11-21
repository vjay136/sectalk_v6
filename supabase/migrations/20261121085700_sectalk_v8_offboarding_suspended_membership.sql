begin;

create table sectalk_private.st_v8_offboarding_suspended_member_copies (
  request_id uuid not null,
  member_id uuid not null,
  owner_id uuid not null,
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  issued_at timestamptz not null default clock_timestamp(),
  primary key(request_id,member_id,sha256)
);
create table sectalk_private.st_v8_offboarding_suspended_member_plans (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null,
  workspace uuid not null,
  member_id uuid not null,
  member_label text not null,
  owner_id uuid not null,
  reviewer_id uuid not null check(reviewer_id<>owner_id),
  copy_sha256 text not null check(copy_sha256~'^[a-f0-9]{64}$'),
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  unique(request_id,member_id,sha256)
);
create table sectalk_private.st_v8_offboarding_suspended_member_decisions (
  plan uuid not null references sectalk_private.st_v8_offboarding_suspended_member_plans,
  action text not null check(action in ('approved','removed')),
  actor uuid not null,
  happened_at timestamptz not null default clock_timestamp(),
  primary key(plan,action)
);
create table sectalk_private.st_v8_offboarding_retired_suspended_member (
  plan uuid primary key references sectalk_private.st_v8_offboarding_suspended_member_plans,
  member_id uuid not null,
  workspace uuid not null,
  custody jsonb not null,
  sha256 text not null check(sha256=encode(sha256(convert_to(custody::text,'UTF8')),'hex')),
  unique(workspace,member_id),
  check((custody#>>'{membership,user_id}')::uuid=member_id),
  check((custody#>>'{membership,workspace_id}')::uuid=workspace)
);
create trigger st_v8_suspended_member_copy_immutable before update or delete on sectalk_private.st_v8_offboarding_suspended_member_copies
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_suspended_member_plan_immutable before update or delete on sectalk_private.st_v8_offboarding_suspended_member_plans
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_suspended_member_decision_immutable before update or delete on sectalk_private.st_v8_offboarding_suspended_member_decisions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_retired_suspended_member_immutable before update or delete on sectalk_private.st_v8_offboarding_retired_suspended_member
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_suspended_member_copies enable row level security;
alter table sectalk_private.st_v8_offboarding_suspended_member_plans enable row level security;
alter table sectalk_private.st_v8_offboarding_suspended_member_decisions enable row level security;
alter table sectalk_private.st_v8_offboarding_retired_suspended_member enable row level security;
revoke all on sectalk_private.st_v8_offboarding_suspended_member_copies,sectalk_private.st_v8_offboarding_suspended_member_plans,
  sectalk_private.st_v8_offboarding_suspended_member_decisions,sectalk_private.st_v8_offboarding_retired_suspended_member
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_offboarding_guard_suspended_membership()
returns trigger language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
begin
  if tg_op='DELETE' then
    if exists(select 1 from sectalk_private.st_v8_offboarding_requests r
      where r.workspace=old.workspace_id and r.state='read_only'
        and not exists(select 1 from sectalk_private.st_v8_offboarding_retired_suspended_member t
          join sectalk_private.st_v8_offboarding_suspended_member_plans p on p.id=t.plan
          where (t.workspace,t.member_id,p.request_id)=(old.workspace_id,old.user_id,r.id)
            and t.custody->'membership'=to_jsonb(old))) then
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
create trigger st_v8_offboarding_guard_suspended_member_reuse before insert or update of workspace_id,user_id on public.st_v2_members
  for each row execute function sectalk_private.st_v8_offboarding_guard_suspended_membership();
create trigger st_v8_offboarding_guard_staged_roster_delete before delete on public.st_v2_members
  for each row execute function sectalk_private.st_v8_offboarding_guard_suspended_membership();

create function sectalk_private.st_v8_offboarding_suspended_member_source(
  r sectalk_private.st_v8_offboarding_requests,p_member uuid
) returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  select jsonb_build_object('membership',to_jsonb(m),'acceptedInvitation',i.id,'workspaceAudit',a.events)
  from public.st_v2_members m
  join public.st_v2_invites i on (i.workspace_id,i.invitee,i.created_by,i.status)=(m.workspace_id,m.user_id,r.requester,'accepted')
  cross join lateral (
    select jsonb_agg(to_jsonb(j) order by j.id) as events, count(*) as total,
      min(j.id) filter(where j.event='member.invited' and j.actor=r.requester and j.created_at=i.created_at) as invited,
      min(j.id) filter(where j.event='member.joined' and j.actor=m.user_id and j.created_at=m.joined_at) as joined,
      min(j.id) filter(where j.event='member.suspend' and j.actor=r.requester) as suspended,
      coalesce(bool_and(exists(select 1 from sectalk_private.st_v6_audit_chain c
          where (c.source,c.source_id,c.operation,c.row_hash)=
            ('public.st_v2_workspace_audit',j.id,'INSERT',sectalk_private.st_v6_audit_row_hash(to_jsonb(j))))
        and not exists(select 1 from sectalk_private.st_v6_audit_chain c where
          (c.source,c.source_id)=('public.st_v2_workspace_audit',j.id) and c.operation<>'INSERT')),false) as original
    from public.st_v2_workspace_audit j where j.workspace_id=r.workspace and (j.target=m.user_id or j.actor=m.user_id)
  ) a
  where (m.workspace_id,m.user_id,m.role)=(r.workspace,p_member,'member')
    and m.suspended_at is not null and m.user_id not in (r.requester,r.reviewer)
    and sectalk_private.st_v2_active(m.user_id)
    and a.total=3 and a.invited<a.joined and a.joined<a.suspended and a.original
    and not exists(select 1 from sectalk_private.st_v7_billing_admins x where (x.workspace,x.account)=(r.workspace,m.user_id))
    and not exists(select 1 from public.st_v6_workspace_group_members x where (x.workspace_id,x.user_id)=(r.workspace,m.user_id))
    and not exists(select 1 from sectalk_private.st_v6_impersonation_watch x where (x.workspace_id,x.member_id)=(r.workspace,m.user_id))
    and not exists(select 1 from sectalk_private.st_v7_school_class_people x where (x.workspace,x.person)=(r.workspace,m.user_id))
    and not exists(select 1 from sectalk_private.st_v7_custom_role_assignments x where (x.workspace,x.account)=(r.workspace,m.user_id))
    and not exists(select 1 from sectalk_private.st_v7_workspace_sso x where x.workspace=r.workspace)
    and not exists(select 1 from sectalk_private.st_v7_workspace_sso_sessions x where (x.workspace,x.principal)=(r.workspace,m.user_id))
    and not exists(select 1 from sectalk_private.st_v7_sso_departures x where (x.workspace,x.principal)=(r.workspace,m.user_id))
    and not exists(select 1 from sectalk_private.st_v8_scim_users x where (x.workspace,x.principal)=(r.workspace,m.user_id))
    and not exists(select 1 from sectalk_private.st_v7_managed_accounts x where x.workspace=r.workspace
      and m.user_id in (x.supervisor,x.participant))
    and not exists(select 1 from sectalk_private.st_v8_workspace_seats x where x.workspace=r.workspace and x.subscription is not null)
    and not exists(select 1 from sectalk_private.st_v8_workspace_seat_changes x
      where x.workspace=r.workspace and (x.finished_at is null or x.actor=m.user_id))
    and not exists(select 1 from sectalk_private.st_v6_webhooks x where x.workspace_id=r.workspace and x.revoked_at is null)
    and not exists(select 1 from public.st_v6_rooms x where x.workspace_id=r.workspace and
      (x.creator=m.user_id or exists(select 1 from public.st_v6_room_members y where (y.room_id,y.user_id)=(x.id,m.user_id))
        or exists(select 1 from public.st_v6_room_entries y where (y.room_id,y.user_id)=(x.id,m.user_id))
        or exists(select 1 from public.st_v6_room_bans y where (y.room_id,y.user_id)=(x.id,m.user_id))
        or exists(select 1 from public.st_v6_room_timeouts y where (y.room_id,y.user_id)=(x.id,m.user_id))
        or exists(select 1 from public.st_v6_room_posts y where (y.room_id,y.sender)=(x.id,m.user_id))
        or exists(select 1 from public.st_v6_tasks y where (y.room_id,y.author_id)=(x.id,m.user_id))))
    and not exists(select 1 from public.st_v2_channels x where x.workspace_id=r.workspace and
      (x.owner=m.user_id or exists(select 1 from sectalk_private.st_v6_channel_members y where (y.channel_id,y.user_id)=(x.id,m.user_id))
        or exists(select 1 from public.st_v2_posts y where (y.channel_id,y.sender)=(x.id,m.user_id))))
    and not exists(select 1 from public.st_v2_items x where (x.workspace_id,x.created_by)=(r.workspace,m.user_id))
    and not exists(select 1 from sectalk_private.st_v8_managed_room_posts x where (x.workspace,x.sender)=(r.workspace,m.user_id))
    and not exists(select 1 from sectalk_private.st_v6_workspace_files x where (x.workspace,x.uploader)=(r.workspace,m.user_id))
    and not exists(select 1 from sectalk_private.st_v6_room_files x where (x.workspace,x.uploader)=(r.workspace,m.user_id))
    and not exists(select 1 from sectalk_private.st_v6_room_reports x where x.workspace_id=r.workspace and m.user_id in (x.reporter,x.subject))
    and not exists(select 1 from sectalk_private.st_v7_channel_reports x where x.workspace_id=r.workspace and m.user_id in (x.reporter,x.subject))
    and not exists(select 1 from sectalk_private.st_v6_workspace_holds x where (x.workspace_id,x.member_id)=(r.workspace,m.user_id))
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
      where f.contype='f' and f.confrelid='public.st_v2_members'::regclass
        and (referenced.columns is distinct from array['workspace_id','user_id']
          or dependent.columns is distinct from case f.conrelid
            when 'sectalk_private.st_v7_billing_admins'::regclass then array['workspace','account']
            when 'public.st_v6_workspace_group_members'::regclass then array['workspace_id','user_id']
            when 'sectalk_private.st_v6_impersonation_watch'::regclass then array['workspace_id','member_id']
            when 'sectalk_private.st_v7_school_class_people'::regclass then array['workspace','person']
            when 'sectalk_private.st_v7_custom_role_assignments'::regclass then array['workspace','account']
            else null end))
$$;
create function public.st_v8_offboarding_suspended_member_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
begin
  if not sectalk_private.st_v8_directory_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace) then raise insufficient_privilege; end if;
  return jsonb_build_object('held',sectalk_private.st_v8_offboarding_holds(p_workspace),
    'members',case when auth.uid()=r.requester then coalesce((select jsonb_agg(to_jsonb(x) order by x.name,x.id) from (
      select c.user_id as id,'Suspended member' as name,exists(select 1 from sectalk_private.st_v8_offboarding_suspended_member_copies a
        where (a.request_id,a.member_id,a.owner_id,a.sha256)=(r.id,c.user_id,r.requester,
          encode(sha256(convert_to(s.source::text,'UTF8')),'hex'))) as copied
      from public.st_v2_members c cross join lateral (select sectalk_private.st_v8_offboarding_suspended_member_source(r,c.user_id)
        as source offset 0) s
      where c.workspace_id=p_workspace and c.suspended_at is not null and s.source is not null order by c.suspended_at desc,c.user_id limit 100
    ) x),'[]') else '[]'::jsonb end,
    'plans',coalesce((select jsonb_agg(to_jsonb(p) order by p."createdAt" desc,p.plan) from (
      select x.id as plan,x.member_id as member,x.member_label as name,x.sha256,x.copy_sha256 as "copySha256",
        x.created_at as "createdAt",d.happened_at as "approvedAt",z.happened_at as "deletedAt"
      from sectalk_private.st_v8_offboarding_suspended_member_plans x
      left join sectalk_private.st_v8_offboarding_suspended_member_decisions d on (d.plan,d.action)=(x.id,'approved')
      left join sectalk_private.st_v8_offboarding_suspended_member_decisions z on (z.plan,z.action)=(x.id,'removed')
      where (x.request_id,x.workspace)=(r.id,p_workspace) and (x.expires_at>statement_timestamp() or z.happened_at is not null)
      order by x.created_at desc,x.id limit 50
    ) p),'[]'));
end $$;

create function public.st_v8_offboarding_suspended_member(
  p_workspace uuid,p_member uuid,p_action text,p_confirmation text,p_plan uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  caller uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_suspended_member_plans;
  source jsonb; metadata_sha text; fingerprint text;
  inventory_until timestamptz; approved_at timestamptz; deleted_at timestamptz;
begin
  if p_workspace is null or p_member is null or p_action is null or p_action not in ('copy','capture','approve','delete')
    or p_confirmation is distinct from p_workspace::text then raise insufficient_privilege; end if;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if not sectalk_private.st_v8_directory_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace)
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
  if not sectalk_private.st_v8_directory_sso_allows(p_workspace) or not sectalk_private.st_v8_audit_sso_allows(p_workspace)
    or caller is distinct from (case when p_action='approve' then r.reviewer else r.requester end)
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_offboarding_suspended_member',12);

  if p_action in ('approve','delete') then
    select p.* into plan from sectalk_private.st_v8_offboarding_suspended_member_plans p
      where (p.id,p.workspace,p.request_id,p.member_id,p.sha256)=(p_plan,p_workspace,r.id,p_member,p_sha256);
    if plan.id is null then raise exception 'Confirm the exact suspended membership retirement digest' using errcode='PT409'; end if;
    select x.happened_at into approved_at from sectalk_private.st_v8_offboarding_suspended_member_decisions x
      where (x.plan,x.action,x.actor)=(plan.id,'approved',r.reviewer);
    select x.happened_at into deleted_at from sectalk_private.st_v8_offboarding_suspended_member_decisions x
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
    perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-member-retirement:'||p_workspace::text,0));
  end if;
  perform 1 from public.st_v2_members k where (k.workspace_id,k.user_id)=(p_workspace,p_member) for update nowait;
  if not found then raise insufficient_privilege; end if;
  perform 1 from public.st_v2_invites i where (i.workspace_id,i.invitee,i.status)=(p_workspace,p_member,'accepted') for share nowait;
  perform 1 from public.st_v2_workspace_audit a where (a.workspace_id,a.target)=(p_workspace,p_member) order by a.id limit 4 for share nowait;
  source:=sectalk_private.st_v8_offboarding_suspended_member_source(r,p_member);
  if source is null then raise exception 'This membership or its access evidence is not eligible for roster retirement' using errcode='PT409'; end if;
  metadata_sha:=encode(sha256(convert_to(source::text,'UTF8')),'hex');
  perform 1 from auth.sessions n join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
    join auth.mfa_amr_claims a on a.session_id=n.id and a.authentication_method='totp'
    where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',caller) and n.aal='aal2' and f.status='verified' and f.factor_type='totp'
      and a.updated_at>clock_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp() for share of n,f,a;
  if not found or inventory_until<=clock_timestamp() then raise insufficient_privilege; end if;

  if p_action='copy' then
    insert into sectalk_private.st_v8_offboarding_suspended_member_copies(request_id,member_id,owner_id,sha256)
      values(r.id,p_member,caller,metadata_sha) on conflict do nothing;
    return jsonb_build_object('format','sectalk-offboarding-suspended-membership-retirement-copy-v1','membership',p_member,
      'sha256',metadata_sha,'json',source::text);
  end if;
  if not exists(select 1 from sectalk_private.st_v8_offboarding_suspended_member_copies a
    where (a.request_id,a.member_id,a.owner_id,a.sha256)=(r.id,p_member,r.requester,metadata_sha)) then
    raise exception 'Download the exact suspended membership copy first' using errcode='PT409'; end if;
  fingerprint:=encode(sha256(convert_to(jsonb_build_array('sectalk-offboarding-suspended-membership-retirement-v1',p_workspace,r.id,
    r.snapshot_sha256,p_member,metadata_sha)::text,'UTF8')),'hex');
  if p_action='capture' then
    insert into sectalk_private.st_v8_offboarding_suspended_member_plans(request_id,workspace,member_id,member_label,
      owner_id,reviewer_id,copy_sha256,sha256,expires_at)
      values(r.id,p_workspace,p_member,'Suspended member',r.requester,r.reviewer,metadata_sha,fingerprint,inventory_until)
      on conflict do nothing;
    select x.* into strict plan from sectalk_private.st_v8_offboarding_suspended_member_plans x
      where (x.request_id,x.workspace,x.member_id,x.sha256)=(r.id,p_workspace,p_member,fingerprint);
  elsif plan.sha256 is distinct from fingerprint or plan.expires_at<=clock_timestamp() then
    raise exception 'The exact membership approval changed or expired' using errcode='PT409';
  elsif p_action='approve' and approved_at is null then
    insert into sectalk_private.st_v8_offboarding_suspended_member_decisions(plan,action,actor)
      values(plan.id,'approved',caller) returning happened_at into approved_at;
  elsif p_action='delete' then
    if approved_at is null then raise insufficient_privilege; end if;
    if sectalk_private.st_v8_offboarding_suspended_member_source(r,p_member) is distinct from source then
      raise exception 'The membership or its dependent access evidence changed' using errcode='PT409';
    end if;
    insert into sectalk_private.st_v8_offboarding_retired_suspended_member(plan,member_id,workspace,custody,sha256)
      values(plan.id,p_member,p_workspace,source,metadata_sha);
    delete from public.st_v2_members c where (c.workspace_id,c.user_id)=(p_workspace,p_member);
    if not found then raise exception 'The exact suspended membership could not be retired' using errcode='PT409'; end if;
    insert into sectalk_private.st_v8_offboarding_suspended_member_decisions(plan,action,actor)
      values(plan.id,'removed',caller) returning happened_at into deleted_at;
  end if;
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'approvedAt',approved_at,'deletedAt',deleted_at);
end $$;

revoke all on function sectalk_private.st_v8_offboarding_guard_suspended_membership(),
  sectalk_private.st_v8_offboarding_suspended_member_source(sectalk_private.st_v8_offboarding_requests,uuid),
  public.st_v8_offboarding_suspended_member_status(uuid),public.st_v8_offboarding_suspended_member(uuid,uuid,text,text,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_suspended_member_status(uuid),
  public.st_v8_offboarding_suspended_member(uuid,uuid,text,text,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
