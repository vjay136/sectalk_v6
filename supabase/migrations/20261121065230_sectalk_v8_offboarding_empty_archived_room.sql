begin;

create table sectalk_private.st_v8_offboarding_archived_room_copies (
  request_id uuid not null,
  room uuid not null,
  owner_id uuid not null,
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  issued_at timestamptz not null default clock_timestamp(),
  primary key(request_id,room,sha256)
);
create table sectalk_private.st_v8_offboarding_archived_room_plans (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null,
  workspace uuid not null,
  room uuid not null,
  room_name text not null,
  owner_id uuid not null,
  reviewer_id uuid not null check(reviewer_id<>owner_id),
  copy_sha256 text not null check(copy_sha256~'^[a-f0-9]{64}$'),
  archive_sha256 text not null check(archive_sha256~'^[a-f0-9]{64}$'),
  sha256 text not null check(sha256~'^[a-f0-9]{64}$'),
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  unique(request_id,room,sha256)
);
create table sectalk_private.st_v8_offboarding_archived_room_decisions (
  plan uuid not null references sectalk_private.st_v8_offboarding_archived_room_plans,
  action text not null check(action in ('approved','removed')),
  actor uuid not null,
  happened_at timestamptz not null default clock_timestamp(),
  primary key(plan,action)
);
create table sectalk_private.st_v8_offboarding_retained_room_proof (
  plan uuid primary key references sectalk_private.st_v8_offboarding_archived_room_plans,
  room uuid not null unique,
  proof jsonb not null,
  sha256 text not null check(sha256=encode(sha256(convert_to(proof::text,'UTF8')),'hex')),
  check((proof#>>'{creatorMembership,room_id}')::uuid=room)
);
create trigger st_v8_archived_room_copy_immutable before update or delete on sectalk_private.st_v8_offboarding_archived_room_copies
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_archived_room_plan_immutable before update or delete on sectalk_private.st_v8_offboarding_archived_room_plans
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_archived_room_decision_immutable before update or delete on sectalk_private.st_v8_offboarding_archived_room_decisions
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_retained_room_proof_immutable before update or delete on sectalk_private.st_v8_offboarding_retained_room_proof
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_archived_room_copies enable row level security;
alter table sectalk_private.st_v8_offboarding_archived_room_plans enable row level security;
alter table sectalk_private.st_v8_offboarding_archived_room_decisions enable row level security;
alter table sectalk_private.st_v8_offboarding_retained_room_proof enable row level security;
revoke all on sectalk_private.st_v8_offboarding_archived_room_copies,sectalk_private.st_v8_offboarding_archived_room_plans,
  sectalk_private.st_v8_offboarding_archived_room_decisions,sectalk_private.st_v8_offboarding_retained_room_proof
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_prevent_archived_room_id_reuse()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform pg_advisory_xact_lock(hashtextextended('sectalk-room-identifier:'||new.id::text,0));
  if exists(select 1 from sectalk_private.st_v8_offboarding_retained_room_proof x where x.room=new.id) then
    raise exception 'This room identifier is permanently retired' using errcode='PT409';
  end if;
  return new;
end $$;
create trigger st_v8_prevent_archived_room_id_reuse before insert or update of id on public.st_v6_rooms
  for each row execute function sectalk_private.st_v8_prevent_archived_room_id_reuse();

-- A new inbound foreign key automatically adds another preservation check.
-- Unsupported reference shapes keep the room ineligible.
create function sectalk_private.st_v8_offboarding_room_has_dependents(p_room uuid)
returns boolean language plpgsql stable set search_path='' as $$
declare dependency record; present boolean;
begin
  for dependency in
    select n.nspname,c.relname,a.attname,cardinality(f.conkey)=1 and cardinality(f.confkey)=1
      and f.confkey[1]=(select attnum from pg_attribute where attrelid=f.confrelid and attname='id') as single_room
    from pg_constraint f join pg_class c on c.oid=f.conrelid join pg_namespace n on n.oid=c.relnamespace
    join pg_attribute a on a.attrelid=c.oid and a.attnum=f.conkey[1]
    where f.contype='f' and f.confrelid='public.st_v6_rooms'::regclass
      and not (f.conrelid in ('public.st_v6_room_members'::regclass,'public.st_v6_room_audit'::regclass)
        and a.attname='room_id' and cardinality(f.conkey)=1)
    order by n.nspname,c.relname,a.attname
  loop
    if not dependency.single_room then return true; end if;
    execute format('select exists(select 1 from %I.%I where %I=$1)',
      dependency.nspname,dependency.relname,dependency.attname) into present using p_room;
    if present then return true; end if;
  end loop;
  return false;
end $$;

create function sectalk_private.st_v8_offboarding_archived_room_source(
  r sectalk_private.st_v8_offboarding_requests,p_room uuid
) returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  select jsonb_build_object('room',to_jsonb(x),'retainedProof',jsonb_build_object(
    'creatorMembership',to_jsonb(m),'auditEvents',jsonb_build_array(to_jsonb(c),to_jsonb(a))))
  from public.st_v6_rooms x
  join public.st_v6_room_members m on (m.room_id,m.user_id,m.role)=(x.id,r.requester,'owner')
  join public.st_v6_room_audit c on (c.room_id,c.actor,c.action)=(x.id,r.requester,'room.created')
  join public.st_v6_room_audit a on (a.room_id,a.actor,a.action)=(x.id,r.requester,'room.archive')
  where (x.workspace_id,x.id,x.creator)=(r.workspace,p_room,r.requester)
    and (x.kind,x.template,x.encryption_mode)=('public','blank','standard')
    and x.classification in ('public','internal') and x.archived and not x.locked and x.slow_seconds=0
    and sectalk_private.st_v8_standard_room_session_allowed(x.id)
    and c.target is null and c.details='{}'::jsonb and a.target is null and a.details='{}'::jsonb and c.id<a.id
    and not exists(select 1 from public.st_v6_room_members other where other.room_id=x.id and other.user_id<>m.user_id)
    and not exists(select 1 from public.st_v6_room_audit other where other.room_id=x.id and other.id not in (c.id,a.id))
    and exists(select 1 from sectalk_private.st_v6_audit_chain j where
      (j.source,j.source_id,j.operation,j.row_hash)=
        ('public.st_v6_room_audit',c.id,'INSERT',sectalk_private.st_v6_audit_row_hash(to_jsonb(c))))
    and exists(select 1 from sectalk_private.st_v6_audit_chain j where
      (j.source,j.source_id,j.operation,j.row_hash)=
        ('public.st_v6_room_audit',a.id,'INSERT',sectalk_private.st_v6_audit_row_hash(to_jsonb(a))))
    and not exists(select 1 from sectalk_private.st_v6_audit_chain j where
      j.source='public.st_v6_room_audit' and j.source_id in (c.id,a.id) and j.operation<>'INSERT')
    and not sectalk_private.st_v8_offboarding_room_has_dependents(x.id)
    and not exists(select 1 from public.st_v3_meetings y where y.room_id=x.id)
    and not exists(select 1 from public.st_v3_notifications y where y.room_id=x.id)
    and not exists(select 1 from public.st_v6_thread_follows y where y.room_id=x.id)
    and not exists(select 1 from sectalk_private.room_read_receipts y where y.room_id=x.id)
    and not exists(select 1 from sectalk_private.st_v6_room_reactions y where y.room_id=x.id)
    and not exists(select 1 from sectalk_private.st_v6_thread_summary_consent y where y.room=x.id)
    and not exists(select 1 from sectalk_private.st_v6_admin_notification_runs y where y.room_id=x.id)
    and not exists(select 1 from sectalk_private.st_v6_admin_notification_receipts y where y.room_id=x.id)
    and not exists(select 1 from sectalk_private.st_v6_room_reports y where y.room_id=x.id)
    and not exists(select 1 from sectalk_private.st_v7_evidence_snapshots y where y.room_id=x.id)
    and not exists(select 1 from sectalk_private.st_v7_room_quarantine_evidence y where y.room=x.id)
    and not exists(select 1 from sectalk_private.st_v8_managed_room_evidence y where y.room=x.id)
    and not exists(select 1 from sectalk_private.st_v8_managed_room_rewrap_audit y where y.room=x.id)
    and not exists(select 1 from sectalk_private.st_v6_preserved_post_versions y where (y.source,y.scope_id)=('room',x.id))
    and not exists(select 1 from sectalk_private.st_v7_dlp_delivery_receipts y where (y.scope_type,y.scope_id)=('room',x.id))
    and not exists(select 1 from sectalk_private.st_v7_dlp_acknowledgements y where (y.scope_type,y.scope_id)=('room',x.id))
    and not exists(select 1 from sectalk_private.st_v6_export_objects y where y.scope_id=x.id)
    and not exists(select 1 from sectalk_private.st_v8_content_export_entries y where y.scope_id=x.id)
    and not exists(select 1 from sectalk_private.st_v6_room_files y where y.room=x.id)
    and not exists(select 1 from storage.objects y where y.bucket_id='sectalk-workspace-files'
      and y.name like (x.workspace_id::text||'/rooms/'||x.id::text||'/%'))
    and not exists(select 1 from sectalk_private.st_v8_offboarding_room_file_retirements y where y.room=x.id)
    and not exists(select 1 from sectalk_private.st_v8_offboarding_room_post_deletions y where y.room=x.id)
    and not exists(select 1 from sectalk_private.st_v8_offboarding_room_task_deletions y where y.room=x.id)
    and not exists(select 1 from sectalk_private.st_v8_offboarding_room_thread_deletions y where y.room=x.id);
$$;
create function public.st_v8_offboarding_archived_room_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
begin
  if not sectalk_private.st_v8_room_structure_sso_allows(p_workspace) then raise insufficient_privilege; end if;
  return jsonb_build_object('held',sectalk_private.st_v8_offboarding_holds(p_workspace),
    'rooms',case when auth.uid()=r.requester then coalesce((select jsonb_agg(to_jsonb(x) order by x.name,x.id) from (
      select c.id,c.name,exists(select 1 from sectalk_private.st_v8_offboarding_archived_room_copies a
        where (a.request_id,a.room,a.owner_id,a.sha256)=(r.id,c.id,r.requester,
          encode(sha256(convert_to(s.source::text,'UTF8')),'hex'))) as copied
      from public.st_v6_rooms c cross join lateral (select sectalk_private.st_v8_offboarding_archived_room_source(r,c.id)
        as source offset 0) s
      where c.workspace_id=p_workspace and c.archived and s.source is not null order by c.name,c.id limit 100
    ) x),'[]') else '[]'::jsonb end,
    'plans',coalesce((select jsonb_agg(to_jsonb(p) order by p."createdAt" desc,p.plan) from (
      select x.id as plan,x.room,x.room_name as name,x.sha256,x.copy_sha256 as "copySha256",x.archive_sha256 as "archiveSha256",
        x.created_at as "createdAt",d.happened_at as "approvedAt",z.happened_at as "deletedAt"
      from sectalk_private.st_v8_offboarding_archived_room_plans x
      left join sectalk_private.st_v8_offboarding_archived_room_decisions d on (d.plan,d.action)=(x.id,'approved')
      left join sectalk_private.st_v8_offboarding_archived_room_decisions z on (z.plan,z.action)=(x.id,'removed')
      where (x.request_id,x.workspace)=(r.id,p_workspace) and (x.expires_at>statement_timestamp() or z.happened_at is not null)
      order by x.created_at desc,x.id limit 50
    ) p),'[]'));
end $$;

create function public.st_v8_offboarding_archived_room(
  p_workspace uuid,p_room uuid,p_action text,p_confirmation text,p_plan uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  caller uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_archived_room_plans;
  source jsonb; audit_row jsonb; metadata_sha text; event_sha text; key_sha text; fingerprint text;
  inventory_until timestamptz; approved_at timestamptz; deleted_at timestamptz;
begin
  if p_workspace is null or p_room is null or p_action is null or p_action not in ('copy','capture','approve','delete')
    or p_confirmation is distinct from p_workspace::text then raise insufficient_privilege; end if;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if not sectalk_private.st_v8_room_structure_sso_allows(p_workspace)
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
  if not sectalk_private.st_v8_room_structure_sso_allows(p_workspace)
    or caller is distinct from (case when p_action='approve' then r.reviewer else r.requester end)
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_offboarding_archived_room',12);

  if p_action in ('approve','delete') then
    select p.* into plan from sectalk_private.st_v8_offboarding_archived_room_plans p
      where (p.id,p.workspace,p.request_id,p.room,p.sha256)=(p_plan,p_workspace,r.id,p_room,p_sha256);
    if plan.id is null then raise exception 'Confirm the exact room deletion digest' using errcode='PT409'; end if;
    select x.happened_at into approved_at from sectalk_private.st_v8_offboarding_archived_room_decisions x
      where (x.plan,x.action,x.actor)=(plan.id,'approved',r.reviewer);
    select x.happened_at into deleted_at from sectalk_private.st_v8_offboarding_archived_room_decisions x
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
    perform pg_advisory_xact_lock(hashtextextended('sectalk-room-identifier:'||p_room::text,0));
  end if;
  perform 1 from public.st_v6_rooms c where (c.workspace_id,c.id)=(p_workspace,p_room) for update nowait;
  if not found then raise insufficient_privilege; end if;
  perform 1 from public.st_v6_room_members m where m.room_id=p_room order by m.user_id limit 2 for update nowait;
  perform 1 from public.st_v6_room_audit a where a.room_id=p_room order by a.id limit 3 for update nowait;
  source:=sectalk_private.st_v8_offboarding_archived_room_source(r,p_room);
  if source is null then raise exception 'The empty archived room or its archive evidence is ineligible' using errcode='PT409'; end if;
  audit_row:=source->'retainedProof';
  metadata_sha:=encode(sha256(convert_to(source::text,'UTF8')),'hex');
  event_sha:=encode(sha256(convert_to(audit_row::text,'UTF8')),'hex');
  select encode(sha256(convert_to(jsonb_build_array(s.current_version,
    coalesce((select jsonb_agg(jsonb_build_array(k.version,k.custody,k.provider_ref,k.wrapped) order by k.version)
      from sectalk_private.st_v7_tenant_key_versions k where k.workspace=s.workspace),'[]'))::text,'UTF8')),'hex')
    into key_sha from sectalk_private.st_v7_tenant_key_state s where s.workspace=p_workspace and s.destroyed_at is null
      and exists(select 1 from sectalk_private.st_v7_tenant_key_versions k where (k.workspace,k.version)=(s.workspace,s.current_version));
  if key_sha is null
    or exists(select 1 from sectalk_private.st_v7_tenant_key_destroy k where k.workspace=p_workspace and k.result is null)
    or exists(select 1 from sectalk_private.st_v7_tenant_rotation_tickets k where k.workspace=p_workspace and k.expires_at>clock_timestamp())
    then raise exception 'Live stable key custody is required' using errcode='PT409'; end if;
  perform 1 from auth.sessions n join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
    join auth.mfa_amr_claims a on a.session_id=n.id and a.authentication_method='totp'
    where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',caller) and n.aal='aal2' and f.status='verified' and f.factor_type='totp'
      and a.updated_at>clock_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp() for share of n,f,a;
  if not found or inventory_until<=clock_timestamp() then raise insufficient_privilege; end if;

  if p_action='copy' then
    insert into sectalk_private.st_v8_offboarding_archived_room_copies(request_id,room,owner_id,sha256)
      values(r.id,p_room,caller,metadata_sha) on conflict do nothing;
    return jsonb_build_object('format','sectalk-offboarding-archived-room-copy-v1','room',p_room,
      'sha256',metadata_sha,'json',source::text);
  end if;
  if not exists(select 1 from sectalk_private.st_v8_offboarding_archived_room_copies a
    where (a.request_id,a.room,a.owner_id,a.sha256)=(r.id,p_room,r.requester,metadata_sha)) then
    raise exception 'Download the exact approved room copy first' using errcode='PT409'; end if;
  fingerprint:=encode(sha256(convert_to(jsonb_build_array('sectalk-offboarding-archived-room-v1',p_workspace,r.id,
    r.snapshot_sha256,p_room,metadata_sha,event_sha,key_sha)::text,'UTF8')),'hex');
  if p_action='capture' then
    insert into sectalk_private.st_v8_offboarding_archived_room_plans(request_id,workspace,room,room_name,
      owner_id,reviewer_id,copy_sha256,archive_sha256,sha256,expires_at)
      values(r.id,p_workspace,p_room,source#>>'{room,name}',r.requester,r.reviewer,metadata_sha,event_sha,fingerprint,inventory_until)
      on conflict do nothing;
    select x.* into strict plan from sectalk_private.st_v8_offboarding_archived_room_plans x
      where (x.request_id,x.workspace,x.room,x.sha256)=(r.id,p_workspace,p_room,fingerprint);
  elsif plan.sha256 is distinct from fingerprint or plan.expires_at<=clock_timestamp() then
    raise exception 'The exact room approval changed or expired' using errcode='PT409';
  elsif p_action='approve' and approved_at is null then
    insert into sectalk_private.st_v8_offboarding_archived_room_decisions(plan,action,actor)
      values(plan.id,'approved',caller) returning happened_at into approved_at;
  elsif p_action='delete' then
    if approved_at is null then raise insufficient_privilege; end if;
    insert into sectalk_private.st_v8_offboarding_retained_room_proof(plan,room,proof,sha256)
      values(plan.id,p_room,audit_row,event_sha);
    delete from public.st_v6_rooms c where (c.workspace_id,c.id)=(p_workspace,p_room);
    if not found then raise exception 'The exact room could not be removed' using errcode='PT409'; end if;
    insert into sectalk_private.st_v8_offboarding_archived_room_decisions(plan,action,actor)
      values(plan.id,'removed',caller) returning happened_at into deleted_at;
  end if;
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'approvedAt',approved_at,'deletedAt',deleted_at);
end $$;

revoke all on function sectalk_private.st_v8_prevent_archived_room_id_reuse(),
  sectalk_private.st_v8_offboarding_room_has_dependents(uuid),
  sectalk_private.st_v8_offboarding_archived_room_source(sectalk_private.st_v8_offboarding_requests,uuid),
  public.st_v8_offboarding_archived_room_status(uuid),public.st_v8_offboarding_archived_room(uuid,uuid,text,text,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_archived_room_status(uuid),
  public.st_v8_offboarding_archived_room(uuid,uuid,text,text,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
