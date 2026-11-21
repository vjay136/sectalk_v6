begin;

create table sectalk_private.st_v8_protected_artifact_wraps (
  artifact uuid primary key references sectalk_private.st_v7_artifact_envelopes on delete cascade,
  workspace uuid not null,
  source_revision text not null check(source_revision~'^[a-f0-9]{64}$'),
  wrapping_version integer not null,
  wrapped_dek text not null check(wrapped_dek~'^[A-Za-z0-9_-]{80}$'),
  foreign key(workspace,wrapping_version) references sectalk_private.st_v7_tenant_key_versions on delete cascade
);
create table sectalk_private.st_v8_protected_artifact_rewrap_audit (
  artifact uuid not null,
  workspace uuid not null,
  kind text not null check(kind in ('compliance','evidence')),
  source_revision text not null check(source_revision~'^[a-f0-9]{64}$'),
  previous_version integer not null,
  wrapping_version integer not null check(wrapping_version>previous_version),
  authorized_by uuid not null,
  occurred_at timestamptz not null default clock_timestamp(),
  primary key(artifact,wrapping_version)
);
create trigger st_v8_immutable_protected_artifact_rewrap_audit before update or delete
  on sectalk_private.st_v8_protected_artifact_rewrap_audit
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_protected_artifact_wraps enable row level security;
alter table sectalk_private.st_v8_protected_artifact_rewrap_audit enable row level security;
revoke all on sectalk_private.st_v8_protected_artifact_wraps,sectalk_private.st_v8_protected_artifact_rewrap_audit
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_protected_artifact_revision(a sectalk_private.st_v6_export_objects,
  e sectalk_private.st_v7_artifact_envelopes)
returns text language sql immutable strict set search_path='' as $$
  select encode(sha256(convert_to(jsonb_build_array(a.id,a.scope_id,a.actor_id,a.kind,a.sha256,a.bytes,
    e.workspace,e.key_version,e.nonce,e.tag,e.wrapped_dek)::text,'UTF8')),'hex');
$$;

create function sectalk_private.st_v8_protected_artifact_rewrap_target(p_workspace uuid,p_artifact uuid)
returns table(kind text,source_revision text,policy_revision uuid,authorized_by uuid,
  previous_version integer,wrapping_version integer,wrapped_key text,previous_dek text)
language sql stable set search_path='' as $$
  select a.kind,sectalk_private.st_v8_protected_artifact_revision(a,e),p.revision,p.authorized_by,
    src.version,dst.version,dst.wrapped,coalesce(w.wrapped_dek,e.wrapped_dek)
  from sectalk_private.st_v6_export_objects a
  join sectalk_private.st_v7_artifact_envelopes e on e.artifact=a.id and e.workspace=p_workspace
  join sectalk_private.st_v8_tenant_rotation_schedules p on p.workspace=e.workspace
  join sectalk_private.st_v7_tenant_key_state s on s.workspace=e.workspace and s.destroyed_at is null
  join sectalk_private.st_v7_tenant_key_versions original on (original.workspace,original.version)=(e.workspace,e.key_version)
    and original.custody='managed'
  join sectalk_private.st_v7_tenant_key_versions dst on (dst.workspace,dst.version)=(s.workspace,s.current_version)
    and dst.custody='managed'
  left join sectalk_private.st_v8_protected_artifact_wraps w on (w.artifact,w.workspace)=(a.id,e.workspace)
    and w.source_revision=sectalk_private.st_v8_protected_artifact_revision(a,e)
  join sectalk_private.st_v7_tenant_key_versions src on (src.workspace,src.version)=(e.workspace,coalesce(w.wrapping_version,e.key_version))
    and src.custody='managed' and src.version<dst.version
  where a.id=p_artifact and a.ready and a.envelope_required and a.kind in ('compliance','evidence')
    and a.expires_at>statement_timestamp() and sectalk_private.st_v8_scheduled_rotation_allowed(p.workspace,p.authorized_by)
    and (a.kind<>'evidence' or exists(select 1 from sectalk_private.st_v7_evidence_snapshots snap
      where (snap.workspace_id,snap.artifact)=(p_workspace,p_artifact) and sectalk_private.st_v7_evidence_read_live(snap)));
$$;

create or replace function public.st_v7_export_key_context(p_ticket uuid,p_artifact uuid,p_mode text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare space uuid:=sectalk_private.st_v7_export_key_workspace(p_ticket,p_artifact,p_mode);
  a sectalk_private.st_v6_export_objects; k sectalk_private.st_v7_tenant_key_versions;
  e sectalk_private.st_v7_artifact_envelopes; state sectalk_private.st_v7_tenant_key_state;
  sidecar sectalk_private.st_v8_protected_artifact_wraps; target jsonb;
begin
  if space is null then return null; end if;
  select * into strict a from sectalk_private.st_v6_export_objects where id=p_artifact;
  if p_mode='read' and not a.envelope_required then return jsonb_build_object('legacy',true); end if;
  select * into state from sectalk_private.st_v7_tenant_key_state where workspace=space;
  if state.destroyed_at is not null then return null; end if;
  if p_mode='read' then
    select * into e from sectalk_private.st_v7_artifact_envelopes where artifact=p_artifact and workspace=space;
    if e.artifact is null then return null; end if;
    select * into sidecar from sectalk_private.st_v8_protected_artifact_wraps w
      where (w.artifact,w.workspace)=(p_artifact,space) and w.source_revision=sectalk_private.st_v8_protected_artifact_revision(a,e);
    select jsonb_build_object('source_revision',t.source_revision,'policy_revision',t.policy_revision,
      'version',t.wrapping_version,'wrapped',t.wrapped_key) into target
    from sectalk_private.st_v8_protected_artifact_rewrap_target(space,p_artifact) t;
  end if;
  select * into k from sectalk_private.st_v7_tenant_key_versions where workspace=space and version=
    case when p_mode='read' then coalesce(sidecar.wrapping_version,e.key_version) else state.current_version end;
  if k.version is null and state.workspace is not null then return null; end if;
  return jsonb_build_object('workspace',space,'kind',a.kind,'sha256',a.sha256,'bytes',a.bytes,
    'version',k.version,'custody',k.custody,'ref',k.provider_ref,'wrapped',k.wrapped,
    'data_version',e.key_version,'wrapped_dek',coalesce(sidecar.wrapped_dek,e.wrapped_dek),
    'nonce',e.nonce,'tag',e.tag,'rewrap',target);
end $$;

create function public.st_v8_commit_protected_artifact_rewrap(p_ticket uuid,p_artifact uuid,p_policy_revision uuid,
  p_source_revision text,p_previous integer,p_target integer,p_wrapped_dek text)
returns boolean language plpgsql security definer set search_path='' as $$
declare space uuid:=sectalk_private.st_v7_export_key_workspace(p_ticket,p_artifact,'read'); candidate record;
begin
  if space is null or p_policy_revision is null or p_previous is null or p_target is null
    or p_previous>=p_target or (p_source_revision~'^[a-f0-9]{64}$') is not true
    or (p_wrapped_dek~'^[A-Za-z0-9_-]{80}$') is not true then return false; end if;
  perform 1 from public.st_v2_workspaces where id=space for share;
  if not found then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||space::text,0));
  perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-workspace-hold:'||space::text,0));
  perform 1 from sectalk_private.st_v6_export_objects a join sectalk_private.st_v7_artifact_envelopes e on e.artifact=a.id
    where (e.workspace,a.id)=(space,p_artifact) for update of a,e;
  if not found or sectalk_private.st_v7_export_key_workspace(p_ticket,p_artifact,'read') is distinct from space then return false; end if;
  select * into candidate from sectalk_private.st_v8_protected_artifact_rewrap_target(space,p_artifact);
  if not found or (candidate.source_revision,candidate.policy_revision,candidate.previous_version,candidate.wrapping_version)
    is distinct from (p_source_revision,p_policy_revision,p_previous,p_target) or p_wrapped_dek=candidate.previous_dek then return false; end if;
  insert into sectalk_private.st_v8_protected_artifact_wraps(artifact,workspace,source_revision,wrapping_version,wrapped_dek)
    values(p_artifact,space,p_source_revision,p_target,p_wrapped_dek)
    on conflict(artifact) do update set source_revision=excluded.source_revision,
      wrapping_version=excluded.wrapping_version,wrapped_dek=excluded.wrapped_dek;
  insert into sectalk_private.st_v8_protected_artifact_rewrap_audit(artifact,workspace,kind,source_revision,
    previous_version,wrapping_version,authorized_by)
    values(p_artifact,space,candidate.kind,p_source_revision,p_previous,p_target,candidate.authorized_by);
  return true;
end $$;

revoke all on function sectalk_private.st_v8_protected_artifact_revision(sectalk_private.st_v6_export_objects,
  sectalk_private.st_v7_artifact_envelopes),sectalk_private.st_v8_protected_artifact_rewrap_target(uuid,uuid),
  public.st_v8_commit_protected_artifact_rewrap(uuid,uuid,uuid,text,integer,integer,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_commit_protected_artifact_rewrap(uuid,uuid,uuid,text,integer,integer,text) to service_role;

commit;
