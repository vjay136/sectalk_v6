begin;

create table sectalk_private.st_v7_tenant_key_state (
  workspace uuid primary key,
  current_version integer not null check(current_version>=1),
  destroyed_at timestamptz
);
create table sectalk_private.st_v7_tenant_key_versions (
  workspace uuid not null,
  version integer not null,
  custody text not null check(custody in ('managed','byok')),
  provider_ref text check(provider_ref ~ '^[A-Za-z0-9_-]{1,96}$'),
  wrapped text not null check(char_length(wrapped) between 40 and 2048 and wrapped ~ '^[A-Za-z0-9_-]+$'),
  created_at timestamptz not null default clock_timestamp(),
  primary key(workspace,version),
  check((custody='byok')=(provider_ref is not null))
);
alter table sectalk_private.st_v6_export_objects add column envelope_required boolean not null default false;
create table sectalk_private.st_v7_artifact_envelopes (
  artifact uuid primary key references sectalk_private.st_v6_export_objects on delete cascade,
  workspace uuid not null,
  key_version integer not null,
  wrapped_dek text not null check(wrapped_dek ~ '^[A-Za-z0-9_-]{80}$'),
  nonce text not null check(nonce ~ '^[A-Za-z0-9_-]{16}$'),
  tag text not null check(tag ~ '^[A-Za-z0-9_-]{22}$')
);
create table sectalk_private.st_v7_tenant_rotation_tickets (
  id uuid primary key default gen_random_uuid(),
  workspace uuid not null,
  actor uuid not null,
  native_session uuid not null,
  custody text not null check(custody in ('managed','byok')),
  previous_version integer not null check(previous_version>=0),
  reason text not null,
  expires_at timestamptz not null default clock_timestamp()+interval '45 seconds'
);
create index st_v7_tenant_rotation_expiry on sectalk_private.st_v7_tenant_rotation_tickets(expires_at);
create table sectalk_private.st_v7_tenant_destroy_reviewers (
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  actor uuid not null references auth.users on delete cascade,
  primary key(workspace,actor)
);
create table sectalk_private.st_v7_tenant_key_destroy (
  id uuid primary key default gen_random_uuid(),
  workspace uuid not null,
  requester uuid not null,
  reason text not null,
  version integer not null,
  requested_at timestamptz not null default clock_timestamp(),
  reviewer uuid,
  decided_at timestamptz,
  decision_reason text,
  result text check(result in ('destroyed','rejected')),
  check(requester is distinct from reviewer),
  check((result is null)=(reviewer is null) and (result is null)=(decided_at is null) and (result is null)=(decision_reason is null))
);
create unique index st_v7_tenant_one_pending_key_destroy on sectalk_private.st_v7_tenant_key_destroy(workspace) where result is null;
create table sectalk_private.st_v7_tenant_key_audit (
  id bigint generated always as identity primary key,
  workspace uuid not null,
  actor uuid not null,
  event text not null check(event in ('provisioned','rotated','destroy_requested','destroyed','rejected')),
  version integer not null,
  reason text,
  occurred_at timestamptz not null default clock_timestamp()
);
create index st_v7_tenant_key_audit_workspace on sectalk_private.st_v7_tenant_key_audit(workspace,id desc);
create trigger st_v7_immutable_tenant_key_audit before update or delete on sectalk_private.st_v7_tenant_key_audit
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

alter table sectalk_private.st_v7_tenant_key_state enable row level security;
alter table sectalk_private.st_v7_tenant_key_versions enable row level security;
alter table sectalk_private.st_v7_artifact_envelopes enable row level security;
alter table sectalk_private.st_v7_tenant_rotation_tickets enable row level security;
alter table sectalk_private.st_v7_tenant_destroy_reviewers enable row level security;
alter table sectalk_private.st_v7_tenant_key_destroy enable row level security;
alter table sectalk_private.st_v7_tenant_key_audit enable row level security;
revoke all on sectalk_private.st_v7_tenant_key_state,sectalk_private.st_v7_tenant_key_versions,sectalk_private.st_v7_artifact_envelopes,
  sectalk_private.st_v7_tenant_rotation_tickets,sectalk_private.st_v7_tenant_destroy_reviewers,
  sectalk_private.st_v7_tenant_key_destroy,sectalk_private.st_v7_tenant_key_audit from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_tenant_key_role(p_workspace uuid)
returns text language sql stable set search_path='' as $$
  select case when r.role not in ('owner','admin') or r.role is null or public.st_v7_current_session_valid() is not true
    or sectalk_private.st_v2_active(auth.uid()) is not true or public.st_v7_account_under_lockdown()
    then 'none' when sectalk_private.st_v7_admin_fresh() is not true then 'mfa' else r.role end
  from (select sectalk_private.st_v2_role(p_workspace,auth.uid()) role) r;
$$;

create function sectalk_private.st_v7_export_key_workspace(p_ticket uuid,p_artifact uuid,p_mode text)
returns uuid language sql stable set search_path='' as $$
  select found.workspace from (
    select c.workspace_id workspace
    from sectalk_private.st_v6_export_objects a join sectalk_private.st_v7_compliance_cases c on c.id=a.scope_id
    where a.id=p_artifact and a.kind='compliance' and a.actor_id=c.requester and c.ticket=p_ticket
      and a.expires_at>statement_timestamp() and sectalk_private.st_v7_compliance_grant_live(c)
      and sectalk_private.st_v7_compliance_operation_live(c)
      and ((p_mode='write' and c.operation='build' and not a.ready and a.sha256=c.bundle_sha256 and a.bytes=c.bundle_bytes)
        or (p_mode='read' and c.operation='download' and c.artifact=a.id and a.ready))
    union all
    select c.workspace_id workspace
    from sectalk_private.st_v6_export_objects a join sectalk_private.st_v7_evidence_operations o on o.snapshot_id=a.scope_id
    join sectalk_private.st_v7_compliance_cases c on c.id=o.case_id
    where a.id=p_artifact and a.kind='evidence' and a.actor_id=o.actor and o.ticket=p_ticket
      and a.expires_at>statement_timestamp() and sectalk_private.st_v7_compliance_grant_live(c)
      and a.sha256=o.sha256 and sectalk_private.st_v7_evidence_operation_live(o)
      and ((p_mode='write' and o.operation='capture' and not a.ready)
        or (p_mode='read' and o.operation='download' and a.ready and exists(
          select 1 from sectalk_private.st_v7_evidence_snapshots s
          where s.id=o.snapshot_id and s.workspace_id=c.workspace_id and s.artifact=a.id)))
  ) found;
$$;

create function public.st_v7_export_key_context(p_ticket uuid,p_artifact uuid,p_mode text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare space uuid:=sectalk_private.st_v7_export_key_workspace(p_ticket,p_artifact,p_mode);
  a sectalk_private.st_v6_export_objects; k sectalk_private.st_v7_tenant_key_versions;
  e sectalk_private.st_v7_artifact_envelopes; state sectalk_private.st_v7_tenant_key_state;
begin
  if space is null then return null; end if;
  select * into strict a from sectalk_private.st_v6_export_objects where id=p_artifact;
  if p_mode='read' and not a.envelope_required then return jsonb_build_object('legacy',true); end if;
  select * into state from sectalk_private.st_v7_tenant_key_state where workspace=space;
  if state.destroyed_at is not null then return null; end if;
  if p_mode='read' then
    select * into e from sectalk_private.st_v7_artifact_envelopes where artifact=p_artifact and workspace=space;
    if e.artifact is null then return null; end if;
  end if;
  select * into k from sectalk_private.st_v7_tenant_key_versions where workspace=space and version=
    case when p_mode='read' then e.key_version else state.current_version end;
  if k.version is null and state.workspace is not null then return null; end if;
  return jsonb_build_object('workspace',space,'kind',a.kind,'sha256',a.sha256,'bytes',a.bytes,
    'version',k.version,'custody',k.custody,'ref',k.provider_ref,'wrapped',k.wrapped,
    'wrapped_dek',e.wrapped_dek,'nonce',e.nonce,'tag',e.tag);
end $$;

create function public.st_v7_provision_export_key(p_ticket uuid,p_artifact uuid,p_wrapped text)
returns boolean language plpgsql security definer set search_path='' as $$
declare space uuid:=sectalk_private.st_v7_export_key_workspace(p_ticket,p_artifact,'write'); owner_id uuid;
begin
  if space is null then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||space::text,0));
  if exists(select 1 from sectalk_private.st_v7_tenant_key_state where workspace=space) then return false; end if;
  insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values(space,1);
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,wrapped) values(space,1,'managed',p_wrapped);
  select actor_id into strict owner_id from sectalk_private.st_v6_export_objects where id=p_artifact;
  insert into sectalk_private.st_v7_tenant_key_audit(workspace,actor,event,version)
    values(space,owner_id,'provisioned',1);
  return true;
end $$;

create function public.st_v7_bind_export_envelope(p_ticket uuid,p_artifact uuid,p_version integer,p_key text,p_nonce text,p_tag text)
returns boolean language plpgsql security definer set search_path='' as $$
declare space uuid:=sectalk_private.st_v7_export_key_workspace(p_ticket,p_artifact,'write');
begin
  if space is null then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||space::text,0));
  if not exists(select 1 from sectalk_private.st_v7_tenant_key_state s join sectalk_private.st_v7_tenant_key_versions k
    on k.workspace=s.workspace where s.workspace=space and s.destroyed_at is null and k.version=p_version) then return false; end if;
  update sectalk_private.st_v6_export_objects set envelope_required=true
    where id=p_artifact and not ready and not envelope_required;
  if not found then return false; end if;
  insert into sectalk_private.st_v7_artifact_envelopes(artifact,workspace,key_version,wrapped_dek,nonce,tag)
    values(p_artifact,space,p_version,p_key,p_nonce,p_tag);
  return true;
end $$;

-- Legacy ready objects retain their historical format. Newly finalized managed objects must carry an envelope.
create or replace function public.st_v6_finish_export_object(p_artifact uuid)
returns boolean language sql security definer set search_path='' as $$
  with updated as (
    update sectalk_private.st_v6_export_objects a set ready=true,expires_at=clock_timestamp()+interval '24 hours'
    where a.id=p_artifact and not a.ready and a.expires_at>clock_timestamp()
      and (a.kind not in ('compliance','evidence') or (a.envelope_required and exists(
        select 1 from sectalk_private.st_v7_artifact_envelopes e where e.artifact=a.id)))
      and exists(select 1 from storage.objects o where o.bucket_id='sectalk-exports' and o.name=a.id::text)
    returning 1
  ) select exists(select 1 from updated)
$$;

create function public.st_v7_tenant_key_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_tenant_key_role(p_workspace);
begin
  if access not in ('owner','admin') then return jsonb_build_object('access',access); end if;
  return jsonb_build_object('access',access,
    'enterprise',coalesce((sectalk_private.st_v7_workspace_entitlements(p_workspace)).plan='enterprise',false),
    'active',(select jsonb_build_object('version',s.current_version,'destroyed_at',s.destroyed_at,'custody',k.custody)
      from sectalk_private.st_v7_tenant_key_state s left join sectalk_private.st_v7_tenant_key_versions k
      on (k.workspace,k.version)=(s.workspace,s.current_version) where s.workspace=p_workspace),
    'reviewer',access='admin' and exists(select 1 from sectalk_private.st_v7_tenant_destroy_reviewers r
      where r.workspace=p_workspace and r.actor=auth.uid()),
    'can_request_destroy',access='owner' and exists(select 1 from sectalk_private.st_v7_tenant_destroy_reviewers r
      where r.workspace=p_workspace and sectalk_private.st_v2_role(p_workspace,r.actor)='admin')
      and exists(select 1 from sectalk_private.st_v7_tenant_key_state s where s.workspace=p_workspace and s.destroyed_at is null),
    'pending',(select jsonb_build_object('id',d.id,'reason',d.reason,'version',d.version)
      from sectalk_private.st_v7_tenant_key_destroy d where d.workspace=p_workspace and d.result is null),
    'audit',coalesce((select jsonb_agg(to_jsonb(x) order by x.id desc) from (
      select a.id,a.event,a.version,a.reason,a.occurred_at from sectalk_private.st_v7_tenant_key_audit a
      where a.workspace=p_workspace order by a.id desc limit 30) x),'[]'::jsonb));
end $$;

create function public.st_v7_begin_tenant_key_rotation(p_workspace uuid,p_custody text,p_reason text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare key_state sectalk_private.st_v7_tenant_key_state; key_ticket uuid; note text:=btrim(p_reason); version integer;
begin
  if sectalk_private.st_v7_tenant_key_role(p_workspace)<>'owner'
    or p_custody='byok' and (sectalk_private.st_v7_workspace_entitlements(p_workspace)).plan is distinct from 'enterprise' then
    raise exception 'Fresh and entitled workspace owner verification required' using errcode='42501'; end if;
  if p_custody is null or p_custody not in ('managed','byok') or note is null or char_length(note) not between 15 and 240 then
    raise exception 'Choose custody and enter an audit reason' using errcode='22023'; end if;
  perform sectalk_private.limit_action('v7_rotate_tenant_key',8);
  select * into key_state from sectalk_private.st_v7_tenant_key_state where workspace=p_workspace;
  if key_state.destroyed_at is not null then raise exception 'Destroyed keys cannot be recreated' using errcode='PT409'; end if;
  version:=coalesce(key_state.current_version,0);
  delete from sectalk_private.st_v7_tenant_rotation_tickets where expires_at<statement_timestamp();
  insert into sectalk_private.st_v7_tenant_rotation_tickets(workspace,actor,native_session,custody,previous_version,reason)
    values(p_workspace,auth.uid(),(auth.jwt()->>'session_id')::uuid,p_custody,version,note) returning id into key_ticket;
  return jsonb_build_object('ticket',key_ticket,'version',version+1);
end $$;

create function public.st_v7_commit_tenant_key_rotation(p_ticket uuid,p_actor uuid,p_wrapped text,p_ref text)
returns boolean language plpgsql security definer set search_path='' as $$
declare t sectalk_private.st_v7_tenant_rotation_tickets; state sectalk_private.st_v7_tenant_key_state;
begin
  delete from sectalk_private.st_v7_tenant_rotation_tickets where id=p_ticket and actor=p_actor
    and expires_at>statement_timestamp() returning * into t;
  if t.id is null then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||t.workspace::text,0));
  select * into state from sectalk_private.st_v7_tenant_key_state where workspace=t.workspace;
  if state.destroyed_at is not null or coalesce(state.current_version,0)<>t.previous_version
    or sectalk_private.st_v2_role(t.workspace,t.actor) is distinct from 'owner'
    or sectalk_private.st_v2_active(t.actor) is not true
    or not exists(select 1 from auth.sessions s where s.id=t.native_session and s.user_id=t.actor
      and s.aal='aal2' and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
      and exists(select 1 from auth.mfa_factors f where f.id=s.factor_id and f.user_id=s.user_id
        and f.status='verified' and f.factor_type='totp')
      and exists(select 1 from auth.mfa_amr_claims a where a.session_id=s.id and a.authentication_method='totp'
        and a.updated_at>statement_timestamp()-interval '5 minutes'))
    or t.custody='byok' and (sectalk_private.st_v7_workspace_entitlements(t.workspace)).plan is distinct from 'enterprise'
  then return false; end if;
  insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values(t.workspace,t.previous_version+1)
    on conflict(workspace) do update set current_version=excluded.current_version;
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,provider_ref,wrapped)
    values(t.workspace,t.previous_version+1,t.custody,p_ref,p_wrapped);
  insert into sectalk_private.st_v7_tenant_key_audit(workspace,actor,event,version,reason)
    values(t.workspace,t.actor,'rotated',t.previous_version+1,t.reason);
  return true;
end $$;

create function public.st_v7_request_tenant_key_destroy(p_workspace uuid,p_confirmation text,p_reason text)
returns uuid language plpgsql security definer set search_path='' as $$
declare task uuid; ver integer; note text:=btrim(p_reason);
begin
  if sectalk_private.st_v7_tenant_key_role(p_workspace)<>'owner' or not exists(
    select 1 from sectalk_private.st_v7_tenant_destroy_reviewers q
    where q.workspace=p_workspace and sectalk_private.st_v2_role(p_workspace,q.actor)='admin')
  then raise exception 'Destruction requires a verified owner and assigned independent reviewer' using errcode='42501'; end if;
  if p_confirmation is distinct from p_workspace::text or note is null or char_length(note) not between 15 and 240 then
    raise exception 'Confirm the exact workspace ID and enter the reason' using errcode='22023'; end if;
  perform sectalk_private.limit_action('v7_request_tenant_key_destroy',4);
  select current_version into ver from sectalk_private.st_v7_tenant_key_state where workspace=p_workspace and destroyed_at is null;
  if ver is null then raise exception 'There is no active protected key to destroy' using errcode='PT409'; end if;
  insert into sectalk_private.st_v7_tenant_key_destroy(workspace,requester,reason,version)
    values(p_workspace,auth.uid(),note,ver) returning id into task;
  insert into sectalk_private.st_v7_tenant_key_audit(workspace,actor,event,version,reason)
    values(p_workspace,auth.uid(),'destroy_requested',ver,note);
  return task;
end $$;

create function public.st_v7_decide_tenant_key_destroy(p_request uuid,p_approve boolean,p_confirmation text,p_reason text)
returns text language plpgsql security definer set search_path='' as $$
declare task sectalk_private.st_v7_tenant_key_destroy; outcome text:='rejected'; note text:=btrim(p_reason);
begin
  select * into task from sectalk_private.st_v7_tenant_key_destroy where id=p_request;
  if task.id is null or task.requester=auth.uid() or sectalk_private.st_v7_tenant_key_role(task.workspace)<>'admin'
    or not exists(select 1 from sectalk_private.st_v7_tenant_destroy_reviewers q where q.workspace=task.workspace and q.actor=auth.uid())
    then raise exception 'Fresh independent reviewer verification required' using errcode='42501'; end if;
  if p_approve is null or p_confirmation is distinct from task.workspace::text or note is null or char_length(note) not between 15 and 240
    then raise exception 'Confirm the exact workspace ID and enter the decision reason' using errcode='22023'; end if;
  select * into strict task from sectalk_private.st_v7_tenant_key_destroy where id=p_request for update;
  if task.result is not null then
    if task.reviewer=auth.uid() and p_approve=(task.result='destroyed') then return task.result; end if;
    raise exception 'This request has already been decided' using errcode='PT409';
  end if;
  perform sectalk_private.limit_action('v7_review_tenant_key_destroy',4);
  if p_approve then
    perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||task.workspace::text,0));
    perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||task.workspace::text,0));
    perform 1 from sectalk_private.st_v7_tenant_destroy_reviewers q
      where q.workspace=task.workspace and q.actor=auth.uid() for share;
    if not found or sectalk_private.st_v2_role(task.workspace,task.requester) is distinct from 'owner'
      or sectalk_private.st_v2_active(task.requester) is not true
      or task.requested_at<=statement_timestamp()-interval '24 hours'
      or not exists(select 1 from sectalk_private.st_v7_tenant_key_state s where s.workspace=task.workspace
        and s.current_version=task.version and s.destroyed_at is null)
      or exists(select 1 from sectalk_private.st_v7_tenant_key_versions k where k.workspace=task.workspace and k.custody='byok')
      or exists(select 1 from sectalk_private.st_v6_workspace_holds h where h.workspace_id=task.workspace and h.released_at is null)
      or exists(select 1 from sectalk_private.st_v7_compliance_cases c where c.workspace_id=task.workspace and c.ticket_until>now())
      or exists(select 1 from sectalk_private.st_v7_evidence_operations o join sectalk_private.st_v7_compliance_cases c on c.id=o.case_id
        where c.workspace_id=task.workspace and o.expires_at>now()) then
      raise exception 'Key history changed, evidence is protected, or external key destruction is required' using errcode='PT409';
    end if;
    delete from sectalk_private.st_v7_tenant_key_versions where workspace=task.workspace;
    update sectalk_private.st_v7_tenant_key_state set destroyed_at=clock_timestamp() where workspace=task.workspace;
    outcome:='destroyed';
  end if;
  update sectalk_private.st_v7_tenant_key_destroy set reviewer=auth.uid(),result=outcome,
    decision_reason=note,decided_at=clock_timestamp() where id=p_request;
  insert into sectalk_private.st_v7_tenant_key_audit(workspace,actor,event,version,reason)
    values(task.workspace,auth.uid(),outcome,task.version,note);
  return outcome;
end $$;

revoke all on function sectalk_private.st_v7_tenant_key_role(uuid),sectalk_private.st_v7_export_key_workspace(uuid,uuid,text),
  public.st_v7_export_key_context(uuid,uuid,text),public.st_v7_provision_export_key(uuid,uuid,text),
  public.st_v7_bind_export_envelope(uuid,uuid,integer,text,text,text),public.st_v7_tenant_key_status(uuid),
  public.st_v7_begin_tenant_key_rotation(uuid,text,text),public.st_v7_commit_tenant_key_rotation(uuid,uuid,text,text),
  public.st_v7_request_tenant_key_destroy(uuid,text,text),public.st_v7_decide_tenant_key_destroy(uuid,boolean,text,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_export_key_context(uuid,uuid,text),public.st_v7_provision_export_key(uuid,uuid,text),
  public.st_v7_bind_export_envelope(uuid,uuid,integer,text,text,text),public.st_v7_commit_tenant_key_rotation(uuid,uuid,text,text)
  to service_role;
grant execute on function public.st_v7_tenant_key_status(uuid),public.st_v7_begin_tenant_key_rotation(uuid,text,text),
  public.st_v7_request_tenant_key_destroy(uuid,text,text),public.st_v7_decide_tenant_key_destroy(uuid,boolean,text,text) to authenticated;

notify pgrst,'reload schema';
commit;
