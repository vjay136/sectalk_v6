begin;

create table sectalk_private.st_v8_provider_erasure_tickets (
  id uuid primary key default gen_random_uuid(),
  request uuid not null references sectalk_private.st_v8_offboarding_requests on delete cascade,
  workspace uuid not null,
  actor uuid not null,
  native_session uuid not null,
  version integer not null,
  provider_pin text not null check(provider_pin~'^[A-Za-z0-9_-]{43}$'),
  expires_at timestamptz not null default clock_timestamp()+interval '45 seconds'
);
create index st_v8_provider_erasure_ticket_expiry on sectalk_private.st_v8_provider_erasure_tickets(expires_at);
create table sectalk_private.st_v8_provider_erasure_receipts (
  request uuid not null,
  workspace uuid not null,
  actor uuid not null,
  version integer not null check(version>0),
  provider_pin text not null check(provider_pin~'^[A-Za-z0-9_-]{43}$'),
  provider_event uuid not null unique,
  provider_event_time timestamptz not null,
  provider_event_sha256 text not null check(provider_event_sha256~'^[a-f0-9]{64}$'),
  recorded_at timestamptz not null default clock_timestamp(),
  primary key(request,version)
);
create trigger st_v8_immutable_provider_erasure_receipt before update or delete on sectalk_private.st_v8_provider_erasure_receipts
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_provider_erasure_tickets enable row level security;
alter table sectalk_private.st_v8_provider_erasure_receipts enable row level security;
revoke all on sectalk_private.st_v8_provider_erasure_tickets,sectalk_private.st_v8_provider_erasure_receipts
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_provider_erasure_reviewer(r sectalk_private.st_v8_offboarding_requests,p_actor uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce(r.state='read_only' and r.integration_shutdown is not null and r.reviewer=p_actor and r.requester<>p_actor
    and sectalk_private.st_v8_offboarding_role(r.workspace,r.requester)='owner'
    and sectalk_private.st_v8_offboarding_role(r.workspace,p_actor)='reviewer'
    and exists(select 1 from sectalk_private.st_v7_tenant_destroy_reviewers d where (d.workspace,d.actor)=(r.workspace,p_actor))
    and not sectalk_private.st_v8_offboarding_holds(r.workspace),false);
$$;

create function public.st_v8_tenant_provider_erasure_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare r sectalk_private.st_v8_offboarding_requests; actor uuid:=auth.uid();
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false) or not sectalk_private.st_v7_admin_fresh() then return null; end if;
  select * into r from sectalk_private.st_v8_offboarding_requests where workspace=p_workspace and state='read_only'
    and integration_shutdown is not null;
  if r.id is null or not ((actor=r.requester and sectalk_private.st_v8_offboarding_role(p_workspace,actor)='owner')
    or (actor=r.reviewer and sectalk_private.st_v8_offboarding_role(p_workspace,actor)='reviewer')) then return null; end if;
  return jsonb_build_object('canVerify',sectalk_private.st_v8_provider_erasure_reviewer(r,actor),
    'held',sectalk_private.st_v8_offboarding_holds(p_workspace),'sourceDeletion','unverified','backupErasure','unverified',
    'versions',coalesce((select jsonb_agg(jsonb_build_object('version',k.version,'eventTime',e.provider_event_time,
       'eventDigest',e.provider_event_sha256) order by k.version)
      from sectalk_private.st_v7_tenant_key_versions k left join sectalk_private.st_v8_provider_erasure_receipts e
        on (e.request,e.version)=(r.id,k.version)
      where k.workspace=p_workspace and k.custody='byok' and k.wrapped~'^external_v2_[A-Za-z0-9_-]{43}_[A-Za-z0-9_-]{43}$'),'[]'::jsonb));
end $$;

create function public.st_v8_begin_tenant_provider_erasure(p_workspace uuid,p_version integer,p_confirmation text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare r sectalk_private.st_v8_offboarding_requests; k sectalk_private.st_v7_tenant_key_versions;
  actor uuid:=auth.uid(); token uuid;
begin
  if p_workspace is null or p_version is null or p_version<1 or p_confirmation is distinct from p_workspace::text
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false) or not sectalk_private.st_v7_admin_fresh() then
    raise insufficient_privilege; end if;
  select * into r from sectalk_private.st_v8_offboarding_requests where workspace=p_workspace and state='read_only';
  if not sectalk_private.st_v8_provider_erasure_reviewer(r,actor) then raise insufficient_privilege; end if;
  select * into k from sectalk_private.st_v7_tenant_key_versions where (workspace,version)=(p_workspace,p_version)
    and custody='byok' and wrapped~'^external_v2_[A-Za-z0-9_-]{43}_[A-Za-z0-9_-]{43}$';
  if k.version is null then raise exception 'Pinned external key version unavailable' using errcode='PT409'; end if;
  if exists(select 1 from sectalk_private.st_v8_provider_erasure_receipts e where (e.request,e.version)=(r.id,k.version)) then
    return jsonb_build_object('verified',true); end if;
  perform sectalk_private.limit_action('v8_provider_erasure_verify',12);
  delete from sectalk_private.st_v8_provider_erasure_tickets where expires_at<=statement_timestamp();
  insert into sectalk_private.st_v8_provider_erasure_tickets(request,workspace,actor,native_session,version,provider_pin)
    values(r.id,p_workspace,actor,(auth.jwt()->>'session_id')::uuid,k.version,substr(k.wrapped,13,43)) returning id into token;
  return jsonb_build_object('ticket',token,'version',k.version,'marker',k.wrapped,'reference',k.provider_ref,'stagedAt',r.staged_at);
end $$;

create function public.st_v8_commit_tenant_provider_erasure(p_ticket uuid,p_actor uuid,p_event uuid,p_event_time timestamptz,p_sha256 text)
returns boolean language plpgsql security definer set search_path='' as $$
declare t sectalk_private.st_v8_provider_erasure_tickets; r sectalk_private.st_v8_offboarding_requests;
begin
  if p_event is null or p_event_time is null or (p_sha256~'^[a-f0-9]{64}$') is not true then return false; end if;
  delete from sectalk_private.st_v8_provider_erasure_tickets where id=p_ticket and actor=p_actor
    and expires_at>clock_timestamp() returning * into t;
  if t.id is null then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||t.workspace::text,0));
  perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-workspace-hold:'||t.workspace::text,0));
  select * into r from sectalk_private.st_v8_offboarding_requests where (id,workspace)=(t.request,t.workspace);
  if not sectalk_private.st_v8_provider_erasure_reviewer(r,t.actor) or p_event_time<r.staged_at
    or p_event_time>clock_timestamp()+interval '30 seconds' or t.expires_at<=clock_timestamp()
    or exists(select 1 from sectalk_private.st_v7_account_lockdowns where user_id=t.actor and released_at is null)
    or not exists(select 1 from sectalk_private.st_v7_tenant_key_versions k where (k.workspace,k.version)=(t.workspace,t.version)
      and k.custody='byok' and substr(k.wrapped,13,43)=t.provider_pin)
    or not exists(select 1 from auth.sessions s join auth.mfa_factors f on f.id=s.factor_id and f.user_id=s.user_id
      join auth.mfa_amr_claims a on a.session_id=s.id and a.authentication_method='totp'
      where (s.id,s.user_id)=(t.native_session,t.actor) and s.aal='aal2' and f.factor_type='totp' and f.status='verified'
      and a.updated_at>clock_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>clock_timestamp()) then return false; end if;
  insert into sectalk_private.st_v8_provider_erasure_receipts(request,workspace,actor,version,provider_pin,provider_event,
    provider_event_time,provider_event_sha256)
    values(t.request,t.workspace,t.actor,t.version,t.provider_pin,p_event,p_event_time,p_sha256) on conflict do nothing;
  return exists(select 1 from sectalk_private.st_v8_provider_erasure_receipts e
    where (e.request,e.version,e.provider_pin,e.provider_event,e.provider_event_sha256)=
      (t.request,t.version,t.provider_pin,p_event,p_sha256));
end $$;

revoke all on function sectalk_private.st_v8_provider_erasure_reviewer(sectalk_private.st_v8_offboarding_requests,uuid),
  public.st_v8_tenant_provider_erasure_status(uuid),public.st_v8_begin_tenant_provider_erasure(uuid,integer,text),
  public.st_v8_commit_tenant_provider_erasure(uuid,uuid,uuid,timestamptz,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_tenant_provider_erasure_status(uuid),
  public.st_v8_begin_tenant_provider_erasure(uuid,integer,text) to authenticated;
grant execute on function public.st_v8_commit_tenant_provider_erasure(uuid,uuid,uuid,timestamptz,text) to service_role;

commit;
