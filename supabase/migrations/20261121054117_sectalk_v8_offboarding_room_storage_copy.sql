begin;

create table sectalk_private.st_v8_offboarding_room_storage_copy_tickets (
  id uuid primary key default gen_random_uuid(),
  plan uuid not null,
  workspace uuid not null,
  export_id uuid not null,
  room uuid not null,
  file uuid not null,
  actor uuid not null,
  native_session uuid not null,
  expires_at timestamptz not null default clock_timestamp()+interval '45 seconds'
);
create index st_v8_offboarding_room_storage_copy_expiry on sectalk_private.st_v8_offboarding_room_storage_copy_tickets(expires_at);
create table sectalk_private.st_v8_offboarding_room_storage_copy_receipts (
  id uuid primary key default gen_random_uuid(),
  plan uuid not null,
  workspace uuid not null,
  export_id uuid not null,
  room uuid not null,
  file uuid not null,
  actor uuid not null,
  object_id uuid not null,
  object_version text not null,
  bytes integer not null check(bytes between 1 and 4194304),
  sha256 text not null check(sha256~'^[0-9a-f]{64}$'),
  verified_at timestamptz not null default clock_timestamp(),
  unique(plan,export_id,room,file)
);
create trigger st_v8_offboarding_room_storage_copy_immutable before update or delete
  on sectalk_private.st_v8_offboarding_room_storage_copy_receipts for each row
  execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_room_storage_copy_tickets enable row level security;
alter table sectalk_private.st_v8_offboarding_room_storage_copy_receipts enable row level security;
revoke all on sectalk_private.st_v8_offboarding_room_storage_copy_tickets,sectalk_private.st_v8_offboarding_room_storage_copy_receipts
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_offboarding_room_storage_source(
  p sectalk_private.st_v8_offboarding_storage_plans,p_workspace uuid,p_export uuid,p_room uuid,p_file uuid
) returns jsonb language sql stable set search_path='' set timezone='UTC' as $$
  select reviewed.item
  from sectalk_private.st_v8_content_exports c
  join sectalk_private.st_v8_content_export_entries e
    on (e.export_id,e.kind,e.scope_id,e.record_id)=(c.id,'room_file',p_room,p_file)
  cross join lateral sectalk_private.st_v8_offboarding_room_file_records(p_workspace,p.requester,p.reviewer,p_room,p_file) live
  cross join lateral (select i as item from jsonb_array_elements(p.snapshot->'items') i
    where (i->>'name',i->>'status')=(p_workspace::text||'/rooms/'||p_room::text||'/'||p_file::text,'published')) reviewed
  where (c.id,c.workspace,c.requester,c.reviewer)=(p_export,p_workspace,p.requester,p.reviewer)
    and c.include_room_files and c.withdrawn_at is null and c.expires_at>statement_timestamp()
    and live.item->>'roomKind'='public' and live.item->>'classification' in ('public','internal')
    and e.sha256=encode(sha256(convert_to(live.item::text,'UTF8')),'hex')
    and live.item->>'sha256'=reviewed.item->>'fingerprint'
    and live.item->>'bytes'=reviewed.item->>'registered_bytes';
$$;

create function public.st_v8_begin_offboarding_room_storage_copy(p_room uuid,p_plan uuid,p_export uuid,p_file uuid)
returns uuid language plpgsql security definer set search_path='' as $$
declare p sectalk_private.st_v8_offboarding_storage_plans; tenant uuid; token uuid; context jsonb;
begin
  context:=public.st_v8_scoped_file_context('room',p_room);
  if context->>'access' is distinct from 'allowed' then raise insufficient_privilege; end if;
  select r.workspace_id into tenant from public.st_v6_rooms r where r.id=p_room;
  p:=sectalk_private.st_v8_offboarding_current_storage_plan(tenant,p_plan);
  if p.id is null or p.requester is distinct from auth.uid()
    or public.st_v8_offboarding_room_file_access(p_room,p_export,p_file,null) is null
    or sectalk_private.st_v8_offboarding_room_storage_source(p,tenant,p_export,p_room,p_file) is null then
    raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_offboarding_room_storage_copy',20);
  delete from sectalk_private.st_v8_offboarding_room_storage_copy_tickets where expires_at<=clock_timestamp();
  insert into sectalk_private.st_v8_offboarding_room_storage_copy_tickets(plan,workspace,export_id,room,file,actor,native_session)
    values(p_plan,tenant,p_export,p_room,p_file,auth.uid(),(context->>'session')::uuid) returning id into token;
  return token;
end $$;

create function public.st_v8_finish_offboarding_room_storage_copy(p_ticket uuid,p_sha256 text,p_bytes integer)
returns uuid language plpgsql security definer set search_path='' as $$
declare t sectalk_private.st_v8_offboarding_room_storage_copy_tickets; p sectalk_private.st_v8_offboarding_storage_plans;
  reviewed jsonb; current_file jsonb; receipt uuid;
begin
  if (p_sha256~'^[0-9a-f]{64}$') is not true or p_bytes is null or p_bytes not between 1 and 4194304 then return null; end if;
  delete from sectalk_private.st_v8_offboarding_room_storage_copy_tickets x where x.id=p_ticket and x.expires_at>clock_timestamp()
    returning * into t;
  if t.id is null then return null; end if;
  perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-workspace-hold:'||t.workspace::text,0));
  perform 1 from public.st_v2_workspaces where id=t.workspace for share;
  perform 1 from public.st_v6_rooms r where (r.workspace_id,r.id)=(t.workspace,t.room) for share;
  if not found then return null; end if;
  perform 1 from sectalk_private.st_v6_room_files f where (f.workspace,f.room,f.id)=(t.workspace,t.room,t.file) for share;
  if not found then return null; end if;
  p:=sectalk_private.st_v8_offboarding_current_storage_plan(t.workspace,t.plan);
  if p.id is null or p.requester is distinct from t.actor or t.expires_at<=clock_timestamp() then return null; end if;
  perform 1 from sectalk_private.st_v8_content_exports c where (c.id,c.workspace,c.requester,c.reviewer)=
    (t.export_id,t.workspace,p.requester,p.reviewer) and c.withdrawn_at is null and c.expires_at>clock_timestamp() for share;
  if not found then return null; end if;
  reviewed:=sectalk_private.st_v8_offboarding_room_storage_source(p,t.workspace,t.export_id,t.room,t.file);
  if reviewed is null or reviewed->>'registered_bytes' is distinct from p_bytes::text
    or reviewed->>'fingerprint' is distinct from p_sha256 then return null; end if;
  perform 1 from storage.objects o where (o.bucket_id,o.name,o.id::text,o.version)=(
    'sectalk-workspace-files',reviewed->>'name',reviewed->>'object_id',reviewed->>'version') for share;
  if not found then return null; end if;
  perform 1 from auth.sessions n join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
    join auth.mfa_amr_claims a on a.session_id=n.id and a.authentication_method='totp'
    where (n.id,n.user_id)=(t.native_session,t.actor) and n.aal='aal2' and f.status='verified' and f.factor_type='totp'
      and a.updated_at>clock_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp()
    for share of n,f,a;
  if not found or t.expires_at<=clock_timestamp() or p.captured_at<=clock_timestamp()-interval '24 hours'
    or exists(select 1 from sectalk_private.st_v7_account_lockdowns l
      where l.user_id=t.actor and l.released_at is null)
    or exists(select 1 from sectalk_private.st_v8_workspace_standard_room_sso policy where policy.workspace=t.workspace
      and not exists(select 1 from sectalk_private.st_v7_workspace_sso_sessions session
        join sectalk_private.st_v7_workspace_sso setup on setup.workspace=session.workspace
        where (session.workspace,session.principal,session.session)=(t.workspace,t.actor,t.native_session)
          and (session.protocol,session.provider)=(policy.protocol,policy.provider)
          and (setup.protocol,setup.provider)=(policy.protocol,policy.provider)
          and sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol)=setup.provider))
    then return null; end if;
  current_file:=public.st_v8_scoped_file_command('room',t.room,t.actor,t.native_session,'get',t.file,null,null,null);
  if current_file is null or current_file->>'workspace' is distinct from t.workspace::text
    or current_file->>'size_bytes' is distinct from p_bytes::text or current_file->>'sha256' is distinct from p_sha256
    then return null; end if;
  insert into sectalk_private.st_v8_offboarding_room_storage_copy_receipts(
    plan,workspace,export_id,room,file,actor,object_id,object_version,bytes,sha256)
    values(t.plan,t.workspace,t.export_id,t.room,t.file,t.actor,(reviewed->>'object_id')::uuid,reviewed->>'version',p_bytes,p_sha256)
    on conflict do nothing;
  select x.id into receipt from sectalk_private.st_v8_offboarding_room_storage_copy_receipts x
    where (x.plan,x.export_id,x.room,x.file,x.object_id::text,x.object_version,x.bytes,x.sha256)=
      (t.plan,t.export_id,t.room,t.file,reviewed->>'object_id',reviewed->>'version',p_bytes,p_sha256);
  return receipt;
end $$;

create function public.st_v8_offboarding_room_storage_copies(p_workspace uuid,p_plan uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare p sectalk_private.st_v8_offboarding_storage_plans;
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v7_admin_fresh(),false) then raise insufficient_privilege; end if;
  p:=sectalk_private.st_v8_offboarding_current_storage_plan(p_workspace,p_plan);
  if p.id is null or auth.uid() not in (p.requester,p.reviewer)
    or not coalesce(sectalk_private.st_v8_file_sso_allows(p_workspace),false) then raise insufficient_privilege; end if;
  return jsonb_build_object('verifiedCopies',coalesce((select jsonb_agg(jsonb_build_object('id',x.id,'room',x.room,
    'file',x.file,'bytes',x.bytes,'sha256',x.sha256,'verifiedAt',x.verified_at) order by x.room,x.file)
    from sectalk_private.st_v8_offboarding_room_storage_copy_receipts x
    cross join lateral (select sectalk_private.st_v8_offboarding_room_storage_source(
      p,p_workspace,x.export_id,x.room,x.file) as item offset 0) reviewed
    where (x.workspace,x.plan)=(p_workspace,p_plan) and sectalk_private.st_v8_standard_room_session_allowed(x.room)
      and (x.object_id::text,x.object_version,x.bytes::text,x.sha256)=
        (reviewed.item->>'object_id',reviewed.item->>'version',reviewed.item->>'registered_bytes',reviewed.item->>'fingerprint')),'[]'));
end $$;

revoke all on function sectalk_private.st_v8_offboarding_room_storage_source(sectalk_private.st_v8_offboarding_storage_plans,uuid,uuid,uuid,uuid),
  public.st_v8_begin_offboarding_room_storage_copy(uuid,uuid,uuid,uuid),public.st_v8_finish_offboarding_room_storage_copy(uuid,text,integer),
  public.st_v8_offboarding_room_storage_copies(uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_begin_offboarding_room_storage_copy(uuid,uuid,uuid,uuid),
  public.st_v8_offboarding_room_storage_copies(uuid,uuid) to authenticated;
grant execute on function public.st_v8_finish_offboarding_room_storage_copy(uuid,text,integer) to service_role;
notify pgrst,'reload schema';
commit;
