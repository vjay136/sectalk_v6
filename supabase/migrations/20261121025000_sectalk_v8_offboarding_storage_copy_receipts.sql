begin;

create table sectalk_private.st_v8_offboarding_storage_copy_tickets (
  id uuid primary key default gen_random_uuid(),
  plan uuid not null,
  workspace uuid not null,
  export_id uuid not null,
  file uuid not null,
  actor uuid not null,
  native_session uuid not null,
  expires_at timestamptz not null default clock_timestamp()+interval '45 seconds'
);
create index st_v8_offboarding_storage_copy_expiry on sectalk_private.st_v8_offboarding_storage_copy_tickets(expires_at);
create table sectalk_private.st_v8_offboarding_storage_copy_receipts (
  id uuid primary key default gen_random_uuid(),
  plan uuid not null,
  workspace uuid not null,
  export_id uuid not null,
  file uuid not null,
  actor uuid not null,
  object_id uuid not null,
  object_version text not null,
  bytes integer not null check(bytes>0),
  sha256 text not null check(sha256~'^[0-9a-f]{64}$'),
  verified_at timestamptz not null default clock_timestamp(),
  unique(plan,export_id,file)
);
create trigger st_v8_offboarding_storage_copy_receipt_immutable before update or delete
  on sectalk_private.st_v8_offboarding_storage_copy_receipts for each row
  execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_storage_copy_tickets enable row level security;
alter table sectalk_private.st_v8_offboarding_storage_copy_receipts enable row level security;
revoke all on sectalk_private.st_v8_offboarding_storage_copy_tickets,sectalk_private.st_v8_offboarding_storage_copy_receipts
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_offboarding_current_storage_plan(p_workspace uuid,p_plan uuid)
returns sectalk_private.st_v8_offboarding_storage_plans language plpgsql stable security definer set search_path='' as $$
declare p sectalk_private.st_v8_offboarding_storage_plans; snapshot jsonb;
begin
  select s.* into p from sectalk_private.st_v8_offboarding_requests r
    join lateral(select x.* from sectalk_private.st_v8_offboarding_storage_plans x where x.request=r.id
      order by x.captured_at desc,x.id desc limit 1) s on true
    where r.workspace=p_workspace and r.state='read_only' and r.integration_shutdown is not null
      and (s.id,s.requester,s.reviewer)=(p_plan,r.requester,r.reviewer) and s.reviewed_at is not null
      and s.captured_at>statement_timestamp()-interval '24 hours';
  if p.id is null or sectalk_private.st_v8_offboarding_role(p_workspace,p.requester) is distinct from 'owner'
    or sectalk_private.st_v8_offboarding_role(p_workspace,p.reviewer) is distinct from 'reviewer'
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then return null; end if;
  snapshot:=sectalk_private.st_v8_offboarding_storage_snapshot(p_workspace);
  if p.sha256 is distinct from encode(sha256(convert_to(snapshot::text,'UTF8')),'hex') then return null; end if;
  return p;
end $$;

create function public.st_v8_begin_offboarding_storage_copy(p_workspace uuid,p_plan uuid,p_export uuid,p_file uuid)
returns uuid language plpgsql security definer set search_path='' as $$
declare p sectalk_private.st_v8_offboarding_storage_plans; id uuid; context jsonb;
begin
  p:=sectalk_private.st_v8_offboarding_current_storage_plan(p_workspace,p_plan);
  if p.id is null or p.requester is distinct from auth.uid()
    or public.st_v8_offboarding_file_access(p_workspace,p_export,p_file) is null then raise insufficient_privilege; end if;
  context:=public.st_v8_scoped_file_context('workspace',p_workspace);
  if context->>'access' is distinct from 'allowed' then raise insufficient_privilege; end if;
  if not exists(select 1 from jsonb_array_elements(p.snapshot->'items') i
    where (i->>'name',i->>'status')=(p_workspace::text||'/'||p_file::text,'published')) then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_offboarding_storage_copy',20);
  delete from sectalk_private.st_v8_offboarding_storage_copy_tickets where expires_at<=clock_timestamp();
  insert into sectalk_private.st_v8_offboarding_storage_copy_tickets(plan,workspace,export_id,file,actor,native_session)
    values(p_plan,p_workspace,p_export,p_file,auth.uid(),(context->>'session')::uuid) returning st_v8_offboarding_storage_copy_tickets.id into id;
  return id;
end $$;

create function public.st_v8_finish_offboarding_storage_copy(p_ticket uuid,p_sha256 text,p_bytes integer)
returns uuid language plpgsql security definer set search_path='' as $$
declare t sectalk_private.st_v8_offboarding_storage_copy_tickets; p sectalk_private.st_v8_offboarding_storage_plans;
  reviewed jsonb; current_file jsonb; receipt uuid;
begin
  if (p_sha256~'^[0-9a-f]{64}$') is not true or p_bytes is null or p_bytes<1 then return null; end if;
  delete from sectalk_private.st_v8_offboarding_storage_copy_tickets x where x.id=p_ticket and x.expires_at>clock_timestamp()
    returning * into t;
  if t.id is null then return null; end if;
  perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-workspace-hold:'||t.workspace::text,0));
  perform 1 from public.st_v2_workspaces where id=t.workspace for share;
  p:=sectalk_private.st_v8_offboarding_current_storage_plan(t.workspace,t.plan);
  if p.id is null or p.requester is distinct from t.actor or t.expires_at<=clock_timestamp() then return null; end if;
  select i into reviewed from jsonb_array_elements(p.snapshot->'items') i
    where (i->>'name',i->>'status')=(t.workspace::text||'/'||t.file::text,'published');
  if reviewed is null or reviewed->>'registered_bytes' is distinct from p_bytes::text
    or reviewed->>'fingerprint' is distinct from encode(sectalk_private.st_v6_workspace_file_fingerprint(t.workspace,p_sha256),'hex')
    or exists(select 1 from sectalk_private.st_v6_malware_hashes m where m.sha256=decode(p_sha256,'hex'))
    or public.st_v7_upload_digest_blocked(p_sha256) then return null; end if;
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
    where l.user_id=t.actor and l.released_at is null) then return null; end if;
  current_file:=public.st_v8_scoped_file_command('workspace',t.workspace,t.actor,t.native_session,'get',t.file,null,null,null);
  if current_file is null or current_file->>'fingerprint' is distinct from reviewed->>'fingerprint' then return null; end if;
  perform 1 from sectalk_private.st_v8_content_exports c
    join sectalk_private.st_v8_content_export_entries e on (e.export_id,e.kind,e.scope_id,e.record_id)=(c.id,'workspace_file',t.workspace,t.file)
    cross join lateral sectalk_private.st_v8_offboarding_file_records(t.workspace,p.requester,p.reviewer,t.file) f
    where (c.id,c.workspace,c.requester,c.reviewer)=(t.export_id,t.workspace,p.requester,p.reviewer)
      and c.withdrawn_at is null and c.expires_at>clock_timestamp() and c.include_workspace_files
      and e.sha256=encode(sha256(convert_to(f.item::text,'UTF8')),'hex') for share of c;
  if not found then return null; end if;
  insert into sectalk_private.st_v8_offboarding_storage_copy_receipts(plan,workspace,export_id,file,actor,object_id,object_version,bytes,sha256)
    values(t.plan,t.workspace,t.export_id,t.file,t.actor,(reviewed->>'object_id')::uuid,reviewed->>'version',p_bytes,p_sha256)
    on conflict do nothing;
  select x.id into receipt from sectalk_private.st_v8_offboarding_storage_copy_receipts x
    where (x.plan,x.export_id,x.file,x.sha256)=(t.plan,t.export_id,t.file,p_sha256);
  return receipt;
end $$;

create function public.st_v8_offboarding_storage_copies(p_workspace uuid,p_plan uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare p sectalk_private.st_v8_offboarding_storage_plans;
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v7_admin_fresh(),false) then raise insufficient_privilege; end if;
  p:=sectalk_private.st_v8_offboarding_current_storage_plan(p_workspace,p_plan);
  if p.id is null or auth.uid() not in (p.requester,p.reviewer)
    or not coalesce(sectalk_private.st_v8_file_sso_allows(p_workspace),false) then raise insufficient_privilege; end if;
  return jsonb_build_object('verifiedCopies',coalesce((select jsonb_agg(jsonb_build_object('id',x.id,'file',x.file,
    'bytes',x.bytes,'sha256',x.sha256,'verifiedAt',x.verified_at) order by x.file) from sectalk_private.st_v8_offboarding_storage_copy_receipts x
    join sectalk_private.st_v8_content_exports c on c.id=x.export_id and c.withdrawn_at is null and c.expires_at>statement_timestamp()
    join sectalk_private.st_v8_content_export_entries e on (e.export_id,e.kind,e.scope_id,e.record_id)=(c.id,'workspace_file',x.workspace,x.file)
    cross join lateral sectalk_private.st_v8_offboarding_file_records(p_workspace,p.requester,p.reviewer,x.file) f
    where (x.workspace,x.plan)=(p_workspace,p_plan) and e.sha256=encode(sha256(convert_to(f.item::text,'UTF8')),'hex')
      and not exists(select 1 from sectalk_private.st_v6_malware_hashes m where m.sha256=decode(x.sha256,'hex'))
      and not public.st_v7_upload_digest_blocked(x.sha256)),'[]'));
end $$;

revoke all on function sectalk_private.st_v8_offboarding_current_storage_plan(uuid,uuid),
  public.st_v8_begin_offboarding_storage_copy(uuid,uuid,uuid,uuid),public.st_v8_finish_offboarding_storage_copy(uuid,text,integer),
  public.st_v8_offboarding_storage_copies(uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_begin_offboarding_storage_copy(uuid,uuid,uuid,uuid),
  public.st_v8_offboarding_storage_copies(uuid,uuid) to authenticated;
grant execute on function public.st_v8_finish_offboarding_storage_copy(uuid,text,integer) to service_role;
notify pgrst,'reload schema';
commit;
