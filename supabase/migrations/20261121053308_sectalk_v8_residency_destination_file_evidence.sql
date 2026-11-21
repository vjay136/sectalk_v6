begin;

create table sectalk_private.st_v8_residency_file_verifications (
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  approval uuid not null,
  kind text not null check(kind in ('workspace_file','room_file')),
  scope uuid not null,
  file uuid not null,
  object_id uuid not null,
  object_version text not null,
  object_updated_at timestamptz not null,
  manifest_sha256 text not null check(manifest_sha256~'^[0-9a-f]{64}$'),
  checked_at timestamptz not null default clock_timestamp(),
  primary key(workspace,approval,kind,scope,file,object_id,object_version,object_updated_at,manifest_sha256)
);
alter table sectalk_private.st_v8_residency_file_verifications enable row level security;
revoke all on sectalk_private.st_v8_residency_file_verifications from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_residency_file_snapshot(p_kind text,p_scope uuid,p_approval uuid,p_file uuid,p_actor uuid)
returns jsonb language sql stable set search_path='' as $$
  select jsonb_build_object('workspace',c.workspace,'manifest',c.manifest_sha256,'object',o.id,'version',o.version,
    'updatedAt',o.updated_at,'bytes',payload.data->'bytes','digest',case p_kind when 'room' then payload.data->>'sha256'
      else payload.data->>'fingerprint' end)
  from sectalk_private.st_v8_residency_workspace_claims c
  join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
  join sectalk_private.st_v8_residency_cells t on t.id=c.cell and t.retired_at is null and t.project_reference<>c.source_project
  join sectalk_private.st_v8_residency_content_admissions a on (a.cell,a.workspace,a.source_project,a.approval)=
    (c.cell,c.workspace,c.source_project,c.approval)
  join sectalk_private.st_v8_residency_staged_content s on (s.cell,s.workspace,s.source_project,s.approval)=
    (a.cell,a.workspace,a.source_project,a.approval)
  left join public.st_v6_rooms r on p_kind='room' and (r.workspace_id,r.id)=(c.workspace,p_scope)
  join storage.objects o on (o.bucket_id,o.name)=('sectalk-workspace-files',c.workspace::text||
    case p_kind when 'room' then '/rooms/'||r.id::text else '' end||'/'||p_file::text)
  cross join lateral jsonb_array_elements(s.records) x
  cross join lateral (select (x->>'json')::jsonb as data) payload
  where (c.approval,c.owner_id)=(p_approval,p_actor) and c.claimed_at is not null and c.manifest_sha256=a.manifest_sha256
    and least(c.expires_at,a.expires_at)>statement_timestamp()
    and sectalk_private.st_v8_offboarding_role(c.workspace,p_actor)='owner'
    and ((p_kind='workspace' and c.workspace=p_scope) or (p_kind='room' and r.id=p_scope and not r.archived
      and (r.kind,r.classification,r.encryption_mode)=('private','confidential','standard')))
    and (x->>'kind',x->>'scope',x->>'id')=(p_kind||'_file',p_scope::text,p_file::text)
    and x->>'sha256'=encode(sha256(convert_to(x->>'json','UTF8')),'hex')
    and o.version is not null and o.updated_at is not null and o.metadata->>'size'=payload.data->>'bytes';
$$;

create function public.st_v8_residency_file_verification_snapshot(p_kind text,p_scope uuid,p_approval uuid,p_file uuid)
returns jsonb language plpgsql stable security definer set search_path='' set timezone='UTC' as $$
declare item jsonb;
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
    or public.st_v8_scoped_file_context(p_kind,p_scope)->>'access' is distinct from 'allowed'
    then raise insufficient_privilege; end if;
  item:=sectalk_private.st_v8_residency_file_snapshot(p_kind,p_scope,p_approval,p_file,auth.uid());
  if item is null or not coalesce(sectalk_private.st_v8_organization_sso_allows((item->>'workspace')::uuid),false)
    then raise insufficient_privilege; end if;
  return item;
end $$;

create function public.st_v8_record_residency_file_verification(p_kind text,p_scope uuid,p_approval uuid,p_file uuid,
  p_actor uuid,p_session uuid,p_snapshot jsonb,p_sha256 text,p_bytes integer)
returns boolean language plpgsql security definer set search_path='' set timezone='UTC' as $$
declare current_item jsonb; current_file jsonb; workspace_id uuid;
begin
  if not coalesce(p_sha256~'^[0-9a-f]{64}$' and p_bytes between 1 and 4194304,false)
    or p_snapshot is null or octet_length(p_snapshot::text)>2048 then return false; end if;
  current_item:=sectalk_private.st_v8_residency_file_snapshot(p_kind,p_scope,p_approval,p_file,p_actor);
  if current_item is distinct from p_snapshot or current_item->'bytes' is distinct from to_jsonb(p_bytes) then return false; end if;
  workspace_id:=(current_item->>'workspace')::uuid;
  if current_item->>'digest' is distinct from (case when p_kind='workspace' then
    encode(sectalk_private.st_v6_workspace_file_fingerprint(workspace_id,p_sha256),'hex') else p_sha256 end) then return false; end if;

  perform 1 from auth.sessions n join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
    join auth.mfa_amr_claims amr on amr.session_id=n.id and amr.authentication_method='totp'
    where (n.id,n.user_id)=(p_session,p_actor) and n.aal='aal2' and f.status='verified' and f.factor_type='totp'
      and amr.updated_at>statement_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>statement_timestamp()
    for share of n,f,amr;
  if not found then return false; end if;
  current_file:=public.st_v8_scoped_file_command(p_kind,p_scope,p_actor,p_session,'get',p_file,null,null,null);
  if current_file is null or current_file->'size_bytes' is distinct from to_jsonb(p_bytes) or
    (current_file->>case when p_kind='workspace' then 'fingerprint' else 'sha256' end) is distinct from current_item->>'digest'
    or exists(select 1 from sectalk_private.st_v8_workspace_organization_sso policy where policy.workspace=workspace_id
      and not exists(select 1 from sectalk_private.st_v7_workspace_sso_sessions receipt
        join sectalk_private.st_v7_workspace_sso setup on setup.workspace=receipt.workspace
        where (receipt.workspace,receipt.principal,receipt.session)=(workspace_id,p_actor,p_session)
          and (receipt.protocol,receipt.provider)=(policy.protocol,policy.provider)
          and (setup.protocol,setup.provider)=(policy.protocol,policy.provider)
          and sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol)=setup.provider))
    then return false; end if;
  perform 1 from storage.objects o where (o.id,o.version,o.updated_at)=
    ((current_item->>'object')::uuid,current_item->>'version',(current_item->>'updatedAt')::timestamptz) for share;
  if not found then return false; end if;
  insert into sectalk_private.st_v8_residency_file_verifications(workspace,approval,kind,scope,file,object_id,object_version,
    object_updated_at,manifest_sha256) values(workspace_id,p_approval,p_kind||'_file',p_scope,p_file,
      (current_item->>'object')::uuid,current_item->>'version',(current_item->>'updatedAt')::timestamptz,current_item->>'manifest')
    on conflict do nothing;
  return true;
end $$;

alter function public.st_v8_residency_compare_destination(uuid,uuid) set schema sectalk_private;
revoke all on function sectalk_private.st_v8_residency_compare_destination(uuid,uuid) from public,anon,authenticated,service_role;
create function public.st_v8_residency_compare_destination(p_workspace uuid,p_approval uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare comparison jsonb; verified jsonb;
begin
  if auth.uid() is null then raise insufficient_privilege; end if;
  comparison:=sectalk_private.st_v8_residency_compare_destination(p_workspace,p_approval);
  if not coalesce((comparison->>'approvalCurrent')::boolean,false) then return comparison; end if;
  select jsonb_agg(case when x->>'status'='check_bytes' and exists(
    select 1 from sectalk_private.st_v8_residency_file_verifications e
    join storage.objects o on (o.id,o.version,o.updated_at)=(e.object_id,e.object_version,e.object_updated_at)
      and (o.bucket_id,o.name)=('sectalk-workspace-files',e.workspace::text||
        case e.kind when 'room_file' then '/rooms/'||e.scope::text else '' end||'/'||e.file::text)
    where (e.workspace,e.approval,e.kind,e.scope,e.file,e.manifest_sha256)=
      (p_workspace,p_approval,x->>'kind',(x->>'scope')::uuid,(x->>'id')::uuid,comparison->>'manifestSha256')
  ) then jsonb_set(x,'{status}','"matched"') else x end order by position) into verified
  from jsonb_array_elements(comparison->'records') with ordinality as entry(x,position);
  return jsonb_set(comparison,'{records}',verified);
end $$;

revoke all on function sectalk_private.st_v8_residency_file_snapshot(text,uuid,uuid,uuid,uuid),
  public.st_v8_residency_file_verification_snapshot(text,uuid,uuid,uuid),
  public.st_v8_record_residency_file_verification(text,uuid,uuid,uuid,uuid,uuid,jsonb,text,integer),
  public.st_v8_residency_compare_destination(uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_file_verification_snapshot(text,uuid,uuid,uuid),
  public.st_v8_residency_compare_destination(uuid,uuid) to authenticated;
grant execute on function public.st_v8_record_residency_file_verification(text,uuid,uuid,uuid,uuid,uuid,jsonb,text,integer) to service_role;
notify pgrst,'reload schema';
commit;
