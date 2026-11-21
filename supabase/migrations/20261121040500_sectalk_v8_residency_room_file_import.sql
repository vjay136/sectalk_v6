begin;

create table sectalk_private.st_v8_residency_room_file_imports (
  cell uuid not null,
  workspace uuid not null,
  source_project text not null,
  approval uuid not null,
  room uuid not null,
  file uuid not null,
  actor uuid not null,
  published_at timestamptz,
  primary key (room,file),
  foreign key (cell,workspace,source_project,approval,room)
    references sectalk_private.st_v8_residency_room_imports on delete cascade
);
alter table sectalk_private.st_v8_residency_room_file_imports enable row level security;
revoke all on sectalk_private.st_v8_residency_room_file_imports from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_residency_room_file_scope(p_room uuid,p_approval uuid,p_actor uuid,
  p_file uuid,p_name text,p_bytes integer,p_hash text)
returns table(cell uuid,workspace uuid,source_project text)
language sql stable set search_path='' as $$
  select c.cell,c.workspace,c.source_project
  from sectalk_private.st_v8_residency_workspace_claims c
  join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
  join sectalk_private.st_v8_residency_cells t on t.id=c.cell and t.retired_at is null and t.project_reference<>c.source_project
  join sectalk_private.st_v8_residency_content_admissions a
    on (a.cell,a.workspace,a.source_project,a.approval)=(c.cell,c.workspace,c.source_project,c.approval)
  join sectalk_private.st_v8_residency_staged_content s
    on (s.cell,s.workspace,s.source_project,s.approval)=(a.cell,a.workspace,a.source_project,a.approval)
  join sectalk_private.st_v8_residency_room_imports j
    on (j.cell,j.workspace,j.source_project,j.approval,j.room)=(c.cell,c.workspace,c.source_project,c.approval,p_room)
  join public.st_v6_rooms r on (r.workspace_id,r.id)=(c.workspace,j.room)
  cross join lateral jsonb_array_elements(s.records) as x
  cross join lateral (select (x->>'json')::jsonb as record) item
  where (c.approval,c.owner_id,j.actor,r.creator)=(p_approval,p_actor,p_actor,p_actor)
    and c.claimed_at is not null and least(c.expires_at,a.expires_at)>statement_timestamp()
    and c.manifest_sha256=a.manifest_sha256
    and sectalk_private.st_v8_offboarding_role(c.workspace,p_actor)='owner'
    and sectalk_private.st_v6_room_role(p_room,p_actor)='owner'
    and not r.archived and not r.locked and r.kind='private'
    and r.classification='confidential' and r.encryption_mode='standard'
    and not sectalk_private.st_v8_offboarding_holds(c.workspace)
    and p_hash~'^[0-9a-f]{64}$' and p_bytes between 1 and 4194304
    and (x->>'kind',x->>'scope',x->>'id')=('room_file',p_room::text,p_file::text)
    and encode(sha256(convert_to(x->>'json','UTF8')),'hex')=x->>'sha256'
    and (item.record->>'room',item.record->>'file',item.record->>'filename',item.record->>'sha256')=
      (p_room::text,p_file::text,p_name,p_hash)
    and item.record->'bytes'=to_jsonb(p_bytes)
    and ((item.record->>'roomKind'='public' and item.record->>'classification' in ('public','internal'))
      or (item.record->>'roomKind'='private' and item.record->>'classification'='confidential'));
$$;

create function public.st_v8_residency_room_file_import_access(p_room uuid,p_approval uuid,p_file uuid,
  p_name text,p_bytes integer,p_hash text)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    and sectalk_private.st_v7_admin_fresh()
    and exists(select 1 from sectalk_private.st_v8_residency_room_file_scope(
      p_room,p_approval,auth.uid(),p_file,p_name,p_bytes,p_hash) s
      where sectalk_private.st_v8_file_sso_allows(s.workspace)
        and sectalk_private.st_v8_organization_sso_allows(s.workspace)
        and not exists(select 1 from sectalk_private.st_v8_workspace_standard_room_sso policy
          where policy.workspace=s.workspace and sectalk_private.st_v8_workspace_session_receipt(
            policy.workspace,policy.protocol,policy.provider) is not true));
$$;

create function public.st_v8_residency_room_file_import_command(p_room uuid,p_approval uuid,p_actor uuid,p_session uuid,
  p_action text,p_file uuid,p_name text,p_bytes integer,p_hash text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare admitted record; receipt sectalk_private.st_v8_residency_room_file_imports; result jsonb;
begin
  if p_action is null or p_action not in ('reserve','publish') then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended('room_file:'||p_room::text,0));
  perform 1 from public.st_v6_rooms where id=p_room for share;
  if not found then return null; end if;
  select * into admitted from sectalk_private.st_v8_residency_room_file_scope(
    p_room,p_approval,p_actor,p_file,p_name,p_bytes,p_hash);
  if not found then return null; end if;
  perform sectalk_private.st_v7_require_workspace_write(admitted.workspace);
  select * into receipt from sectalk_private.st_v8_residency_room_file_imports where (room,file)=(p_room,p_file);
  if found then
    if (receipt.cell,receipt.workspace,receipt.source_project,receipt.approval,receipt.actor) is distinct from
      (admitted.cell,admitted.workspace,admitted.source_project,p_approval,p_actor) then return null; end if;
  elsif p_action='publish' then
    return null;
  elsif exists(select 1 from sectalk_private.st_v6_room_files where (room,id)=(p_room,p_file))
    or exists(select 1 from storage.objects where bucket_id='sectalk-workspace-files'
      and name=admitted.workspace::text||'/rooms/'||p_room::text||'/'||p_file::text) then
    raise exception 'The approved room file identifier is already in use' using errcode='PT409';
  end if;
  result:=public.st_v8_scoped_file_command(
    'room',p_room,p_actor,p_session,p_action,p_file,p_name,p_bytes,p_hash);
  if result is null then return null; end if;
  if p_action='reserve' and receipt.file is null then
    insert into sectalk_private.st_v8_residency_room_file_imports(cell,workspace,source_project,approval,room,file,actor)
      values(admitted.cell,admitted.workspace,admitted.source_project,p_approval,p_room,p_file,p_actor);
  elsif p_action='publish' and receipt.published_at is null then
    update sectalk_private.st_v8_residency_room_file_imports set published_at=statement_timestamp()
      where (room,file)=(p_room,p_file);
  end if;
  return result;
end $$;

revoke all on function sectalk_private.st_v8_residency_room_file_scope(uuid,uuid,uuid,uuid,text,integer,text),
  public.st_v8_residency_room_file_import_access(uuid,uuid,uuid,text,integer,text),
  public.st_v8_residency_room_file_import_command(uuid,uuid,uuid,uuid,text,uuid,text,integer,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_room_file_import_access(uuid,uuid,uuid,text,integer,text) to authenticated;
grant execute on function public.st_v8_residency_room_file_import_command(uuid,uuid,uuid,uuid,text,uuid,text,integer,text)
  to service_role;
notify pgrst,'reload schema';
commit;
