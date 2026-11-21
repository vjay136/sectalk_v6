begin;

create function public.st_v8_residency_file_import_access(p_workspace uuid,p_approval uuid,p_file uuid,
  p_filename text,p_bytes integer,p_hash text)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    and sectalk_private.st_v7_admin_fresh()
    and sectalk_private.st_v8_offboarding_role(p_workspace,auth.uid())='owner'
    and sectalk_private.st_v8_file_sso_allows(p_workspace)
    and p_hash~'^[0-9a-f]{64}$' and p_bytes between 1 and 4194304
    and exists(
      select 1 from sectalk_private.st_v8_residency_workspace_claims c
      join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
      join sectalk_private.st_v8_residency_cells t on t.id=c.cell and t.retired_at is null
      join sectalk_private.st_v8_residency_content_admissions a
        on (a.cell,a.workspace,a.source_project,a.approval)=(c.cell,c.workspace,c.source_project,c.approval)
      join sectalk_private.st_v8_residency_staged_content s
        on (s.cell,s.workspace,s.source_project,s.approval)=(a.cell,a.workspace,a.source_project,a.approval)
      cross join lateral jsonb_array_elements(s.records) x
      cross join lateral (select (x->>'json')::jsonb as record) item
      where (c.workspace,c.approval,c.owner_id)=(p_workspace,p_approval,auth.uid()) and c.claimed_at is not null
        and least(c.expires_at,a.expires_at)>statement_timestamp()
        and c.manifest_sha256=a.manifest_sha256
        and (x->>'kind',x->>'scope',x->>'id')=('workspace_file',p_workspace::text,p_file::text)
        and encode(sha256(convert_to(x->>'json','UTF8')),'hex')=x->>'sha256'
        and item.record->>'file'=p_file::text and item.record->>'filename'=p_filename
        and item.record->'bytes'=to_jsonb(p_bytes)
        and item.record->>'fingerprint'=encode(sectalk_private.st_v6_workspace_file_fingerprint(p_workspace,p_hash),'hex')
    );
$$;
revoke all on function public.st_v8_residency_file_import_access(uuid,uuid,uuid,text,integer,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_file_import_access(uuid,uuid,uuid,text,integer,text) to authenticated;
notify pgrst,'reload schema';
commit;
