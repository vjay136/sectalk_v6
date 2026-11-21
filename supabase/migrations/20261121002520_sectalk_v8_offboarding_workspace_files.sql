begin;
alter table sectalk_private.st_v8_content_exports add column include_workspace_files boolean not null default false;

create function sectalk_private.st_v8_offboarding_file_records(p_workspace uuid,p_owner uuid,p_reviewer uuid,p_file uuid default null)
returns table(kind text,scope_id uuid,record_id uuid,item jsonb)
language sql stable security definer set search_path='' set timezone='UTC' as $$
  select 'workspace_file',f.workspace,f.id,jsonb_build_object('file',f.id,'filename',f.filename,
    'bytes',f.size_bytes,'publishedAt',f.published_at,'fingerprint',encode(f.fingerprint,'hex'))
  from sectalk_private.st_v6_workspace_files f
  where f.workspace=p_workspace and (p_file is null or f.id=p_file)
    and f.published_at is not null and f.deleted_at is null and f.fingerprint is not null
    and exists(select 1 from storage.objects o where o.bucket_id='sectalk-workspace-files'
      and o.name=f.workspace::text||'/'||f.id::text and o.metadata->>'size'=f.size_bytes::text)
    and sectalk_private.st_v8_offboarding_role(p_workspace,p_owner)='owner'
    and sectalk_private.st_v8_offboarding_role(p_workspace,p_reviewer)='reviewer'
    and not sectalk_private.st_v8_offboarding_holds(p_workspace)
    and not exists(select 1 from sectalk_private.st_v7_file_egress_policies p
      where p.workspace=p_workspace and p.policy->>'mode' is distinct from 'inherit')
    and not exists(select 1 from sectalk_private.st_v7_file_custom_role_required p
      where (p.workspace,p.file)=(f.workspace,f.id))
    and (f.uploader=p_owner or sectalk_private.open_pair(f.uploader,p_owner))
    and (f.uploader=p_reviewer or sectalk_private.open_pair(f.uploader,p_reviewer))
  order by f.id limit 501;
$$;

create function public.st_v8_offboarding_file_access(p_workspace uuid,p_export uuid,p_file uuid,p_hash text default null)
returns jsonb language sql stable security definer set search_path='' as $$
  select f.item from sectalk_private.st_v8_content_exports e
  join sectalk_private.st_v8_content_export_entries m on m.export_id=e.id and m.kind='workspace_file'
    and m.scope_id=e.workspace and m.record_id=p_file
  cross join lateral sectalk_private.st_v8_offboarding_file_records(e.workspace,e.requester,e.reviewer,p_file) f
  where (e.workspace,e.id,e.requester)=(p_workspace,p_export,auth.uid())
    and e.include_workspace_files and e.withdrawn_at is null and e.expires_at>statement_timestamp()
    and sectalk_private.st_v7_billing_admin_session() and sectalk_private.st_v7_admin_fresh()
    and (public.st_v7_explain_file_egress('workspace',p_workspace,p_file,'download')->>'allowed')='true'
    and m.sha256=encode(sha256(convert_to(f.item::text,'UTF8')),'hex')
    and (p_hash is null or case when p_hash~'^[0-9a-f]{64}$' then
      encode(sectalk_private.st_v6_workspace_file_fingerprint(p_workspace,p_hash),'hex')=f.item->>'fingerprint'
      and not exists(select 1 from sectalk_private.st_v6_malware_hashes mh where mh.sha256=decode(p_hash,'hex'))
      and not public.st_v7_upload_digest_blocked(p_hash) else false end);
$$;

create function sectalk_private.st_v8_offboarding_file_scope_immutable()
returns trigger language plpgsql set search_path='' as $$
begin
  if old.include_workspace_files is distinct from new.include_workspace_files then
    raise exception 'Approved workspace file scope is immutable' using errcode='42501'; end if;
  return new;
end $$;
create trigger st_v8_offboarding_file_scope_immutable before update on sectalk_private.st_v8_content_exports
  for each row execute function sectalk_private.st_v8_offboarding_file_scope_immutable();

revoke all on function sectalk_private.st_v8_offboarding_file_records(uuid,uuid,uuid,uuid),
  sectalk_private.st_v8_offboarding_file_scope_immutable(),public.st_v8_offboarding_file_access(uuid,uuid,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_file_access(uuid,uuid,uuid,text) to authenticated;

create or replace function public.st_v8_offboarding_content(p_workspace uuid,p_action text default 'status',
  p_id uuid default null,p_confirmation text default null,p_after integer default 0)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); access_kind text:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
  export_row sectalk_private.st_v8_content_exports; entries jsonb; total integer; fingerprint text;
  after_position integer; end_position integer; fresh jsonb;
begin
  if access_kind='none' or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not sectalk_private.st_v7_admin_fresh() then
    raise exception 'Verified content export access unavailable' using errcode='42501'; end if;
  if p_action='status' then
    select * into export_row from sectalk_private.st_v8_content_exports where workspace=p_workspace and withdrawn_at is null;
    return jsonb_build_object('role',access_kind,'id',export_row.id,'records',export_row.record_count,
      'manifestSha256',export_row.manifest_sha256,'expiresAt',export_row.expires_at,'includesFiles',export_row.include_workspace_files);
  end if;
  if p_id is null or p_confirmation is distinct from p_workspace::text then
    raise exception 'Confirm the workspace for this content export' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v8_offboarding_content',30);
  if p_action='page' then
    select * into export_row from sectalk_private.st_v8_content_exports where workspace=p_workspace and id=p_id for share;
  else
    perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
    select * into export_row from sectalk_private.st_v8_content_exports where workspace=p_workspace and id=p_id for update;
    access_kind:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
  end if;
  if p_action in ('export_content','export_content_files') and access_kind='owner' then
    if export_row.id is null then
      if exists(select 1 from sectalk_private.st_v8_content_exports e where e.workspace=p_workspace and e.withdrawn_at is null) then
        raise exception 'Withdraw the existing content approval before starting another' using errcode='PT409';
      end if;
      insert into sectalk_private.st_v8_content_exports(id,workspace,requester,include_workspace_files) values(p_id,p_workspace,actor_id,p_action='export_content_files');
    elsif export_row.requester<>actor_id or export_row.withdrawn_at is not null or export_row.include_workspace_files<>(p_action='export_content_files') then
      raise exception 'Content export unavailable' using errcode='42501'; end if;
  elsif p_action='approve' and access_kind='reviewer' and export_row.requester<>actor_id
    and export_row.withdrawn_at is null
    and sectalk_private.st_v8_offboarding_role(p_workspace,export_row.requester)='owner' then
    if export_row.reviewer=actor_id then return jsonb_build_object('id',p_id); end if;
    if export_row.reviewer is not null or export_row.created_at<statement_timestamp()-interval '24 hours' then
      raise exception 'Content approval unavailable' using errcode='42501'; end if;
    with picked as (
      select s.kind,s.scope_id,s.record_id,encode(sha256(convert_to(s.item::text,'UTF8')),'hex') as sha
      from (
        select * from sectalk_private.st_v8_content_export_records(p_workspace,export_row.requester,actor_id)
        union all
        select * from sectalk_private.st_v8_offboarding_file_records(p_workspace,export_row.requester,actor_id)
          where export_row.include_workspace_files
      ) s
      order by s.kind,s.scope_id,s.record_id limit 501
    )
    insert into sectalk_private.st_v8_content_export_entries(export_id,position,kind,scope_id,record_id,sha256)
      select p_id,row_number() over(order by s.kind,s.scope_id,s.record_id),s.kind,s.scope_id,s.record_id,s.sha from picked s;
    get diagnostics total=row_count;
    if total>500 then raise exception 'Content export exceeds the 500-record approval limit' using errcode='22023'; end if;
    select encode(sha256(convert_to(jsonb_build_object('format','sectalk-workspace-content-v1','workspace',p_workspace,
      'approval',p_id,'entries',coalesce(jsonb_agg(jsonb_build_array(m.position,m.kind,m.scope_id,m.record_id,m.sha256)
      order by m.position),'[]'))::text,'UTF8')),'hex')
      into fingerprint from sectalk_private.st_v8_content_export_entries m where m.export_id=p_id;
    update sectalk_private.st_v8_content_exports set reviewer=actor_id,approved_at=statement_timestamp(),
      expires_at=statement_timestamp()+interval '24 hours',record_count=total,manifest_sha256=fingerprint where id=p_id;
  elsif p_action='page' and access_kind='owner' and export_row.requester=actor_id and export_row.withdrawn_at is null
    and export_row.expires_at>statement_timestamp()
    and sectalk_private.st_v8_offboarding_role(p_workspace,export_row.reviewer)='reviewer' then
    if p_after is null or p_after<0 or p_after>export_row.record_count or p_after%25<>0 then
      raise exception 'Invalid content page cursor' using errcode='22023'; end if;
    after_position:=p_after;
    end_position:=least(p_after+25,export_row.record_count);
    select jsonb_agg(jsonb_build_object('position',m.position,'kind',m.kind,'scope',m.scope_id,'id',m.record_id,
      'sha256',m.sha256,'json',s.item::text) order by m.position),count(s.item)
      into fresh,total from sectalk_private.st_v8_content_export_entries m
      left join lateral (
        select source.item from sectalk_private.st_v8_content_export_records(p_workspace,actor_id,export_row.reviewer,m.kind,m.scope_id,m.record_id) source
          where m.kind<>'workspace_file'
        union all select source.item from sectalk_private.st_v8_offboarding_file_records(p_workspace,actor_id,export_row.reviewer,m.record_id) source
          where m.kind='workspace_file' and export_row.include_workspace_files
      ) s
        on encode(sha256(convert_to(s.item::text,'UTF8')),'hex')=m.sha256
      where m.export_id=p_id and m.position>after_position and m.position<=end_position;
    if total<>end_position-after_position then
      raise exception 'An approved record changed or access ended' using errcode='42501'; end if;
    return jsonb_build_object('id',p_id,'manifestSha256',export_row.manifest_sha256,'records',coalesce(fresh,'[]'),
      'next',case when end_position<export_row.record_count then end_position end);
  elsif p_action='withdraw' and access_kind='owner' and export_row.id is not null then
    update sectalk_private.st_v8_content_exports set withdrawn_at=coalesce(withdrawn_at,statement_timestamp()) where id=p_id;
  else raise exception 'Content export unavailable' using errcode='42501';
  end if;
  return jsonb_build_object('id',p_id);
end $$;

notify pgrst,'reload schema';
commit;
