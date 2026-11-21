begin;

create table sectalk_private.st_v8_residency_channel_imports (
  cell uuid not null,
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  source_project text not null,
  approval uuid not null,
  channel uuid not null,
  channel_name text not null check(channel_name~'^[a-z0-9][a-z0-9-]{0,39}$'),
  actor uuid not null,
  evidence_count integer not null check(evidence_count between 1 and 500),
  imported_at timestamptz not null default clock_timestamp(),
  primary key(cell,workspace,source_project,approval,channel),
  foreign key(cell,workspace,source_project,approval)
    references sectalk_private.st_v8_residency_staged_content on delete restrict
);
alter table sectalk_private.st_v8_residency_channel_imports enable row level security;
revoke all on sectalk_private.st_v8_residency_channel_imports from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_residency_channel_candidates(p_records jsonb)
returns table(channel uuid,name text,evidence_count integer)
language sql stable set search_path='' as $$
  select (e->>'scope')::uuid,min(payload->>'name'),count(*)::integer
  from jsonb_array_elements(p_records) e
  cross join lateral (select (e->>'json')::jsonb payload) material
  where e->>'kind'='channel_message' and e->>'scope'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
  group by e->>'scope'
  having count(distinct payload->>'name')=1 and bool_and(coalesce(
    jsonb_typeof(payload)='object' and payload ?& array['channel','name','message','body','createdAt']
    and payload-array['channel','name','message','body','createdAt']='{}'::jsonb
    and payload->>'channel'=e->>'scope' and payload->>'message'=e->>'id'
    and payload->>'name'~'^[a-z0-9][a-z0-9-]{0,39}$'
    and encode(sha256(convert_to(e->>'json','UTF8')),'hex')=e->>'sha256',false));
$$;

create function public.st_v8_residency_channel_import(p_workspace uuid,p_approval uuid default null,
  p_channel uuid default null,p_confirmation text default null)
returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' as $$
declare actor_id uuid:=auth.uid(); admitted record; candidate record; receipt sectalk_private.st_v8_residency_channel_imports;
  fingerprint text; published uuid; options jsonb;
begin
  if p_workspace is null or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or (p_approval is null)<>(p_channel is null) then raise insufficient_privilege; end if;
  if p_channel is not null then
    if p_confirmation is distinct from p_workspace::text or sectalk_private.st_v7_admin_fresh() is not true
      then raise insufficient_privilege; end if;
    perform 1 from public.st_v2_workspaces where id=p_workspace for update;
    if not found then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-standard-channel-sso:'||p_workspace::text,0));
  end if;
  if sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'owner'
    or sectalk_private.st_v8_organization_sso_allows(p_workspace) is not true
    or exists(select 1 from sectalk_private.st_v8_workspace_standard_channel_sso policy where policy.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(policy.workspace,policy.protocol,policy.provider) is not true)
    then raise insufficient_privilege; end if;

  select c.cell,c.source_project,c.approval,c.manifest_sha256,least(c.expires_at,a.expires_at) expires_at,s.records
    into admitted from sectalk_private.st_v8_residency_workspace_claims c
    join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
    join sectalk_private.st_v8_residency_cells t on t.id=c.cell and t.retired_at is null and t.project_reference<>c.source_project
    join sectalk_private.st_v8_residency_content_admissions a on (a.cell,a.workspace,a.source_project,a.approval)=
      (c.cell,c.workspace,c.source_project,c.approval)
    join sectalk_private.st_v8_residency_staged_content s on (s.cell,s.workspace,s.source_project,s.approval)=
      (c.cell,c.workspace,c.source_project,c.approval)
    where c.workspace=p_workspace and c.owner_id=actor_id and c.claimed_at is not null
      and c.manifest_sha256=a.manifest_sha256 and (p_approval is null or c.approval=p_approval) for share of c,i,t,a,s;
  if not found then
    if p_channel is not null then raise insufficient_privilege; end if;
    return null;
  end if;
  if p_channel is null then
    select coalesce(jsonb_agg(jsonb_build_object('id',x.channel,'name',x.name,'evidenceCount',x.evidence_count,
      'importedAt',r.imported_at) order by x.name,x.channel),'[]'::jsonb) into options
    from sectalk_private.st_v8_residency_channel_candidates(admitted.records) x
    left join sectalk_private.st_v8_residency_channel_imports r on (r.cell,r.workspace,r.source_project,r.approval,r.channel)=
      (admitted.cell,p_workspace,admitted.source_project,admitted.approval,x.channel)
    where admitted.expires_at>statement_timestamp() or r.imported_at is not null;
    return jsonb_build_object('approval',admitted.approval,'manifestSha256',admitted.manifest_sha256,'channels',options);
  end if;

  select * into receipt from sectalk_private.st_v8_residency_channel_imports r
    where (r.cell,r.workspace,r.source_project,r.approval,r.channel)=
      (admitted.cell,p_workspace,admitted.source_project,p_approval,p_channel);
  if found then return jsonb_build_object('channel',receipt.channel,'name',receipt.channel_name,'importedAt',receipt.imported_at); end if;
  if admitted.expires_at<=statement_timestamp() then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_residency_channel_import',20);
  perform sectalk_private.st_v7_require_workspace_write(p_workspace);
  select encode(sha256(convert_to(jsonb_build_object('format','sectalk-workspace-content-v1','workspace',p_workspace,
    'approval',p_approval,'entries',jsonb_agg(jsonb_build_array(position,e->>'kind',e->>'scope',e->>'id',e->>'sha256')
      order by position))::text,'UTF8')),'hex') into fingerprint
  from jsonb_array_elements(admitted.records) with ordinality as item(e,position);
  if fingerprint is distinct from admitted.manifest_sha256 then
    raise exception 'The approved destination manifest changed' using errcode='PT409'; end if;
  select * into candidate from sectalk_private.st_v8_residency_channel_candidates(admitted.records) x where x.channel=p_channel;
  if not found then raise exception 'No matching approved standard channel exists' using errcode='PT409'; end if;
  if (select count(*) from public.st_v2_channels where workspace_id=p_workspace)>=100 then
    raise exception 'Channel limit reached' using errcode='PT409'; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-channel-mode:'||p_workspace::text,0));
  if exists(select 1 from sectalk_private.st_v8_channel_encryption_policy p where p.workspace=p_workspace and p.managed) then
    raise exception 'The destination currently requires managed encryption for new channels' using errcode='PT409'; end if;
  insert into public.st_v2_channels(id,workspace_id,owner,name,visibility)
    values(p_channel,p_workspace,actor_id,candidate.name,'workspace') on conflict do nothing returning id into published;
  if published is null then
    raise exception 'The approved channel ID or name already exists. No channel was changed.' using errcode='PT409'; end if;
  insert into sectalk_private.st_v8_residency_channel_imports(cell,workspace,source_project,approval,channel,
    channel_name,actor,evidence_count)
    values(admitted.cell,p_workspace,admitted.source_project,p_approval,p_channel,candidate.name,actor_id,candidate.evidence_count)
    returning * into receipt;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor_id,'channel.residency_imported',p_channel);
  return jsonb_build_object('channel',receipt.channel,'name',receipt.channel_name,'importedAt',receipt.imported_at);
end $$;

revoke all on function sectalk_private.st_v8_residency_channel_candidates(jsonb),
  public.st_v8_residency_channel_import(uuid,uuid,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_channel_import(uuid,uuid,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
