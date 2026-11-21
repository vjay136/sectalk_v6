begin;

create table sectalk_private.st_v8_residency_content_admissions (
  cell uuid not null references sectalk_private.st_v8_residency_cells(id) on delete restrict,
  workspace uuid not null,
  source_project text not null check (source_project ~ '^[a-z0-9-]{1,80}$'),
  approval uuid not null,
  manifest_sha256 text not null check (manifest_sha256 ~ '^[0-9a-f]{64}$'),
  record_count integer not null check (record_count between 1 and 500),
  expires_at timestamptz not null,
  primary key (cell, workspace, source_project, approval)
);

create table sectalk_private.st_v8_residency_staged_content (
  cell uuid not null,
  workspace uuid not null,
  source_project text not null,
  approval uuid not null,
  records jsonb not null,
  staged_at timestamptz not null default clock_timestamp(),
  primary key (cell, workspace, source_project, approval),
  foreign key (cell, workspace, source_project, approval)
    references sectalk_private.st_v8_residency_content_admissions on delete restrict
);

alter table sectalk_private.st_v8_residency_content_admissions enable row level security;
alter table sectalk_private.st_v8_residency_staged_content enable row level security;
revoke all on sectalk_private.st_v8_residency_content_admissions, sectalk_private.st_v8_residency_staged_content
  from public, anon, authenticated, service_role;
create function public.st_v8_stage_residency_content(p_cell uuid, p_nonce uuid, p_source text,
  p_workspace uuid, p_approval uuid, p_records jsonb)
returns jsonb language plpgsql security definer set search_path='' as $$
declare admission sectalk_private.st_v8_residency_content_admissions;
  fingerprint text; seen integer; valid integer; distinct_records integer; canonical jsonb; wrote boolean;
begin
  select a.* into admission from sectalk_private.st_v8_residency_content_admissions a
    join sectalk_private.st_v8_residency_installation i on i.cell=a.cell and i.installation_nonce=p_nonce
    join sectalk_private.st_v8_residency_cells c on c.id=a.cell and c.retired_at is null
    where (a.cell,a.workspace,a.source_project,a.approval)=(p_cell,p_workspace,p_source,p_approval)
      and c.project_reference<>p_source and a.expires_at>statement_timestamp()
    for update of a;
  if not found then raise exception 'Target transfer approval unavailable' using errcode='42501'; end if;
  if jsonb_typeof(p_records) is distinct from 'array' or octet_length(p_records::text)>8388608
    or jsonb_array_length(p_records)<>admission.record_count then
    raise exception 'Invalid approved transfer size' using errcode='22023'; end if;

  with checked as (
    select entry, position, entry->>'kind' as kind, entry->>'scope' as scope,
      entry->>'id' as record, entry->>'sha256' as digest
    from jsonb_array_elements(p_records) with ordinality as item(entry,position)
  )
  select count(*), count(*) filter (where jsonb_typeof(entry)='object'
      and entry ?& array['position','kind','scope','id','sha256','json']
      and entry - array['position','kind','scope','id','sha256','json']='{}'::jsonb
      and entry->'position'=to_jsonb(position)
      and kind in ('channel_message','room_message','workspace_task','room_task','workspace_file','room_file')
      and scope~'^[0-9a-f-]{36}$' and record~'^[0-9a-f-]{36}$'
      and jsonb_typeof(entry->'json')='string'
      and encode(sha256(convert_to(entry->>'json','UTF8')),'hex')=digest),
    count(distinct (kind,scope,record)),
    jsonb_agg(jsonb_build_array(position,kind,scope,record,digest) order by position)
    into seen,valid,distinct_records,canonical from checked;
  if seen<>valid or seen<>distinct_records then
    raise exception 'Approved content is incomplete or changed' using errcode='22023'; end if;

  fingerprint:=encode(sha256(convert_to(jsonb_build_object('format','sectalk-workspace-content-v1',
    'workspace',p_workspace,'approval',p_approval,'entries',canonical)::text,'UTF8')),'hex');
  if fingerprint<>admission.manifest_sha256 then
    raise exception 'Approved manifest differs' using errcode='42501'; end if;
  insert into sectalk_private.st_v8_residency_staged_content (cell,workspace,source_project,approval,records)
    values(p_cell,p_workspace,p_source,p_approval,p_records) on conflict do nothing;
  wrote:=found;
  if not exists(select 1 from sectalk_private.st_v8_residency_staged_content s
    where (s.cell,s.workspace,s.source_project,s.approval)=(p_cell,p_workspace,p_source,p_approval)
      and s.records=p_records) then
    raise exception 'Target transfer differs from existing archive' using errcode='PT409'; end if;
  return jsonb_build_object('staged',wrote,'count',seen,'manifestSha256',fingerprint);
end $$;

revoke all on function public.st_v8_stage_residency_content(uuid,uuid,text,uuid,uuid,jsonb)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_stage_residency_content(uuid,uuid,text,uuid,uuid,jsonb) to service_role;

commit;
