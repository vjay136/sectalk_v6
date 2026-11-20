begin;

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('sectalk-workspace-files','sectalk-workspace-files',false,4194304,array['application/octet-stream'])
on conflict(id) do update set public=false,file_size_limit=excluded.file_size_limit,allowed_mime_types=excluded.allowed_mime_types;
create policy st_v6_private_workspace_file_objects on storage.objects as restrictive for all to public
  using(bucket_id<>'sectalk-workspace-files') with check(bucket_id<>'sectalk-workspace-files');

create table sectalk_private.st_v6_workspace_files (
  workspace uuid not null,
  id uuid not null,
  uploader uuid not null,
  filename text not null check(char_length(filename) between 1 and 140),
  size_bytes integer not null check(size_bytes between 1 and 4194304),
  fingerprint bytea check(octet_length(fingerprint)=32),
  created_at timestamptz not null default clock_timestamp(),
  upload_until timestamptz,
  published_at timestamptz,
  deleted_at timestamptz,
  maintenance_lease uuid,
  maintenance_after timestamptz not null default '-infinity',
  primary key(workspace,id)
);
create index st_v6_workspace_file_fingerprints on sectalk_private.st_v6_workspace_files(workspace,fingerprint)
  where published_at is not null and deleted_at is null and fingerprint is not null;
create index st_v6_workspace_file_ready on sectalk_private.st_v6_workspace_files(workspace,published_at desc,id)
  where published_at is not null and deleted_at is null;
create index st_v6_workspace_file_maintenance on sectalk_private.st_v6_workspace_files(maintenance_after,created_at,workspace,id);
alter table sectalk_private.st_v6_workspace_files enable row level security;
revoke all on sectalk_private.st_v6_workspace_files from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_workspace_file_fingerprint(p_workspace uuid,p_hash text)
returns bytea language sql immutable strict set search_path='' as $$
  select sha256(convert_to('workspace-file:'||p_workspace::text||':'||p_hash,'UTF8'))
$$;

create function public.st_v6_workspace_file_command(p_workspace uuid,p_actor uuid,p_action text,p_id uuid,
  p_filename text,p_bytes integer,p_hash text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare scope_role text;
declare entry sectalk_private.st_v6_workspace_files;
declare scoped bytea;
declare duplicate boolean;
begin
  scope_role:=sectalk_private.st_v2_role(p_workspace,p_actor);
  if scope_role is null or not sectalk_private.st_v2_active(p_actor) then return null; end if;
  if p_action='access' then return jsonb_build_object('allowed',true); end if;
  if p_action='list' then
    return coalesce((select jsonb_agg(jsonb_build_object('id',r.id,'filename',r.filename,'size_bytes',r.size_bytes,
        'can_remove',r.uploader=p_actor or scope_role in ('owner','admin')) order by r.published_at desc,r.id)
      from (
        select f.id,f.filename,f.size_bytes,f.uploader,f.published_at
        from sectalk_private.st_v6_workspace_files f where f.workspace=p_workspace
          and f.published_at is not null and f.deleted_at is null order by f.published_at desc,f.id limit 200
      ) r),'[]'::jsonb);
  end if;
  if p_id is null or p_action is null or p_action not in ('get','remove','reserve','publish','malware') then return null; end if;
  if p_action in ('reserve','publish','malware') then
    if p_hash is null or p_hash !~ '^[0-9a-f]{64}$' then raise exception 'Invalid workspace file digest' using errcode='22023'; end if;
    if p_action='malware' then
      insert into sectalk_private.st_v6_malware_hashes(sha256) values(decode(p_hash,'hex')) on conflict do nothing;
      return jsonb_build_object('recorded',true);
    end if;
    scoped:=sectalk_private.st_v6_workspace_file_fingerprint(p_workspace,p_hash);
  end if;
  if p_action<>'get' then
    perform pg_advisory_xact_lock(hashtextextended('workspace_file:'||p_workspace::text,0));
    scope_role:=sectalk_private.st_v2_role(p_workspace,p_actor);
    if scope_role is null or not sectalk_private.st_v2_active(p_actor) then return null; end if;
  end if;
  select * into entry from sectalk_private.st_v6_workspace_files f where f.workspace=p_workspace and f.id=p_id;
  if p_action in ('get','remove') then
    if entry.published_at is null or entry.deleted_at is not null then return null; end if;
    if p_action='remove' then
      if entry.uploader<>p_actor and scope_role not in ('owner','admin') then return null; end if;
      update sectalk_private.st_v6_workspace_files f set deleted_at=clock_timestamp(),maintenance_after=clock_timestamp()
        where f.workspace=p_workspace and f.id=p_id;
      return jsonb_build_object('removed',true);
    end if;
    return jsonb_build_object('size_bytes',entry.size_bytes,
      'fingerprint',encode(entry.fingerprint,'hex'));
  end if;
  if exists(select 1 from sectalk_private.st_v6_malware_hashes m where m.sha256=decode(p_hash,'hex')) then
    raise exception 'The workspace file was blocked by security scanning.' using errcode='PT422';
  end if;
  if p_action='reserve' then
    if p_filename is null or char_length(p_filename) not between 1 and 140 or p_filename ~ '[/[:cntrl:]]'
      or strpos(p_filename,chr(92))>0 or p_bytes is null or p_bytes not between 1 and 4194304 then
      raise exception 'Choose a supported workspace file up to 4 MiB.' using errcode='22023';
    end if;
    if entry.id is null then
      if exists(select 1 from sectalk_private.st_v6_workspace_files f where f.workspace=p_workspace
        group by f.workspace having count(*)>=200 or sum(f.size_bytes)+p_bytes>67108864) then
        raise exception 'The workspace file storage limit was reached.' using errcode='PT413';
      end if;
      insert into sectalk_private.st_v6_workspace_files(workspace,id,uploader,filename,size_bytes,fingerprint,upload_until)
        values(p_workspace,p_id,p_actor,p_filename,p_bytes,scoped,clock_timestamp()+interval '2 minutes');
      return jsonb_build_object('reserved',true);
    end if;
    if entry.uploader<>p_actor or entry.deleted_at is not null or entry.filename<>p_filename
      or entry.size_bytes<>p_bytes or entry.fingerprint is distinct from scoped
      or (entry.published_at is null and entry.created_at<=clock_timestamp()-interval '15 minutes') then return null; end if;
    if entry.published_at is not null then return jsonb_build_object('reserved',true,'uploaded',true); end if;
    update sectalk_private.st_v6_workspace_files f set upload_until=clock_timestamp()+interval '2 minutes'
      where f.workspace=p_workspace and f.id=p_id;
    return jsonb_build_object('reserved',true);
  end if;
  if entry.id is null or entry.uploader<>p_actor or entry.deleted_at is not null or entry.fingerprint is distinct from scoped
    or (entry.published_at is null and entry.created_at<=clock_timestamp()-interval '15 minutes') then return null; end if;
  perform 1 from storage.objects s where s.bucket_id='sectalk-workspace-files'
    and s.name=p_workspace::text||'/'||p_id::text and s.metadata->>'size'=entry.size_bytes::text;
  if not found then return null; end if;
  select exists(select 1 from sectalk_private.st_v6_workspace_files f
    where f.workspace=p_workspace and f.id<>p_id and f.fingerprint=scoped and f.published_at is not null
      and f.deleted_at is null) into duplicate;
  update sectalk_private.st_v6_workspace_files f set published_at=coalesce(f.published_at,clock_timestamp()),upload_until=null
    where f.workspace=p_workspace and f.id=p_id;
  return jsonb_build_object('id',p_id,'duplicate',duplicate);
end
$$;

create function public.st_v6_workspace_file_maintenance_claim()
returns table(workspace uuid,id uuid,size_bytes integer,lease uuid,task text)
language sql security definer set search_path='' as $$
  with eligible as (
    select f.workspace,f.id,case when f.deleted_at is not null or f.published_at is null or
      not exists(select 1 from public.st_v2_workspaces w where w.id=f.workspace) then 'purge' else 'index' end as task
    from sectalk_private.st_v6_workspace_files f where f.maintenance_after<=clock_timestamp()
      and (f.upload_until is null or f.upload_until<=clock_timestamp()) and (
      f.deleted_at is not null or not exists(select 1 from public.st_v2_workspaces w where w.id=f.workspace)
      or (f.published_at is null and f.created_at<=clock_timestamp()-interval '15 minutes')
      or (f.published_at is not null and f.fingerprint is null))
    order by f.maintenance_after,f.created_at,f.workspace,f.id limit 12 for update of f skip locked
  )
  update sectalk_private.st_v6_workspace_files f set maintenance_lease=gen_random_uuid(),
    maintenance_after=clock_timestamp()+interval '5 minutes'
  from eligible where f.workspace=eligible.workspace and f.id=eligible.id
  returning f.workspace,f.id,f.size_bytes,f.maintenance_lease,eligible.task
$$;

create function public.st_v6_workspace_file_maintenance_finish(p_workspace uuid,p_id uuid,p_lease uuid,p_hash text)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  perform pg_advisory_xact_lock(hashtextextended('workspace_file:'||p_workspace::text,0));
  if p_hash is null then
    delete from sectalk_private.st_v6_workspace_files f where f.workspace=p_workspace and f.id=p_id
      and f.maintenance_lease=p_lease and (f.deleted_at is not null
        or not exists(select 1 from public.st_v2_workspaces w where w.id=f.workspace)
        or (f.published_at is null and f.created_at<=clock_timestamp()-interval '15 minutes'))
      and not exists(select 1 from storage.objects s where s.bucket_id='sectalk-workspace-files'
        and s.name=p_workspace::text||'/'||p_id::text);
  else
    if p_hash !~ '^[0-9a-f]{64}$' then return false; end if;
    update sectalk_private.st_v6_workspace_files f
    set fingerprint=sectalk_private.st_v6_workspace_file_fingerprint(p_workspace,p_hash),maintenance_lease=null
    where f.workspace=p_workspace and f.id=p_id and f.maintenance_lease=p_lease
      and f.published_at is not null and f.deleted_at is null and f.fingerprint is null
      and exists(select 1 from storage.objects s where s.bucket_id='sectalk-workspace-files'
        and s.name=p_workspace::text||'/'||p_id::text and s.metadata->>'size'=f.size_bytes::text);
  end if;
  return found;
end
$$;

revoke all on function sectalk_private.st_v6_workspace_file_fingerprint(uuid,text) from public,anon,authenticated,service_role;
revoke all on function public.st_v6_workspace_file_command(uuid,uuid,text,uuid,text,integer,text),
  public.st_v6_workspace_file_maintenance_claim(),public.st_v6_workspace_file_maintenance_finish(uuid,uuid,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_workspace_file_command(uuid,uuid,text,uuid,text,integer,text),
  public.st_v6_workspace_file_maintenance_claim(),public.st_v6_workspace_file_maintenance_finish(uuid,uuid,uuid,text) to service_role;

commit;
