begin;

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('sectalk-exports','sectalk-exports',false,1048576,array['application/json','text/csv','application/pdf'])
on conflict(id) do update set public=false,file_size_limit=excluded.file_size_limit,allowed_mime_types=excluded.allowed_mime_types;

create policy st_v6_no_direct_export_objects on storage.objects as restrictive for all to public
  using(bucket_id<>'sectalk-exports') with check(bucket_id<>'sectalk-exports');

create table sectalk_private.st_v6_export_objects (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid not null,
  kind text not null check(kind in ('audit','operations','security')),
  scope_id uuid,
  period text,
  filename text not null check(filename ~ '^[a-z0-9-]{1,75}[.](json|csv|pdf)$'),
  media_type text not null check(media_type in ('application/json','text/csv','application/pdf')),
  bytes integer not null check(bytes between 1 and 1048576),
  sha256 text not null check(sha256 ~ '^[0-9a-f]{64}$'),
  ready boolean not null default false,
  expires_at timestamptz not null default (clock_timestamp()+interval '10 minutes'),
  lease uuid,
  lease_until timestamptz,
  check ((kind='audit' and scope_id is not null and period is null and media_type='application/json') or
    (kind='operations' and scope_id is not null and period is null and media_type='text/csv') or
    (kind='security' and scope_id is null and period is not null and period in ('daily','weekly')
      and media_type in ('text/csv','application/pdf')))
);
create index st_v6_export_objects_owner on sectalk_private.st_v6_export_objects(actor_id);
create index st_v6_export_objects_expiry on sectalk_private.st_v6_export_objects(expires_at,id);
alter table sectalk_private.st_v6_export_objects enable row level security;
revoke all on sectalk_private.st_v6_export_objects from public,anon,authenticated,service_role;

create function public.st_v6_begin_export_object(p_actor uuid,p_kind text,p_scope uuid,p_period text,
  p_filename text,p_media text,p_bytes integer,p_sha256 text)
returns uuid language plpgsql security definer set search_path='' as $$
declare artifact uuid;
begin
  perform pg_advisory_xact_lock(hashtextextended('export_object:'||p_actor::text,0));
  if (select count(*) from sectalk_private.st_v6_export_objects where actor_id=p_actor)>=20 then return null; end if;
  insert into sectalk_private.st_v6_export_objects(actor_id,kind,scope_id,period,filename,media_type,bytes,sha256)
    values(p_actor,p_kind,p_scope,p_period,p_filename,p_media,p_bytes,p_sha256) returning id into artifact;
  return artifact;
end
$$;

create function public.st_v6_finish_export_object(p_artifact uuid)
returns boolean language sql security definer set search_path='' as $$
  with updated as (
    update sectalk_private.st_v6_export_objects a set ready=true,expires_at=clock_timestamp()+interval '24 hours'
    where a.id=p_artifact and not a.ready and a.expires_at>clock_timestamp()
      and exists(select 1 from storage.objects o where o.bucket_id='sectalk-exports' and o.name=a.id::text)
    returning 1
  ) select exists(select 1 from updated)
$$;

create function public.st_v6_get_export_object(p_artifact uuid,p_actor uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('kind',a.kind,'scope_id',a.scope_id,'period',a.period,'filename',a.filename,
    'media_type',a.media_type,'bytes',a.bytes,'sha256',a.sha256)
  from sectalk_private.st_v6_export_objects a
  where a.id=p_artifact and a.actor_id=p_actor and a.ready and a.expires_at>now()
$$;

create function public.st_v6_claim_export_cleanup()
returns table(id uuid,lease uuid) language sql security definer set search_path='' as $$
  with candidates as (
    select a.id from sectalk_private.st_v6_export_objects a where a.expires_at<=clock_timestamp()
      and (a.lease_until is null or a.lease_until<=clock_timestamp())
    order by a.expires_at,a.id limit 20 for update skip locked
  )
  update sectalk_private.st_v6_export_objects a
  set lease=gen_random_uuid(),lease_until=clock_timestamp()+interval '2 minutes'
  from candidates where candidates.id=a.id returning a.id,a.lease
$$;

create function public.st_v6_finish_export_cleanup(p_artifact uuid,p_lease uuid)
returns boolean language sql security definer set search_path='' as $$
  with deleted as (
    delete from sectalk_private.st_v6_export_objects a where a.id=p_artifact and a.lease=p_lease
      and not exists(select 1 from storage.objects o where o.bucket_id='sectalk-exports' and o.name=a.id::text)
    returning 1
  ) select exists(select 1 from deleted)
$$;

revoke all on function public.st_v6_begin_export_object(uuid,text,uuid,text,text,text,integer,text),
  public.st_v6_finish_export_object(uuid), public.st_v6_get_export_object(uuid,uuid), public.st_v6_claim_export_cleanup(),
  public.st_v6_finish_export_cleanup(uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_begin_export_object(uuid,text,uuid,text,text,text,integer,text),
  public.st_v6_finish_export_object(uuid), public.st_v6_get_export_object(uuid,uuid), public.st_v6_claim_export_cleanup(),
  public.st_v6_finish_export_cleanup(uuid,uuid) to service_role;

commit;
