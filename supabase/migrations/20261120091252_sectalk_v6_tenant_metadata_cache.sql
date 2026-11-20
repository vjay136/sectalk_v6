begin;

-- This cache can hold only non-content aggregate counts.
create unlogged table sectalk_private.st_v6_tenant_metadata_cache (
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  metric text not null check(metric='member_count'),
  schema_version smallint not null check(schema_version>0),
  value bigint not null check(value>=0),
  expires_at timestamptz not null,
  primary key(workspace_id,metric,schema_version)
);
alter table sectalk_private.st_v6_tenant_metadata_cache enable row level security;
revoke all on sectalk_private.st_v6_tenant_metadata_cache from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_cached_member_count(p_workspace uuid)
returns bigint language plpgsql set search_path='' as $$
declare result bigint;
begin
  select c.value into result from sectalk_private.st_v6_tenant_metadata_cache c
  where c.workspace_id=p_workspace and c.metric='member_count' and c.schema_version=1
    and c.expires_at>clock_timestamp();
  if found then return result; end if;

  -- Share the workspace lock used by membership mutations, so a roster
  -- update cannot invalidate the cache just before an older fill arrives.
  perform w.id from public.st_v2_workspaces w where w.id=p_workspace for share;
  if not found then return null; end if;
  select count(*) into result from public.st_v2_members m where m.workspace_id=p_workspace;
  insert into sectalk_private.st_v6_tenant_metadata_cache(workspace_id,metric,schema_version,value,expires_at)
    values(p_workspace,'member_count',1,result,clock_timestamp()+interval '10 seconds')
  on conflict(workspace_id,metric,schema_version) do update
    set value=excluded.value,expires_at=excluded.expires_at
    where st_v6_tenant_metadata_cache.expires_at<=clock_timestamp();
  return result;
end
$$;

create function sectalk_private.st_v6_invalidate_member_count()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if tg_op<>'INSERT' then
    delete from sectalk_private.st_v6_tenant_metadata_cache where workspace_id=old.workspace_id and metric='member_count';
  end if;
  if tg_op<>'DELETE' then
    delete from sectalk_private.st_v6_tenant_metadata_cache where workspace_id=new.workspace_id and metric='member_count';
  end if;
  return null;
end
$$;
create trigger st_v6_invalidate_member_count
after insert or delete or update of workspace_id on public.st_v2_members
for each row execute function sectalk_private.st_v6_invalidate_member_count();

create or replace function public.st_v6_tenant_view(p_workspace uuid)
returns table(id uuid,name text,created_at timestamptz,member_count bigint)
language plpgsql security definer set search_path='' as $$
begin
  if public.st_v6_tenant_operations_status()<>'verified' then
    raise exception 'Verified tenant operator access required' using errcode='42501';
  end if;
  if p_workspace is null then raise exception 'Choose a workspace' using errcode='22023'; end if;
  perform sectalk_private.limit_action('v6_tenant_lookup',60);
  insert into sectalk_private.st_v6_tenant_access_log(actor,action,workspace_id)
    values(auth.uid(),'view',p_workspace);
  return query select w.id,w.name,w.created_at,sectalk_private.st_v6_cached_member_count(w.id)
    from public.st_v2_workspaces w where w.id=p_workspace;
end
$$;

revoke all on function sectalk_private.st_v6_cached_member_count(uuid),sectalk_private.st_v6_invalidate_member_count()
  from public,anon,authenticated,service_role;
commit;
