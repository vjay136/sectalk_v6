begin;

create table sectalk_private.st_v6_tenant_operators (
  account_id uuid primary key references public.st_profiles on delete cascade
);

create table sectalk_private.st_v6_tenant_access_log (
  id bigint generated always as identity primary key,
  actor uuid not null,
  action text not null check (action in ('search','view')),
  workspace_id uuid,
  created_at timestamptz not null default clock_timestamp(),
  check ((action='view')=(workspace_id is not null))
);

alter table sectalk_private.st_v6_tenant_operators enable row level security;
alter table sectalk_private.st_v6_tenant_access_log enable row level security;
revoke all on sectalk_private.st_v6_tenant_operators,sectalk_private.st_v6_tenant_access_log
  from public,anon,authenticated;

create index st_v6_tenant_name_lookup
  on public.st_v2_workspaces ((lower(name) collate "C"),id);

create function public.st_v6_tenant_operations_status()
returns text language sql stable security definer set search_path='' as $$
  select case
    when not exists (
      select 1 from sectalk_private.st_v6_tenant_operators where account_id=auth.uid()
    ) or sectalk_private.st_v2_active(auth.uid()) is not true then 'none'
    when auth.jwt()->>'aal'='aal2' and exists (
      select 1 from auth.sessions s join auth.mfa_factors f
        on f.id=s.factor_id and f.user_id=s.user_id
      where s.id=(auth.jwt()->>'session_id')::uuid and s.user_id=auth.uid()
        and s.aal='aal2' and (s.not_after is null or s.not_after>now())
        and f.status='verified' and f.factor_type='totp'
    ) then 'verified'
    else 'mfa'
  end
$$;

create function public.st_v6_tenant_search(p_query text)
returns table(id uuid,name text,created_at timestamptz)
language plpgsql security definer set search_path='' as $$
declare
  query text;
  prefix text;
begin
  if public.st_v6_tenant_operations_status()<>'verified' then
    raise exception 'Verified tenant operator access required' using errcode='42501';
  end if;
  if p_query is null or length(p_query)>64 or length(btrim(p_query))<2 then
    raise exception 'Enter a workspace ID or 2 to 64 characters of its name' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v6_tenant_lookup',60);
  insert into sectalk_private.st_v6_tenant_access_log(actor,action) values(auth.uid(),'search');

  query := lower(btrim(p_query));
  if query ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$' then
    return query select w.id,w.name,w.created_at from public.st_v2_workspaces w where w.id=query::uuid;
    return;
  end if;
  prefix := replace(replace(replace(query,chr(92),chr(92)||chr(92)),'%',chr(92)||'%'),'_',chr(92)||'_');
  return query select w.id,w.name,w.created_at from public.st_v2_workspaces w
    where lower(w.name) collate "C" like prefix||'%'
    order by lower(w.name) collate "C",w.id limit 25;
end
$$;

create function public.st_v6_tenant_view(p_workspace uuid)
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
  return query select w.id,w.name,w.created_at,
    (select count(*) from public.st_v2_members m where m.workspace_id=w.id)
    from public.st_v2_workspaces w where w.id=p_workspace;
end
$$;

revoke all on function public.st_v6_tenant_operations_status(),
  public.st_v6_tenant_search(text),public.st_v6_tenant_view(uuid) from public,anon,authenticated;
grant execute on function public.st_v6_tenant_operations_status(),
  public.st_v6_tenant_search(text),public.st_v6_tenant_view(uuid) to authenticated;

commit;
