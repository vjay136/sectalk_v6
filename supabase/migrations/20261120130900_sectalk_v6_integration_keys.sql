begin;

create table sectalk_private.st_v6_integration_keys (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  created_by uuid not null,
  label text not null check (char_length(btrim(label)) between 1 and 48),
  display_prefix text not null check (display_prefix ~ '^[A-Za-z0-9_-]{10}$'),
  digest bytea not null unique check(octet_length(digest)=32),
  scopes text[] not null check(cardinality(scopes) between 1 and 2
    and scopes <@ array['workspace:read','rooms:read']::text[]),
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  revoked_at timestamptz
);
create index st_v6_integration_keys_workspace on sectalk_private.st_v6_integration_keys(workspace_id,created_at desc);
create index st_v6_api_rooms_visible on public.st_v6_rooms(workspace_id,id)
  where kind='public' and classification in ('public','internal') and not archived;
create table sectalk_private.st_v6_api_rate (
  key_id uuid not null references sectalk_private.st_v6_integration_keys on delete cascade,
  minute timestamptz not null,
  requests integer not null,
  primary key (key_id,minute)
);
alter table sectalk_private.st_v6_integration_keys enable row level security;
alter table sectalk_private.st_v6_api_rate enable row level security;
revoke all on sectalk_private.st_v6_integration_keys,sectalk_private.st_v6_api_rate
  from public,anon,authenticated,service_role;

create function public.st_v6_integration_access(p_workspace uuid)
returns text language sql stable security definer set search_path='' as $$
  select case
    when sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner'
      or not coalesce(sectalk_private.st_v2_active(auth.uid()),false) then 'none'
    when sectalk_private.st_v2_effective_plan(auth.uid()) not in ('business','enterprise') then 'upgrade'
    when sectalk_private.st_v6_holds_access(p_workspace)='verified'
      and exists(select from auth.mfa_amr_claims p where p.session_id::text=auth.jwt()->>'session_id'
        and p.authentication_method='totp' and p.updated_at>now()-interval '10 minutes') then 'verified'
    else 'mfa'
  end
$$;

create function public.st_v6_integration_key_list(p_workspace uuid)
returns table(id uuid,label text,display_prefix text,scopes text[],created_at timestamptz,expires_at timestamptz,revoked_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
begin
  if public.st_v6_integration_access(p_workspace)<>'verified' then
    raise exception using errcode='42501',message='Fresh integration administrator verification required';
  end if;
  return query select k.id,k.label,k.display_prefix,k.scopes,k.created_at,k.expires_at,k.revoked_at
    from sectalk_private.st_v6_integration_keys k where k.workspace_id=p_workspace
    order by k.created_at desc,k.id limit 100;
end $$;

create function public.st_v6_create_integration_key(p_workspace uuid,p_label text,p_prefix text,p_digest text,p_scopes text[],p_lifetime_days integer)
returns uuid language plpgsql security definer set search_path='' as $$
declare created uuid;
begin
  if public.st_v6_integration_access(p_workspace)<>'verified' then
    raise exception using errcode='42501',message='Fresh integration administrator verification required';
  end if;
  if char_length(btrim(coalesce(p_label,''))) not between 1 and 48
    or (p_prefix ~ '^[A-Za-z0-9_-]{10}$') is not true or (p_digest ~ '^[a-f0-9]{64}$') is not true
    or (p_lifetime_days between 1 and 365) is not true
    or (cardinality(p_scopes) between 1 and 2 and p_scopes <@ array['workspace:read','rooms:read']::text[]) is not true then
    raise exception using errcode='22023',message='Choose a label, API scopes and expiry';
  end if;
  perform sectalk_private.limit_action('v6_api_key_create',12);
  perform 1 from public.st_v2_workspaces where id=p_workspace for update;
  if public.st_v6_integration_access(p_workspace)<>'verified' then
    raise exception using errcode='42501',message='Integration access changed';
  end if;
  if (select count(*) from sectalk_private.st_v6_integration_keys k
    where k.workspace_id=p_workspace and k.revoked_at is null and k.expires_at>now())>=20 then
    raise exception using errcode='22023',message='The workspace has reached its active API key limit';
  end if;
  insert into sectalk_private.st_v6_integration_keys(workspace_id,created_by,label,display_prefix,digest,scopes,expires_at)
    values(p_workspace,auth.uid(),btrim(p_label),p_prefix,decode(p_digest,'hex'),
      array(select distinct value from unnest(p_scopes) valueset(value) order by value),now()+make_interval(days=>p_lifetime_days))
    returning id into created;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,auth.uid(),'integration.key_created',created);
  return created;
end $$;

create function public.st_v6_revoke_integration_key(p_workspace uuid,p_key uuid)
returns void language plpgsql security definer set search_path='' as $$
begin
  if public.st_v6_integration_access(p_workspace)<>'verified' then
    raise exception using errcode='42501',message='Fresh integration administrator verification required';
  end if;
  update sectalk_private.st_v6_integration_keys
    set revoked_at=clock_timestamp() where id=p_key and workspace_id=p_workspace and revoked_at is null;
  if found then insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,auth.uid(),'integration.key_revoked',p_key);
  end if;
end $$;

create function public.st_v6_integration_read(p_digest text,p_resource text,p_after uuid,p_limit integer)
returns jsonb language plpgsql security definer set search_path='' as $$
declare api_key sectalk_private.st_v6_integration_keys; tenant public.st_v2_workspaces; result jsonb; used integer;
begin
  if (p_digest ~ '^[a-f0-9]{64}$') is not true or (p_resource in ('workspace','rooms')) is not true
    or (p_limit between 1 and 100) is not true then
    raise exception using errcode='22023',message='Invalid API request';
  end if;
  select * into api_key from sectalk_private.st_v6_integration_keys k where k.digest=decode(p_digest,'hex')
    and k.revoked_at is null and k.expires_at>now() for share;
  if not found then raise exception using errcode='PT401',message='Invalid API key'; end if;
  select * into tenant from public.st_v2_workspaces w where w.id=api_key.workspace_id;
  if not found or tenant.owner is distinct from api_key.created_by or sectalk_private.st_v2_active(tenant.owner) is not true
    or sectalk_private.st_v2_effective_plan(tenant.owner) not in ('business','enterprise')
    or not (p_resource||':read'=any(api_key.scopes)) then
    raise exception using errcode='42501',message='API key scope is unavailable';
  end if;
  insert into sectalk_private.st_v6_api_rate as budget(key_id,minute,requests)
    values(api_key.id,date_trunc('minute',statement_timestamp()),1)
    on conflict(key_id,minute) do update set requests=budget.requests+1 where budget.requests<120
    returning requests into used;
  if used is null then raise exception using errcode='PT429',message='API request limit reached'; end if;
  if p_resource='workspace' then
    return jsonb_build_object('data',jsonb_build_object('id',tenant.id,'name',tenant.name,'created_at',tenant.created_at));
  end if;
  select jsonb_build_object('data',coalesce(jsonb_agg(jsonb_build_object('id',page.id,'name',page.name,'created_at',page.created_at)
    order by page.id) filter(where page.position<=p_limit),'[]'::jsonb),
    'next_cursor',case when count(*)>p_limit then (array_agg(page.id order by page.id))[p_limit] end)
  into result from (
    select r.id,r.name,r.created_at,row_number() over(order by r.id) position from public.st_v6_rooms r
    where r.workspace_id=tenant.id and r.kind='public' and r.classification in ('public','internal') and not r.archived
      and (p_after is null or r.id>p_after)
    order by r.id limit p_limit+1
  ) page;
  return result;
end $$;

revoke all on function public.st_v6_integration_access(uuid),public.st_v6_integration_key_list(uuid),
  public.st_v6_create_integration_key(uuid,text,text,text,text[],integer),public.st_v6_revoke_integration_key(uuid,uuid),
  public.st_v6_integration_read(text,text,uuid,integer) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_integration_access(uuid),public.st_v6_integration_key_list(uuid),
  public.st_v6_create_integration_key(uuid,text,text,text,text[],integer),public.st_v6_revoke_integration_key(uuid,uuid) to authenticated;
grant execute on function public.st_v6_integration_read(text,text,uuid,integer) to service_role;
select cron.schedule('sectalk-v6-prune-api-rate','17 4 * * *',
  $job$delete from sectalk_private.st_v6_api_rate where minute<now()-interval '1 day'$job$);
notify pgrst,'reload schema';
commit;
