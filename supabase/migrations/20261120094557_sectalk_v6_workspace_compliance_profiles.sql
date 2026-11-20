begin;

create table public.st_v6_compliance_profiles (
  id text primary key,
  label text not null,
  sort_order integer unique not null,
  room_kinds text[] not null,
  invite_hours integer not null check (invite_hours between 1 and 168),
  require_domains boolean not null,
  individual_admission boolean not null
);
insert into public.st_v6_compliance_profiles values
  ('healthcare','Healthcare',1,array['private','admin'],24,true,true),
  ('education','Education',2,array['private','admin','announcement'],72,true,true),
  ('finance','Finance',3,array['private','admin'],24,true,true),
  ('gdpr','GDPR-style privacy',4,array['private','admin','announcement'],168,true,false);
alter table public.st_v6_compliance_profiles enable row level security;
revoke all on public.st_v6_compliance_profiles from public,anon,authenticated;
grant select on public.st_v6_compliance_profiles to authenticated;
create policy st_v6_compliance_profiles_read on public.st_v6_compliance_profiles
  for select to authenticated using (true);

alter table public.st_v6_workspace_policy add column compliance_profile text
  references public.st_v6_compliance_profiles(id);
create index st_v6_workspace_policy_profile_idx on public.st_v6_workspace_policy(compliance_profile)
  where compliance_profile is not null;
grant select(compliance_profile) on public.st_v6_workspace_policy to authenticated;

create function public.st_v6_create_profiled_workspace(p_id uuid,p_name text,p_type text,p_profile text)
returns uuid language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  preset public.st_v6_compliance_profiles;
  existing public.st_v6_workspace_policy;
  workspace uuid;
begin
  if not sectalk_private.st_v2_active(actor) then raise exception 'Workspace access is restricted'; end if;
  select * into preset from public.st_v6_compliance_profiles where id=p_profile;
  if not found then raise exception 'Choose a compliance profile'; end if;
  perform id from public.st_profiles where id=actor for update;
  select * into existing from public.st_v6_workspace_policy where created_by=actor and request_id=p_id;
  if found and existing.compliance_profile is distinct from preset.id then
    raise exception 'Workspace setup request ID is already in use';
  end if;
  workspace:=public.st_v6_create_typed_workspace(p_id,p_name,p_type);
  if existing.workspace_id is not null then return workspace; end if;

  update public.st_v6_workspace_policy p
    set compliance_profile=preset.id,
        room_kinds=array(select kind from unnest(p.room_kinds) kind where kind=any(preset.room_kinds)),
        bulk_admit=p.bulk_admit and not preset.individual_admission
    where p.workspace_id=workspace;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(workspace,actor,'workspace.compliance_profile_initialized',workspace);
  return workspace;
end
$$;
revoke all on function public.st_v6_create_profiled_workspace(uuid,text,text,text)
  from public,anon,authenticated;
grant execute on function public.st_v6_create_profiled_workspace(uuid,text,text,text) to authenticated;

create or replace function sectalk_private.st_v6_link_domain_allowed(p_workspace uuid,p_email text)
returns boolean language sql stable set search_path='' as $$
  select case
    when coalesce(cardinality(lp.domains),0)>0 then split_part(p_email,'@',2)=any(lp.domains)
    else not coalesce(cp.require_domains,false)
  end
  from (values(p_workspace)) target(workspace_id)
  left join sectalk_private.st_v6_workspace_link_policy lp using(workspace_id)
  left join public.st_v6_workspace_policy wp using(workspace_id)
  left join public.st_v6_compliance_profiles cp on cp.id=wp.compliance_profile
$$;

create function sectalk_private.st_v6_compliance_link_expiry()
returns trigger language plpgsql security definer set search_path='' as $$
declare max_hours integer;
begin
  select cp.invite_hours into max_hours
    from public.st_v6_workspace_policy p join public.st_v6_compliance_profiles cp on cp.id=p.compliance_profile
    where p.workspace_id=new.workspace_id;
  if found and new.expires_at>clock_timestamp()+make_interval(hours=>max_hours) then
    raise exception 'Invitation exceeds this workspace profile expiration limit';
  end if;
  return new;
end
$$;
revoke all on function sectalk_private.st_v6_compliance_link_expiry() from public,anon,authenticated;
create trigger st_v6_compliance_link_expiry before insert on sectalk_private.st_v6_workspace_link_invites
  for each row execute function sectalk_private.st_v6_compliance_link_expiry();

commit;
