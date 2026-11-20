begin;

create table sectalk_private.st_v6_impersonation_watch (
  workspace_id uuid not null,
  member_id uuid not null,
  tier text not null check(tier in ('executive','vip')),
  updated_at timestamptz not null default clock_timestamp(),
  primary key(workspace_id,member_id),
  foreign key(workspace_id,member_id) references public.st_v2_members(workspace_id,user_id) on delete cascade
);
alter table sectalk_private.st_v6_impersonation_watch enable row level security;
revoke all on sectalk_private.st_v6_impersonation_watch from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_impersonation_watch_list(p_workspace uuid)
returns table(member_id uuid,tier text)
language plpgsql stable security definer set search_path='' as $$
begin
  if not coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(auth.uid())
  then raise exception 'Watch list unavailable' using errcode='42501'; end if;
  return query
    select w.member_id,w.tier from sectalk_private.st_v6_impersonation_watch w
    where w.workspace_id=p_workspace order by w.updated_at,w.member_id;
end
$$;

create function sectalk_private.st_v6_set_impersonation_watch(p_workspace uuid,p_member uuid,p_tier text)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor)
  then raise exception 'Watch list unavailable' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v6_impersonation_watch',20);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor)
  then raise exception 'Watch list unavailable' using errcode='42501'; end if;
  if p_tier is null then
    delete from sectalk_private.st_v6_impersonation_watch where workspace_id=p_workspace and member_id=p_member;
  else
    if p_tier not in ('executive','vip') or sectalk_private.st_v2_role(p_workspace,p_member) is null
      or not sectalk_private.st_v2_active(p_member)
    then raise exception 'Choose an active workspace member and watch category'; end if;
    if not exists(select 1 from sectalk_private.st_v6_impersonation_watch where workspace_id=p_workspace and member_id=p_member)
      and (select count(*) from sectalk_private.st_v6_impersonation_watch where workspace_id=p_workspace)>=100
    then raise exception 'This workspace watch list is full'; end if;
    insert into sectalk_private.st_v6_impersonation_watch(workspace_id,member_id,tier)
      values(p_workspace,p_member,p_tier) on conflict(workspace_id,member_id) do update
      set tier=excluded.tier,updated_at=clock_timestamp()
      where st_v6_impersonation_watch.tier is distinct from excluded.tier;
  end if;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,case when p_tier is null then 'impersonation.watch_removed' else 'impersonation.watch_saved' end,p_member);
  end if;
end
$$;

create function public.st_v6_impersonation_watch_list(p_workspace uuid)
returns table(member_id uuid,tier text) language sql stable set search_path='' begin atomic
  select * from sectalk_private.st_v6_impersonation_watch_list(p_workspace);
end;

create function public.st_v6_set_impersonation_watch(p_workspace uuid,p_member uuid,p_tier text)
returns void language sql set search_path=''
return sectalk_private.st_v6_set_impersonation_watch(p_workspace,p_member,p_tier);

revoke all on function sectalk_private.st_v6_impersonation_watch_list(uuid),
  sectalk_private.st_v6_set_impersonation_watch(uuid,uuid,text),
  public.st_v6_impersonation_watch_list(uuid), public.st_v6_set_impersonation_watch(uuid,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v6_impersonation_watch_list(uuid),
  sectalk_private.st_v6_set_impersonation_watch(uuid,uuid,text),
  public.st_v6_impersonation_watch_list(uuid), public.st_v6_set_impersonation_watch(uuid,uuid,text)
  to authenticated;

commit;
