begin;

create table public.st_v6_workspace_groups (
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  id uuid not null,
  kind text not null check(kind in ('group','team','department')),
  name text not null check(char_length(btrim(name)) between 1 and 80),
  description text not null default '' check(char_length(description)<=500),
  archived_at timestamptz,
  primary key(workspace_id,id)
);
create unique index st_v6_workspace_group_names on public.st_v6_workspace_groups(workspace_id,kind,lower(name));

create table public.st_v6_workspace_group_members (
  workspace_id uuid not null,
  group_id uuid not null,
  user_id uuid not null,
  primary key(workspace_id,group_id,user_id),
  foreign key(workspace_id,group_id) references public.st_v6_workspace_groups(workspace_id,id) on delete cascade,
  foreign key(workspace_id,user_id) references public.st_v2_members(workspace_id,user_id) on delete cascade
);
create index st_v6_workspace_group_members_user on public.st_v6_workspace_group_members(workspace_id,user_id);

alter table public.st_v6_workspace_groups enable row level security;
alter table public.st_v6_workspace_group_members enable row level security;
revoke all on public.st_v6_workspace_groups,public.st_v6_workspace_group_members from public,anon,authenticated;
grant select on public.st_v6_workspace_groups,public.st_v6_workspace_group_members to authenticated;

create function sectalk_private.st_v6_group_directory_access(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v2_active(auth.uid())
    and sectalk_private.st_v2_role(p_workspace,auth.uid()) is not null
$$;
revoke all on function sectalk_private.st_v6_group_directory_access(uuid) from public,anon,authenticated;
grant execute on function sectalk_private.st_v6_group_directory_access(uuid) to authenticated;

create policy st_v6_workspace_groups_read on public.st_v6_workspace_groups for select to authenticated
  using(sectalk_private.st_v6_group_directory_access(workspace_id));
create policy st_v6_workspace_group_members_read on public.st_v6_workspace_group_members for select to authenticated
  using(sectalk_private.st_v6_group_directory_access(workspace_id));

create function public.st_v6_workspace_group_create(p_workspace uuid,p_id uuid,p_kind text,p_name text,p_description text)
returns uuid language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  display_name text:=btrim(p_name);
  summary text:=btrim(coalesce(p_description,''));
begin
  perform sectalk_private.limit_action('v6_group_create',10);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor) then raise exception 'Workspace action unavailable'; end if;
  if p_id is null or p_kind is null or p_kind not in ('group','team','department')
    or display_name is null or char_length(display_name) not between 1 and 80 or char_length(summary)>500
    then raise exception 'Choose a valid type, name, and description'; end if;
  if exists(select 1 from public.st_v6_workspace_groups where workspace_id=p_workspace and id=p_id
    and kind=p_kind and name=display_name and description=summary) then return p_id; end if;
  if exists(select 1 from public.st_v6_workspace_groups where workspace_id=p_workspace and kind=p_kind and lower(name)=lower(display_name))
    then raise exception 'This workspace already has that name for the selected type'; end if;
  insert into public.st_v6_workspace_groups(workspace_id,id,kind,name,description)
    values(p_workspace,p_id,p_kind,display_name,summary);
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(p_workspace,actor,'group.created',p_id);
  return p_id;
end $$;

create function public.st_v6_workspace_group_change(p_workspace uuid,p_id uuid,p_action text,
  p_name text default null,p_description text default null,p_user uuid default null)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  item public.st_v6_workspace_groups;
  display_name text:=btrim(p_name);
  summary text:=btrim(coalesce(p_description,''));
begin
  perform sectalk_private.limit_action('v6_group_change',30);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor) then raise exception 'Workspace action unavailable'; end if;
  select * into item from public.st_v6_workspace_groups where workspace_id=p_workspace and id=p_id;
  if not found then raise exception 'Workspace group unavailable'; end if;
  if item.archived_at is not null and p_action not in ('archive','restore') then
    raise exception 'Restore this entry before making changes'; end if;
  case p_action
    when 'rename' then
      if display_name is null or char_length(display_name) not between 1 and 80 or char_length(summary)>500
        then raise exception 'Choose a valid name and description'; end if;
      if exists(select 1 from public.st_v6_workspace_groups where workspace_id=p_workspace and id<>p_id
        and kind=item.kind and lower(name)=lower(display_name)) then raise exception 'That name is already in use'; end if;
      update public.st_v6_workspace_groups set name=display_name,description=summary where workspace_id=p_workspace and id=p_id
        and (name,description) is distinct from (display_name,summary);
    when 'archive' then
      update public.st_v6_workspace_groups set archived_at=clock_timestamp()
        where workspace_id=p_workspace and id=p_id and archived_at is null;
    when 'restore' then
      update public.st_v6_workspace_groups set archived_at=null where workspace_id=p_workspace and id=p_id and archived_at is not null;
    when 'member_added' then
      if p_user is null or sectalk_private.st_v2_role(p_workspace,p_user) is null or not sectalk_private.st_v2_active(p_user)
        then raise exception 'Choose a current workspace member'; end if;
      insert into public.st_v6_workspace_group_members(workspace_id,group_id,user_id)
        values(p_workspace,p_id,p_user) on conflict do nothing;
    when 'member_removed' then
      delete from public.st_v6_workspace_group_members where workspace_id=p_workspace and group_id=p_id and user_id=p_user;
    else raise exception 'Unsupported workspace group action';
  end case;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,'group.'||p_action,p_id);
  end if;
end $$;

revoke all on function public.st_v6_workspace_group_create(uuid,uuid,text,text,text),
  public.st_v6_workspace_group_change(uuid,uuid,text,text,text,uuid) from public,anon,authenticated;
grant execute on function public.st_v6_workspace_group_create(uuid,uuid,text,text,text),
  public.st_v6_workspace_group_change(uuid,uuid,text,text,text,uuid) to authenticated;

commit;
