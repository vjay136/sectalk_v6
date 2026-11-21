begin;

create table sectalk_private.st_v8_workspace_planner_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_planner_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_planner_sso from public,anon,authenticated,service_role;

-- This policy applies to current-caller planner requests. Workspace role and
-- cross-user task audience checks keep their own worker and assignee semantics.
create function sectalk_private.st_v8_planner_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_planner_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_planner_sso_allows(uuid) from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v8_planner_sso_allows(uuid) to authenticated;

create function public.st_v8_workspace_planner_requires_sso(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v2_active(auth.uid())
    and sectalk_private.st_v2_role(p_workspace,auth.uid()) is not null
    and not sectalk_private.st_v8_planner_sso_allows(p_workspace);
$$;

create function public.st_v8_workspace_planner_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_planner_sso_policy',5);
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
      raise insufficient_privilege;
    end if;
    if p_require then
      select * into setup from sectalk_private.st_v7_workspace_sso c where c.workspace=p_workspace;
      if not found or sectalk_private.st_v7_workspace_sso_provider(p_workspace,setup.domain,setup.protocol)
        is distinct from setup.provider or not exists(
          select 1 from sectalk_private.st_v7_workspace_sso_sessions r join auth.sessions s on (s.id,s.user_id)=(r.session,r.principal)
          where r.workspace=p_workspace and (r.protocol,r.provider)=(setup.protocol,setup.provider)
            and sectalk_private.st_v2_active(r.principal) and sectalk_private.st_v2_role(p_workspace,r.principal) is not null
            and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
        ) then return '{"access":"verified","error":"verified_provider_session_required"}'; end if;
      insert into sectalk_private.st_v8_workspace_planner_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_planner_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.planner_sso_required'
          else 'workspace.planner_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_planner_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_planner_policy(uuid,boolean),
  public.st_v8_workspace_planner_requires_sso(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_planner_policy(uuid,boolean),
  public.st_v8_workspace_planner_requires_sso(uuid) to authenticated;

create policy st_v8_planner_sso on public.st_v2_items as restrictive for select to authenticated
  using(sectalk_private.st_v8_planner_sso_allows(workspace_id));

create or replace function public.st_v2_add_item(p_workspace uuid,p_kind text,p_title text,p_details text,p_due timestamptz)
returns uuid language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); member_role text; item uuid;
begin
  perform sectalk_private.limit_action('v2_item',20);
  member_role:=sectalk_private.st_v2_role(p_workspace,me);
  if member_role is null or not sectalk_private.st_v2_active(me)
    or p_kind='announcement' and member_role not in ('owner','admin') then raise exception 'Workspace action unavailable'; end if;
  if not sectalk_private.st_v8_planner_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to create a board or calendar item' using errcode='42501';
  end if;
  insert into public.st_v2_items(workspace_id,kind,title,details,due_at,created_by)
    values(p_workspace,p_kind,btrim(p_title),btrim(coalesce(p_details,'')),p_due,me) returning id into item;
  return item;
end $$;

create or replace function public.st_v2_complete_task(p_item uuid,p_complete boolean)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('v2_task',30);
  update public.st_v2_items set completed=p_complete where id=p_item and kind='task'
    and sectalk_private.st_v2_role(workspace_id,auth.uid()) is not null and sectalk_private.st_v2_active(auth.uid())
    and sectalk_private.st_v8_planner_sso_allows(workspace_id);
  if not found then raise exception 'Task unavailable'; end if;
end $$;

create or replace function public.st_v4_task_change(p_task uuid,p_action text,p_person uuid default null,p_item uuid default null,p_label text default null,p_done boolean default null)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  task public.st_v2_items;
  member_role text;
  assigned uuid;
begin
  if actor is null then raise exception 'Sign in first'; end if;
  perform sectalk_private.limit_action('v4_task_change',60);
  select * into task from public.st_v2_items where id=p_task and kind='task' for update;
  member_role:=sectalk_private.st_v2_role(task.workspace_id,actor);
  if member_role is null or not sectalk_private.st_v2_active(actor)
    then raise exception 'Task action unavailable'; end if;
  if not sectalk_private.st_v8_planner_sso_allows(task.workspace_id) then
    raise exception 'Sign in through your workspace provider to update this task' using errcode='42501';
  end if;
  select assignee into assigned from public.st_v4_task_assignments where task_id=p_task;
  if p_action='assign' then
    if task.created_by<>actor and member_role not in ('owner','admin') then raise exception 'Task assignment is restricted'; end if;
    if p_person is null then
      delete from public.st_v4_task_assignments where task_id=p_task;
    else
      if sectalk_private.st_v2_role(task.workspace_id,p_person) is null then raise exception 'Choose a workspace member'; end if;
      insert into public.st_v4_task_assignments(task_id,assignee) values(p_task,p_person)
        on conflict(task_id) do update set assignee=excluded.assignee;
    end if;
  elsif p_action in ('checklist.add','checklist.toggle','complete') then
    if task.created_by<>actor and actor is distinct from assigned and member_role not in ('owner','admin')
      then raise exception 'Task editing is restricted'; end if;
    if p_action='checklist.add' then
      if p_item is null or p_label is null or char_length(btrim(p_label)) not between 1 and 150 then raise exception 'Enter a checklist label'; end if;
      if exists(select 1 from public.st_v4_checklist where id=p_item and task_id=p_task and label=btrim(p_label)) then return; end if;
      if (select count(*) from public.st_v4_checklist where task_id=p_task)>=30 then raise exception 'Checklist limit reached'; end if;
      insert into public.st_v4_checklist(id,task_id,label) values(p_item,p_task,btrim(p_label));
    elsif p_action='checklist.toggle' then
      if p_done is null then raise exception 'Choose a checklist state'; end if;
      update public.st_v4_checklist set completed=p_done where id=p_item and task_id=p_task;
      if not found then raise exception 'Checklist item unavailable'; end if;
    else
      if p_done is null then raise exception 'Choose a task state'; end if;
      update public.st_v2_items set completed=p_done where id=p_task;
    end if;
  else
    raise exception 'Unsupported task action';
  end if;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(task.workspace_id,actor,'task.'||p_action,p_task);
end $$;

create or replace function sectalk_private.st_v6_task_can_read(p_id uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v6_tasks t where t.id=p_id
    and sectalk_private.st_v6_task_audience(t.room_id,t.chat_id,auth.uid())
    and (t.room_id is null or exists(select 1 from public.st_v6_rooms r where r.id=t.room_id
      and sectalk_private.st_v8_planner_sso_allows(r.workspace_id))))
$$;

create or replace function sectalk_private.st_v6_task_scope_write(p_room uuid,p_chat uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce(sectalk_private.st_v6_task_audience(p_room,p_chat,auth.uid())
    and (p_room is null or (sectalk_private.st_v6_room_role(p_room) <> 'read_only'
      and exists(select 1 from public.st_v6_rooms r where r.id=p_room and not r.archived
        and sectalk_private.st_v8_planner_sso_allows(r.workspace_id) and (
        (not r.locked and r.kind not in ('announcement','broadcast'))
        or sectalk_private.st_v6_room_role(p_room) in ('owner','moderator')))
      and not exists(select 1 from public.st_v6_room_timeouts r where r.room_id=p_room and r.user_id=auth.uid() and r.until_at>now()))),false)
$$;

commit;
