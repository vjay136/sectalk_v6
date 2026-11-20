begin;

create table public.st_v4_task_assignments (
  task_id uuid primary key references public.st_v2_items on delete cascade,
  assignee uuid not null references public.st_profiles on delete cascade
);
create index st_v4_assignee_lookup on public.st_v4_task_assignments(assignee,task_id);

create table public.st_v4_checklist (
  id uuid primary key default gen_random_uuid(),
  task_id uuid not null references public.st_v2_items on delete cascade,
  label text not null check(char_length(btrim(label)) between 1 and 150),
  completed boolean not null default false,
  created_at timestamptz not null default now()
);
create index st_v4_checklist_task on public.st_v4_checklist(task_id,created_at,id);

alter table public.st_v4_task_assignments enable row level security;
alter table public.st_v4_checklist enable row level security;
revoke all on public.st_v4_task_assignments,public.st_v4_checklist from public,anon,authenticated;
grant select on public.st_v4_task_assignments,public.st_v4_checklist to authenticated;
create policy st_v4_assignment_read on public.st_v4_task_assignments for select to authenticated
  using(exists(select 1 from public.st_v2_items t where t.id=task_id and t.kind='task'));
create policy st_v4_checklist_read on public.st_v4_checklist for select to authenticated
  using(exists(select 1 from public.st_v2_items t where t.id=task_id and t.kind='task'));

create function public.st_v4_task_change(p_task uuid,p_action text,p_person uuid default null,p_item uuid default null,p_label text default null,p_done boolean default null)
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

revoke all on function public.st_v4_task_change(uuid,text,uuid,uuid,text,boolean) from public,anon,authenticated;
grant execute on function public.st_v4_task_change(uuid,text,uuid,uuid,text,boolean) to authenticated;
commit;
