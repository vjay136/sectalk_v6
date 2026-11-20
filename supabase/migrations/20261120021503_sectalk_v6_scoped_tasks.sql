begin;

create table public.st_v6_tasks (
  id uuid primary key,
  room_id uuid references public.st_v6_rooms on delete cascade,
  chat_id uuid references public.st_chats on delete cascade,
  author_id uuid not null references public.st_profiles,
  title text not null check(char_length(title) between 1 and 120),
  status text not null default 'todo' check(status in ('todo','in_progress','blocked','done','cancelled')),
  priority text not null default 'normal' check(priority in ('low','normal','high','urgent')),
  labels text[] not null default '{}' check(cardinality(labels)<=8),
  due_at timestamptz,
  created_at timestamptz not null default clock_timestamp(),
  updated_at timestamptz not null default clock_timestamp(),
  check(num_nonnulls(room_id,chat_id)=1)
);
create index st_v6_tasks_room on public.st_v6_tasks(room_id,created_at desc,id desc) where room_id is not null;
create index st_v6_tasks_chat on public.st_v6_tasks(chat_id,created_at desc,id desc) where chat_id is not null;
create index st_v6_tasks_due on public.st_v6_tasks(due_at,id) where due_at is not null and status not in ('done','cancelled');

create table sectalk_private.st_v6_task_sources (
  task_id uuid primary key references public.st_v6_tasks on delete cascade,
  message_id uuid not null,
  message_created_at timestamptz not null,
  snapshot text not null
);
alter table sectalk_private.st_v6_task_sources enable row level security;
revoke all on sectalk_private.st_v6_task_sources from public,anon,authenticated;

create table public.st_v6_task_people (
  task_id uuid not null references public.st_v6_tasks on delete cascade,
  user_id uuid not null references public.st_profiles on delete cascade,
  kind text not null check(kind in ('assignee','watcher')),
  primary key(task_id,user_id,kind)
);
create table public.st_v6_task_audit (
  id bigint generated always as identity primary key,
  task_id uuid not null references public.st_v6_tasks on delete cascade,
  actor_id uuid not null references public.st_profiles,
  action text not null,
  detail jsonb not null,
  created_at timestamptz not null default clock_timestamp()
);
create index st_v6_task_audit_feed on public.st_v6_task_audit(task_id,id desc);
create table public.st_v6_task_notices (
  id bigint generated always as identity primary key,
  event_id bigint references public.st_v6_task_audit on delete cascade,
  recipient uuid not null references public.st_profiles on delete cascade,
  task_id uuid not null references public.st_v6_tasks on delete cascade,
  due_at timestamptz,
  kind text not null check(kind in ('completed','due')),
  created_at timestamptz not null default clock_timestamp(),
  read_at timestamptz,
  check((kind='completed' and event_id is not null and due_at is null)
    or (kind='due' and event_id is null and due_at is not null))
);
create index st_v6_task_notices_recipient on public.st_v6_task_notices(recipient,id desc);
create unique index st_v6_task_notice_event on public.st_v6_task_notices(event_id,recipient) where event_id is not null;
create unique index st_v6_task_notice_due on public.st_v6_task_notices(task_id,recipient,due_at) where kind='due';

create function sectalk_private.st_v6_task_audience(p_room uuid,p_chat uuid,p_user uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v2_active(p_user) and (
    (p_chat is not null and exists(select 1 from public.st_chats c
      where c.id=p_chat and p_user in(c.member_a,c.member_b) and c.status='accepted'
        and sectalk_private.open_pair(c.member_a,c.member_b)))
    or (p_room is not null and exists(select 1 from public.st_v6_rooms r
      where r.id=p_room and sectalk_private.st_v2_role(r.workspace_id,p_user) is not null
        and not exists(select 1 from public.st_v6_room_bans b where b.room_id=r.id and b.user_id=p_user)
        and case when r.kind='admin' then sectalk_private.st_v2_role(r.workspace_id,p_user) in ('owner','admin')
          else exists(select 1 from public.st_v6_room_members m where m.room_id=r.id and m.user_id=p_user) end))
  )
$$;

create function sectalk_private.st_v6_task_can_read(p_id uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v6_tasks t where t.id=p_id
    and sectalk_private.st_v6_task_audience(t.room_id,t.chat_id,auth.uid()))
$$;

create function sectalk_private.st_v6_task_scope_write(p_room uuid,p_chat uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce(sectalk_private.st_v6_task_audience(p_room,p_chat,auth.uid())
    and (p_room is null or (sectalk_private.st_v6_room_role(p_room) <> 'read_only'
      and exists(select 1 from public.st_v6_rooms r where r.id=p_room and not r.archived and (
        (not r.locked and r.kind not in ('announcement','broadcast'))
        or sectalk_private.st_v6_room_role(p_room) in ('owner','moderator')))
      and not exists(select 1 from public.st_v6_room_timeouts r where r.room_id=p_room and r.user_id=auth.uid() and r.until_at>now()))),false)
$$;

create function sectalk_private.st_v6_task_labels(p_labels text[])
returns text[] language plpgsql immutable set search_path='' as $$
begin
  if p_labels is null or cardinality(p_labels)>8 or exists(select 1 from unnest(p_labels) label
      where label is null or char_length(btrim(label)) not between 1 and 30 or label ~ '[[:cntrl:]]') then
    raise exception 'Use up to eight labels of 1–30 characters';
  end if;
  return array(select distinct lower(btrim(label)) from unnest(p_labels) label order by 1);
end $$;

alter table public.st_v6_tasks enable row level security;
alter table public.st_v6_task_people enable row level security;
alter table public.st_v6_task_audit enable row level security;
alter table public.st_v6_task_notices enable row level security;
revoke all on public.st_v6_tasks,public.st_v6_task_people,public.st_v6_task_audit,public.st_v6_task_notices from public,anon,authenticated;
grant select on public.st_v6_tasks,public.st_v6_task_people,public.st_v6_task_audit,public.st_v6_task_notices to authenticated;
revoke all on function sectalk_private.st_v6_task_audience(uuid,uuid,uuid),sectalk_private.st_v6_task_can_read(uuid),
  sectalk_private.st_v6_task_scope_write(uuid,uuid),sectalk_private.st_v6_task_labels(text[]) from public,anon,authenticated;
grant execute on function sectalk_private.st_v6_task_can_read(uuid) to authenticated;

create policy st_v6_tasks_read on public.st_v6_tasks for select to authenticated using(sectalk_private.st_v6_task_can_read(id));
create policy st_v6_task_people_read on public.st_v6_task_people for select to authenticated using(
  (kind='assignee' or user_id=(select auth.uid())) and sectalk_private.st_v6_task_can_read(task_id)
);
create policy st_v6_task_audit_read on public.st_v6_task_audit for select to authenticated using(sectalk_private.st_v6_task_can_read(task_id));
create policy st_v6_task_notices_read on public.st_v6_task_notices for select to authenticated using(
  recipient=(select auth.uid()) and sectalk_private.st_v6_task_can_read(task_id)
);

create function public.st_v6_task_create(p_id uuid,p_room uuid,p_chat uuid,p_title text,p_source uuid default null,
  p_due_at timestamptz default null,p_priority text default 'normal',p_labels text[] default '{}')
returns uuid language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); normalized text[]; snapshot text; source_created timestamptz; inserted uuid;
begin
  perform sectalk_private.limit_action('v6_task_create',12);
  if num_nonnulls(p_room,p_chat)<>1 or not sectalk_private.st_v6_task_scope_write(p_room,p_chat)
    then raise exception 'Task scope unavailable'; end if;
  normalized:=sectalk_private.st_v6_task_labels(p_labels);
  if p_source is not null then
    if p_room is not null then
      select m.body,m.created_at into snapshot,source_created from public.st_v6_room_posts m where m.room_id=p_room and m.id=p_source for share;
    else
      select m.body,m.created_at into snapshot,source_created from public.st_messages m where m.chat_id=p_chat and m.id=p_source
        and m.revoked_at is null and not exists(select 1 from public.st_v5_hidden_messages h
          where h.user_id=actor and h.message_id=m.id) for share;
    end if;
    if snapshot is null then raise exception 'Source message unavailable'; end if;
  end if;
  insert into public.st_v6_tasks(id,room_id,chat_id,author_id,title,due_at,priority,labels)
    values(p_id,p_room,p_chat,actor,btrim(p_title),p_due_at,p_priority,normalized)
    on conflict(id) do nothing returning id into inserted;
  if inserted is null then
    if exists(select 1 from public.st_v6_tasks t left join sectalk_private.st_v6_task_sources s on s.task_id=t.id
      where t.id=p_id and t.author_id=actor and t.room_id is not distinct from p_room and t.chat_id is not distinct from p_chat
        and t.title=btrim(p_title) and t.due_at is not distinct from p_due_at and t.priority=p_priority and t.labels=normalized
        and s.message_id is not distinct from p_source) then return p_id; end if;
    raise exception 'Task ID already in use';
  end if;
  if p_source is not null then
    insert into sectalk_private.st_v6_task_sources(task_id,message_id,message_created_at,snapshot) values(p_id,p_source,source_created,snapshot);
  end if;
  insert into public.st_v6_task_audit(task_id,actor_id,action,detail)
    values(p_id,actor,'created',jsonb_build_object('status','todo','priority',p_priority));
  return p_id;
end $$;

create function public.st_v6_task_source(p_id uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare origin sectalk_private.st_v6_task_sources; task public.st_v6_tasks; live_body text;
begin
  if not sectalk_private.st_v6_task_can_read(p_id) then raise exception 'Task unavailable'; end if;
  select * into task from public.st_v6_tasks where id=p_id;
  select * into origin from sectalk_private.st_v6_task_sources where task_id=p_id;
  if not found then return null; end if;
  if task.room_id is not null then
    select m.body into live_body from public.st_v6_room_posts m where m.room_id=task.room_id and m.id=origin.message_id
      and m.created_at=origin.message_created_at;
  else
    select m.body into live_body from public.st_messages m where m.chat_id=task.chat_id and m.id=origin.message_id
      and m.created_at=origin.message_created_at
      and m.revoked_at is null and not exists(select 1 from public.st_v5_hidden_messages h
        where h.user_id=auth.uid() and h.message_id=m.id);
  end if;
  if live_body is null then return jsonb_build_object('available',false); end if;
  return jsonb_build_object('available',true,'messageId',origin.message_id,'snapshot',origin.snapshot,'currentText',live_body,'edited',live_body<>origin.snapshot);
end $$;

create function public.st_v6_task_update(p_id uuid,p_action text,p_value text default null,p_person uuid default null,
  p_enabled boolean default null,p_labels text[] default null,p_due_at timestamptz default null)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); task public.st_v6_tasks; manager boolean; assigned boolean; details jsonb;
        event bigint; changed integer; normalized text[];
begin
  perform sectalk_private.limit_action('v6_task_update',40);
  select * into task from public.st_v6_tasks where id=p_id for update;
  if not found or not sectalk_private.st_v6_task_can_read(p_id) then raise exception 'Task unavailable'; end if;
  if p_action='watch' then
    if p_enabled is null then raise exception 'Choose a watch state'; end if;
    if p_enabled then insert into public.st_v6_task_people values(p_id,actor,'watcher') on conflict do nothing;
    else delete from public.st_v6_task_people where task_id=p_id and user_id=actor and kind='watcher'; end if;
    return;
  end if;
  if not sectalk_private.st_v6_task_scope_write(task.room_id,task.chat_id) then raise exception 'Task unavailable'; end if;
  manager:=task.author_id=actor or coalesce(sectalk_private.st_v6_room_role(task.room_id) in ('owner','moderator'),false);
  assigned:=exists(select 1 from public.st_v6_task_people where task_id=p_id and user_id=actor and kind='assignee');
  if p_action='assign' and manager then
    if p_person is null or p_enabled is null then raise exception 'Select an assignee'; end if;
    if p_enabled then
      if not sectalk_private.st_v6_task_audience(task.room_id,task.chat_id,p_person)
        then raise exception 'Assignee must have access to the task scope'; end if;
      insert into public.st_v6_task_people values(p_id,p_person,'assignee') on conflict do nothing;
    else
      delete from public.st_v6_task_people where task_id=p_id and user_id=p_person and kind='assignee';
    end if;
    get diagnostics changed=row_count;
    if changed=0 then return; end if;
    details:=jsonb_build_object('assignee',p_person,'assigned',p_enabled);
  elsif p_action='status' and (manager or assigned) then
    if task.status=p_value then return; end if;
    if p_value is null or p_value not in ('todo','in_progress','blocked','done','cancelled')
      or (task.status in ('done','cancelled') and (p_value<>'todo' or not manager)) then raise exception 'Invalid status transition'; end if;
    update public.st_v6_tasks set status=p_value where id=p_id;
    details:=jsonb_build_object('from',task.status,'to',p_value);
  elsif p_action='priority' and manager then
    if p_value is null or p_value not in ('low','normal','high','urgent') then raise exception 'Invalid priority'; end if;
    if task.priority=p_value then return; end if;
    update public.st_v6_tasks set priority=p_value where id=p_id;
    details:=jsonb_build_object('from',task.priority,'to',p_value);
  elsif p_action='labels' and manager then
    normalized:=sectalk_private.st_v6_task_labels(p_labels);
    if task.labels=normalized then return; end if;
    update public.st_v6_tasks set labels=normalized where id=p_id;
    details:=jsonb_build_object('from',task.labels,'to',normalized);
  elsif p_action='due' and manager then
    if task.due_at is not distinct from p_due_at then return; end if;
    update public.st_v6_tasks set due_at=p_due_at where id=p_id;
    details:=jsonb_build_object('from',task.due_at,'to',p_due_at);
  else raise exception 'Task action unavailable'; end if;
  update public.st_v6_tasks set updated_at=clock_timestamp() where id=p_id;
  insert into public.st_v6_task_audit(task_id,actor_id,action,detail) values(p_id,actor,p_action,details) returning id into event;
  if p_action='status' and p_value='done' then
    insert into public.st_v6_task_notices(event_id,recipient,task_id,kind)
      select event,participant,p_id,'completed' from (
        select task.author_id as participant union select user_id from public.st_v6_task_people where task_id=p_id
      ) recipients where participant<>actor and sectalk_private.st_v6_task_audience(task.room_id,task.chat_id,participant)
      on conflict do nothing;
  end if;
end $$;

create function public.st_v6_task_notice_read(p_notice bigint)
returns void language sql security definer set search_path='' as $$
  update public.st_v6_task_notices set read_at=clock_timestamp() where id=p_notice and recipient=auth.uid()
    and read_at is null and sectalk_private.st_v6_task_can_read(task_id)
$$;

create function sectalk_private.st_v6_task_send_reminders()
returns integer language sql security definer set search_path='' as $$
  with inserted as (
    insert into public.st_v6_task_notices(recipient,task_id,kind,due_at)
    select recipient.user_id,t.id,'due',t.due_at
    from public.st_v6_tasks t cross join lateral (
      select t.author_id as user_id union select p.user_id from public.st_v6_task_people p where p.task_id=t.id
    ) recipient
    where t.status not in ('done','cancelled')
      and t.due_at between now()-interval '1 day' and now()+interval '1 day'
      and sectalk_private.st_v6_task_audience(t.room_id,t.chat_id,recipient.user_id)
      and not exists(select 1 from public.st_v6_task_notices n where n.task_id=t.id
        and n.recipient=recipient.user_id and n.kind='due' and n.due_at=t.due_at)
    order by t.due_at,t.id,recipient.user_id limit 500
    on conflict do nothing returning id
  )
  select count(*)::integer from inserted
$$;
revoke all on function sectalk_private.st_v6_task_send_reminders() from public,anon,authenticated;

create extension if not exists pg_cron with schema pg_catalog;
select cron.schedule('sectalk-v6-task-reminders','* * * * *','select sectalk_private.st_v6_task_send_reminders()');

revoke all on function public.st_v6_task_create(uuid,uuid,uuid,text,uuid,timestamptz,text,text[]),
  public.st_v6_task_source(uuid),public.st_v6_task_update(uuid,text,text,uuid,boolean,text[],timestamptz),
  public.st_v6_task_notice_read(bigint) from public,anon,authenticated;
grant execute on function public.st_v6_task_create(uuid,uuid,uuid,text,uuid,timestamptz,text,text[]),
  public.st_v6_task_source(uuid),public.st_v6_task_update(uuid,text,text,uuid,boolean,text[],timestamptz),
  public.st_v6_task_notice_read(bigint) to authenticated;

create or replace function public.st_v6_ready()
returns boolean language sql stable security invoker set search_path='' as $$
  select to_regclass('public.st_v6_saved_messages') is not null
    and to_regclass('public.st_v6_rooms') is not null
    and to_regclass('public.st_v6_saved_searches') is not null
    and to_regclass('public.st_v6_thread_follows') is not null
    and to_regclass('public.st_v6_tasks') is not null
$$;

alter publication supabase_realtime add table public.st_v6_tasks,public.st_v6_task_notices;
commit;
