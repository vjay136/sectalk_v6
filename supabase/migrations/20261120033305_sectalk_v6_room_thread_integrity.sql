begin;

alter table public.st_v6_room_posts
  add column edited_at timestamptz,
  add column removed_at timestamptz,
  add constraint st_v6_room_posts_tombstone check(removed_at is null or body='Message removed');

create function public.st_v6_room_post_action(p_room uuid,p_post uuid,p_action text,p_body text default null)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  r public.st_v6_rooms;
  post public.st_v6_room_posts;
  actor_role text;
  target_role text;
  staff boolean;
  replacement text:=btrim(p_body);
  action_time timestamptz;
begin
  perform sectalk_private.limit_action('v6_room_post_action',30);
  select * into r from public.st_v6_rooms where id=p_room for no key update;
  actor_role:=sectalk_private.st_v6_room_role(p_room);
  staff:=coalesce(actor_role in ('owner','moderator'),false);
  if r.id is null or r.archived or actor_role is null or actor_role='read_only'
    or p_action is null or p_action not in ('edit','delete','redact')
    then raise exception 'Room message unavailable'; end if;
  select * into post from public.st_v6_room_posts where room_id=p_room and id=p_post for update;
  if not found then raise exception 'Room message unavailable'; end if;
  action_time:=clock_timestamp();

  if p_action='redact' then
    if not staff or post.sender=actor then raise exception 'Room message unavailable'; end if;
    if r.kind='admin' then
      target_role:=sectalk_private.st_v2_role(r.workspace_id,post.sender);
      if actor_role='moderator' and target_role in ('owner','admin')
        then raise exception 'Room message unavailable'; end if;
    else
      select role into target_role from public.st_v6_room_members where room_id=p_room and user_id=post.sender;
      if actor_role='moderator' and target_role in ('owner','moderator')
        then raise exception 'Room message unavailable'; end if;
    end if;
  elsif post.sender<>actor then raise exception 'Room message unavailable';
  end if;

  if p_action='edit' then
    if post.removed_at is not null or post.created_at<action_time-interval '24 hours'
      or (not staff and (r.locked or r.kind in ('announcement','broadcast') or post.kind='announcement'))
      or exists(select 1 from public.st_v6_room_timeouts where room_id=p_room and user_id=actor and until_at>action_time)
      then raise exception 'Message can no longer be edited'; end if;
    if replacement is null or char_length(replacement) not between 1 and 4000
      then raise exception 'Enter a message between 1 and 4000 characters'; end if;
    if post.body=replacement then return; end if;
    update public.st_v6_room_posts set body=replacement,edited_at=action_time where room_id=p_room and id=p_post;
  else
    if post.removed_at is not null then return; end if;
    update public.st_v6_room_posts set body='Message removed',removed_at=action_time where room_id=p_room and id=p_post;
    delete from public.st_v6_room_pins where room_id=p_room and post_id=p_post;
  end if;
  insert into public.st_v6_room_audit(room_id,actor,action,target) values
    (p_room,actor,case p_action when 'edit' then 'post.edited' when 'delete' then 'post.deleted' else 'post.redacted' end,p_post);
end $$;

revoke all on function public.st_v6_room_post_action(uuid,uuid,text,text) from public,anon,authenticated;
grant execute on function public.st_v6_room_post_action(uuid,uuid,text,text) to authenticated;

create function sectalk_private.st_v6_room_pin_allowed()
returns trigger language plpgsql set search_path='' as $$
begin
  perform id from public.st_v6_room_posts where room_id=new.room_id and id=new.post_id and removed_at is null for share;
  if not found then raise exception 'Message unavailable'; end if;
  return new;
end $$;
revoke all on function sectalk_private.st_v6_room_pin_allowed() from public,anon,authenticated;
create trigger st_v6_room_pin_allowed before insert on public.st_v6_room_pins
  for each row execute function sectalk_private.st_v6_room_pin_allowed();

create or replace function public.st_v6_task_create(p_id uuid,p_room uuid,p_chat uuid,p_title text,p_source uuid default null,
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
      select m.body,m.created_at into snapshot,source_created from public.st_v6_room_posts m where m.room_id=p_room
        and m.id=p_source and m.removed_at is null for share;
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

create or replace function public.st_v6_task_source(p_id uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare origin sectalk_private.st_v6_task_sources; task public.st_v6_tasks; live_body text;
begin
  if not sectalk_private.st_v6_task_can_read(p_id) then raise exception 'Task unavailable'; end if;
  select * into task from public.st_v6_tasks where id=p_id;
  select * into origin from sectalk_private.st_v6_task_sources where task_id=p_id;
  if not found then return null; end if;
  if task.room_id is not null then
    select m.body into live_body from public.st_v6_room_posts m where m.room_id=task.room_id and m.id=origin.message_id
      and m.created_at=origin.message_created_at and m.removed_at is null;
  else
    select m.body into live_body from public.st_messages m where m.chat_id=task.chat_id and m.id=origin.message_id
      and m.created_at=origin.message_created_at
      and m.revoked_at is null and not exists(select 1 from public.st_v5_hidden_messages h
        where h.user_id=auth.uid() and h.message_id=m.id);
  end if;
  if live_body is null then return jsonb_build_object('available',false); end if;
  return jsonb_build_object('available',true,'messageId',origin.message_id,'snapshot',origin.snapshot,'currentText',live_body,'edited',live_body<>origin.snapshot);
end $$;

commit;
