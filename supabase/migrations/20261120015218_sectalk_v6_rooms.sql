begin;

create table public.st_v6_rooms (
  id uuid primary key,
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  name text not null check (char_length(btrim(name)) between 1 and 64),
  kind text not null check (kind in ('public','private','admin','announcement','broadcast')),
  template text not null check (template in ('blank','class','incident','family','project')),
  creator uuid not null references public.st_profiles,
  archived boolean not null default false,
  locked boolean not null default false,
  slow_seconds integer not null default 0 check (slow_seconds between 0 and 300),
  created_at timestamptz not null default now()
);
create unique index st_v6_room_name on public.st_v6_rooms(workspace_id,lower(name));
create table public.st_v6_room_members (
  room_id uuid not null references public.st_v6_rooms on delete cascade,
  user_id uuid not null references public.st_profiles on delete cascade,
  role text not null check (role in ('owner','moderator','member','guest','read_only')),
  primary key(room_id,user_id)
);
create table public.st_v6_room_bans (
  room_id uuid not null references public.st_v6_rooms on delete cascade,
  user_id uuid not null references public.st_profiles on delete cascade,
  primary key(room_id,user_id)
);
create table public.st_v6_room_timeouts (
  room_id uuid not null references public.st_v6_rooms on delete cascade,
  user_id uuid not null references public.st_profiles on delete cascade,
  until_at timestamptz not null,
  primary key(room_id,user_id)
);
create table public.st_v6_room_entries (
  room_id uuid not null references public.st_v6_rooms on delete cascade,
  user_id uuid not null references public.st_profiles on delete cascade,
  kind text not null check(kind in ('invite','request')),
  invited_role text not null check(invited_role in ('member','guest','read_only')),
  expires_at timestamptz not null,
  primary key(room_id,user_id)
);
create index st_v6_room_entries_target on public.st_v6_room_entries(user_id,expires_at);
create table public.st_v6_room_posts (
  room_id uuid not null references public.st_v6_rooms on delete cascade,
  id uuid not null,
  sender uuid not null references public.st_profiles,
  body text not null check(char_length(btrim(body)) between 1 and 4000),
  kind text not null check(kind in ('message','announcement')),
  parent_id uuid,
  created_at timestamptz not null default clock_timestamp(),
  primary key(room_id,id),
  foreign key(room_id,parent_id) references public.st_v6_room_posts(room_id,id)
);
create index st_v6_room_post_feed on public.st_v6_room_posts(room_id,parent_id,created_at desc,id desc);
create index st_v6_room_post_rate on public.st_v6_room_posts(room_id,sender,created_at desc);
create table public.st_v6_room_pins (
  room_id uuid not null,
  post_id uuid not null,
  pinned_at timestamptz not null default clock_timestamp(),
  primary key(room_id,post_id),
  foreign key(room_id,post_id) references public.st_v6_room_posts(room_id,id) on delete cascade
);
create table public.st_v6_room_audit (
  id bigint generated always as identity primary key,
  room_id uuid not null references public.st_v6_rooms on delete cascade,
  actor uuid not null references public.st_profiles,
  action text not null,
  target uuid,
  occurred_at timestamptz not null default clock_timestamp()
);
create index st_v6_room_audit_feed on public.st_v6_room_audit(room_id,id desc);

create function sectalk_private.st_v6_room_role(p_room uuid)
returns text language sql stable security definer set search_path='' as $$
  select case when r.kind='admin' and sectalk_private.st_v2_role(r.workspace_id,auth.uid()) in ('owner','admin')
    then case when sectalk_private.st_v2_role(r.workspace_id,auth.uid())='owner' then 'owner' else 'moderator' end
    when r.kind<>'admin' then m.role end
  from public.st_v6_rooms r left join public.st_v6_room_members m on m.room_id=r.id and m.user_id=auth.uid()
  where r.id=p_room and sectalk_private.st_v2_active(auth.uid())
    and sectalk_private.st_v2_role(r.workspace_id,auth.uid()) is not null
    and not exists(select 1 from public.st_v6_room_bans b where b.room_id=r.id and b.user_id=auth.uid())
$$;

create function sectalk_private.st_v6_room_directory(p_room uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v6_rooms r
    where r.id=p_room and sectalk_private.st_v2_active(auth.uid())
      and sectalk_private.st_v2_role(r.workspace_id,auth.uid()) is not null and (
        sectalk_private.st_v6_room_role(r.id) is not null
        or (not r.archived and (
          r.kind in ('public','announcement','broadcast')
          or (r.kind='private' and exists(select 1 from public.st_v6_room_entries e where e.room_id=r.id
            and e.user_id=auth.uid() and e.kind='invite' and e.expires_at>now()))
        ) and not exists(select 1 from public.st_v6_room_bans b where b.room_id=r.id and b.user_id=auth.uid()))
      ))
$$;

do $$
declare t text;
begin
  foreach t in array array['rooms','room_members','room_bans','room_timeouts','room_entries','room_posts','room_pins','room_audit']
  loop
    execute format('alter table public.%I enable row level security','st_v6_'||t);
    execute format('revoke all on public.%I from public, anon, authenticated','st_v6_'||t);
  end loop;
end $$;
grant select on public.st_v6_rooms,public.st_v6_room_members,public.st_v6_room_entries,
  public.st_v6_room_posts,public.st_v6_room_pins,public.st_v6_room_audit,public.st_v6_room_bans,public.st_v6_room_timeouts to authenticated;
revoke all on function sectalk_private.st_v6_room_role(uuid),sectalk_private.st_v6_room_directory(uuid) from public,anon,authenticated;
grant execute on function sectalk_private.st_v6_room_role(uuid),sectalk_private.st_v6_room_directory(uuid) to authenticated;
create policy st_v6_room_read on public.st_v6_rooms for select to authenticated using(sectalk_private.st_v6_room_directory(id));
create policy st_v6_room_roster on public.st_v6_room_members for select to authenticated
  using(sectalk_private.st_v6_room_role(room_id) in ('owner','moderator','member','read_only')
    or (user_id=(select auth.uid()) and sectalk_private.st_v6_room_role(room_id)='guest'));
create policy st_v6_room_bans_staff on public.st_v6_room_bans for select to authenticated
  using(sectalk_private.st_v6_room_role(room_id) in ('owner','moderator'));
create policy st_v6_room_timeouts_staff on public.st_v6_room_timeouts for select to authenticated
  using(sectalk_private.st_v6_room_role(room_id) in ('owner','moderator'));
create policy st_v6_room_requests on public.st_v6_room_entries for select to authenticated using(
  (user_id=(select auth.uid()) and sectalk_private.st_v6_room_directory(room_id))
  or sectalk_private.st_v6_room_role(room_id) in ('owner','moderator')
);
create policy st_v6_room_feed on public.st_v6_room_posts for select to authenticated
  using(sectalk_private.st_v6_room_role(room_id) is not null);
create policy st_v6_room_pins on public.st_v6_room_pins for select to authenticated
  using(sectalk_private.st_v6_room_role(room_id) is not null);
create policy st_v6_room_audit on public.st_v6_room_audit for select to authenticated
  using(sectalk_private.st_v6_room_role(room_id) in ('owner','moderator'));

create function public.st_v6_room_create(p_id uuid,p_workspace uuid,p_name text,p_kind text,p_template text)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); affected integer;
begin
  perform sectalk_private.limit_action('v6_room_create',8);
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor) then raise exception 'Room unavailable'; end if;
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if exists(select 1 from public.st_v6_rooms where id=p_id and workspace_id=p_workspace and creator=actor
      and name=btrim(p_name) and kind=p_kind and template=p_template) then return p_id; end if;
  if (select count(*) from public.st_v6_rooms where workspace_id=p_workspace)>=100 then raise exception 'Workspace room limit reached'; end if;
  insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator)
    values(p_id,p_workspace,btrim(p_name),p_kind,p_template,actor);
  if p_kind<>'admin' then
    insert into public.st_v6_room_members(room_id,user_id,role) values(p_id,actor,'owner');
  end if;
  insert into public.st_v6_room_audit(room_id,actor,action) values(p_id,actor,'room.created');
  return p_id;
end $$;

create function public.st_v6_room_membership(p_room uuid,p_action text,p_target uuid default null,p_role text default 'member')
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); r public.st_v6_rooms; stage public.st_v6_room_entries; room_role text;
        target uuid:=coalesce(p_target,actor); target_role text;
begin
  perform sectalk_private.limit_action('v6_room_membership',30);
  select * into r from public.st_v6_rooms where id=p_room for update;
  if not found or r.kind='admin' or r.archived or not sectalk_private.st_v2_active(actor)
    or sectalk_private.st_v2_role(r.workspace_id,actor) is null
    or exists(select 1 from public.st_v6_room_bans where room_id=p_room and user_id=actor)
    then raise exception 'Room unavailable'; end if;
  room_role:=sectalk_private.st_v6_room_role(p_room);
  select role into target_role from public.st_v6_room_members where room_id=p_room and user_id=target;
  select * into stage from public.st_v6_room_entries where room_id=p_room and user_id=target and expires_at>now();

  if p_action in ('join','request','accept','decline') and target=actor then
    if p_action='join' and r.kind in ('public','announcement','broadcast') then
      insert into public.st_v6_room_members(room_id,user_id,role)
        values(p_room,actor,case when r.kind='broadcast' then 'read_only' else 'member' end) on conflict do nothing;
    elsif p_action='request' and r.kind='private' and room_role is null then
      insert into public.st_v6_room_entries values(p_room,actor,'request','member',now()+interval '7 days')
        on conflict(room_id,user_id) do update set expires_at=excluded.expires_at
        where public.st_v6_room_entries.kind='request' or public.st_v6_room_entries.expires_at<=now();
    elsif p_action in ('accept','decline') and stage.kind='invite' then
      if p_action='accept' then
        insert into public.st_v6_room_members values(p_room,actor,stage.invited_role) on conflict do nothing;
      end if;
      delete from public.st_v6_room_entries where room_id=p_room and user_id=actor;
    else raise exception 'Room unavailable'; end if;
  elsif p_action in ('invite','approve','deny','role','remove','ban','unban','mute','timeout','unmute')
    and room_role in ('owner','moderator') and target<>actor and target_role is distinct from 'owner'
    and (target_role is distinct from 'moderator' or room_role='owner') then
    if p_action in ('invite','approve','role') then
      if sectalk_private.st_v2_role(r.workspace_id,target) is null or not sectalk_private.st_v2_active(target)
        or exists(select 1 from public.st_v6_room_bans where room_id=p_room and user_id=target)
        or p_role is null or p_role not in ('member','guest','read_only','moderator')
        or (p_role='moderator' and (room_role<>'owner' or p_action<>'role')) then raise exception 'Room action unavailable'; end if;
      if p_action='invite' and target_role is null then
        insert into public.st_v6_room_entries values(p_room,target,'invite',p_role,now()+interval '7 days')
          on conflict(room_id,user_id) do update set kind='invite',invited_role=excluded.invited_role,expires_at=excluded.expires_at;
      elsif p_action='approve' and stage.kind='request' then
        insert into public.st_v6_room_members values(p_room,target,p_role) on conflict do nothing;
        delete from public.st_v6_room_entries where room_id=p_room and user_id=target;
      elsif p_action='role' and target_role is not null then
        update public.st_v6_room_members set role=p_role where room_id=p_room and user_id=target;
      else raise exception 'Room action unavailable'; end if;
    elsif p_action='deny' and stage.kind='request' then
      delete from public.st_v6_room_entries where room_id=p_room and user_id=target;
    elsif p_action in ('remove','ban') then
      if p_action='ban' then
        insert into public.st_v6_room_bans values(p_room,target) on conflict do nothing;
      end if;
      delete from public.st_v6_room_members where room_id=p_room and user_id=target;
      delete from public.st_v6_room_entries where room_id=p_room and user_id=target;
    elsif p_action='unban' then
      delete from public.st_v6_room_bans where room_id=p_room and user_id=target;
    elsif p_action in ('mute','timeout') and target_role is not null then
      insert into public.st_v6_room_timeouts values(p_room,target,case when p_action='mute' then 'infinity'::timestamptz else now()+interval '15 minutes' end)
        on conflict(room_id,user_id) do update set until_at=excluded.until_at;
    elsif p_action='unmute' then
      delete from public.st_v6_room_timeouts where room_id=p_room and user_id=target;
    else raise exception 'Room action unavailable'; end if;
  else raise exception 'Room action unavailable'; end if;
  insert into public.st_v6_room_audit(room_id,actor,action,target) values(p_room,actor,'membership.'||p_action,target);
end $$;

create function public.st_v6_room_post(p_room uuid,p_id uuid,p_body text,p_kind text default 'message',p_parent uuid default null)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); r public.st_v6_rooms; actor_room_role text;
begin
  perform sectalk_private.limit_action('v6_room_post',45);
  select * into r from public.st_v6_rooms where id=p_room for update;
  actor_room_role:=sectalk_private.st_v6_room_role(p_room);
  if not found or r.archived or actor_room_role is null or actor_room_role='read_only'
    or (r.locked and actor_room_role not in ('owner','moderator'))
    or ((r.kind in ('announcement','broadcast') or p_kind='announcement') and actor_room_role not in ('owner','moderator'))
    or (r.kind='announcement' and p_kind is distinct from 'announcement')
    or (p_kind='announcement' and p_parent is not null)
    or exists(select 1 from public.st_v6_room_timeouts where room_id=p_room and user_id=actor and until_at>now())
    then raise exception 'Posting is unavailable'; end if;
  if exists(select 1 from public.st_v6_room_posts where room_id=p_room and id=p_id) then
    if exists(select 1 from public.st_v6_room_posts where room_id=p_room and id=p_id and sender=actor
      and body=btrim(p_body) and kind=p_kind and parent_id is not distinct from p_parent) then return; end if;
    raise exception 'Message ID already in use';
  end if;
  if p_parent is not null and not exists(select 1 from public.st_v6_room_posts where room_id=p_room and id=p_parent and parent_id is null)
    then raise exception 'Thread unavailable'; end if;
  if r.slow_seconds>0 and actor_room_role not in ('owner','moderator')
    and exists(select 1 from public.st_v6_room_posts where room_id=p_room and sender=actor and created_at>clock_timestamp()-make_interval(secs=>r.slow_seconds))
    then raise exception 'Slow mode is on. Wait before posting again.'; end if;
  insert into public.st_v6_room_posts(room_id,id,sender,body,kind,parent_id)
    values(p_room,p_id,actor,btrim(p_body),p_kind,p_parent);
  if p_kind='announcement' then
    insert into public.st_v6_room_audit(room_id,actor,action,target) values(p_room,actor,'post.announcement',p_id);
  end if;
end $$;

create function public.st_v6_room_settings(p_room uuid,p_action text,p_post uuid default null,p_seconds integer default 0)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); r public.st_v6_rooms; actor_room_role text;
begin
  perform sectalk_private.limit_action('v6_room_settings',20);
  select * into r from public.st_v6_rooms where id=p_room for update;
  actor_room_role:=sectalk_private.st_v6_room_role(p_room);
  if not found or not coalesce(actor_room_role in ('owner','moderator'),false)
    or (r.archived and p_action is distinct from 'restore')
    then raise exception 'Room settings unavailable'; end if;
  case p_action
    when 'pin' then
      if not exists(select 1 from public.st_v6_room_posts where room_id=p_room and id=p_post and parent_id is null)
        then raise exception 'Message unavailable'; end if;
      insert into public.st_v6_room_pins(room_id,post_id) values(p_room,p_post) on conflict do nothing;
    when 'unpin' then delete from public.st_v6_room_pins where room_id=p_room and post_id=p_post;
    when 'lock' then update public.st_v6_rooms set locked=true where id=p_room;
    when 'unlock' then update public.st_v6_rooms set locked=false where id=p_room;
    when 'slow' then update public.st_v6_rooms set slow_seconds=p_seconds where id=p_room;
    when 'archive' then
      if actor_room_role<>'owner' then raise exception 'Room settings unavailable'; end if;
      update public.st_v6_rooms set archived=true where id=p_room;
    when 'restore' then
      if actor_room_role<>'owner' then raise exception 'Room settings unavailable'; end if;
      update public.st_v6_rooms set archived=false where id=p_room;
    else raise exception 'Room settings unavailable';
  end case;
  insert into public.st_v6_room_audit(room_id,actor,action,target) values(p_room,actor,'room.'||p_action,p_post);
end $$;

create function public.st_v6_room_my_role(p_room uuid)
returns text language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v6_room_role(p_room)
$$;
revoke all on function public.st_v6_room_create(uuid,uuid,text,text,text),public.st_v6_room_membership(uuid,text,uuid,text),
  public.st_v6_room_post(uuid,uuid,text,text,uuid),public.st_v6_room_settings(uuid,text,uuid,integer),
  public.st_v6_room_my_role(uuid) from public,anon,authenticated;
grant execute on function public.st_v6_room_create(uuid,uuid,text,text,text),public.st_v6_room_membership(uuid,text,uuid,text),
  public.st_v6_room_post(uuid,uuid,text,text,uuid),public.st_v6_room_settings(uuid,text,uuid,integer),
  public.st_v6_room_my_role(uuid) to authenticated;
alter publication supabase_realtime add table public.st_v6_room_posts;
commit;
