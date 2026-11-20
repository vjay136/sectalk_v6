begin;

create table public.st_v3_meetings (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  host_id uuid not null references public.st_profiles,
  title text not null check(char_length(btrim(title)) between 1 and 100),
  agenda text not null default '' check(char_length(agenda)<=2000),
  starts_at timestamptz not null,
  ends_at timestamptz not null,
  status text not null default 'scheduled' check(status in ('scheduled','live','ended')),
  created_at timestamptz not null default now(),
  check(ends_at > starts_at and ends_at <= starts_at + interval '8 hours')
);
create index st_v3_meetings_workspace on public.st_v3_meetings(workspace_id,starts_at desc);
create table public.st_v3_attendance (
  meeting_id uuid not null references public.st_v3_meetings on delete cascade,
  user_id uuid not null references public.st_profiles,
  status text not null check(status in ('waiting','admitted','declined','left')),
  requested_at timestamptz not null default now(),
  admitted_at timestamptz,
  left_at timestamptz,
  primary key(meeting_id,user_id)
);
create table public.st_v3_notifications (
  id bigint generated always as identity primary key,
  recipient uuid not null references public.st_profiles,
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  meeting_id uuid references public.st_v3_meetings on delete cascade,
  kind text not null check(kind in ('meeting.scheduled','meeting.admitted','meeting.declined')),
  created_at timestamptz not null default now(),
  read_at timestamptz,
  unique(recipient,meeting_id,kind)
);
create index st_v3_notifications_recipient on public.st_v3_notifications(recipient,id desc);

create table public.st_v3_presence (
  user_id uuid primary key references public.st_profiles,
  state text not null check(state in ('online','away','busy','offline')),
  expires_at timestamptz not null
);
create function sectalk_private.st_v3_presence_visible(p_peer uuid,p_self uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select p_peer=p_self or exists(select 1 from public.st_chats
    where member_a=least(p_peer,p_self) and member_b=greatest(p_peer,p_self) and status='accepted'
      and sectalk_private.open_pair(p_peer,p_self))
$$;
alter table public.st_v3_presence enable row level security;
revoke all on public.st_v3_presence from public,anon,authenticated;
grant select on public.st_v3_presence to authenticated;
create policy st_v3_visible_presence on public.st_v3_presence for select to authenticated
using(user_id=(select auth.uid()) or (state<>'offline' and expires_at>now()
  and sectalk_private.st_v3_presence_visible(user_id,(select auth.uid()))));
create function public.st_v3_set_presence(p_state text)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('v3_presence_set',10);
  if not sectalk_private.st_v2_active(auth.uid()) then return; end if;
  insert into public.st_v3_presence(user_id,state,expires_at)
    values(auth.uid(),p_state,case when p_state='offline' then now() else now()+interval '100 seconds' end)
    on conflict(user_id) do update set state=excluded.state,expires_at=excluded.expires_at;
end $$;
create function public.st_v3_ping()
returns void language sql security definer set search_path='' as $$
  update public.st_v3_presence set expires_at=now()+interval '100 seconds'
    where user_id=auth.uid() and state<>'offline' and expires_at<now()+interval '65 seconds'
      and sectalk_private.st_v2_active(auth.uid())
$$;

create function sectalk_private.st_v3_meeting_visible(m uuid,u uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v3_meetings where id=m
    and sectalk_private.st_v2_role(workspace_id,u) is not null)
$$;
create function sectalk_private.st_v3_is_host(m uuid,u uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v3_meetings where id=m and host_id=u
    and sectalk_private.st_v2_role(workspace_id,u) in ('owner','admin'))
$$;

alter table public.st_v3_meetings enable row level security;
alter table public.st_v3_attendance enable row level security;
alter table public.st_v3_notifications enable row level security;
revoke all on public.st_v3_meetings,public.st_v3_attendance,public.st_v3_notifications from public,anon,authenticated;
grant select on public.st_v3_meetings,public.st_v3_attendance,public.st_v3_notifications to authenticated;
create policy st_v3_meetings_read on public.st_v3_meetings for select to authenticated
using(sectalk_private.st_v2_role(workspace_id,(select auth.uid())) is not null);
create policy st_v3_attendance_read on public.st_v3_attendance for select to authenticated
using((user_id=(select auth.uid()) and sectalk_private.st_v3_meeting_visible(meeting_id,(select auth.uid())))
   or sectalk_private.st_v3_is_host(meeting_id,(select auth.uid())));
create policy st_v3_notification_read on public.st_v3_notifications for select to authenticated
using(recipient=(select auth.uid()) and sectalk_private.st_v2_role(workspace_id,(select auth.uid())) is not null);

create function public.st_v3_schedule(p_workspace uuid,p_title text,p_agenda text,p_start timestamptz,p_end timestamptz,p_id uuid)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); m public.st_v3_meetings;
begin
  perform sectalk_private.limit_action('v3_schedule',8);
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor) then raise exception 'Meeting action unavailable'; end if;
  if p_start<now()-interval '2 minutes' or p_start>now()+interval '365 days'
    then raise exception 'Choose a start time in the next year'; end if;
  insert into public.st_v3_meetings(id,workspace_id,host_id,title,agenda,starts_at,ends_at)
    values(p_id,p_workspace,actor,btrim(p_title),btrim(coalesce(p_agenda,'')),p_start,p_end)
    on conflict(id) do nothing returning * into m;
  if not found then
    if exists(select 1 from public.st_v3_meetings where id=p_id and host_id=actor and workspace_id=p_workspace
      and title=btrim(p_title) and agenda=btrim(coalesce(p_agenda,'')) and starts_at=p_start and ends_at=p_end) then return p_id; end if;
    raise exception 'Meeting ID already in use';
  end if;
  insert into public.st_v3_notifications(recipient,workspace_id,meeting_id,kind)
    select user_id,p_workspace,p_id,'meeting.scheduled' from public.st_v2_members
    where workspace_id=p_workspace and user_id<>actor on conflict do nothing;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(p_workspace,actor,'meeting.scheduled',p_id);
  return m.id;
end $$;

create function public.st_v3_meeting_state(p_meeting uuid,p_state text)
returns void language plpgsql security definer set search_path='' as $$
declare m public.st_v3_meetings; actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v3_meeting_state',20);
  select * into m from public.st_v3_meetings where id=p_meeting for update;
  if not found or not sectalk_private.st_v3_is_host(p_meeting,actor) or not sectalk_private.st_v2_active(actor)
    then raise exception 'Meeting action unavailable'; end if;
  if p_state is null or p_state not in ('live','ended') then raise exception 'Invalid meeting state'; end if;
  if p_state=m.status then return; end if;
  if p_state='live' and (m.status<>'scheduled' or m.starts_at>now()+interval '15 minutes' or now()>=m.ends_at) then
    raise exception 'A meeting can start up to 15 minutes before it is scheduled'; end if;
  update public.st_v3_meetings set status=p_state where id=p_meeting;
  if p_state='live' then
    insert into public.st_v3_attendance(meeting_id,user_id,status,admitted_at) values(p_meeting,actor,'admitted',clock_timestamp())
      on conflict(meeting_id,user_id) do update set status='admitted',admitted_at=clock_timestamp(),left_at=null;
  else
    update public.st_v3_attendance set status='left',left_at=clock_timestamp() where meeting_id=p_meeting and status in ('admitted','waiting');
  end if;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(m.workspace_id,actor,'meeting.'||p_state,p_meeting);
end $$;

create function public.st_v3_request_admission(p_meeting uuid)
returns text language plpgsql security definer set search_path='' as $$
declare m public.st_v3_meetings; actor uuid:=auth.uid(); access_state text;
begin
  perform sectalk_private.limit_action('v3_join',16);
  select * into m from public.st_v3_meetings where id=p_meeting for update;
  if not found or not sectalk_private.st_v3_meeting_visible(p_meeting,actor) or not sectalk_private.st_v2_active(actor)
    or m.status='ended' or m.ends_at<=now() or m.starts_at>now()+interval '15 minutes'
    or not sectalk_private.open_pair(actor,m.host_id) then raise exception 'Meeting is unavailable or has not opened yet'; end if;
  if actor=m.host_id and m.status='live' and sectalk_private.st_v3_is_host(p_meeting,actor) then
    insert into public.st_v3_attendance(meeting_id,user_id,status,admitted_at)
      values(p_meeting,actor,'admitted',clock_timestamp())
      on conflict(meeting_id,user_id) do update set status='admitted',admitted_at=coalesce(public.st_v3_attendance.admitted_at,clock_timestamp()),left_at=null;
  else
    insert into public.st_v3_attendance(meeting_id,user_id,status) values(p_meeting,actor,'waiting') on conflict(meeting_id,user_id)
      do update set status='waiting',requested_at=clock_timestamp(),admitted_at=null,left_at=null
      where public.st_v3_attendance.status='left';
  end if;
  select status into access_state from public.st_v3_attendance where meeting_id=p_meeting and user_id=actor;
  return access_state;
end $$;

create function public.st_v3_admit(p_meeting uuid,p_user uuid,p_allow boolean)
returns void language plpgsql security definer set search_path='' as $$
declare m public.st_v3_meetings; actor uuid:=auth.uid(); activity text;
begin
  perform sectalk_private.limit_action('v3_admit',45);
  select * into m from public.st_v3_meetings where id=p_meeting for update;
  if not found or p_allow is null or m.status<>'live' or m.ends_at<=now() or p_user=actor
    or not sectalk_private.st_v3_is_host(p_meeting,actor) or not sectalk_private.st_v3_meeting_visible(p_meeting,p_user)
    or not sectalk_private.open_pair(actor,p_user) then raise exception 'Meeting action unavailable'; end if;
  if p_allow and (select count(*) from public.st_v3_attendance where meeting_id=p_meeting and status='admitted')>=12
    then raise exception 'The meeting is at its attendee limit'; end if;
  update public.st_v3_attendance set status=case when p_allow then 'admitted' else 'declined' end,
    admitted_at=case when p_allow then clock_timestamp() else null end
    where meeting_id=p_meeting and user_id=p_user and status='waiting';
  if not found then raise exception 'Attendee is no longer waiting'; end if;
  activity:=case when p_allow then 'meeting.admitted' else 'meeting.declined' end;
  insert into public.st_v3_notifications(recipient,workspace_id,meeting_id,kind)
    values(p_user,m.workspace_id,p_meeting,activity)
    on conflict(recipient,meeting_id,kind) do update set read_at=null,created_at=clock_timestamp();
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(m.workspace_id,actor,activity,p_meeting);
end $$;

create function public.st_v3_leave(p_meeting uuid)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('v3_leave',16);
  update public.st_v3_attendance set status='left',left_at=clock_timestamp()
    where meeting_id=p_meeting and user_id=auth.uid() and status in ('waiting','admitted');
end $$;

create function public.st_v3_media_access(p_meeting uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v3_meetings m join public.st_v3_attendance a on m.id=a.meeting_id
    where m.id=p_meeting and a.user_id=auth.uid() and a.status='admitted' and m.status='live' and m.ends_at>now()
      and sectalk_private.st_v2_role(m.workspace_id,auth.uid()) is not null and sectalk_private.open_pair(m.host_id,auth.uid()))
$$;

create function public.st_v3_mark_notification(p_id bigint)
returns void language sql security definer set search_path='' as $$
  update public.st_v3_notifications set read_at=clock_timestamp()
    where recipient=auth.uid() and (p_id is null or id=p_id) and read_at is null
      and sectalk_private.st_v2_role(workspace_id,auth.uid()) is not null
$$;

create function public.st_v3_search(p_query text,p_kind text)
returns table(kind text,id uuid,scope_id uuid,title text,snippet text,at timestamptz)
language plpgsql security invoker set search_path='' as $$
declare needle text:=lower(btrim(p_query));
begin
  if needle is null or char_length(needle) not between 2 and 120 then return; end if;
  return query
  select r.category,r.obj,r.scope,r.heading,r.preview,r.ts from (
    (select 'direct'::text as category,m.id as obj,m.chat_id as scope,'Direct message'::text as heading,left(m.body,180) as preview,m.created_at as ts
      from public.st_messages m where (p_kind is null or p_kind='direct') and strpos(lower(m.body),needle)>0
      order by m.created_at desc,m.id desc limit 30)
    union all
    (select 'channel',p.id,c.workspace_id,'#'||c.name,left(p.body,180),p.created_at
      from public.st_v2_posts p join public.st_v2_channels c on p.channel_id=c.id
      where (p_kind is null or p_kind='channel') and strpos(lower(p.body),needle)>0
      order by p.created_at desc,p.id desc limit 30)
    union all
    (select 'board',i.id,i.workspace_id,i.title,left(i.details,180),i.created_at from public.st_v2_items i
      where (p_kind is null or p_kind='board') and (strpos(lower(i.title),needle)>0 or strpos(lower(i.details),needle)>0)
      order by i.created_at desc,i.id desc limit 30)
    union all
    (select 'meeting',m.id,m.workspace_id,m.title,left(m.agenda,180),m.starts_at from public.st_v3_meetings m
      where (p_kind is null or p_kind='meeting') and (strpos(lower(m.title),needle)>0 or strpos(lower(m.agenda),needle)>0)
      order by m.starts_at desc,m.id desc limit 30)
  ) r order by r.ts desc,r.obj desc limit 40;
end $$;

-- Vault objects contain encrypted bytes only. The owner is inferred from the authenticated folder.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('sectalk-vault','sectalk-vault',false,8392704,array['application/octet-stream']);

create policy st_v3_vault_read on storage.objects for select to authenticated using(
  bucket_id='sectalk-vault' and (storage.foldername(name))[1]=(select auth.uid())::text
);
create policy st_v3_vault_insert on storage.objects for insert to authenticated with check(
  bucket_id='sectalk-vault' and (storage.foldername(name))[1]=(select auth.uid())::text
  and name ~ '^[0-9a-f-]{36}/[0-9a-f-]{36}[.]stvault$'
);
create policy st_v3_vault_remove on storage.objects for delete to authenticated using(
  bucket_id='sectalk-vault' and (storage.foldername(name))[1]=(select auth.uid())::text
);
-- Restrict the new bucket even if legacy bucket policies allow broadly scoped actions.
create policy st_v3_vault_isolation on storage.objects as restrictive for all to public using(
  bucket_id <> 'sectalk-vault' or ((select auth.uid()) is not null and (storage.foldername(name))[1]=(select auth.uid())::text)
) with check(
  bucket_id <> 'sectalk-vault' or ((select auth.uid()) is not null and (storage.foldername(name))[1]=(select auth.uid())::text
    and name ~ '^[0-9a-f-]{36}/[0-9a-f-]{36}[.]stvault$')
);

revoke execute on function sectalk_private.st_v3_meeting_visible(uuid,uuid),sectalk_private.st_v3_is_host(uuid,uuid) from public,anon,authenticated;
grant execute on function sectalk_private.st_v3_meeting_visible(uuid,uuid),sectalk_private.st_v3_is_host(uuid,uuid) to authenticated;
revoke execute on function sectalk_private.st_v3_presence_visible(uuid,uuid) from public,anon,authenticated;
grant execute on function sectalk_private.st_v3_presence_visible(uuid,uuid) to authenticated;
do $$
declare sig text;
begin
  for sig in select p.oid::regprocedure::text from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and left(p.proname,6)='st_v3_'
  loop
    execute 'revoke all on function '||sig||' from public,anon,authenticated';
    execute 'grant execute on function '||sig||' to authenticated';
  end loop;
end $$;
alter publication supabase_realtime add table public.st_v3_meetings,public.st_v3_attendance,public.st_v3_notifications;
commit;
