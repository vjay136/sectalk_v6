begin;

alter table public.st_v3_meetings add column room_id uuid;
create index st_v6_room_calls_recent on public.st_v3_meetings(room_id,starts_at desc,id) where room_id is not null;
alter table public.st_v3_meetings add constraint st_v6_room_managed_media check(room_id is null or media_protection=0);

create or replace function sectalk_private.st_v3_meeting_visible(m uuid,u uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v3_meetings meeting where meeting.id=m
    and sectalk_private.st_v2_role(meeting.workspace_id,u) is not null
    and (meeting.room_id is null or (sectalk_private.st_v6_room_role(meeting.room_id,u) is not null
      and exists(select 1 from public.st_v6_rooms r where r.id=meeting.room_id
        and r.workspace_id=meeting.workspace_id and not r.archived))))
$$;

create or replace function sectalk_private.st_v3_is_host(m uuid,u uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v3_meetings meeting where meeting.id=m and meeting.host_id=u
    and sectalk_private.st_v2_role(meeting.workspace_id,u) in ('owner','admin')
    and (meeting.room_id is null or (sectalk_private.st_v3_meeting_visible(m,u)
      and sectalk_private.st_v6_room_role(meeting.room_id,u) in ('owner','moderator'))))
$$;

alter policy st_v3_meetings_read on public.st_v3_meetings to authenticated
  using(sectalk_private.st_v3_meeting_visible(id,(select auth.uid())));
create policy st_v6_room_call_attendance_scope on public.st_v3_attendance as restrictive for select to authenticated
  using(sectalk_private.st_v3_meeting_visible(meeting_id,(select auth.uid())));

create or replace function public.st_v3_media_access(p_meeting uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v3_meetings m join public.st_v3_attendance a on m.id=a.meeting_id
    where m.id=p_meeting and m.media_protection=0 and a.user_id=auth.uid() and a.status='admitted' and m.status='live' and m.ends_at>now()
      and sectalk_private.st_v3_meeting_visible(m.id,auth.uid())
      and sectalk_private.st_v2_active(auth.uid()) and sectalk_private.st_v3_is_host(m.id,m.host_id)
      and sectalk_private.st_v2_active(m.host_id) and sectalk_private.open_pair(m.host_id,auth.uid()))
$$;

create or replace function sectalk_private.st_v6_is_meeting_moderator(p_meeting uuid,p_actor uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select p_actor is not null and sectalk_private.st_v2_active(p_actor) and (
    sectalk_private.st_v3_is_host(p_meeting,p_actor) or exists (
      select 1 from public.st_v3_meetings m join public.st_v3_attendance a on a.meeting_id=m.id
      where m.id=p_meeting and m.status='live' and m.ends_at>now()
        and a.user_id=p_actor and a.status='admitted' and a.is_cohost
        and sectalk_private.st_v3_meeting_visible(m.id,p_actor)
        and sectalk_private.st_v2_active(m.host_id) and sectalk_private.st_v3_is_host(m.id,m.host_id)
        and sectalk_private.open_pair(m.host_id,p_actor)
    )
  )
$$;

create or replace function sectalk_private.st_v6_engagement_author(p_meeting uuid,p_author uuid,p_admitted_at timestamptz)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(
    select 1 from public.st_v3_attendance a join public.st_v3_meetings m on m.id=a.meeting_id
    where a.meeting_id=p_meeting and a.user_id=p_author and a.status='admitted'
      and a.admitted_at=p_admitted_at and sectalk_private.st_v3_meeting_visible(m.id,p_author)
      and sectalk_private.st_v2_active(p_author) and sectalk_private.open_pair(m.host_id,p_author)
  )
$$;

create function sectalk_private.st_v6_room_call_may_host(p_room uuid,p_workspace uuid,p_actor uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce(sectalk_private.st_v2_role(p_workspace,p_actor) in ('owner','admin')
    and sectalk_private.st_v6_room_role(p_room,p_actor) in ('owner','moderator'),false)
$$;

create function public.st_v6_start_room_call(p_room uuid,p_id uuid,p_title text)
returns uuid language plpgsql security definer set search_path='' as $$
declare target public.st_v6_rooms;
declare actor uuid:=auth.uid();
declare title_value text:=coalesce(nullif(btrim(p_title),''),'Room call');
declare instant timestamptz:=clock_timestamp();
begin
  perform sectalk_private.limit_action('v3_schedule',8);
  select * into target from public.st_v6_rooms r where r.id=p_room for update;
  if not found or target.archived or target.locked or
    not sectalk_private.st_v6_room_call_may_host(p_room,target.workspace_id,actor) then
    raise exception 'Room call cannot be started.' using errcode='42501';
  end if;
  if p_id is null or char_length(title_value)>100 then
    raise exception 'Choose a room call title up to 100 characters.' using errcode='22023';
  end if;
  if exists(select 1 from public.st_v3_meetings m where m.id=p_id and m.room_id=p_room and m.host_id=actor
    and m.title=title_value and m.is_instant) then return p_id; end if;
  if exists(select 1 from public.st_v3_meetings m where m.room_id=p_room and m.status='live' and m.ends_at>instant)
    then raise exception 'There is already a live call in this room.' using errcode='PT409'; end if;
  insert into public.st_v3_meetings(id,workspace_id,host_id,title,starts_at,ends_at,status,is_instant,room_id)
    values(p_id,target.workspace_id,actor,title_value,instant,instant+interval '30 minutes','live',true,p_room);
  insert into public.st_v3_attendance(meeting_id,user_id,status,admitted_at)
    values(p_id,actor,'admitted',instant);
  insert into public.st_v6_room_audit(room_id,actor,action,target) values(p_room,actor,'meeting.live',p_id);
  return p_id;
end
$$;

create function public.st_v6_room_calls(p_room uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare target public.st_v6_rooms;
declare actor uuid:=auth.uid();
begin
  select * into target from public.st_v6_rooms r where r.id=p_room;
  if not found or sectalk_private.st_v6_room_role(p_room,actor) is null or target.archived then return null; end if;
  return jsonb_build_object('can_start',not target.locked and
    sectalk_private.st_v6_room_call_may_host(p_room,target.workspace_id,actor),'calls',coalesce((
      select jsonb_agg(jsonb_build_object('id',m.id,'title',m.title,'starts_at',m.starts_at,
        'live',m.status='live' and m.ends_at>now(),
        'roster',case when m.status='live' and m.ends_at>now() then coalesce((
          select jsonb_agg(r.name order by r.host desc,r.name) from (
            select pr.name,a.user_id=m.host_id as host from public.st_v3_attendance a
            join public.st_profiles pr on pr.id=a.user_id where a.meeting_id=m.id and a.status='admitted'
              and sectalk_private.st_v3_meeting_visible(m.id,a.user_id) and sectalk_private.open_pair(actor,a.user_id)
            order by (a.user_id=m.host_id) desc,a.admitted_at,a.user_id limit 12
          ) r
        ),'[]'::jsonb) else '[]'::jsonb end,
        'your_status',(select a.status from public.st_v3_attendance a where a.meeting_id=m.id and a.user_id=actor))
        order by m.starts_at desc,m.id)
      from (select * from public.st_v3_meetings call where call.room_id=p_room and call.workspace_id=target.workspace_id
        and sectalk_private.st_v3_meeting_visible(call.id,actor) and sectalk_private.open_pair(actor,call.host_id)
        order by call.starts_at desc,call.id limit 20) m
    ),'[]'::jsonb));
end
$$;

create function sectalk_private.st_v6_route_room_call_audit()
returns trigger language plpgsql security definer set search_path='' as $$
declare associated uuid;
begin
  if new.event not like 'meeting.%' or new.target is null then return new; end if;
  select m.room_id into associated from public.st_v3_meetings m where m.id=new.target and m.workspace_id=new.workspace_id;
  if associated is null then return new; end if;
  if exists(select 1 from public.st_v6_rooms r where r.id=associated and r.workspace_id=new.workspace_id) then
    insert into public.st_v6_room_audit(room_id,actor,action,target) values(associated,new.actor,new.event,new.target);
  end if;
  return null;
end
$$;
create trigger st_v6_route_room_call_audit before insert on public.st_v2_workspace_audit
  for each row execute function sectalk_private.st_v6_route_room_call_audit();

create function sectalk_private.st_v6_gate_room_call_notice()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.meeting_id is not null and exists(select 1 from public.st_v3_meetings m where m.id=new.meeting_id and m.room_id is not null)
    then return null; end if;
  return new;
end
$$;
create trigger st_v6_gate_room_call_notice before insert on public.st_v3_notifications
  for each row execute function sectalk_private.st_v6_gate_room_call_notice();

create function sectalk_private.st_v6_gate_room_call_guests()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.enabled and exists(select 1 from public.st_v3_meetings m where m.id=new.meeting and m.room_id is not null)
    then raise exception 'Room calls require workspace room access.' using errcode='42501'; end if;
  return new;
end
$$;
create trigger st_v6_gate_room_call_guests before insert or update of enabled on sectalk_private.st_v6_guest_policy
  for each row execute function sectalk_private.st_v6_gate_room_call_guests();

create function sectalk_private.st_v6_revoke_room_call_admission()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  with ended as (
    update public.st_v3_meetings m set status='ended'
    where m.room_id=old.room_id and m.host_id=old.user_id and m.status='live'
      and not sectalk_private.st_v3_is_host(m.id,old.user_id)
    returning m.id
  )
  update public.st_v3_attendance a set status='left',left_at=clock_timestamp()
  where a.status in ('waiting','admitted') and (a.meeting_id in (select id from ended) or
    (a.user_id=old.user_id and exists(select 1 from public.st_v3_meetings m where m.id=a.meeting_id
      and m.room_id=old.room_id and m.status='live' and not sectalk_private.st_v3_meeting_visible(m.id,a.user_id))));
  return null;
end
$$;
create trigger st_v6_revoke_room_call_admission after delete or update of role on public.st_v6_room_members
  for each row execute function sectalk_private.st_v6_revoke_room_call_admission();

revoke all on function sectalk_private.st_v6_room_call_may_host(uuid,uuid,uuid),
  sectalk_private.st_v6_route_room_call_audit(),sectalk_private.st_v6_gate_room_call_notice(),
  sectalk_private.st_v6_gate_room_call_guests(),sectalk_private.st_v6_revoke_room_call_admission(),
  public.st_v6_start_room_call(uuid,uuid,text),public.st_v6_room_calls(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_start_room_call(uuid,uuid,text),public.st_v6_room_calls(uuid) to authenticated;

create table sectalk_private.st_v6_room_files (
  room uuid not null,
  workspace uuid not null,
  id uuid not null,
  uploader uuid not null,
  filename text not null check(char_length(filename) between 1 and 140),
  size_bytes integer not null check(size_bytes between 1 and 4194304),
  sha256 text not null check(sha256 ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default clock_timestamp(),
  upload_until timestamptz,
  published_at timestamptz,
  deleted_at timestamptz,
  lease uuid,
  retry_at timestamptz not null default '-infinity',
  primary key(room,id)
);
create index st_v6_room_files_recent on sectalk_private.st_v6_room_files(room,published_at desc,id)
  where published_at is not null and deleted_at is null;
create index st_v6_room_files_cleanup on sectalk_private.st_v6_room_files(retry_at,created_at);
alter table sectalk_private.st_v6_room_files enable row level security;
revoke all on sectalk_private.st_v6_room_files from public,anon,authenticated,service_role;

create function public.st_v6_room_file_command(p_room uuid,p_actor uuid,p_action text,p_id uuid,
  p_name text,p_bytes integer,p_hash text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare target public.st_v6_rooms;
declare entry sectalk_private.st_v6_room_files;
declare scope_role text;
declare can_write boolean;
begin
  select * into target from public.st_v6_rooms r where r.id=p_room;
  scope_role:=sectalk_private.st_v6_room_role(p_room,p_actor);
  if target.id is null or scope_role is null then return null; end if;
  can_write:=not target.archived and not target.locked and
    (scope_role in ('owner','moderator') or (scope_role='member' and target.kind in ('public','private')));
  if p_action='access' then return case when can_write then jsonb_build_object('allowed',true) end; end if;
  if p_action='list' then
    return jsonb_build_object('can_upload',can_write,'files',coalesce((
      select jsonb_agg(jsonb_build_object('id',f.id,'filename',f.filename,'size_bytes',f.size_bytes,
        'can_remove',not target.archived and (scope_role in ('owner','moderator') or f.uploader=p_actor))
        order by f.published_at desc,f.id)
      from (select * from sectalk_private.st_v6_room_files files where files.room=p_room
        and files.workspace=target.workspace_id and files.published_at is not null and files.deleted_at is null
        order by files.published_at desc,files.id limit 100) f
    ),'[]'::jsonb));
  end if;
  if p_id is null or p_action is null or p_action not in ('get','reserve','publish','remove') then return null; end if;
  if p_action<>'get' then
    perform pg_advisory_xact_lock(hashtextextended('room_file:'||p_room::text,0));
    if sectalk_private.st_v6_room_role(p_room,p_actor) is distinct from scope_role then return null; end if;
    perform 1 from public.st_v6_rooms r where r.id=p_room and r.archived=target.archived and r.locked=target.locked for share;
    if not found then return null; end if;
  end if;
  select * into entry from sectalk_private.st_v6_room_files f where f.room=p_room and f.id=p_id and f.workspace=target.workspace_id;
  if p_action in ('get','remove') then
    if entry.published_at is null or entry.deleted_at is not null then return null; end if;
    if p_action='remove' then
      if target.archived or (entry.uploader<>p_actor and scope_role not in ('owner','moderator')) then return null; end if;
      update sectalk_private.st_v6_room_files f set deleted_at=clock_timestamp(),retry_at=clock_timestamp()
        where f.room=p_room and f.id=p_id;
      return jsonb_build_object('removed',true);
    end if;
    return jsonb_build_object('workspace',target.workspace_id,'size_bytes',entry.size_bytes,'sha256',entry.sha256);
  end if;
  if not can_write or p_hash is null or p_hash !~ '^[0-9a-f]{64}$' then return null; end if;
  if exists(select 1 from sectalk_private.st_v6_malware_hashes m where m.sha256=decode(p_hash,'hex')) then
    raise exception 'The room file was blocked by security scanning.' using errcode='PT422';
  end if;
  if entry.id is not null and (entry.uploader<>p_actor or entry.sha256<>p_hash or entry.size_bytes<>p_bytes
    or entry.filename is distinct from p_name or entry.deleted_at is not null or
    (entry.published_at is null and entry.created_at<=clock_timestamp()-interval '15 minutes')) then return null; end if;
  if p_action='reserve' then
    if p_name is null or char_length(p_name) not between 1 and 140 or p_name ~ '[/[:cntrl:]]' or strpos(p_name,chr(92))>0
      or p_bytes is null or p_bytes not between 1 and 4194304 then return null; end if;
    if entry.id is null then
      if exists(select 1 from sectalk_private.st_v6_room_files f where f.room=p_room group by f.room
        having count(*)>=100 or sum(f.size_bytes)+p_bytes>33554432) then
        raise exception 'The room file storage limit was reached.' using errcode='PT413';
      end if;
      insert into sectalk_private.st_v6_room_files(room,workspace,id,uploader,filename,size_bytes,sha256,upload_until)
        values(p_room,target.workspace_id,p_id,p_actor,p_name,p_bytes,p_hash,clock_timestamp()+interval '2 minutes');
    elsif entry.published_at is null then
      update sectalk_private.st_v6_room_files f set upload_until=clock_timestamp()+interval '2 minutes'
        where f.room=p_room and f.id=p_id;
    end if;
    return jsonb_build_object('workspace',target.workspace_id,'uploaded',entry.published_at is not null);
  end if;
  if entry.id is null or not exists(select 1 from storage.objects s where s.bucket_id='sectalk-workspace-files'
    and s.name=target.workspace_id::text||'/rooms/'||p_room::text||'/'||p_id::text
    and s.metadata->>'size'=entry.size_bytes::text) then return null; end if;
  update sectalk_private.st_v6_room_files f set published_at=coalesce(f.published_at,clock_timestamp()),upload_until=null
    where f.room=p_room and f.id=p_id;
  return jsonb_build_object('id',p_id);
end
$$;

create function public.st_v6_claim_room_file_cleanup()
returns table(room uuid,workspace uuid,id uuid,lease uuid) language sql security definer set search_path='' as $$
  with candidates as (
    select f.room,f.id from sectalk_private.st_v6_room_files f where f.retry_at<=clock_timestamp()
      and (f.upload_until is null or f.upload_until<=clock_timestamp())
      and (f.deleted_at is not null or not exists(select 1 from public.st_v6_rooms r where r.id=f.room and r.workspace_id=f.workspace)
        or (f.published_at is null and f.created_at<=clock_timestamp()-interval '15 minutes'))
    order by f.retry_at,f.created_at,f.room,f.id limit 12 for update of f skip locked
  )
  update sectalk_private.st_v6_room_files f set lease=gen_random_uuid(),retry_at=clock_timestamp()+interval '5 minutes'
  from candidates where f.room=candidates.room and f.id=candidates.id returning f.room,f.workspace,f.id,f.lease
$$;

create function public.st_v6_finish_room_file_cleanup(p_room uuid,p_id uuid,p_lease uuid)
returns boolean language sql security definer set search_path='' as $$
  with removed as (
    delete from sectalk_private.st_v6_room_files f where f.room=p_room and f.id=p_id and f.lease=p_lease
      and not exists(select 1 from storage.objects s where s.bucket_id='sectalk-workspace-files'
        and s.name=f.workspace::text||'/rooms/'||f.room::text||'/'||f.id::text)
    returning 1
  ) select exists(select 1 from removed)
$$;

revoke all on function public.st_v6_room_file_command(uuid,uuid,text,uuid,text,integer,text),
  public.st_v6_claim_room_file_cleanup(),public.st_v6_finish_room_file_cleanup(uuid,uuid,uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_room_file_command(uuid,uuid,text,uuid,text,integer,text),
  public.st_v6_claim_room_file_cleanup(),public.st_v6_finish_room_file_cleanup(uuid,uuid,uuid) to service_role;

commit;
