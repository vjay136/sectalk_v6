begin;

create table sectalk_private.st_v6_room_role_overrides (
  room uuid not null references public.st_v6_rooms(id) on delete cascade,
  role text not null check(role in ('owner','moderator','member')),
  rules jsonb not null check(jsonb_typeof(rules)='object'),
  primary key(room,role)
);
alter table sectalk_private.st_v6_room_role_overrides enable row level security;
revoke all on sectalk_private.st_v6_room_role_overrides from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_room_role_rule(p_room uuid,p_actor uuid,p_action text)
returns text language sql stable set search_path='' as $$
  select coalesce((select o.rules->>p_action from sectalk_private.st_v6_room_role_overrides o
    where o.room=p_room and o.role=sectalk_private.st_v6_room_role(p_room,p_actor)),'inherit')
$$;

create function sectalk_private.st_v6_room_all_mentions(p_room uuid,p_actor uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce((case sectalk_private.st_v6_room_role_rule(p_room,p_actor,'mention_all')
    when 'deny' then false
    when 'allow' then sectalk_private.st_v6_room_role(p_room,p_actor) in ('owner','moderator','member')
    else sectalk_private.st_v6_room_role(p_room,p_actor) in ('owner','moderator')
  end),false)
$$;

create function public.st_v6_room_permission_state(p_room uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare member_role text:=sectalk_private.st_v6_room_role(p_room,actor);
declare target public.st_v6_rooms;
declare can_write boolean;
begin
  if member_role is null then return null; end if;
  select * into target from public.st_v6_rooms r where r.id=p_room;
  if not found then return null; end if;
  can_write:=member_role<>'read_only' and not target.archived and
    (member_role in ('owner','moderator') or (not target.locked and target.kind not in ('announcement','broadcast')));
  return jsonb_build_object(
    'post',can_write and sectalk_private.st_v6_room_role_rule(p_room,actor,'post')<>'deny',
    'react',can_write and sectalk_private.st_v6_room_role_rule(p_room,actor,'react')<>'deny',
    'mention_all',sectalk_private.st_v6_room_all_mentions(p_room,actor),
    'editable',case when target.archived then '{}'::jsonb else coalesce((
      select jsonb_object_agg(a.role,coalesce(r.rules,'{}'::jsonb))
      from (values('owner'),('moderator'),('member')) a(role)
      left join sectalk_private.st_v6_room_role_overrides r on r.room=p_room and r.role=a.role
      where member_role='owner' or (member_role='moderator' and a.role='member')
    ),'{}'::jsonb) end
  );
end
$$;

create function public.st_v6_set_room_role_overrides(p_room uuid,p_role text,p_rules jsonb)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare member_role text;
begin
  perform sectalk_private.limit_action('v6_room_role_overrides',20);
  perform 1 from public.st_v6_rooms r where r.id=p_room and not r.archived for no key update;
  if not found then raise exception 'Room permissions are unavailable.' using errcode='42501'; end if;
  member_role:=sectalk_private.st_v6_room_role(p_room,actor);
  if p_role is null or p_role not in ('owner','moderator','member') or member_role is null
    or not (member_role='owner' or (member_role='moderator' and p_role='member')) then
    raise exception 'You cannot change permissions for that room role.' using errcode='42501';
  end if;
  if p_rules is null or jsonb_typeof(p_rules)<>'object' or exists(
    select 1 from jsonb_each(p_rules) rule where rule.key not in ('post','react','upload','mention_all','start_call')
      or rule.value not in ('"allow"'::jsonb,'"deny"'::jsonb)
  ) then raise exception 'Choose valid room permissions.' using errcode='22023'; end if;
  if p_rules='{}'::jsonb then
    delete from sectalk_private.st_v6_room_role_overrides r where r.room=p_room and r.role=p_role;
  else
    insert into sectalk_private.st_v6_room_role_overrides as current_rule(room,role,rules) values(p_room,p_role,p_rules)
      on conflict(room,role) do update set rules=excluded.rules where current_rule.rules is distinct from excluded.rules;
  end if;
  if found then
    insert into public.st_v6_room_audit(room_id,actor,action,details)
      values(p_room,actor,'room.role_permissions',jsonb_build_object('role',p_role,'rules',p_rules));
  end if;
end
$$;

create function sectalk_private.st_v6_guard_room_post_override()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.sender=auth.uid() and new.removed_at is null
    and (tg_op='INSERT' or new.body is distinct from old.body)
    and sectalk_private.st_v6_room_role_rule(new.room_id,new.sender,'post')='deny' then
    raise exception 'Posting is blocked for your room role.' using errcode='42501';
  end if;
  return new;
end
$$;
create trigger st_v6_guard_room_post_override before insert or update of body on public.st_v6_room_posts
  for each row execute function sectalk_private.st_v6_guard_room_post_override();

create function sectalk_private.st_v6_guard_room_reaction_override()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if sectalk_private.st_v6_room_role_rule(new.room_id,new.actor_id,'react')='deny' then
    raise exception 'Reactions are blocked for your room role.' using errcode='42501';
  end if;
  return new;
end
$$;
create trigger st_v6_guard_room_reaction_override before insert on sectalk_private.st_v6_room_reactions
  for each row execute function sectalk_private.st_v6_guard_room_reaction_override();

alter table public.st_v3_meetings add column room_host_grant text
  check(room_host_grant is null or (room_id is not null and room_host_grant in ('owner','moderator','member')));

create or replace function sectalk_private.st_v6_room_call_may_host(p_room uuid,p_workspace uuid,p_actor uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce((case sectalk_private.st_v6_room_role_rule(p_room,p_actor,'start_call')
    when 'deny' then false
    when 'allow' then sectalk_private.st_v6_room_role(p_room,p_actor) in ('owner','moderator','member')
    else sectalk_private.st_v2_role(p_workspace,p_actor) in ('owner','admin')
      and sectalk_private.st_v6_room_role(p_room,p_actor) in ('owner','moderator')
  end),false)
$$;

create or replace function sectalk_private.st_v3_is_host(m uuid,u uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v3_meetings meeting where meeting.id=m and meeting.host_id=u
    and (case when meeting.room_id is null then sectalk_private.st_v2_role(meeting.workspace_id,u) in ('owner','admin')
      else sectalk_private.st_v3_meeting_visible(m,u) and (
        (sectalk_private.st_v2_role(meeting.workspace_id,u) in ('owner','admin')
          and sectalk_private.st_v6_room_role(meeting.room_id,u) in ('owner','moderator'))
        or (meeting.room_host_grant is not null and meeting.room_host_grant=sectalk_private.st_v6_room_role(meeting.room_id,u))
      ) end))
$$;

revoke all on function sectalk_private.st_v6_room_role_rule(uuid,uuid,text),
  sectalk_private.st_v6_room_all_mentions(uuid,uuid),sectalk_private.st_v6_guard_room_post_override(),
  sectalk_private.st_v6_guard_room_reaction_override(),public.st_v6_room_permission_state(uuid),
  public.st_v6_set_room_role_overrides(uuid,text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_room_permission_state(uuid),public.st_v6_set_room_role_overrides(uuid,text,jsonb) to authenticated;

create or replace function public.st_v6_start_room_call(p_room uuid,p_id uuid,p_title text)
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
  insert into public.st_v3_meetings(id,workspace_id,host_id,title,starts_at,ends_at,status,is_instant,room_id,room_host_grant)
    values(p_id,target.workspace_id,actor,title_value,instant,instant+interval '30 minutes','live',true,p_room,
      case when not coalesce(sectalk_private.st_v2_role(target.workspace_id,actor) in ('owner','admin') and
        sectalk_private.st_v6_room_role(p_room,actor) in ('owner','moderator'),false)
        then sectalk_private.st_v6_room_role(p_room,actor) end);
  insert into public.st_v3_attendance(meeting_id,user_id,status,admitted_at)
    values(p_id,actor,'admitted',instant);
  insert into public.st_v6_room_audit(room_id,actor,action,target) values(p_room,actor,'meeting.live',p_id);
  return p_id;
end
$$;

create or replace function public.st_v6_room_file_command(p_room uuid,p_actor uuid,p_action text,p_id uuid,
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
    sectalk_private.st_v6_room_role_rule(p_room,p_actor,'upload')<>'deny' and
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
  if not can_write or sectalk_private.st_v6_room_role_rule(p_room,p_actor,'upload')='deny'
    or p_hash is null or p_hash !~ '^[0-9a-f]{64}$' then return null; end if;
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

create or replace function sectalk_private.st_v6_room_post_alert()
returns trigger language plpgsql security definer set search_path='' as $$
declare
  can_broadcast boolean:=coalesce(sectalk_private.st_v6_room_role(new.room_id) in ('owner','moderator'),false);
  can_mention_all boolean:=sectalk_private.st_v6_room_all_mentions(new.room_id,auth.uid());
  alert record;
  admin_post uuid;
  mandatory text[]:=sectalk_private.st_v6_mandatory_workspace_alerts(
    (select workspace_id from public.st_v6_rooms where id=new.room_id));
begin
  insert into sectalk_private.st_v6_admin_notification_runs(room_id,post_id,shared_audience)
  select r.id,new.id,(select count(*)>1 from (
    select 1 from public.st_v2_members m
    where m.workspace_id=r.workspace_id and m.role in ('owner','admin') and m.suspended_at is null and m.user_id<>new.sender
      and sectalk_private.st_v2_active(m.user_id)
      and sectalk_private.open_pair(new.sender,m.user_id)
      and not exists(select 1 from public.st_v6_room_bans b where b.room_id=r.id and b.user_id=m.user_id)
    limit 2
  ) recipients)
  from public.st_v6_rooms r where r.id=new.room_id and r.kind='admin'
  returning post_id into admin_post;

  for alert in
  with tokens as materialized (
    select lower(replace(match[2],'""','"')) as group_name,
      lower(match[3]) as explicit_handle,lower(match[4]) as handle
    from regexp_matches(new.body,
      '(^|[^[:alnum:]_@])@(?:group:"((?:[^"]|""){1,80})"|user:([a-z0-9_]{3,24})|(?!(?:group|user):)([a-z0-9_]{3,24}))(?![[:alnum:]_@])',
      'gi') as match
    where not new.forwarded
  ), audiences as materialized (
    select r.workspace_id,r.kind as room_kind,recipients.user_id,
      sectalk_private.st_v6_workspace_alert_quiet(recipients.user_id,r.workspace_id,r.id,null) as quiet
    from public.st_v6_rooms r
    cross join lateral (
      select m.user_id from public.st_v6_room_members m where r.kind<>'admin' and m.room_id=r.id
      union all
      select m.user_id from public.st_v2_members m
        where r.kind='admin' and m.workspace_id=r.workspace_id and m.role in ('owner','admin')
    ) recipients
    where r.id=new.room_id and recipients.user_id<>new.sender and not r.archived
      and sectalk_private.st_v2_active(recipients.user_id)
      and sectalk_private.st_v2_role(r.workspace_id,recipients.user_id) is not null
      and not exists(select 1 from public.st_v6_room_bans b where b.room_id=r.id and b.user_id=recipients.user_id)
      and sectalk_private.open_pair(new.sender,recipients.user_id)

  ), group_recipients as (
    select distinct membership.user_id
    from tokens
    join public.st_v6_workspace_groups item on item.workspace_id=(select workspace_id from public.st_v6_rooms where id=new.room_id)
      and item.kind='group' and item.archived_at is null and lower(item.name)=tokens.group_name
    join public.st_v6_workspace_group_members membership on (membership.workspace_id,membership.group_id)=(item.workspace_id,item.id)
    where can_broadcast
  ), notices as (
    insert into public.st_v3_notifications(recipient,workspace_id,room_id,room_post_id,kind)
    select audience.user_id,audience.workspace_id,new.room_id,new.id,mention.kind
    from audiences audience
    join public.st_profiles profile on profile.id=audience.user_id
    cross join lateral (values (case
      when exists(select 1 from tokens where explicit_handle=profile.handle
        or (handle=profile.handle and handle not in ('channel','here')))
        then 'mention.user'
      when can_broadcast and exists(select 1 from group_recipients where user_id=audience.user_id)
        then 'mention.group'
      when can_mention_all and exists(select 1 from tokens where handle='here') and exists(
        select 1 from public.st_v3_presence presence
        where presence.user_id=audience.user_id and sectalk_private.st_v6_shares_presence(audience.user_id)
          and presence.state='online' and presence.expires_at>clock_timestamp()
      ) then 'mention.here'
      when can_mention_all and exists(select 1 from tokens where handle='channel') then 'mention.channel'
    end)) mention(kind)
    where mention.kind is not null and (not audience.quiet or 'mention'=any(mandatory))
    on conflict (room_id,room_post_id,recipient) do nothing
    returning recipient,kind
  )
  select audience.user_id,audience.room_kind,audience.quiet,notices.kind,
    new.parent_id is not null and exists(select 1 from public.st_v6_thread_follows f
      where (f.room_id,f.post_id,f.user_id)=(new.room_id,new.parent_id,audience.user_id)) as following
  from audiences audience
  left join notices on notices.recipient=audience.user_id
  loop
    if alert.kind is not null and 'mention'=any(mandatory) then
      perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,alert.kind,alert.quiet,new.room_id,admin_post,'room:'||new.room_id||':'||new.id);
    elsif alert.following and 'thread'=any(mandatory) then
      perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,'thread.reply',alert.quiet,new.room_id,admin_post,'room:'||new.room_id||':'||new.id);
    elsif alert.room_kind='admin' and 'admin'=any(mandatory) then
      perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,'admin.room',alert.quiet,new.room_id,admin_post,'room:'||new.room_id||':'||new.id);
    elsif not alert.quiet then
      if alert.kind is not null
        and sectalk_private.st_v6_deliver_account_alert(alert.user_id,alert.kind,false,new.room_id,admin_post,'room:'||new.room_id||':'||new.id) then
        continue;
      end if;
      if new.parent_id is not null then
        if not sectalk_private.st_v6_notification_enabled(alert.user_id,'thread') then continue; end if;
        if alert.following then
          perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,'thread.reply',false,new.room_id,admin_post,'room:'||new.room_id||':'||new.id);
          continue;
        end if;
      end if;
      if alert.kind is null then
        if alert.room_kind='admin' then
          perform sectalk_private.st_v6_deliver_account_alert(alert.user_id,'admin.room',false,new.room_id,admin_post,'room:'||new.room_id||':'||new.id);
        else
          perform realtime.send(jsonb_build_object('room_id',new.room_id),
            'room_activity','st:account:'||alert.user_id,true);
        end if;
      end if;
    end if;
  end loop;
  return new;
end
$$;

commit;
