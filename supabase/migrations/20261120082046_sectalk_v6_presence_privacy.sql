begin;

alter table public.st_v3_presence drop constraint st_v3_presence_state_check,
  add constraint st_v3_presence_state_check check(state in ('online','away','busy','offline','invisible'));

create table sectalk_private.st_v6_presence_privacy (
  user_id uuid primary key references public.st_profiles on delete cascade,
  share_availability boolean not null
);
create table sectalk_private.st_v6_workspace_presence_policy (
  workspace_id uuid primary key references public.st_v2_workspaces on delete cascade
);
alter table sectalk_private.st_v6_presence_privacy enable row level security;
alter table sectalk_private.st_v6_workspace_presence_policy enable row level security;
revoke all on sectalk_private.st_v6_presence_privacy,sectalk_private.st_v6_workspace_presence_policy
  from public,anon,authenticated;

create function sectalk_private.st_v6_presence_required(actor uuid)
returns boolean language sql stable set search_path='' as $$
  select exists (
    select 1 from public.st_v2_members m
    join sectalk_private.st_v6_workspace_presence_policy p on p.workspace_id=m.workspace_id
    where m.user_id=actor and m.suspended_at is null
  )
$$;

create function sectalk_private.st_v6_shares_presence(actor uuid)
returns boolean language sql stable set search_path='' as $$
  select sectalk_private.st_v2_active(actor)
    and not exists(select 1 from sectalk_private.st_v6_presence_privacy p
      where p.user_id=actor and not p.share_availability)
    and not exists(select 1 from public.st_v3_presence p
      where p.user_id=actor and p.state='invisible')
$$;

create or replace function sectalk_private.st_v3_presence_visible(p_peer uuid,p_self uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select p_self=auth.uid() and sectalk_private.st_v2_active(p_self) and
    (p_peer=p_self or (sectalk_private.st_v5_profile_visible(p_peer,p_self)
      and sectalk_private.st_v6_shares_presence(p_peer)))
$$;

alter policy st_v3_visible_presence on public.st_v3_presence using(
  user_id=(select auth.uid()) or (state in ('online','away','busy') and expires_at>now()
    and sectalk_private.st_v3_presence_visible(user_id,(select auth.uid())))
);

alter policy st_v5_profile_details_read on public.st_v5_profile_details
  using(sectalk_private.st_v3_presence_visible(user_id,(select auth.uid())));

create function public.st_v6_profile_photo_revision(p_user uuid)
returns uuid language sql stable security definer set search_path='' as $$
  select d.photo_revision from public.st_v5_profile_details d
  where d.user_id=p_user and sectalk_private.st_v5_profile_visible(p_user,auth.uid())
$$;

create or replace function sectalk_private.st_v6_availability_hint(actor uuid, contacts boolean)
returns void language plpgsql set search_path='' as $$
begin
  perform realtime.send('{}'::jsonb,'availability','st:account:'||actor,true);
  if contacts and sectalk_private.st_v6_shares_presence(actor) then
    perform realtime.send('{}'::jsonb,'availability','st:account:'||peers.id,true)
    from (
      select case when c.member_a=actor then c.member_b else c.member_a end as id
      from public.st_chats c
      where actor in(c.member_a,c.member_b) and c.status='accepted'
    ) peers where sectalk_private.open_pair(actor,peers.id);
  end if;
end
$$;

create function sectalk_private.st_v6_contact_presence_refresh(actor uuid)
returns void language sql set search_path='' as $$
  select realtime.send('{}'::jsonb,'presence','st:account:'||peers.id,true)
  from (
    select case when c.member_a=actor then c.member_b else c.member_a end as id
    from public.st_chats c
    where actor in(c.member_a,c.member_b) and c.status='accepted'
  ) peers where sectalk_private.open_pair(actor,peers.id)
    and sectalk_private.st_v2_active(peers.id)
$$;

create or replace function sectalk_private.st_v6_presence_hint()
returns trigger language plpgsql security definer set search_path='' as $$
declare
  was_visible boolean := false;
  is_visible boolean := new.state in ('online','away','busy') and new.expires_at>clock_timestamp();
  was_invisible boolean := false;
begin
  if tg_op='UPDATE' then
    was_invisible:=old.state='invisible';
    was_visible:=old.state in ('online','away','busy') and old.expires_at>clock_timestamp();
    if old.state=new.state and was_visible=is_visible then return new; end if;
  end if;
  perform realtime.send('{}'::jsonb,'presence','st:account:'||new.user_id,true);
  if (is_visible or was_visible or was_invisible) and sectalk_private.st_v6_shares_presence(new.user_id)
    or new.state='invisible' and not was_invisible
      and sectalk_private.st_v2_active(new.user_id)
      and not exists(select 1 from sectalk_private.st_v6_presence_privacy p
        where p.user_id=new.user_id and not p.share_availability)
  then
    perform sectalk_private.st_v6_contact_presence_refresh(new.user_id);
  end if;
  return new;
end $$;

create or replace function public.st_v3_ping()
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid := auth.uid();
begin
  perform sectalk_private.limit_action('v6_presence_ping',12);
  if not sectalk_private.st_v2_active(actor) then return; end if;
  update public.st_v3_presence set expires_at=clock_timestamp()+interval '100 seconds'
    where user_id=actor and state in ('online','away','busy') and expires_at<=clock_timestamp()+interval '65 seconds';
end $$;

create or replace function public.st_v3_set_presence(p_state text)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  sharing_required boolean;
  resumed_sharing boolean;
begin
  perform sectalk_private.limit_action('v3_presence_set',10);
  if not sectalk_private.st_v2_active(actor) then return; end if;
  if p_state is null or p_state not in ('online','away','busy','offline','invisible') then
    raise exception 'Choose an availability state';
  end if;
  perform id from public.st_profiles where id=actor for update;
  sharing_required:=sectalk_private.st_v6_presence_required(actor);
  if p_state='invisible' and sharing_required then
    raise exception 'A workspace policy requires availability sharing';
  end if;
  insert into public.st_v3_presence(user_id,state,expires_at)
    values(actor,p_state,case when p_state in ('offline','invisible') then now() else now()+interval '100 seconds' end)
    on conflict(user_id) do update set state=excluded.state,expires_at=excluded.expires_at;
  if sharing_required then
    delete from sectalk_private.st_v6_presence_privacy where user_id=actor and not share_availability
      returning true into resumed_sharing;
    if resumed_sharing then perform sectalk_private.st_v6_contact_presence_refresh(actor); end if;
  end if;
end $$;

create function public.st_v6_presence_settings()
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object(
    'required',sectalk_private.st_v6_presence_required(auth.uid()),
    'sharing',coalesce((select share_availability from sectalk_private.st_v6_presence_privacy where user_id=auth.uid()),true)
  ) where sectalk_private.st_v2_active(auth.uid())
$$;

create function public.st_v6_set_presence_privacy(p_share boolean)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  shared_before boolean;
begin
  perform sectalk_private.limit_action('v6_presence_privacy',10);
  if not sectalk_private.st_v2_active(actor) or p_share is null then
    raise exception 'Availability settings unavailable';
  end if;
  perform id from public.st_profiles where id=actor for update;
  if not p_share and sectalk_private.st_v6_presence_required(actor) then
    raise exception 'A workspace policy requires availability sharing';
  end if;
  shared_before:=sectalk_private.st_v6_shares_presence(actor);
  insert into sectalk_private.st_v6_presence_privacy(user_id,share_availability) values(actor,p_share)
    on conflict(user_id) do update set share_availability=excluded.share_availability;
  perform realtime.send('{}'::jsonb,'presence','st:account:'||actor,true);
  if shared_before is distinct from sectalk_private.st_v6_shares_presence(actor) then
    perform sectalk_private.st_v6_contact_presence_refresh(actor);
  end if;
end $$;

create function public.st_v6_workspace_presence_policy(p_workspace uuid)
returns boolean language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_v2_active(auth.uid())
    or sectalk_private.st_v2_role(p_workspace,auth.uid()) is null then
    raise exception 'Workspace presence policy unavailable';
  end if;
  return exists(select 1 from sectalk_private.st_v6_workspace_presence_policy where workspace_id=p_workspace);
end $$;

create function public.st_v6_set_workspace_presence_policy(p_workspace uuid,p_required boolean)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_workspace_presence_policy',10);
  if not sectalk_private.st_v2_active(actor) or p_required is null
    or coalesce(sectalk_private.st_v2_role(p_workspace,actor),'') not in ('owner','admin') then
    raise exception 'Workspace presence policy unavailable';
  end if;
  if p_required then
    insert into sectalk_private.st_v6_workspace_presence_policy(workspace_id) values(p_workspace)
      on conflict do nothing;
  else
    delete from sectalk_private.st_v6_workspace_presence_policy where workspace_id=p_workspace;
  end if;
  if not found then return; end if;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor,case when p_required then 'workspace.presence_required'
      else 'workspace.presence_member_choice' end,p_workspace);
  perform realtime.send('{}'::jsonb,'presence','st:account:'||m.user_id,true)
    from public.st_v2_members m where m.workspace_id=p_workspace and m.suspended_at is null;
end $$;

revoke all on function sectalk_private.st_v6_presence_required(uuid),sectalk_private.st_v6_shares_presence(uuid),
  sectalk_private.st_v6_contact_presence_refresh(uuid) from public,anon,authenticated;

revoke all on function public.st_v6_profile_photo_revision(uuid),public.st_v6_presence_settings(),
  public.st_v6_set_presence_privacy(boolean),public.st_v6_workspace_presence_policy(uuid),
  public.st_v6_set_workspace_presence_policy(uuid,boolean) from public,anon,authenticated;
grant execute on function public.st_v6_profile_photo_revision(uuid),public.st_v6_presence_settings(),
  public.st_v6_set_presence_privacy(boolean),public.st_v6_workspace_presence_policy(uuid),
  public.st_v6_set_workspace_presence_policy(uuid,boolean) to authenticated;



create or replace function public.st_v6_effective_availability(p_user uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare
  rule sectalk_private.st_v6_quiet_rules;
  custom text;
  shared boolean;
begin
  if auth.uid() is null or not sectalk_private.st_v2_active(auth.uid())
    or not sectalk_private.st_v3_presence_visible(p_user,auth.uid()) then
    return null;
  end if;
  select d.status_message into custom from public.st_v5_profile_details d where d.user_id=p_user;
  select exists(
    select 1 from public.st_v3_presence p where p.user_id=p_user and p.state in ('online','away','busy') and p.expires_at>now()
  ) into shared;
  if shared then
    select r.* into rule from sectalk_private.st_v6_quiet_rules r where r.user_id=p_user and r.chat_id is null;
    if rule.scheduled_status is not null and sectalk_private.st_v6_quiet_window(rule,now()) then
      custom:=rule.scheduled_status;
    end if;
  end if;
  return jsonb_build_object('busy',shared and sectalk_private.st_v6_quiet_for(p_user,null),'status',coalesce(custom,''));
end
$$;

create or replace function public.st_v5_last_seen(p_chat uuid)
returns timestamptz language sql stable security definer set search_path='' as $$
  select p.expires_at-interval '100 seconds'
  from public.st_chats c join public.st_v3_presence p on p.user_id=
    case when c.member_a=auth.uid() then c.member_b else c.member_a end
  join public.st_v5_profile_details settings on settings.user_id=p.user_id and settings.share_last_seen
  where c.id=p_chat and auth.uid() in(c.member_a,c.member_b) and c.status='accepted'
    and sectalk_private.st_v3_presence_visible(p.user_id,auth.uid()) and p.state in ('online','away','busy')
    and p.expires_at>now()-interval '7 days'
$$;

create or replace function sectalk_private.st_v6_room_post_alert()
returns trigger language plpgsql security definer set search_path='' as $$
declare
  can_broadcast boolean:=coalesce(sectalk_private.st_v6_room_role(new.room_id) in ('owner','moderator'),false);
  alert record;
begin
  for alert in
  with tokens as materialized (
    select lower(replace(match[2],'""','"')) as group_name,
      lower(match[3]) as explicit_handle,lower(match[4]) as handle
    from regexp_matches(new.body,
      '(^|[^[:alnum:]_@])@(?:group:"((?:[^"]|""){1,80})"|user:([a-z0-9_]{3,24})|(?!(?:group|user):)([a-z0-9_]{3,24}))(?![[:alnum:]_@])',
      'gi') as match
  ), audiences as materialized (
    select r.workspace_id,recipients.user_id
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
      and not sectalk_private.st_v6_room_alert_quiet(recipients.user_id,r.id)
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
      when can_broadcast and exists(select 1 from tokens where handle='here') and exists(
        select 1 from public.st_v3_presence presence
        where presence.user_id=audience.user_id and sectalk_private.st_v6_shares_presence(audience.user_id)
          and presence.state='online' and presence.expires_at>clock_timestamp()
      ) then 'mention.here'
      when can_broadcast and exists(select 1 from tokens where handle='channel') then 'mention.channel'
    end)) mention(kind)
    where mention.kind is not null
    on conflict (room_id,room_post_id,recipient) do nothing
    returning recipient,kind
  )
  select audience.user_id,notices.kind
  from audiences audience
  left join notices on notices.recipient=audience.user_id
  loop
    perform realtime.send(jsonb_strip_nulls(jsonb_build_object('room_id',new.room_id,'mention_kind',alert.kind)),
      'room_activity','st:account:'||alert.user_id,true);
  end loop;
  return new;
end
$$;

commit;
