begin;

create table sectalk_private.read_receipt_preferences (
  user_id uuid primary key references public.st_profiles on delete cascade,
  enabled boolean not null,
  changed_at timestamptz not null
);
create table sectalk_private.workspace_read_receipt_policy (
  workspace_id uuid primary key references public.st_v2_workspaces on delete cascade,
  enabled boolean not null,
  changed_at timestamptz not null
);
create table sectalk_private.room_read_receipt_policy (
  room_id uuid primary key references public.st_v6_rooms on delete cascade,
  enabled boolean not null,
  changed_at timestamptz not null
);
create table sectalk_private.room_read_receipts (
  room_id uuid not null,
  post_id uuid not null,
  reader uuid not null references public.st_profiles on delete cascade,
  shared_at timestamptz not null,
  primary key(room_id,post_id,reader),
  foreign key(room_id,post_id) references public.st_v6_room_posts(room_id,id) on delete cascade
);
alter table sectalk_private.read_receipt_preferences enable row level security;
alter table sectalk_private.workspace_read_receipt_policy enable row level security;
alter table sectalk_private.room_read_receipt_policy enable row level security;
alter table sectalk_private.room_read_receipts enable row level security;
revoke all on sectalk_private.read_receipt_preferences,sectalk_private.workspace_read_receipt_policy,
  sectalk_private.room_read_receipt_policy,sectalk_private.room_read_receipts from public,anon,authenticated;

create function public.st_v6_read_receipt_settings(p_workspace uuid default null,p_room uuid default null)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid(); workspace uuid:=p_workspace; personal boolean; org boolean; room boolean;
begin
  if not sectalk_private.st_v2_active(actor) then return '{}'::jsonb; end if;
  if p_room is not null then
    select r.workspace_id into workspace from public.st_v6_rooms r where r.id=p_room;
    if workspace is null or (p_workspace is not null and p_workspace<>workspace)
      or (sectalk_private.st_v6_room_role(p_room) is null and not sectalk_private.st_v6_room_workspace_manager(p_room))
      then return '{}'::jsonb; end if;
    select enabled into room from sectalk_private.room_read_receipt_policy where room_id=p_room;
  end if;
  if workspace is not null then
    if sectalk_private.st_v2_role(workspace,actor) is null then return '{}'::jsonb; end if;
    select enabled into org from sectalk_private.workspace_read_receipt_policy where workspace_id=workspace;
  end if;
  select enabled into personal from sectalk_private.read_receipt_preferences where user_id=actor;
  return jsonb_build_object('personal_enabled',coalesce(personal,true),
    'workspace_enabled',coalesce(org,true),'room_enabled',coalesce(room,true));
end $$;

create function public.st_v6_set_read_receipt_policy(p_enabled boolean,p_workspace uuid default null,p_room uuid default null)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if p_enabled is null or not sectalk_private.st_v2_active(actor) or num_nonnulls(p_workspace,p_room)>1
    then raise exception 'Read receipt settings unavailable'; end if;
  perform sectalk_private.limit_action('v6_read_receipt_policy',20);
  if p_workspace is not null then
    perform id from public.st_v2_workspaces where id=p_workspace for no key update;
    if not found or not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
      then raise exception 'Read receipt settings unavailable'; end if;
    insert into sectalk_private.workspace_read_receipt_policy as policy
      select p_workspace,p_enabled,clock_timestamp() where not p_enabled or exists(
        select 1 from sectalk_private.workspace_read_receipt_policy where workspace_id=p_workspace)
      on conflict(workspace_id) do update set enabled=excluded.enabled,changed_at=excluded.changed_at
      where policy.enabled<>excluded.enabled;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(p_workspace,actor,'workspace.read_receipt_policy');
    end if;
  elsif p_room is not null then
    perform id from public.st_v6_rooms where id=p_room for no key update;
    if not found or not (coalesce(sectalk_private.st_v6_room_role(p_room) in ('owner','moderator'),false)
      or sectalk_private.st_v6_room_workspace_manager(p_room)) then raise exception 'Read receipt settings unavailable'; end if;
    insert into sectalk_private.room_read_receipt_policy as policy
      select p_room,p_enabled,clock_timestamp() where not p_enabled or exists(
        select 1 from sectalk_private.room_read_receipt_policy where room_id=p_room)
      on conflict(room_id) do update set enabled=excluded.enabled,changed_at=excluded.changed_at
      where policy.enabled<>excluded.enabled;
    if found then
      insert into public.st_v6_room_audit(room_id,actor,action) values(p_room,actor,'room.read_receipt_policy');
    end if;
  else
    perform id from public.st_profiles where id=actor for no key update;
    insert into sectalk_private.read_receipt_preferences as policy
      select actor,p_enabled,clock_timestamp() where not p_enabled or exists(
        select 1 from sectalk_private.read_receipt_preferences where user_id=actor)
      on conflict(user_id) do update set enabled=excluded.enabled,changed_at=excluded.changed_at
      where policy.enabled<>excluded.enabled;
  end if;
end $$;

create function public.st_v6_share_room_reads(p_room uuid,p_posts uuid[])
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); workspace uuid; policy jsonb; shared_at timestamptz;
begin
  if actor is null or not coalesce(cardinality(p_posts) between 1 and 151,false)
    or sectalk_private.st_v6_room_role(p_room) is null then return; end if;
  perform sectalk_private.limit_action('v6_share_room_reads',75);
  select workspace_id into workspace from public.st_v6_rooms where id=p_room;
  perform id from public.st_v2_workspaces where id=workspace for share;
  perform id from public.st_v6_rooms where id=p_room for share;
  perform id from public.st_profiles where id=actor for share;
  if sectalk_private.st_v6_room_role(p_room) is null then return; end if;
  policy:=public.st_v6_read_receipt_settings(workspace,p_room);
  if not (policy @> '{"personal_enabled":true,"workspace_enabled":true,"room_enabled":true}'::jsonb) then return; end if;
  shared_at:=clock_timestamp();
  insert into sectalk_private.room_read_receipts as receipt
    select room_id,id,actor,shared_at from public.st_v6_room_posts
    where room_id=p_room and id=any(p_posts) and sender<>actor and removed_at is null
    on conflict(room_id,post_id,reader) do update set shared_at=excluded.shared_at;
end $$;

create function public.st_v6_room_read_counts(p_room uuid,p_posts uuid[])
returns table(post_id uuid,amount bigint)
language sql stable security definer set search_path='' as $$
  select receipt.post_id,count(*)
  from sectalk_private.room_read_receipts receipt
  join public.st_v6_room_posts post on post.room_id=receipt.room_id and post.id=receipt.post_id
  join public.st_v6_rooms room on room.id=post.room_id
  left join sectalk_private.workspace_read_receipt_policy org on org.workspace_id=room.workspace_id
  left join sectalk_private.room_read_receipt_policy policy on policy.room_id=room.id
  left join sectalk_private.read_receipt_preferences reader on reader.user_id=receipt.reader
  where cardinality(p_posts) between 1 and 151 and receipt.room_id=p_room and receipt.post_id=any(p_posts)
    and post.sender=auth.uid() and post.removed_at is null and sectalk_private.st_v6_room_role(p_room) is not null
    and sectalk_private.st_v6_room_role(p_room,receipt.reader) is not null
    and (org.enabled is null or org.enabled and receipt.shared_at>=org.changed_at)
    and (policy.enabled is null or policy.enabled and receipt.shared_at>=policy.changed_at)
    and (reader.enabled is null or reader.enabled and receipt.shared_at>=reader.changed_at)
  group by receipt.post_id
$$;

alter table public.st_v2_chat_state
  add column receipt_shared_at timestamptz,
  add column receipt_since_sequence bigint;

create or replace function public.st_v2_read(p_chat uuid,p_message uuid)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); m public.st_messages; share boolean; preference_changed timestamptz;
begin
  if not sectalk_private.st_v2_chat_write(p_chat,actor) then return; end if;
  perform id from public.st_profiles where id=actor for share;
  select * into m from public.st_messages where id=p_message and chat_id=p_chat and sender<>actor;
  if not found then return; end if;
  select enabled,changed_at into share,preference_changed from sectalk_private.read_receipt_preferences where user_id=actor;
  insert into public.st_v2_chat_state as s(chat_id,user_id,last_read_at,last_read_id,last_read_sequence,
    receipt_shared_at,receipt_since_sequence)
  values(p_chat,actor,m.created_at,m.id,m.sequence,case when coalesce(share,true) then clock_timestamp() end,
    case when share and preference_changed is not null then m.sequence end)
  on conflict(chat_id,user_id) do update set last_read_at=excluded.last_read_at,last_read_id=excluded.last_read_id,
    last_read_sequence=excluded.last_read_sequence,receipt_shared_at=excluded.receipt_shared_at,
    receipt_since_sequence=case
      when preference_changed is not null and coalesce(s.receipt_shared_at,'-infinity')<preference_changed
        then excluded.receipt_since_sequence
      else s.receipt_since_sequence end
  where s.last_read_sequence is null or s.last_read_sequence<excluded.last_read_sequence;
end $$;

create or replace function public.st_v2_chat_status(p_chat uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare me uuid:=auth.uid(); own public.st_v2_chat_state; peer public.st_v2_chat_state; typing_at timestamptz;
  available boolean; peer_reads boolean;
begin
  if not sectalk_private.member(p_chat,me) then return '{}'::jsonb; end if;
  select * into own from public.st_v2_chat_state where chat_id=p_chat and user_id=me;
  available:=sectalk_private.st_v2_chat_write(p_chat,me);
  if available then
    select * into peer from public.st_v2_chat_state where chat_id=p_chat and user_id<>me;
    if coalesce(peer.share_typing,true) then
      select expires_at into typing_at from public.st_v2_typing
        where chat_id=p_chat and user_id<>me and expires_at>statement_timestamp();
    end if;
    peer_reads:=not exists(select 1 from sectalk_private.read_receipt_preferences preference
      where preference.user_id=peer.user_id and
        (not preference.enabled or peer.receipt_shared_at is null or peer.receipt_shared_at<preference.changed_at));
  end if;
  return jsonb_build_object('muted',coalesce(own.muted,false),
    'read_at',case when peer_reads then peer.last_read_at end,
    'read_id',case when peer_reads then peer.last_read_id end,
    'read_sequence',case when peer_reads then peer.last_read_sequence end,
    'read_since_sequence',case when peer_reads then peer.receipt_since_sequence end,'typing_until',typing_at,
    'share_own_typing',available and coalesce(own.share_typing,true),
    'share_own_read_receipts',coalesce((select enabled from sectalk_private.read_receipt_preferences where user_id=me),true),
    'share_own_edit_history',coalesce(own.share_edit_history,true),
    'share_peer_edit_history',available and coalesce(peer.share_edit_history,true));
end $$;

create or replace function sectalk_private.st_v2_chat_notify()
returns trigger language plpgsql security definer set search_path='' as $$
declare cid uuid; chat public.st_chats;
begin
  if tg_op='DELETE' then cid:=old.chat_id; else cid:=new.chat_id; end if;
  if tg_table_name='st_v2_chat_state' then
    if tg_op='UPDATE' then
      if old.share_edit_history=new.share_edit_history
        and (new.receipt_shared_at is null or old.last_read_id is not distinct from new.last_read_id)
        then return null; end if;
    elsif new.receipt_shared_at is null and new.share_edit_history then return null;
    end if;
  end if;
  select * into chat from public.st_chats where id=cid;
  if not found then return null; end if;
  perform realtime.send(jsonb_build_object('chat_id',cid),'chat_activity','st:account:'||chat.member_a::text,true);
  perform realtime.send(jsonb_build_object('chat_id',cid),'chat_activity','st:account:'||chat.member_b::text,true);
  return null;
end $$;

revoke all on function public.st_v6_read_receipt_settings(uuid,uuid),public.st_v6_set_read_receipt_policy(boolean,uuid,uuid),
  public.st_v6_share_room_reads(uuid,uuid[]),public.st_v6_room_read_counts(uuid,uuid[]) from public,anon,authenticated;
grant execute on function public.st_v6_read_receipt_settings(uuid,uuid),public.st_v6_set_read_receipt_policy(boolean,uuid,uuid),
  public.st_v6_share_room_reads(uuid,uuid[]),public.st_v6_room_read_counts(uuid,uuid[]) to authenticated;

commit;
