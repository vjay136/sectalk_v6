begin;

select vault.create_secret(encode(extensions.gen_random_bytes(32),'hex'),
  'sectalk_v6_hold_archive_key','Encrypts original workspace post revisions under active preservation holds');

create table sectalk_private.st_v6_workspace_holds (
  id uuid primary key,
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  room_id uuid,
  member_id uuid,
  from_at timestamptz,
  until_at timestamptz,
  reason text not null check(char_length(reason) between 12 and 300),
  placed_by uuid not null,
  created_at timestamptz not null default clock_timestamp(),
  released_at timestamptz,
  released_by uuid,
  release_reason text,
  check(from_at is null or until_at is null or from_at<until_at),
  check(room_id is not null or member_id is not null or from_at is not null or until_at is not null)
);
create index st_v6_holds_workspace on sectalk_private.st_v6_workspace_holds(workspace_id,created_at desc);
create index st_v6_active_holds on sectalk_private.st_v6_workspace_holds(workspace_id) where released_at is null;

create table sectalk_private.st_v6_preserved_post_versions (
  id bigint generated always as identity primary key,
  hold_id uuid not null references sectalk_private.st_v6_workspace_holds on delete cascade,
  source text not null check(source in ('room','channel')),
  scope_id uuid not null,
  post_id uuid not null,
  sender uuid not null,
  post_created_at timestamptz not null,
  archived_at timestamptz not null default clock_timestamp(),
  encrypted_body bytea not null
);
create index st_v6_preserved_post_versions_hold on sectalk_private.st_v6_preserved_post_versions(hold_id);
alter table sectalk_private.st_v6_workspace_holds enable row level security;
alter table sectalk_private.st_v6_preserved_post_versions enable row level security;
revoke all on sectalk_private.st_v6_workspace_holds,sectalk_private.st_v6_preserved_post_versions
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_holds_access(p_workspace uuid)
returns text language sql stable set search_path='' as $$
  select case
    when not coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
      or not coalesce(sectalk_private.st_v2_active(auth.uid()),false) then 'none'
    when auth.jwt()->>'aal'='aal2' and exists(
      select 1 from auth.sessions s join auth.mfa_factors f on f.id=s.factor_id and f.user_id=s.user_id
      where s.id::text=auth.jwt()->>'session_id' and s.user_id=auth.uid() and s.aal='aal2'
        and (s.not_after is null or s.not_after>now()) and f.status='verified' and f.factor_type='totp'
    ) then 'verified'
    else 'mfa'
  end
$$;

create function public.st_v6_workspace_hold_state(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare access text:=sectalk_private.st_v6_holds_access(p_workspace);
begin
  if access='none' then
    raise exception 'Workspace governance is unavailable' using errcode='42501';
  end if;
  if access='mfa' then return jsonb_build_object('access',access); end if;
  return jsonb_build_object('access',access,'holds',coalesce((
    select jsonb_agg(to_jsonb(h) order by h.created_at desc,h.id) from (
      select id,room_id,member_id,from_at,until_at,reason,created_at,released_at,release_reason
      from sectalk_private.st_v6_workspace_holds where workspace_id=p_workspace
      order by created_at desc,id limit 100
    ) h
  ),'[]'::jsonb));
end $$;

create function public.st_v6_place_workspace_hold(
  p_workspace uuid,p_id uuid,p_room uuid,p_member uuid,p_from timestamptz,p_until timestamptz,p_reason text
)
returns uuid language plpgsql security definer set search_path='' as $$
declare clean_reason text:=btrim(p_reason);
declare existing sectalk_private.st_v6_workspace_holds;
begin
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Verify an authenticator to manage preservation holds' using errcode='42501';
  end if;
  if p_id is null or clean_reason is null or char_length(clean_reason) not between 12 and 300
    or (p_room is null and p_member is null and p_from is null and p_until is null)
    or (p_from is not null and p_until is not null and p_from>=p_until)
    or (p_from is not null and not isfinite(p_from)) or (p_until is not null and not isfinite(p_until))
  then raise exception 'Choose a scope and provide a clear reason' using errcode='22023'; end if;
  perform sectalk_private.limit_action('v6_workspace_hold',10);
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Workspace governance is unavailable' using errcode='42501';
  end if;
  select * into existing from sectalk_private.st_v6_workspace_holds where id=p_id;
  if found then
    if existing.workspace_id=p_workspace and existing.placed_by=auth.uid()
      and row(existing.room_id,existing.member_id,existing.from_at,existing.until_at,existing.reason)
        is not distinct from row(p_room,p_member,p_from,p_until,clean_reason) then return p_id; end if;
    raise exception 'Preservation hold request ID is already in use';
  end if;
  if (p_room is not null and not exists(select 1 from public.st_v6_rooms where id=p_room and workspace_id=p_workspace))
    or (p_member is not null and not exists(select 1 from public.st_v2_members where user_id=p_member and workspace_id=p_workspace))
  then raise exception 'Choose a room or member of this workspace' using errcode='22023'; end if;
  if (select count(*) from sectalk_private.st_v6_workspace_holds h
    where h.workspace_id=p_workspace and h.released_at is null)>=50
  then raise exception 'The workspace already has 50 active preservation holds'; end if;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,room_id,member_id,from_at,until_at,reason,placed_by)
    values(p_id,p_workspace,p_room,p_member,p_from,p_until,clean_reason,auth.uid());
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,auth.uid(),'workspace.hold_placed',p_id);
  return p_id;
end $$;

create function public.st_v6_release_workspace_hold(p_workspace uuid,p_id uuid,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare clean_reason text:=btrim(p_reason);
begin
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Verify an authenticator to manage preservation holds' using errcode='42501';
  end if;
  if clean_reason is null or char_length(clean_reason) not between 12 and 300 then
    raise exception 'Provide a release reason' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v6_workspace_hold',10);
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Workspace governance is unavailable' using errcode='42501';
  end if;
  update sectalk_private.st_v6_workspace_holds set released_at=clock_timestamp(),released_by=auth.uid(),release_reason=clean_reason
  where id=p_id and workspace_id=p_workspace and released_at is null;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,auth.uid(),'workspace.hold_released',p_id);
  elsif not exists(select 1 from sectalk_private.st_v6_workspace_holds where id=p_id and workspace_id=p_workspace) then
    raise exception 'Preservation hold unavailable' using errcode='42501';
  end if;
end $$;

create function sectalk_private.st_v6_guard_held_post()
returns trigger language plpgsql security definer set search_path='' as $$
declare workspace uuid;
declare scope uuid;
declare room_scope uuid;
declare matches uuid[];
declare encryption_key text;
begin
  if tg_table_name='st_v6_room_posts' then
    scope:=old.room_id;
    room_scope:=scope;
    if tg_op='UPDATE' and (old.body is not distinct from new.body or old.removed_at is not null) then return new; end if;
    select r.workspace_id into workspace from public.st_v6_rooms r where r.id=scope;
  else
    scope:=old.channel_id;
    if tg_op='UPDATE' and old.body is not distinct from new.body then return new; end if;
    select c.workspace_id into workspace from public.st_v2_channels c where c.id=scope;
  end if;
  if workspace is not null then
    perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-workspace-hold:'||workspace::text,0));
    select array_agg(h.id) into matches from sectalk_private.st_v6_workspace_holds h
    where h.workspace_id=workspace and h.released_at is null
      and (h.room_id is null or h.room_id=room_scope)
      and (h.member_id is null or h.member_id=old.sender)
      and (h.from_at is null or old.created_at>=h.from_at)
      and (h.until_at is null or old.created_at<h.until_at);
  end if;
  if tg_op='DELETE' then
    if matches is not null then raise exception 'A workspace retention hold protects this message'; end if;
    return old;
  end if;
  if matches is not null then
    select decrypted_secret into strict encryption_key from vault.decrypted_secrets where name='sectalk_v6_hold_archive_key';
    insert into sectalk_private.st_v6_preserved_post_versions
      (hold_id,source,scope_id,post_id,sender,post_created_at,encrypted_body)
    select h,case when room_scope is null then 'channel' else 'room' end,scope,old.id,old.sender,old.created_at,
      extensions.pgp_sym_encrypt(old.body,encryption_key,'cipher-algo=aes256')
    from unnest(matches) h;
  end if;
  return new;
end $$;

create function sectalk_private.st_v6_room_is_held(p_workspace uuid,p_room uuid)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v6_workspace_holds h
    where h.workspace_id=p_workspace and h.released_at is null
      and (h.room_id=p_room or (h.room_id is null and exists(
        select 1 from public.st_v6_room_posts p where p.room_id=p_room
          and (h.member_id is null or h.member_id=p.sender)
          and (h.from_at is null or p.created_at>=h.from_at)
          and (h.until_at is null or p.created_at<h.until_at)
      ))))
$$;
revoke all on function sectalk_private.st_v6_room_is_held(uuid,uuid) from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_guard_held_workspace_scope()
returns trigger language plpgsql security definer set search_path='' as $$
declare workspace uuid;
begin
  if tg_table_name='st_v2_workspaces' then workspace:=old.id;
  else workspace:=old.workspace_id; end if;
  perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-workspace-hold:'||workspace::text,0));
  if (tg_table_name='st_v6_rooms' and sectalk_private.st_v6_room_is_held(workspace,old.id))
    or exists(select 1 from sectalk_private.st_v6_workspace_holds h
    where h.workspace_id=workspace and h.released_at is null and (
      tg_table_name='st_v2_workspaces'
      or (tg_table_name='st_v2_channels' and h.room_id is null and exists(
        select 1 from public.st_v2_posts p where p.channel_id=old.id
          and (h.member_id is null or h.member_id=p.sender)
          and (h.from_at is null or p.created_at>=h.from_at)
          and (h.until_at is null or p.created_at<h.until_at)
      ))
    ))
  then raise exception 'A workspace retention hold protects this scope'; end if;
  return old;
end $$;

revoke all on function sectalk_private.st_v6_holds_access(uuid),
  sectalk_private.st_v6_guard_held_post(),sectalk_private.st_v6_guard_held_workspace_scope()
  from public,anon,authenticated,service_role;
revoke all on function public.st_v6_workspace_hold_state(uuid),
  public.st_v6_place_workspace_hold(uuid,uuid,uuid,uuid,timestamptz,timestamptz,text),
  public.st_v6_release_workspace_hold(uuid,uuid,text) from public,anon,authenticated;
grant execute on function public.st_v6_workspace_hold_state(uuid),
  public.st_v6_place_workspace_hold(uuid,uuid,uuid,uuid,timestamptz,timestamptz,text),
  public.st_v6_release_workspace_hold(uuid,uuid,text) to authenticated;

create trigger st_v6_room_hold_guard before update of body or delete on public.st_v6_room_posts
  for each row execute function sectalk_private.st_v6_guard_held_post();
create trigger st_v6_channel_hold_guard before update of body or delete on public.st_v2_posts
  for each row execute function sectalk_private.st_v6_guard_held_post();
create trigger st_v6_workspace_hold_guard before delete on public.st_v2_workspaces
  for each row execute function sectalk_private.st_v6_guard_held_workspace_scope();
create trigger st_v6_room_delete_hold_guard before delete on public.st_v6_rooms
  for each row execute function sectalk_private.st_v6_guard_held_workspace_scope();
create trigger st_v6_channel_delete_hold_guard before delete on public.st_v2_channels
  for each row execute function sectalk_private.st_v6_guard_held_workspace_scope();

commit;
