begin;

create table sectalk_private.st_v6_room_guest_link (
  id uuid primary key default gen_random_uuid(),
  room uuid not null references public.st_v6_rooms on delete cascade,
  owner uuid not null references public.st_profiles on delete cascade,
  secret_digest text not null unique,
  post_scope jsonb not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  redemptions integer not null default 0 check(redemptions between 0 and 24)
);
create index st_v6_room_guest_link_room_idx on sectalk_private.st_v6_room_guest_link(room,owner);
create table sectalk_private.st_v6_room_guest_capability (
  secret_digest text primary key,
  link uuid not null references sectalk_private.st_v6_room_guest_link on delete cascade,
  expires_at timestamptz not null
);
alter table sectalk_private.st_v6_room_guest_link enable row level security;
alter table sectalk_private.st_v6_room_guest_capability enable row level security;
revoke all on sectalk_private.st_v6_room_guest_link,sectalk_private.st_v6_room_guest_capability from public,anon,authenticated;

create function sectalk_private.st_v6_room_guest_policy(p_room public.st_v6_rooms)
returns boolean language sql immutable set search_path='' as $$
  select p_room.kind='public' and p_room.classification='public' and p_room.forwarding_allowed
    and not p_room.locked and not p_room.archived;
$$;
revoke all on function sectalk_private.st_v6_room_guest_policy(public.st_v6_rooms) from public,anon,authenticated;

create function sectalk_private.st_v6_revoke_room_guests_on_policy_change()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if not sectalk_private.st_v6_room_guest_policy(new) then
    update sectalk_private.st_v6_room_guest_link set revoked_at=clock_timestamp()
      where room=new.id and revoked_at is null and expires_at>clock_timestamp();
  end if;
  return new;
end
$$;
revoke all on function sectalk_private.st_v6_revoke_room_guests_on_policy_change() from public,anon,authenticated;
create trigger st_v6_revoke_room_guests_on_policy_change
after update of kind,classification,forwarding_allowed,locked,archived on public.st_v6_rooms
for each row execute function sectalk_private.st_v6_revoke_room_guests_on_policy_change();

create function sectalk_private.st_v6_revoke_room_guests_on_owner_change()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if old.role='owner' and (tg_op='DELETE' or new.role is distinct from 'owner') then
    update sectalk_private.st_v6_room_guest_link set revoked_at=clock_timestamp()
      where room=old.room_id and owner=old.user_id and revoked_at is null and expires_at>clock_timestamp();
  end if;
  return null;
end
$$;
revoke all on function sectalk_private.st_v6_revoke_room_guests_on_owner_change() from public,anon,authenticated;
create trigger st_v6_revoke_room_guests_on_owner_change after update of role or delete on public.st_v6_room_members
for each row execute function sectalk_private.st_v6_revoke_room_guests_on_owner_change();

create function public.st_v6_room_guest_command(
  p_action text,p_room uuid default null,p_actor uuid default null,p_link uuid default null,
  p_digest text default null,p_capability text default null,p_posts uuid[] default null
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  room_row public.st_v6_rooms;
  link_row sectalk_private.st_v6_room_guest_link;
  capability sectalk_private.st_v6_room_guest_capability;
  enabled boolean;
  owner_id uuid;
  candidate_rows jsonb:='[]';
  link_rows jsonb;
  scoped_posts jsonb;
  selected_count integer;
  expires timestamptz;
begin
  if p_action='redeem' then
    select * into link_row from sectalk_private.st_v6_room_guest_link where secret_digest=p_digest;
  elsif p_action='read' then
    select * into capability from sectalk_private.st_v6_room_guest_capability where secret_digest=p_capability;
    if capability.link is null or capability.expires_at<=clock_timestamp() then return null; end if;
    select * into link_row from sectalk_private.st_v6_room_guest_link where id=capability.link;
  end if;
  select * into room_row from public.st_v6_rooms where id=coalesce(link_row.room,p_room) for share;
  if not found or (p_room is not null and room_row.id<>p_room) then return null; end if;
  enabled:=sectalk_private.st_v6_room_guest_policy(room_row);
  owner_id:=case when p_action in ('read','redeem') then link_row.owner else p_actor end;
  if owner_id is null or not coalesce(sectalk_private.st_v2_active(owner_id),false)
    or sectalk_private.st_v2_role(room_row.workspace_id,owner_id) is null
    or not exists(select 1 from public.st_v6_room_members where room_id=room_row.id and user_id=owner_id and role='owner')
    or exists(select 1 from public.st_v6_room_bans where room_id=room_row.id and user_id=owner_id) then return null; end if;

  if p_action in ('redeem','read') then
    if not enabled or link_row.id is null then return null; end if;
    if p_action='redeem' then
      select * into link_row from sectalk_private.st_v6_room_guest_link where id=link_row.id for update;
    else
      select * into link_row from sectalk_private.st_v6_room_guest_link where id=link_row.id for share;
    end if;
    if link_row.id is null or link_row.revoked_at is not null or link_row.expires_at<=clock_timestamp() then return null; end if;
    if p_action='redeem' then
      if link_row.redemptions>=24 or p_capability is null or p_capability !~ '^[a-f0-9]{64}$' then return null; end if;
      expires:=least(link_row.expires_at,clock_timestamp()+interval '2 minutes');
      insert into sectalk_private.st_v6_room_guest_capability(secret_digest,link,expires_at) values(p_capability,link_row.id,expires);
      update sectalk_private.st_v6_room_guest_link set redemptions=redemptions+1 where id=link_row.id;
    else
      expires:=capability.expires_at;
    end if;
    select coalesce(jsonb_agg(p.body order by p.created_at,p.id),'[]') into scoped_posts
      from jsonb_to_recordset(link_row.post_scope) as scope(id uuid, body_digest text, edited_at timestamptz)
      join public.st_v6_room_posts p on p.room_id=room_row.id and p.id=scope.id
      where p.sender=owner_id and p.parent_id is null and p.removed_at is null and not p.forwarded
        and p.edited_at is not distinct from scope.edited_at
        and encode(sha256(convert_to(p.body,'UTF8')),'hex')=scope.body_digest;
    return jsonb_build_object('name',room_row.name,'expiresAt',expires,'posts',scoped_posts);
  end if;

  if p_action='create' then
    if not enabled or p_digest is null or p_digest !~ '^[a-f0-9]{64}$'
      or coalesce(cardinality(p_posts),0) not between 1 and 10 then return null; end if;
    perform pg_advisory_xact_lock(hashtextextended(room_row.id::text,414));
    if (select count(*) from sectalk_private.st_v6_room_guest_link where room=room_row.id and owner=owner_id
      and revoked_at is null and expires_at>clock_timestamp())>=6 then return null; end if;
    select count(*),jsonb_agg(jsonb_build_object('id',p.id,'edited_at',p.edited_at,
      'body_digest',encode(sha256(convert_to(p.body,'UTF8')),'hex'))) into selected_count,scoped_posts
      from public.st_v6_room_posts p where p.room_id=room_row.id and p.id=any(p_posts)
        and p.sender=owner_id and p.parent_id is null and p.removed_at is null and not p.forwarded
        and char_length(p.body)<=1600;
    if selected_count<>cardinality(p_posts) then return null; end if;
    insert into sectalk_private.st_v6_room_guest_link(room,owner,secret_digest,post_scope,expires_at)
      values(room_row.id,owner_id,p_digest,scoped_posts,clock_timestamp()+interval '10 minutes') returning * into link_row;
    insert into public.st_v6_room_audit(room_id,actor,action,target)
      values(room_row.id,owner_id,'guest_link.created',link_row.id);
  elsif p_action='revoke' then
    update sectalk_private.st_v6_room_guest_link set revoked_at=clock_timestamp()
      where id=p_link and room=room_row.id and owner=owner_id and revoked_at is null;
    if not found then return null; end if;
    insert into public.st_v6_room_audit(room_id,actor,action,target)
      values(room_row.id,owner_id,'guest_link.revoked',p_link);
  elsif p_action<>'view' then
    return null;
  end if;

  if enabled then
    select coalesce(jsonb_agg(to_jsonb(row) order by row.created_at desc,row.id desc),'[]') into candidate_rows from (
      select id,left(body,160) as preview,created_at from public.st_v6_room_posts
      where room_id=room_row.id and sender=owner_id and parent_id is null and removed_at is null and not forwarded
        and char_length(body)<=1600 order by created_at desc,id desc limit 25
    ) row;
  end if;
  select coalesce(jsonb_agg(to_jsonb(row) order by row.expires_at desc),'[]') into link_rows from (
    select id,expires_at from sectalk_private.st_v6_room_guest_link where room=room_row.id and owner=owner_id
      and revoked_at is null and expires_at>clock_timestamp() order by expires_at desc limit 6
  ) row;
  return jsonb_build_object('allowed',enabled,'links',link_rows,'posts',candidate_rows,
    'created',case when p_action='create' then link_row.id end);
end
$$;
revoke all on function public.st_v6_room_guest_command(text,uuid,uuid,uuid,text,text,uuid[]) from public,anon,authenticated;
grant execute on function public.st_v6_room_guest_command(text,uuid,uuid,uuid,text,text,uuid[]) to service_role;

commit;
