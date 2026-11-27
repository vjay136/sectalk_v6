begin;

create table sectalk_private.st_forward_lineage (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('direct','room')),
  scope_id uuid not null,
  message_id uuid not null,
  body_digest bytea not null,
  root_id uuid references sectalk_private.st_forward_lineage(id),
  actor uuid references public.st_profiles(id) on delete set null,
  original_known boolean not null,
  unique (kind,scope_id,message_id,body_digest)
);
create index st_forward_lineage_root_actor
  on sectalk_private.st_forward_lineage(root_id,actor) where root_id is not null;
alter table sectalk_private.st_forward_lineage enable row level security;
revoke all on sectalk_private.st_forward_lineage from public,anon,authenticated,service_role;

create function sectalk_private.st_record_forward_lineage(
  p_kind text,p_source uuid,p_message uuid,p_destination uuid,p_copy uuid,
  p_body text,p_sender uuid,p_was_forwarded boolean,p_actor uuid
) returns void language plpgsql set search_path='' as $$
declare
  fingerprint bytea := extensions.digest(p_body,'sha256');
  tree uuid;
begin
  -- A DLP transformation produces different content in the destination.
  if p_kind='room' and not exists (
    select from public.st_v6_room_posts p where p.room_id=p_destination and p.id=p_copy
      and p.sender=p_actor and p.body=p_body and p.removed_at is null
  ) then return; end if;
  if p_kind='direct' and not exists (
    select from public.st_messages m where m.chat_id=p_destination and m.id=p_copy
      and m.sender=p_actor and m.body=p_body and m.revoked_at is null
  ) then return; end if;

  insert into sectalk_private.st_forward_lineage(kind,scope_id,message_id,body_digest,actor,original_known)
    values(p_kind,p_source,p_message,fingerprint,p_sender,not p_was_forwarded)
    on conflict (kind,scope_id,message_id,body_digest) do nothing;
  select coalesce(l.root_id,l.id) into strict tree from sectalk_private.st_forward_lineage l
    where l.kind=p_kind and l.scope_id=p_source and l.message_id=p_message and l.body_digest=fingerprint;
  insert into sectalk_private.st_forward_lineage(kind,scope_id,message_id,body_digest,root_id,actor,original_known)
    values(p_kind,p_destination,p_copy,fingerprint,tree,p_actor,false)
    on conflict (kind,scope_id,message_id,body_digest) do nothing;
end;
$$;
revoke all on function sectalk_private.st_record_forward_lineage(text,uuid,uuid,uuid,uuid,text,uuid,boolean,uuid)
  from public,anon,authenticated,service_role;

create function public.st_forward_summary(p_kind text,p_scope uuid,p_messages uuid[])
returns table(message_id uuid, forwards bigint, forwarders bigint, original_sender text)
language sql stable security definer set search_path='' as $$
  with viewer as (
    select auth.uid() as id
    where auth.uid() is not null and cardinality(p_messages) between 1 and 100
      and not public.st_v7_step_up_pending() and not public.st_v7_account_data_unavailable()
  ), visible as (
    select m.id, m.body from public.st_messages m cross join viewer v
    where p_kind='direct' and m.chat_id=p_scope and m.id=any(p_messages)
      and m.revoked_at is null and (m.expires_at is null or m.expires_at>statement_timestamp())
      and sectalk_private.member(p_scope,v.id)
      and not exists(select from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=v.id)
    union all
    select p.id, p.body from public.st_v6_room_posts p cross join viewer
    where p_kind='room' and p.room_id=p_scope and p.id=any(p_messages)
      and p.removed_at is null and sectalk_private.st_v6_room_role(p_scope) is not null
  ), lineage as (
    select l.message_id,coalesce(l.root_id,l.id) as root
    from visible m join sectalk_private.st_forward_lineage l
      on l.kind=p_kind and l.scope_id=p_scope and l.message_id=m.id
      and l.body_digest=extensions.digest(m.body,'sha256')
  ), totals as (
    select f.root_id,count(*) as copies,count(distinct f.actor) as people
    from sectalk_private.st_forward_lineage f
    join (select distinct root from lineage) wanted on wanted.root=f.root_id
    group by f.root_id
  )
  select l.message_id,t.copies,t.people,
    case when origin.original_known and exists(select from visible v
      where origin.scope_id=p_scope and origin.message_id=v.id
        and origin.body_digest=extensions.digest(v.body,'sha256')) then profile.name end
  from lineage l join totals t on t.root_id=l.root
  join sectalk_private.st_forward_lineage origin on origin.id=l.root
  left join public.st_profiles profile on profile.id=origin.actor;
$$;
revoke all on function public.st_forward_summary(text,uuid,uuid[]) from public,anon,authenticated,service_role;
grant execute on function public.st_forward_summary(text,uuid,uuid[]) to authenticated;

create or replace function public.st_v6_forward_direct(p_source_chat uuid,p_source_message uuid,p_destination uuid,p_id uuid)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); snapshot text; source_sender uuid; source_forwarded boolean; outcome text;
begin
  if actor is null or p_id is null or p_source_chat is null or p_destination is null or p_source_chat=p_destination
    then raise exception 'Forwarding is unavailable'; end if;
  perform sectalk_private.limit_action('message',60);
  perform id from public.st_chats where id in (p_source_chat,p_destination) and actor in (member_a,member_b) order by id for update;
  if not exists(select 1 from public.st_chats c where c.id=p_source_chat and actor in (c.member_a,c.member_b)
    and c.status='accepted' and sectalk_private.open_pair(c.member_a,c.member_b))
    then raise exception 'Forwarding is unavailable'; end if;

  select m.body,m.sender,m.forwarded into snapshot,source_sender,source_forwarded from public.st_messages m
  where m.id=p_source_message and m.chat_id=p_source_chat and m.revoked_at is null and m.expires_at is null
    and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=actor)
    and not exists(select 1 from public.st_v5_files f where f.message_id=m.id)
  for share of m;
  if not found then raise exception 'Forwarding is unavailable'; end if;

  outcome:=sectalk_private.st_v6_write_message(actor,p_destination,p_id,snapshot,true);
  if outcome='unavailable' then raise exception 'Forwarding is unavailable'; end if;
  if outcome='collision' then raise exception 'Message ID already in use'; end if;
  perform sectalk_private.st_record_forward_lineage('direct',p_source_chat,p_source_message,p_destination,p_id,snapshot,source_sender,source_forwarded,actor);
end $$;

create or replace function public.st_v6_forward_room(p_source_room uuid,p_source_message uuid,p_destination uuid,p_id uuid)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); snapshot text; source_sender uuid; source_forwarded boolean;
begin
  if actor is null or p_id is null or p_source_room is null or p_destination is null or p_source_room=p_destination
    then raise exception 'Forwarding is unavailable'; end if;
  if not sectalk_private.st_v6_room_can_forward(p_source_room) or not sectalk_private.st_v6_room_can_forward(p_destination)
    or not sectalk_private.st_v6_room_classification_allows_forward(p_source_room,p_destination)
    then raise exception 'Forwarding is unavailable'; end if;
  perform sectalk_private.limit_action('v6_room_post',45);
  perform id from public.st_v6_rooms where id in (p_source_room,p_destination) order by id for update;
  if not sectalk_private.st_v6_room_can_forward(p_source_room) or not sectalk_private.st_v6_room_can_forward(p_destination)
    or not sectalk_private.st_v6_room_classification_allows_forward(p_source_room,p_destination)
    then raise exception 'Forwarding is unavailable'; end if;

  select m.body,m.sender,m.forwarded into snapshot,source_sender,source_forwarded from public.st_v6_room_posts m
  where m.room_id=p_source_room and m.id=p_source_message and m.removed_at is null and m.kind='message'
  for share of m;
  if not found then raise exception 'Forwarding is unavailable'; end if;
  perform sectalk_private.st_v6_write_room_post(p_destination,p_id,snapshot,'message',null,true);
  perform sectalk_private.st_record_forward_lineage('room',p_source_room,p_source_message,p_destination,p_id,snapshot,source_sender,source_forwarded,actor);
end $$;

commit;
