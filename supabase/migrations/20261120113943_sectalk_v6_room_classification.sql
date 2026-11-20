begin;

alter table public.st_v6_rooms add column classification text not null default 'internal'
  check(classification in ('public','internal','confidential','restricted'));
update public.st_v6_rooms set classification='confidential' where kind in ('private','admin');

create function sectalk_private.st_v6_classification_floor()
returns trigger language plpgsql set search_path='' as $$
begin
  if new.kind in ('private','admin') and new.classification in ('public','internal') then
    new.classification:='confidential';
  end if;
  return new;
end $$;
revoke all on function sectalk_private.st_v6_classification_floor() from public,anon,authenticated;
create trigger st_v6_classification_floor before insert or update of kind,classification on public.st_v6_rooms
  for each row execute function sectalk_private.st_v6_classification_floor();

create function public.st_v6_set_room_classification(p_room uuid,p_classification text)
returns text language plpgsql security definer set search_path='' as $$
declare target public.st_v6_rooms;
declare resolved text;
begin
  if p_classification is null or p_classification not in ('public','internal','confidential','restricted') then
    raise exception 'Choose a valid classification' using errcode='22023';
  end if;
  select * into target from public.st_v6_rooms where id=p_room;
  if not found or target.archived or not sectalk_private.st_v6_room_directory(p_room)
    or sectalk_private.st_v6_holds_access(target.workspace_id)<>'verified'
  then raise exception 'Verified workspace administration is required' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v6_room_classification',20);
  select * into target from public.st_v6_rooms where id=p_room for update;
  if not found or target.archived or not sectalk_private.st_v6_room_directory(p_room)
    or sectalk_private.st_v6_holds_access(target.workspace_id)<>'verified'
  then raise exception 'Room classification is unavailable' using errcode='42501'; end if;
  if target.kind in ('admin','private') and p_classification in ('public','internal')
  then raise exception 'Private and admin rooms require Confidential or Restricted'; end if;
  if target.classification=p_classification then return target.classification; end if;
  update public.st_v6_rooms set classification=p_classification where id=p_room returning classification into resolved;
  insert into public.st_v6_room_audit(room_id,actor,action,details)
    values(p_room,auth.uid(),'room.classification_changed',jsonb_build_object(
      'from_classification',target.classification,'to_classification',resolved));
  return resolved;
end $$;
revoke all on function public.st_v6_set_room_classification(uuid,text) from public,anon,authenticated;
grant execute on function public.st_v6_set_room_classification(uuid,text) to authenticated;

create or replace function sectalk_private.st_v6_room_can_forward(p_room uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v6_rooms r where r.id=p_room and r.kind='public'
    and r.classification in ('public','internal') and r.forwarding_allowed and not r.archived and not r.locked
    and sectalk_private.st_v6_room_role(r.id) in ('owner','moderator','member'))
$$;

create function sectalk_private.st_v6_room_classification_allows_forward(p_source uuid,p_destination uuid)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from public.st_v6_rooms s join public.st_v6_rooms d on d.workspace_id=s.workspace_id
    where s.id=p_source and d.id=p_destination and (s.classification='public' or d.classification='internal'))
$$;
revoke all on function sectalk_private.st_v6_room_classification_allows_forward(uuid,uuid) from public,anon,authenticated;

create or replace function public.st_v6_forward_room_destinations(p_room uuid)
returns table(id uuid,name text) language sql stable security definer set search_path='' as $$
  select destination.id,destination.name
  from public.st_v6_rooms source
  join public.st_v6_rooms destination on destination.workspace_id=source.workspace_id and destination.id<>source.id
  where source.id=p_room and sectalk_private.st_v6_room_can_forward(source.id)
    and sectalk_private.st_v6_room_can_forward(destination.id)
    and sectalk_private.st_v6_room_classification_allows_forward(source.id,destination.id)
  order by destination.name,destination.id limit 250
$$;

create or replace function public.st_v6_forward_room(p_source_room uuid,p_source_message uuid,p_destination uuid,p_id uuid)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); snapshot text;
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

  select m.body into snapshot from public.st_v6_room_posts m
  where m.room_id=p_source_room and m.id=p_source_message and m.removed_at is null and m.kind='message'
  for share of m;
  if not found then raise exception 'Forwarding is unavailable'; end if;
  perform sectalk_private.st_v6_write_room_post(p_destination,p_id,snapshot,'message',null,true);
end $$;

commit;
