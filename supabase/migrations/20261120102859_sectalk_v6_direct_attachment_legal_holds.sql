begin;

create table sectalk_private.st_v6_direct_file_hold_scope (
  operator_id uuid not null references sectalk_private.staff(user_id) on delete cascade,
  file_id uuid not null references public.st_v5_files on delete cascade,
  authorization_reference text not null check(char_length(btrim(authorization_reference)) between 4 and 160),
  assigned_at timestamptz not null default clock_timestamp(),
  primary key(operator_id,file_id)
);

create table sectalk_private.st_v6_direct_file_holds (
  id uuid primary key default gen_random_uuid(),
  file_id uuid not null references public.st_v5_files on delete cascade,
  placed_by uuid not null,
  authorization_reference text not null,
  reason text not null check(char_length(btrim(reason)) between 4 and 500),
  placed_at timestamptz not null default clock_timestamp(),
  released_at timestamptz,
  release_reason text check(char_length(btrim(release_reason)) between 4 and 500),
  check((released_at is null)=(release_reason is null))
);
create unique index st_v6_direct_file_active_hold
  on sectalk_private.st_v6_direct_file_holds(file_id,placed_by) where released_at is null;
create index st_v6_direct_file_hold_history
  on sectalk_private.st_v6_direct_file_holds(file_id,placed_by,placed_at desc);
alter table sectalk_private.st_v6_direct_file_hold_scope enable row level security;
alter table sectalk_private.st_v6_direct_file_holds enable row level security;
revoke all on sectalk_private.st_v6_direct_file_hold_scope,sectalk_private.st_v6_direct_file_holds
  from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v6_attachment_retention_held(p_file uuid)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v5_attachment_reports r where r.file_id=p_file)
    or exists(select 1 from sectalk_private.st_v6_direct_file_holds h where h.file_id=p_file and h.released_at is null)
$$;

create function sectalk_private.st_v6_guard_held_attachment_delete()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if exists(select 1 from sectalk_private.st_v6_direct_file_holds h where h.file_id=old.id and h.released_at is null)
  then raise exception 'An active attachment hold protects this file record' using errcode='42501'; end if;
  return old;
end
$$;
create trigger st_v6_guard_held_attachment_delete before delete on public.st_v5_files
  for each row execute function sectalk_private.st_v6_guard_held_attachment_delete();

create function sectalk_private.st_v6_direct_file_hold_entitlement(p_file uuid)
returns text language sql stable set search_path='' as $$
  select s.authorization_reference from sectalk_private.st_v6_direct_file_hold_scope s
    where s.operator_id=auth.uid() and s.file_id=p_file and public.st_staff_status()='verified'
      and sectalk_private.st_v2_active(auth.uid())
$$;

create function public.st_v6_direct_hold_targets()
returns table(file_id uuid)
language sql stable security definer set search_path='' as $$
  select s.file_id from sectalk_private.st_v6_direct_file_hold_scope s
    where s.operator_id=auth.uid() and public.st_staff_status()='verified' and sectalk_private.st_v2_active(auth.uid())
    order by s.assigned_at desc,s.file_id limit 50
$$;

create function public.st_v6_direct_hold_history(p_file uuid)
returns table(id uuid,reason text,placed_at timestamptz,released_at timestamptz,release_reason text)
language plpgsql stable security definer set search_path='' as $$
begin
  if sectalk_private.st_v6_direct_file_hold_entitlement(p_file) is null then
    raise exception 'Attachment hold access unavailable' using errcode='42501';
  end if;
  return query select h.id,h.reason,h.placed_at,h.released_at,h.release_reason
    from sectalk_private.st_v6_direct_file_holds h where h.file_id=p_file and h.placed_by=auth.uid()
    order by (h.released_at is null) desc,h.placed_at desc,h.id limit 50;
end
$$;

create function public.st_v6_place_direct_file_hold(p_file uuid,p_reason text)
returns uuid language plpgsql security definer set search_path='' as $$
declare authorization_reference text:=sectalk_private.st_v6_direct_file_hold_entitlement(p_file);
declare hold_id uuid;
begin
  if authorization_reference is null then raise exception 'Attachment hold access unavailable' using errcode='42501'; end if;
  if (char_length(btrim(p_reason)) between 4 and 500) is not true then
    raise exception 'Enter a reason' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v6_direct_file_holds',20);
  perform 1 from public.st_v5_files f where f.id=p_file and f.message_id is not null and f.purged_at is null
    and (f.purge_lease_until is null or f.purge_lease_until<=clock_timestamp())
    and exists(select 1 from storage.objects o where o.bucket_id='sectalk-chat-files' and o.name=f.id::text)
    for update;
  if not found then raise exception 'Attachment storage is unavailable or purge has started' using errcode='PT409'; end if;
  select s.authorization_reference into authorization_reference from sectalk_private.st_v6_direct_file_hold_scope s
    where s.file_id=p_file and s.operator_id=auth.uid() for share;
  if not found then raise exception 'Attachment hold access unavailable' using errcode='42501'; end if;
  select h.id into hold_id from sectalk_private.st_v6_direct_file_holds h
    where h.file_id=p_file and h.placed_by=auth.uid() and h.released_at is null;
  if hold_id is not null then return hold_id; end if;
  insert into sectalk_private.st_v6_direct_file_holds(file_id,placed_by,authorization_reference,reason)
    values(p_file,auth.uid(),authorization_reference,btrim(p_reason)) returning id into hold_id;
  return hold_id;
end
$$;

create function public.st_v6_release_direct_file_hold(p_file uuid,p_hold uuid,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
begin
  if sectalk_private.st_v6_direct_file_hold_entitlement(p_file) is null then
    raise exception 'Attachment hold access unavailable' using errcode='42501';
  end if;
  if (char_length(btrim(p_reason)) between 4 and 500) is not true then
    raise exception 'Enter a reason' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v6_direct_file_holds',20);
  perform 1 from public.st_v5_files f where f.id=p_file for update;
  perform 1 from sectalk_private.st_v6_direct_file_hold_scope s where s.file_id=p_file and s.operator_id=auth.uid() for share;
  if not found then raise exception 'Attachment hold access unavailable' using errcode='42501'; end if;
  perform 1 from sectalk_private.st_v6_direct_file_holds h
    where h.id=p_hold and h.file_id=p_file and h.placed_by=auth.uid();
  if not found then raise exception 'Attachment hold access unavailable' using errcode='42501'; end if;
  update sectalk_private.st_v6_direct_file_holds h set released_at=clock_timestamp(),release_reason=btrim(p_reason)
    where h.id=p_hold and h.released_at is null;
end
$$;

revoke all on function sectalk_private.st_v6_guard_held_attachment_delete(),
  sectalk_private.st_v6_direct_file_hold_entitlement(uuid) from public,anon,authenticated,service_role;
revoke all on function public.st_v6_direct_hold_targets(),public.st_v6_direct_hold_history(uuid),
  public.st_v6_place_direct_file_hold(uuid,text),public.st_v6_release_direct_file_hold(uuid,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_direct_hold_targets(),public.st_v6_direct_hold_history(uuid),
  public.st_v6_place_direct_file_hold(uuid,text),public.st_v6_release_direct_file_hold(uuid,uuid,text) to authenticated;

commit;
