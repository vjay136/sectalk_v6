begin;

create function public.st_v7_contact_key_manifest(p_peer uuid)
returns table(owner_id uuid,device uuid,signing_key text,agreement_key text,bundle_signature text)
language plpgsql stable security definer set search_path='' as $$
declare me uuid:=auth.uid();
begin
  if p_peer is null or p_peer=me or not sectalk_private.st_v7_manage_sessions()
    or not exists(
      select 1 from sectalk_private.st_v7_device_sessions b
      join sectalk_private.st_v7_devices d on (d.owner,d.id)=(b.owner,b.device_id)
      where b.owner=me and b.session_id::text=auth.jwt()->>'session_id' and d.state in ('trusted','managed')
    ) or not exists(
      select 1 from public.st_chats c where (c.member_a,c.member_b)=(least(me,p_peer),greatest(me,p_peer))
        and c.status='accepted' and sectalk_private.open_pair(me,p_peer)
    ) then return; end if;
  if exists(select 1 from sectalk_private.st_v7_devices d
    where d.owner in (me,p_peer) and d.state in ('trusted','managed')
    group by d.owner having count(*)>64) then
    raise exception using errcode='22023',message='Contact has too many approved devices for this view';
  end if;
  return query select d.owner,d.id,d.signing_key,d.agreement_key,d.bundle_signature
    from sectalk_private.st_v7_devices d where d.owner in (me,p_peer) and d.state in ('trusted','managed')
    order by d.owner,d.id;
end $$;

create function sectalk_private.st_v7_notify_contact_key_change()
returns trigger language plpgsql security definer set search_path='' as $$
declare account uuid; peer uuid;
begin
  if tg_op='UPDATE' and (old.state in ('trusted','managed'))=(new.state in ('trusted','managed')) then return null; end if;
  if tg_op='INSERT' and new.state not in ('trusted','managed') then return null; end if;
  if tg_op='DELETE' and old.state not in ('trusted','managed') then return null; end if;
  account:=case when tg_op='DELETE' then old.owner else new.owner end;
  perform realtime.send('{}'::jsonb,'contact_key_changed','st:account:'||account,true);
  for peer in select case when c.member_a=account then c.member_b else c.member_a end
    from public.st_chats c where account in (c.member_a,c.member_b) and c.status='accepted'
      and sectalk_private.open_pair(c.member_a,c.member_b)
  loop
    perform realtime.send('{}'::jsonb,'contact_key_changed','st:account:'||peer,true);
  end loop;
  return null;
end $$;
create trigger st_v7_contact_key_notice after insert or update of state or delete on sectalk_private.st_v7_devices
for each row execute function sectalk_private.st_v7_notify_contact_key_change();

revoke all on function public.st_v7_contact_key_manifest(uuid),sectalk_private.st_v7_notify_contact_key_change()
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_contact_key_manifest(uuid) to authenticated;
notify pgrst,'reload schema';
commit;
