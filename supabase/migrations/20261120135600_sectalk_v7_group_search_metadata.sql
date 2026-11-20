begin;

create function public.st_group_search_metadata(p_group uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); device_id uuid; matches jsonb;
begin
  if not coalesce(sectalk_private.st_v7_manage_sessions(),false)
     or not coalesce(sectalk_private.st_v2_active(me),false) then
    raise exception using errcode='42501',message='Group search access is unavailable';
  end if;
  select d.id into device_id from sectalk_private.st_v7_device_sessions s
    join sectalk_private.st_v7_devices d on (d.owner,d.id)=(s.owner,s.device_id)
    where s.owner=me and s.session_id::text=auth.jwt()->>'session_id' and d.state in ('trusted','managed');
  if device_id is null then raise exception using errcode='42501',message='Group search access is unavailable'; end if;
  perform 1 from sectalk_private.st_group_chats g join sectalk_private.st_group_members r on r.group_id=g.id
    where g.id=p_group and r.actor=me for share of g;
  if not found then raise exception using errcode='42501',message='Group search access is unavailable'; end if;

  -- No terms, match IDs, plaintext, signatures, ciphertext, or envelopes are accepted or returned.
  select coalesce(jsonb_agg(jsonb_build_object('id',m.id,'sent',m.sent,'epoch',m.epoch)
    order by m.sent desc,m.id desc),'[]') into matches
    from (
      select item.id,item.sent,item.epoch from sectalk_private.st_group_messages item
      where item.group_id=p_group and exists(
        select 1 from sectalk_private.st_group_envelopes e
        where e.group_id=p_group and e.epoch=item.epoch and e.device=device_id
      ) order by item.sent desc,item.id desc limit 200
    ) m;
  return jsonb_build_object('device',device_id,'messages',matches);
end $$;
revoke execute on function public.st_group_search_metadata(uuid) from public,anon;
grant execute on function public.st_group_search_metadata(uuid) to authenticated;

commit;
