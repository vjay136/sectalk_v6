begin;

create function sectalk_private.st_v8_group_message_hint()
returns trigger language plpgsql security definer set search_path='' as $$
declare conversation uuid; recipient uuid;
begin
  if tg_table_name='st_group_members' then
    conversation:=old.group_id;
    recipient:=old.actor;
  else
    conversation:=new.group_id;
  end if;
  perform realtime.send(jsonb_build_object('group',conversation),'group_ciphertext_changed','st:account:'||actor::text,true)
  from (select m.actor from sectalk_private.st_group_members m where m.group_id=conversation
        union select recipient where recipient is not null) audience;
  return null;
end;
$$;

revoke all on function sectalk_private.st_v8_group_message_hint() from public,anon,authenticated,service_role;
create trigger st_v8_group_ciphertext_hint after insert on sectalk_private.st_group_messages
  for each row execute function sectalk_private.st_v8_group_message_hint();
create trigger st_v8_group_ciphertext_member_removed after delete on sectalk_private.st_group_members
  for each row execute function sectalk_private.st_v8_group_message_hint();

commit;
