begin;

create function public.st_v6_pending_file(p_file uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare f public.st_v5_files; actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_file_inspection',12);
  select * into f from public.st_v5_files where id=p_file and uploader=actor;
  if not found or not sectalk_private.st_v2_chat_write(f.chat_id,actor)
    or (f.message_id is null and f.created_at<=now()-interval '15 minutes') then return null; end if;
  return jsonb_build_object('filename',f.filename,'size',f.size_bytes,'published',f.message_id);
end $$;

create function public.st_v6_publish_validated_file(p_file uuid,p_actor uuid,p_caption text)
returns uuid language plpgsql security definer set search_path='' as $$
declare f public.st_v5_files; body_text text; object_size text; outcome text;
begin
  select * into f from public.st_v5_files where id=p_file and uploader=p_actor for update;
  if not found or not sectalk_private.st_v2_chat_write(f.chat_id,p_actor)
    then raise exception 'Attachment unavailable'; end if;
  if f.message_id is not null then return f.message_id; end if;
  if f.created_at<=now()-interval '15 minutes' then raise exception 'Start a new attachment upload'; end if;
  select metadata->>'size' into object_size from storage.objects where bucket_id='sectalk-chat-files' and name=p_file::text;
  if object_size is distinct from f.size_bytes::text then raise exception 'Attachment upload is incomplete'; end if;
  body_text:=coalesce(nullif(btrim(p_caption),''),'Attachment: '||f.filename);
  outcome:=sectalk_private.st_v6_write_message(p_actor,f.chat_id,f.id,body_text);
  if outcome<>'sent' then raise exception 'Attachment could not be published'; end if;
  update public.st_v5_files set message_id=f.id where id=f.id;
  return f.id;
end $$;

revoke all on function public.st_v6_pending_file(uuid) from public,anon,authenticated;
grant execute on function public.st_v6_pending_file(uuid) to authenticated;
revoke all on function public.st_v6_publish_validated_file(uuid,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_publish_validated_file(uuid,uuid,text) to service_role;
revoke execute on function public.st_v5_send_file(uuid,text) from public,anon,authenticated;

commit;
