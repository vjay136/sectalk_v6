begin;

alter table sectalk_private.st_v6_attachment_scans add column validated_document_format text
  check (validated_document_format in ('pdf','docx','docm','xlsx','xlsm','pptx','pptm'));

create function public.st_v6_record_attachment_scan(
  p_file uuid,p_actor uuid,p_hash text,p_verdict text,p_inspection_reason text,p_validated_document_format text
)
returns text language plpgsql security definer set search_path='' as $$
declare outcome text;
begin
  if p_validated_document_format is not null and
    (p_verdict is distinct from 'clean'
      or p_validated_document_format not in ('pdf','docx','docm','xlsx','xlsm','pptx','pptm')
      or not exists(select 1 from public.st_v5_files f where f.id=p_file and f.uploader=p_actor
        and right(lower(f.filename),length(p_validated_document_format)+1)='.'||p_validated_document_format))
  then raise exception 'Invalid document inspection result' using errcode='22023'; end if;
  outcome:=public.st_v6_record_attachment_scan(p_file,p_actor,p_hash,p_verdict,p_inspection_reason);
  if outcome is not null and p_validated_document_format is not null then
    update sectalk_private.st_v6_attachment_scans set validated_document_format=p_validated_document_format
      where file_id=p_file;
  end if;
  return outcome;
end
$$;

revoke all on function public.st_v6_record_attachment_scan(uuid,uuid,text,text,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_record_attachment_scan(uuid,uuid,text,text,text,text) to service_role;

create or replace function public.st_v5_stage_file(p_chat uuid,p_id uuid,p_filename text,p_bytes integer)
returns boolean language plpgsql security definer set search_path='' as $$
declare previous public.st_v5_files; clean_name text; actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v5_attachment_stage',8);
  if not sectalk_private.st_v2_chat_write(p_chat,actor) then raise exception 'Conversation unavailable'; end if;
  clean_name:=regexp_replace(btrim(p_filename),'[/[:cntrl:][:space:]]+',' ','g');
  if clean_name is null or char_length(clean_name) not between 1 and 140 or strpos(clean_name,chr(92))>0
    or clean_name !~* '[.](png|jpe?g|webp|gif|pdf|txt|doc[xm]|xls[xm]|ppt[xm])$' or p_bytes is null or p_bytes not between 1 and 4194304
    then raise exception 'Choose a supported file up to 4 MiB'; end if;

  perform sectalk_private.st_v6_lock_attachment_owner(actor);
  select * into previous from public.st_v5_files where id=p_id;
  if found then
    if previous.uploader<>actor or previous.chat_id<>p_chat or previous.filename<>clean_name or previous.size_bytes<>p_bytes
      or (previous.message_id is null and (previous.deleted_at is not null or not sectalk_private.st_v6_attachment_stage_alive(previous.id,previous.created_at)))
      then raise exception 'Start a new attachment upload'; end if;
    if previous.message_id is null then
      perform sectalk_private.st_v6_require_attachment_capacity(actor,p_bytes,0);
    end if;
  else
    perform sectalk_private.st_v6_require_attachment_capacity(actor,p_bytes,p_bytes);
    insert into public.st_v5_files(id,chat_id,uploader,filename,size_bytes)
      values(p_id,p_chat,actor,clean_name,p_bytes) on conflict(id) do nothing;
    if not found then raise exception 'Start a new attachment upload'; end if;
  end if;
  return exists(select 1 from storage.objects where bucket_id='sectalk-chat-files' and name=p_id::text);
end $$;

create or replace function sectalk_private.st_v6_guard_office_attachment_publish()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if old.message_id is null and new.message_id is not null
    and new.filename ~* '[.](doc[xm]|xls[xm]|ppt[xm])$'
    and not exists(select 1 from sectalk_private.st_v6_attachment_scans s
      where s.file_id=new.id and s.state in ('clean','released')
        and s.validated_document_format=right(lower(new.filename),4))
  then raise exception 'Office attachment inspection is required' using errcode='PT423'; end if;
  return new;
end
$$;

revoke all on function sectalk_private.st_v6_guard_office_attachment_publish() from public,anon,authenticated,service_role;

create trigger st_v6_guard_office_attachment_publish before update of message_id on public.st_v5_files
  for each row execute function sectalk_private.st_v6_guard_office_attachment_publish();

commit;
