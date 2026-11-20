begin;

alter table sectalk_private.st_v6_attachment_scans add column inspection_reason text
  check (inspection_reason in ('document_macro_marker','script_marker',
    'embedded_document_marker','embedded_link_marker','suspicious_link_format'));

create function public.st_v6_record_attachment_scan(p_file uuid,p_actor uuid,p_hash text,p_verdict text,p_inspection_reason text)
returns text language plpgsql security definer set search_path='' as $$
declare candidate public.st_v5_files;
declare previous sectalk_private.st_v6_attachment_scans;
declare digest bytea;
declare outcome text;
begin
  if p_hash is null or p_hash !~ '^[0-9a-f]{64}$' or p_verdict is null or p_verdict not in ('clean','malware','unavailable')
    or (p_inspection_reason is not null and p_inspection_reason not in ('document_macro_marker','script_marker',
      'embedded_document_marker','embedded_link_marker','suspicious_link_format'))
  then raise exception 'Invalid scan result' using errcode='22023'; end if;
  select * into candidate from public.st_v5_files f where f.id=p_file and f.uploader=p_actor for update;
  if not found or candidate.deleted_at is not null or candidate.message_id is not null
    or not sectalk_private.st_v2_chat_write(candidate.chat_id,p_actor)
    or not sectalk_private.st_v6_attachment_stage_alive(p_file,candidate.created_at)
  then return null; end if;
  digest:=decode(p_hash,'hex');
  select * into previous from sectalk_private.st_v6_attachment_scans s where s.file_id=p_file;
  if found and previous.sha256<>digest then raise exception 'Attachment bytes changed' using errcode='PT409'; end if;
  if p_verdict='malware' then
    insert into sectalk_private.st_v6_malware_hashes(sha256) values(digest) on conflict do nothing;
  end if;
  outcome:=case
    when previous.state='malware' or exists(select 1 from sectalk_private.st_v6_malware_hashes h where h.sha256=digest) then 'malware'
    when p_verdict='unavailable' then 'quarantined'
    when previous.state in ('quarantined','awaiting_release') then 'awaiting_release'
    when previous.state='released' then 'released'
    when coalesce(previous.inspection_reason,p_inspection_reason) is not null then 'awaiting_release'
    else 'clean'
  end;
  insert into sectalk_private.st_v6_attachment_scans(file_id,sha256,state,scanned_at,retain_until,inspection_reason)
    values(p_file,digest,outcome,clock_timestamp(),candidate.created_at+interval '24 hours',p_inspection_reason)
    on conflict(file_id) do update set state=excluded.state,scanned_at=excluded.scanned_at,
      inspection_reason=coalesce(st_v6_attachment_scans.inspection_reason,excluded.inspection_reason);
  return outcome;
end
$$;

create or replace function public.st_v6_record_attachment_scan(p_file uuid,p_actor uuid,p_hash text,p_verdict text)
returns text language sql security definer set search_path='' as $$
  select public.st_v6_record_attachment_scan(p_file,p_actor,p_hash,p_verdict,null)
$$;

drop function public.st_v6_my_attachment_quarantine();
drop function public.st_v6_attachment_scan_queue();

create function public.st_v6_my_attachment_quarantine()
returns table(file_id uuid,filename text,state text,retain_until timestamptz,inspection_reason text)
language sql stable security definer set search_path='' as $$
  select s.file_id,f.filename,s.state,s.retain_until,s.inspection_reason
  from sectalk_private.st_v6_attachment_scans s join public.st_v5_files f on f.id=s.file_id
  where f.uploader=auth.uid() and sectalk_private.st_v2_active(auth.uid())
    and f.message_id is null and f.deleted_at is null and s.retain_until>now()
    and s.state in ('quarantined','awaiting_release','released','malware')
  order by s.scanned_at desc,s.file_id limit 25
$$;

create function public.st_v6_attachment_scan_queue()
returns table(file_id uuid,size_bytes integer,state text,scanned_at timestamptz,inspection_reason text)
language plpgsql stable security definer set search_path='' as $$
begin
  if not public.st_v6_is_attachment_scan_reviewer() then
    raise exception 'Attachment quarantine access unavailable' using errcode='42501';
  end if;
  return query select s.file_id,f.size_bytes,s.state,s.scanned_at,s.inspection_reason
    from sectalk_private.st_v6_attachment_scans s join public.st_v5_files f on f.id=s.file_id
    where f.message_id is null and f.deleted_at is null and f.uploader<>auth.uid() and s.retain_until>now()
      and s.state in ('quarantined','awaiting_release','malware')
    order by (s.state='awaiting_release') desc,s.scanned_at desc,s.file_id limit 50;
end
$$;

revoke all on function public.st_v6_record_attachment_scan(uuid,uuid,text,text,text),
  public.st_v6_my_attachment_quarantine(),public.st_v6_attachment_scan_queue()
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_record_attachment_scan(uuid,uuid,text,text,text) to service_role;
grant execute on function public.st_v6_my_attachment_quarantine(),public.st_v6_attachment_scan_queue() to authenticated;

commit;
