begin;

create table sectalk_private.st_v6_case_notes (
  report_id uuid not null references public.st_reports on delete cascade,
  id uuid not null,
  author uuid references public.st_profiles on delete set null,
  body text not null check(char_length(btrim(body)) between 1 and 2000),
  linked_message boolean not null,
  linked_file uuid,
  created_at timestamptz not null default clock_timestamp(),
  primary key(report_id,id)
);
create index st_v6_case_notes_recent on sectalk_private.st_v6_case_notes(report_id,created_at desc,id desc);

create table sectalk_private.st_v6_case_mentions (
  recipient uuid not null references public.st_profiles on delete cascade,
  report_id uuid not null,
  note_id uuid not null,
  created_at timestamptz not null default clock_timestamp(),
  read_at timestamptz,
  primary key(recipient,report_id,note_id),
  foreign key(report_id,note_id) references sectalk_private.st_v6_case_notes(report_id,id) on delete cascade
);
create index st_v6_case_mentions_recent on sectalk_private.st_v6_case_mentions(recipient,created_at desc,note_id desc);
create index st_v6_case_mentions_note on sectalk_private.st_v6_case_mentions(report_id,note_id);
alter table sectalk_private.st_v6_case_notes enable row level security;
alter table sectalk_private.st_v6_case_mentions enable row level security;
revoke all on sectalk_private.st_v6_case_notes,sectalk_private.st_v6_case_mentions
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_case_collaboration_access(p_report uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce(sectalk_private.st_v6_case_redaction_staff(),false) and exists(
    select 1 from public.st_reports r where r.id=p_report and auth.uid() not in (r.reporter,r.subject))
$$;

create function sectalk_private.st_v6_case_shared_file(p_report uuid)
returns uuid language sql stable set search_path='' as $$
  select f.id from sectalk_private.st_v5_attachment_reports share
  join public.st_v5_files f on f.id=share.file_id and f.purged_at is null
  where share.report_id=p_report
$$;

create function public.st_v6_case_collaboration(p_report uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare has_message boolean; shared_file uuid;
begin
  if not sectalk_private.st_v6_case_collaboration_access(p_report) then
    raise exception 'Case collaboration is unavailable' using errcode='42501';
  end if;
  select r.evidence is not null and length(r.evidence)>0 into has_message from public.st_reports r where r.id=p_report;
  shared_file:=sectalk_private.st_v6_case_shared_file(p_report);
  return jsonb_build_object('may_link_message',has_message,'may_link_file',shared_file is not null,
    'notes',coalesce((select jsonb_agg(to_jsonb(recent) order by recent.created_at desc,recent.id desc) from (
      select n.id,coalesce(p.name,'Former staff member') as author_name,n.body,n.created_at,n.linked_message and has_message as has_message,
        coalesce(n.linked_file=shared_file,false) as has_file
      from sectalk_private.st_v6_case_notes n left join public.st_profiles p on p.id=n.author
      where n.report_id=p_report order by n.created_at desc,n.id desc limit 100
    ) recent),'[]'));
end
$$;

create function public.st_v6_append_case_note(
  p_report uuid,p_note uuid,p_body text,p_link_message boolean,p_link_file boolean
)
returns uuid language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  note text:=btrim(p_body);
  targets text[];
  existing sectalk_private.st_v6_case_notes;
  shared_file uuid;
  inserted uuid;
  audience uuid;
begin
  if not sectalk_private.st_v6_case_collaboration_access(p_report) then
    raise exception 'Case collaboration is unavailable' using errcode='42501';
  end if;
  if p_note is null or note is null or char_length(note) not between 1 and 2000
    or p_link_message is null or p_link_file is null then
    raise exception 'Enter a staff note up to 2,000 characters';
  end if;
  select array(select distinct lower(token[2]) from regexp_matches(note,
    '(^|[^[:alnum:]_@])@([a-z0-9_]{3,24})(?![[:alnum:]_])','gi') token limit 6) into targets;
  if cardinality(targets)>5 then raise exception 'Limit a note to five mentions'; end if;
  perform sectalk_private.limit_action('v6_case_note',20);

  select n.* into existing from sectalk_private.st_v6_case_notes n where n.report_id=p_report and n.id=p_note;
  if existing.id is null then
    if p_link_message and not exists(select 1 from public.st_reports r where r.id=p_report and length(r.evidence)>0) then
      raise exception 'Shared evidence is unavailable';
    end if;
    if p_link_file then
      shared_file:=sectalk_private.st_v6_case_shared_file(p_report);
      if shared_file is null or not public.st_v6_file_can_read(shared_file) then raise exception 'Shared evidence is unavailable'; end if;
    end if;
    insert into sectalk_private.st_v6_case_notes(report_id,id,author,body,linked_message,linked_file)
      values(p_report,p_note,actor,note,p_link_message,shared_file)
      on conflict(report_id,id) do nothing returning id into inserted;
    if inserted is null then
      select n.* into existing from sectalk_private.st_v6_case_notes n where n.report_id=p_report and n.id=p_note;
    end if;
  end if;
  if inserted is null then
    if existing.author=actor and existing.body=note and existing.linked_message=p_link_message
      and (existing.linked_file is not null)=p_link_file then return p_note; end if;
    raise exception 'Case note request is unavailable';
  end if;

  insert into sectalk_private.audit(actor,report_id,action,note)
    values(actor,p_report,'case_note_added','Staff collaboration note added');
  for audience in
    insert into sectalk_private.st_v6_case_mentions(recipient,report_id,note_id)
    select p.id,p_report,p_note from public.st_profiles p
    join sectalk_private.staff s on s.user_id=p.id
    join public.st_reports r on r.id=p_report
    where p.handle=any(targets) and p.id not in (actor,r.reporter,r.subject)
      and sectalk_private.st_v2_active(p.id)
      and exists(select 1 from auth.mfa_factors f where f.user_id=p.id and f.status='verified' and f.factor_type='totp')
    returning recipient
  loop
    if not sectalk_private.st_v6_quiet_for(audience,null)
      and sectalk_private.st_v6_notification_enabled(audience,'mention') then
      perform realtime.send('{}'::jsonb,'case_collaboration','st:account:'||audience,true);
    end if;
  end loop;
  return p_note;
end
$$;

create function public.st_v6_case_note_evidence(p_report uuid,p_note uuid,p_kind text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare chosen sectalk_private.st_v6_case_notes; evidence jsonb;
begin
  if not sectalk_private.st_v6_case_collaboration_access(p_report) then
    raise exception 'Case collaboration is unavailable' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v6_case_note_evidence',40);
  select n.* into chosen from sectalk_private.st_v6_case_notes n where n.report_id=p_report and n.id=p_note;
  if p_kind='message' and chosen.linked_message then
    select jsonb_build_object('excerpt',r.evidence) into evidence
    from public.st_reports r where r.id=p_report and length(r.evidence)>0;
  elsif p_kind='file' and chosen.linked_file=sectalk_private.st_v6_case_shared_file(p_report) then
    if public.st_v6_file_can_read(chosen.linked_file) then
      select jsonb_build_object('id',f.id,'filename',f.filename,'size_bytes',f.size_bytes) into evidence
      from public.st_v5_files f where f.id=chosen.linked_file;
    end if;
  end if;
  if evidence is null then raise exception 'Shared evidence is unavailable' using errcode='42501'; end if;
  insert into sectalk_private.audit(actor,report_id,action,note)
    values(auth.uid(),p_report,'case_note_evidence_viewed','Shared evidence opened from a staff note');
  return evidence;
end
$$;

create function public.st_v6_case_collaboration_alerts(p_unread_only boolean default false)
returns table(report_id uuid,note_id uuid,created_at timestamptz,read_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
begin
  if not coalesce(sectalk_private.st_v6_case_redaction_staff(),false) then
    raise exception 'Case collaboration is unavailable' using errcode='42501';
  end if;
  return query select m.report_id,m.note_id,m.created_at,m.read_at
  from sectalk_private.st_v6_case_mentions m
  where m.recipient=auth.uid() and (not coalesce(p_unread_only,false) or m.read_at is null)
    and sectalk_private.st_v6_case_collaboration_access(m.report_id)
  order by m.created_at desc,m.note_id desc limit 50;
end
$$;

create function public.st_v6_read_case_collaboration_alert(p_report uuid,p_note uuid)
returns void language plpgsql security definer set search_path='' as $$
begin
  if not sectalk_private.st_v6_case_collaboration_access(p_report) then
    raise exception 'Case collaboration is unavailable' using errcode='42501';
  end if;
  update sectalk_private.st_v6_case_mentions m set read_at=clock_timestamp()
  where m.recipient=auth.uid() and m.report_id=p_report and m.note_id=p_note and m.read_at is null;
end
$$;

revoke all on function sectalk_private.st_v6_case_collaboration_access(uuid),sectalk_private.st_v6_case_shared_file(uuid),
  public.st_v6_case_collaboration(uuid),public.st_v6_append_case_note(uuid,uuid,text,boolean,boolean),
  public.st_v6_case_note_evidence(uuid,uuid,text),public.st_v6_case_collaboration_alerts(boolean),
  public.st_v6_read_case_collaboration_alert(uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_case_collaboration(uuid),public.st_v6_append_case_note(uuid,uuid,text,boolean,boolean),
  public.st_v6_case_note_evidence(uuid,uuid,text),public.st_v6_case_collaboration_alerts(boolean),
  public.st_v6_read_case_collaboration_alert(uuid,uuid) to authenticated;

commit;
