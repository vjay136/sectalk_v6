begin;

-- The same tombstone and cleanup serve authors and authorized case reviewers.
create function sectalk_private.st_v6_tombstone_direct(p_message uuid)
returns void language plpgsql set search_path='' as $$
begin
  delete from public.st_v2_message_edits where message_id=p_message;
  delete from public.st_v2_reactions where message_id=p_message;
  delete from public.st_v2_pins where message_id=p_message;
  update public.st_messages set body='Message removed',revoked_at=clock_timestamp(),edited_at=clock_timestamp()
    where id=p_message and revoked_at is null;
end
$$;

create or replace function public.st_v5_message_action(p_message uuid,p_action text)
returns void language plpgsql security definer set search_path='' as $$
declare item public.st_messages; actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v5_message_controls',45);
  select * into item from public.st_messages where id=p_message for update;
  if not found or not sectalk_private.member(item.chat_id,actor) then raise exception 'Message unavailable'; end if;
  if p_action='hide' then
    insert into public.st_v5_hidden_messages(message_id,user_id) values(p_message,actor) on conflict do nothing;
  elsif p_action='revoke' and item.sender=actor then
    if item.revoked_at is null then perform sectalk_private.st_v6_tombstone_direct(p_message); end if;
  else
    raise exception 'Message action unavailable';
  end if;
end
$$;

create function sectalk_private.st_v6_case_redaction_staff()
returns boolean language sql stable set search_path='' as $$
  select public.st_staff_status()='verified' and sectalk_private.st_v2_active(auth.uid()) and exists(
    select 1 from auth.sessions s join auth.mfa_factors f on f.id=s.factor_id and f.user_id=s.user_id
    where s.id=(auth.jwt()->>'session_id')::uuid and s.user_id=auth.uid() and s.aal='aal2'
      and (s.not_after is null or s.not_after>now()) and f.status='verified' and f.factor_type='totp'
  )
$$;

create function sectalk_private.st_v6_case_redaction_available(p_report uuid)
returns boolean language sql stable set search_path='' as $$
  select sectalk_private.st_v6_case_redaction_staff() and exists(
    select 1 from public.st_reports r join public.st_messages m
      on m.id=r.message_id and m.chat_id=r.chat_id and m.sender=r.subject
    where r.id=p_report and r.status in ('open','reviewing') and r.reporter<>auth.uid()
      and r.subject<>auth.uid() and not exists(select 1 from sectalk_private.staff s where s.user_id=r.subject)
      and r.evidence is not null and m.revoked_at is null and r.evidence=m.body
  )
$$;

create function sectalk_private.st_v6_case_redact(p_report uuid,p_note text)
returns void language plpgsql security definer set search_path='' as $$
declare target public.st_reports;
declare item public.st_messages;
begin
  if not coalesce(sectalk_private.st_v6_case_redaction_staff(),false)
  then raise exception 'Verified staff access required' using errcode='42501'; end if;
  if p_note is null or char_length(btrim(p_note)) not between 4 and 500 then raise exception 'Enter a reason'; end if;
  perform sectalk_private.limit_action('moderate',20);
  select * into target from public.st_reports where id=p_report for update;
  if not found then raise exception 'Redaction unavailable'; end if;
  select * into item from public.st_messages where id=target.message_id
    and chat_id=target.chat_id and sender=target.subject for update;
  if not found or target.reporter=auth.uid() or target.subject=auth.uid()
    or exists(select 1 from sectalk_private.staff where user_id=target.subject)
  then raise exception 'Redaction unavailable'; end if;
  if item.revoked_at is not null and exists(select 1 from sectalk_private.audit a
    where a.report_id=p_report and a.actor=auth.uid() and a.action='redacted') then return; end if;
  if not sectalk_private.st_v6_case_redaction_available(p_report) then raise exception 'Redaction unavailable'; end if;
  perform sectalk_private.st_v6_tombstone_direct(item.id);
  insert into sectalk_private.audit(actor,report_id,action,note)
    values(auth.uid(),p_report,'redacted',btrim(p_note));
end
$$;

create function public.st_v6_case_redact(p_report uuid,p_note text)
returns void language sql set search_path=''
return sectalk_private.st_v6_case_redact(p_report,p_note);

create or replace function public.st_v5_case(p_report uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare result jsonb; attachment jsonb;
begin
  result:=public.st_case(p_report);
  select jsonb_build_object('id',f.id,'filename',f.filename,'size_bytes',f.size_bytes) into attachment
    from sectalk_private.st_v5_attachment_reports e join public.st_v5_files f on f.id=e.file_id where e.report_id=p_report;
  return result||jsonb_build_object('attachment',attachment,
    'message_redaction_available',sectalk_private.st_v6_case_redaction_available(p_report));
end
$$;

create or replace function public.st_v5_report_timeline(p_report uuid)
returns table(action text,at timestamptz)
language sql stable security definer set search_path='' as $$
  select 'submitted'::text,r.created_at from public.st_reports r where r.id=p_report and r.reporter=auth.uid()
  union all
  select a.action,a.created_at from sectalk_private.audit a join public.st_reports r on r.id=a.report_id
  where r.id=p_report and r.reporter=auth.uid() and a.action in
    ('reviewing','escalated','warn','suspend','restrict','remove','restore','resolved','dismissed','redacted')
  order by 2 desc limit 100
$$;

revoke all on function sectalk_private.st_v6_tombstone_direct(uuid),sectalk_private.st_v6_case_redaction_staff(),
  sectalk_private.st_v6_case_redaction_available(uuid),sectalk_private.st_v6_case_redact(uuid,text),
  public.st_v6_case_redact(uuid,text) from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v6_case_redact(uuid,text),public.st_v6_case_redact(uuid,text) to authenticated;
commit;
