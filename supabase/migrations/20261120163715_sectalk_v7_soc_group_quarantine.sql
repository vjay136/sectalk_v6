begin;

create table sectalk_private.st_v7_group_quarantine (
  group_id uuid not null,
  message_id uuid not null,
  case_id uuid not null,
  quarantined_at timestamptz not null default clock_timestamp(),
  primary key(group_id,message_id)
);
alter table sectalk_private.st_v7_group_quarantine enable row level security;
revoke all on sectalk_private.st_v7_group_quarantine from public,anon,authenticated,service_role;
create trigger st_v7_immutable_group_quarantine before update or delete on sectalk_private.st_v7_group_quarantine
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

create function sectalk_private.st_v7_group_report_target(p_report public.st_reports)
returns uuid language sql stable set search_path='' as $$
  select m.id from sectalk_private.st_group_messages m
  where m.id=p_report.group_message_id and m.group_id=p_report.group_chat_id and m.actor=p_report.subject
    and p_report.evidence is not null and char_length(btrim(p_report.evidence))>0
    and not exists(select 1 from sectalk_private.st_v7_group_quarantine t
      where (t.group_id,t.message_id)=(m.group_id,m.id));
$$;

create function sectalk_private.st_v7_quarantine_reported_message(p_case uuid,p_note text)
returns void language plpgsql set search_path='' as $$
declare evidence_case public.st_reports; message_key uuid;
begin
  select * into strict evidence_case from public.st_reports where id=p_case for update;
  if evidence_case.group_chat_id is null then
    perform sectalk_private.st_v6_case_redact(p_case,p_note);
    return;
  end if;
  perform 1 from sectalk_private.st_group_chats where id=evidence_case.group_chat_id for update;
  if not found then raise exception 'Group is unavailable' using errcode='PT409'; end if;
  message_key:=sectalk_private.st_v7_group_report_target(evidence_case);
  if message_key is null then raise exception 'Consented group message changed' using errcode='PT409'; end if;
  insert into sectalk_private.st_v7_group_quarantine(group_id,message_id,case_id)
    values(evidence_case.group_chat_id,message_key,p_case);
  insert into sectalk_private.audit(actor,report_id,action,note) values(auth.uid(),p_case,'redacted',p_note);
  perform realtime.send(jsonb_build_object('group',evidence_case.group_chat_id,'message',message_key),
    'group_message_quarantined','st:account:'||m.actor,true)
  from sectalk_private.st_group_members m where m.group_id=evidence_case.group_chat_id;
end $$;

-- Apply the existing member/device/envelope authorization before changing the returned message representation.
alter function public.st_group_chat(text,uuid,jsonb) set schema sectalk_private;
revoke all on function sectalk_private.st_group_chat(text,uuid,jsonb) from public,anon,authenticated,service_role;
create function public.st_group_chat(p_action text,p_group uuid default null,p_data jsonb default '{}')
returns jsonb language plpgsql security definer set search_path='' as $$
declare result jsonb; visible jsonb;
begin
  result:=sectalk_private.st_group_chat(p_action,p_group,p_data);
  if p_action='read' then
    select coalesce(jsonb_agg(case when t.message_id is null then x.message else
      jsonb_build_object('id',x.message->'id','actor',x.message->'actor','sent',x.message->'sent',
        'epoch',x.message->'epoch','quarantined',true) end order by x.ordinal),'[]'::jsonb) into visible
    from jsonb_array_elements(result->'messages') with ordinality x(message,ordinal)
    left join sectalk_private.st_v7_group_quarantine t on t.group_id=p_group and t.message_id=(x.message->>'id')::uuid;
    result:=jsonb_set(result,'{messages}',visible);
  end if;
  return result;
end $$;
revoke all on function public.st_group_chat(text,uuid,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_group_chat(text,uuid,jsonb) to authenticated;

alter function public.st_group_search_metadata(uuid) set schema sectalk_private;
revoke all on function sectalk_private.st_group_search_metadata(uuid) from public,anon,authenticated,service_role;
create function public.st_group_search_metadata(p_group uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare result jsonb; allowed jsonb;
begin
  result:=sectalk_private.st_group_search_metadata(p_group);
  select coalesce(jsonb_agg(x.message order by x.ordinal),'[]'::jsonb) into allowed
    from jsonb_array_elements(result->'messages') with ordinality x(message,ordinal)
    where not exists(select 1 from sectalk_private.st_v7_group_quarantine t
      where t.group_id=p_group and t.message_id=(x.message->>'id')::uuid);
  return jsonb_set(result,'{messages}',allowed);
end $$;
revoke all on function public.st_group_search_metadata(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_group_search_metadata(uuid) to authenticated;
revoke all on function sectalk_private.st_v7_group_report_target(public.st_reports),
  sectalk_private.st_v7_quarantine_reported_message(uuid,text) from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v7_soc_case_target(p_case uuid,p_action text,p_subject uuid,p_target uuid,p_other uuid)
returns uuid language plpgsql security definer set search_path='' as $$
declare case_row public.st_reports; object_id uuid;
begin
  select * into case_row from public.st_reports r where r.id=p_case for update;
  if not found or case_row.status not in ('open','reviewing') or case_row.subject in (auth.uid(),p_other)
    or case_row.reporter in (auth.uid(),p_other) or (p_subject is not null and case_row.subject<>p_subject)
    or exists(select 1 from sectalk_private.staff s where s.user_id=case_row.subject)
    or exists(select 1 from sectalk_private.st_v7_account_operators o where o.user_id=case_row.subject) then
    raise exception 'An eligible open report is required' using errcode='42501';
  end if;
  case p_action
    when 'quarantine_message' then
      if case_row.group_chat_id is not null then
        object_id:=sectalk_private.st_v7_group_report_target(case_row);
      elsif sectalk_private.st_v6_case_redaction_available(p_case) then
        object_id:=case_row.message_id;
      end if;
      if object_id is null then
        raise exception 'This report has no matching consented live message' using errcode='42501'; end if;
    when 'quarantine_file' then
      select f.id into object_id from sectalk_private.st_v5_attachment_reports e join public.st_v5_files f on f.id=e.file_id
        where e.report_id=p_case and f.uploader=case_row.subject and f.chat_id=case_row.chat_id
          and f.message_id=case_row.message_id and f.deleted_at is null and f.purged_at is null for update of f;
      if object_id is null then raise exception 'This report has no matching consented live attachment' using errcode='42501'; end if;
    when 'force_logout' then
      if sectalk_private.st_v7_admin_native_target(case_row.subject) is not true then
        raise exception 'This report cannot target a native account action' using errcode='42501'; end if;
      object_id:=case_row.subject;
    when 'revoke_device' then
      if sectalk_private.st_v7_admin_native_target(case_row.subject) is not true then
        raise exception 'This report cannot target a native account action' using errcode='42501'; end if;
      select d.id into object_id from sectalk_private.st_v7_devices d
        where d.owner=case_row.subject and d.id=p_target and d.state<>'blocked' and d.wiped_at is null;
      if object_id is null then raise exception 'Registered device is unavailable for this report' using errcode='42501'; end if;
    when 'suspend_user' then object_id:=case_row.subject;
    else raise exception 'Choose a supported response action' using errcode='22023';
  end case;
  if p_target is not null and p_target<>object_id then
    raise exception 'The reported target changed' using errcode='PT409'; end if;
  return object_id;
end $$;

create or replace function public.st_v7_decide_soc_response(p_id uuid,p_approve boolean,p_reason text)
returns text language plpgsql security definer set search_path='' as $$
declare r sectalk_private.st_v7_soc_responses; next_decision text:='rejected'; current_actor uuid:=auth.uid();
  note text:=btrim(p_reason); stamp timestamptz:=clock_timestamp(); attachment_chat uuid;
begin
  select * into r from sectalk_private.st_v7_soc_responses where id=p_id;
  if not found or not sectalk_private.st_v7_soc_response_verified() or r.requester=current_actor
    or (r.action='lock_room' and not coalesce(sectalk_private.st_v6_room_role(r.target,current_actor) in ('owner','moderator'),false))
    or not sectalk_private.st_v7_soc_response_role(current_actor,r.action,r.workspace,'approver') then
    raise exception 'A separate fresh reviewer with this response scope is required' using errcode='42501'; end if;
  select * into strict r from sectalk_private.st_v7_soc_responses where id=p_id for update;
  perform 1 from sectalk_private.st_v7_soc_response_grants g
    where g.actor=current_actor and g.action=r.action and g.workspace is not distinct from r.workspace and g.role='approver' for share;
  if not found then raise exception 'Response approval access changed' using errcode='42501'; end if;
  if p_approve is null or note is null or char_length(note) not between 10 and 240 then
    raise exception 'Enter a decision reason between 10 and 240 characters' using errcode='22023'; end if;
  if r.decision is not null then
    if r.decider=current_actor and p_approve=(r.decision='executed') then return r.decision; end if;
    raise exception 'The response has already been decided' using errcode='PT409';
  end if;
  perform sectalk_private.limit_action('v7_soc_response_decide',12);
  if p_approve then
    if r.requested_at<=stamp-interval '24 hours'
      or not sectalk_private.st_v7_soc_response_role(r.requester,r.action,r.workspace,'requester') then
      raise exception 'The request expired or lost authorization' using errcode='PT409'; end if;
    perform 1 from sectalk_private.st_v7_soc_response_grants g
      where g.actor=r.requester and g.action=r.action and g.workspace is not distinct from r.workspace and g.role='requester' for share;
    if not found then raise exception 'The requester no longer has this response scope' using errcode='PT409'; end if;
    if r.case_id is not null then
      perform sectalk_private.st_v7_soc_case_target(r.case_id,r.action,r.subject,r.target,r.requester);
    end if;
    case r.action
      when 'quarantine_message' then perform sectalk_private.st_v7_quarantine_reported_message(r.case_id,note);
      when 'quarantine_file' then
        if public.st_staff_status()<>'verified' then raise exception 'Staff verification required' using errcode='42501'; end if;
        update public.st_v5_files f set deleted_at=stamp,purge_after=stamp+interval '24 hours'
          where f.id=r.target and f.deleted_at is null returning f.chat_id into attachment_chat;
        if not found then raise exception 'The reported attachment changed' using errcode='PT409'; end if;
        insert into sectalk_private.audit(actor,report_id,action,note)
          values(current_actor,r.case_id,'attachment_quarantined',note);
        perform realtime.send(jsonb_build_object('chat_id',attachment_chat),'inbox','st:account:'||participants.user_id,true)
          from public.st_chats c cross join lateral(values(c.member_a),(c.member_b)) participants(user_id)
          where c.id=attachment_chat;
      when 'suspend_user' then
        perform public.st_v5_moderate(r.case_id,'suspend',note);
      when 'force_logout' then
        perform public.st_v7_account_admin_action(r.subject,'force_logout',note);
      when 'revoke_device' then
        if not public.st_v7_operator_device_action(r.subject,r.target,'block_device',note) then
          raise exception 'The registered device changed' using errcode='PT409'; end if;
      when 'block_domain' then
        perform public.st_v7_add_abuse_block('domain',r.domain,note,7);
      when 'lock_room' then
        perform 1 from public.st_v6_rooms a where a.id=r.target and a.workspace_id=r.workspace
          and not a.locked and not a.archived
          and sectalk_private.st_v6_room_role(r.target,r.requester) in ('owner','moderator') for update;
        if not found then raise exception 'Room or requester access changed' using errcode='PT409'; end if;
        perform public.st_v6_room_settings(r.target,'lock',null,0);
      else raise exception 'Unsupported response' using errcode='22023';
    end case;
    next_decision:='executed';
  end if;
  update sectalk_private.st_v7_soc_responses set decision=next_decision,decider=current_actor,decision_reason=note,
    decided_at=clock_timestamp() where id=p_id;
  return next_decision;
end $$;

notify pgrst,'reload schema';

commit;
