begin;

create table sectalk_private.st_v7_soc_response_grants (
  actor uuid not null references auth.users on delete cascade,
  action text not null check(action in ('quarantine_message','quarantine_file','suspend_user','force_logout','revoke_device','block_domain','lock_room')),
  workspace uuid references public.st_v2_workspaces on delete cascade,
  role text not null check(role in ('requester','approver')),
  check((action='lock_room')=(workspace is not null)),
  unique nulls not distinct(actor,action,workspace,role)
);
create table sectalk_private.st_v7_soc_responses (
  id uuid primary key default gen_random_uuid(),
  action text not null check(action in ('quarantine_message','quarantine_file','suspend_user','force_logout','revoke_device','block_domain','lock_room')),
  workspace uuid,
  case_id uuid,
  subject uuid,
  target uuid,
  domain text,
  requester uuid not null,
  reason text not null check(char_length(reason) between 10 and 240),
  requested_at timestamptz not null default clock_timestamp(),
  decider uuid,
  decision text check(decision in ('executed','rejected')),
  decision_reason text,
  decided_at timestamptz,
  check(decider is distinct from requester),
  check((decision is null)=(decider is null) and (decision is null)=(decision_reason is null) and (decision is null)=(decided_at is null)),
  check((action='lock_room')=(workspace is not null) and (action='block_domain')=(domain is not null))
);
create index st_v7_soc_response_feed on sectalk_private.st_v7_soc_responses(action,workspace,requested_at desc,id);
create unique index st_v7_soc_pending_target on sectalk_private.st_v7_soc_responses(action,workspace,case_id,target,domain)
  nulls not distinct where decision is null;
alter table sectalk_private.st_v7_soc_response_grants enable row level security;
alter table sectalk_private.st_v7_soc_responses enable row level security;
revoke all on sectalk_private.st_v7_soc_response_grants,sectalk_private.st_v7_soc_responses
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_guard_soc_response()
returns trigger language plpgsql set search_path='' as $$
begin
  if tg_op='UPDATE' and old.decision is null and new.decision is not null
    and (to_jsonb(old)-array['decider','decision','decision_reason','decided_at'])
       =(to_jsonb(new)-array['decider','decision','decision_reason','decided_at']) then return new; end if;
  raise exception 'Response request and decision history is immutable' using errcode='42501';
end $$;
create trigger st_v7_guard_soc_response before update or delete on sectalk_private.st_v7_soc_responses
  for each row execute function sectalk_private.st_v7_guard_soc_response();

create function sectalk_private.st_v7_soc_response_verified()
returns boolean language sql stable set search_path='' as $$
  select sectalk_private.st_v7_admin_fresh() is true
    and sectalk_private.st_v2_active(auth.uid()) is true and public.st_v7_account_under_lockdown() is false;
$$;

create function sectalk_private.st_v7_soc_response_role(p_user uuid,p_action text,p_space uuid,p_role text)
returns boolean language sql stable set search_path='' as $$
  select sectalk_private.st_v2_active(p_user) is true and exists(
    select 1 from sectalk_private.st_v7_soc_response_grants g
    where g.actor=p_user and g.action=p_action and g.workspace is not distinct from p_space and g.role=p_role
  ) and case
    when p_action in ('quarantine_message','quarantine_file','suspend_user') then
      exists(select 1 from sectalk_private.staff s where s.user_id=p_user)
    when p_action in ('force_logout','revoke_device') then
      exists(select 1 from sectalk_private.st_v7_account_operators o where o.user_id=p_user and o.capability='operator')
    when p_action='block_domain' then
      exists(select 1 from sectalk_private.st_v7_abuse_blocklist_operators o where o.user_id=p_user)
    when p_action='lock_room' then coalesce(sectalk_private.st_v2_role(p_space,p_user) in ('owner','admin'),false)
    else false end;
$$;

-- Resolve identifiers from a consented case and recheck the same subject and exact object at execution.
create function sectalk_private.st_v7_soc_case_target(p_case uuid,p_action text,p_subject uuid,p_target uuid,p_other uuid)
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
      if sectalk_private.st_v6_case_redaction_available(p_case) is not true then
        raise exception 'This report has no matching consented live message' using errcode='42501'; end if;
      object_id:=case_row.message_id;
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

create function public.st_v7_soc_response_catalog()
returns jsonb language sql stable security definer set search_path='' as $$
  select coalesce(jsonb_agg(jsonb_build_object('action',g.action,'workspace',g.workspace,'role',g.role,'name',w.name)
    order by g.action,g.workspace,g.role),'[]'::jsonb)
  from sectalk_private.st_v7_soc_response_grants g left join public.st_v2_workspaces w on w.id=g.workspace
  where g.actor=auth.uid() and sectalk_private.st_v7_soc_response_verified()
    and sectalk_private.st_v7_soc_response_role(g.actor,g.action,g.workspace,g.role);
$$;

create function public.st_v7_soc_response_targets(p_workspace uuid,p_case uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare account uuid;
begin
  if not sectalk_private.st_v7_soc_response_verified() then return '[]'::jsonb; end if;
  if p_workspace is not null and p_case is null
    and sectalk_private.st_v7_soc_response_role(auth.uid(),'lock_room',p_workspace,'requester') then
    return (select coalesce(jsonb_agg(to_jsonb(room)),'[]'::jsonb) from (
      select r.id,r.name from public.st_v6_rooms r where r.workspace_id=p_workspace and not r.archived and not r.locked
        and sectalk_private.st_v6_room_role(r.id,auth.uid()) in ('owner','moderator')
      order by r.name,r.id limit 100) room);
  end if;
  if p_case is not null and p_workspace is null
    and sectalk_private.st_v7_soc_response_role(auth.uid(),'revoke_device',null,'requester') then
    account:=sectalk_private.st_v7_soc_case_target(p_case,'force_logout',null,null,null);
    return (select coalesce(jsonb_agg(to_jsonb(device)),'[]'::jsonb) from (
      select d.id,d.state as name from sectalk_private.st_v7_devices d
      where d.owner=account and d.state<>'blocked' and d.wiped_at is null order by d.created_at desc,d.id limit 30) device);
  end if;
  return '[]'::jsonb;
end $$;

create function public.st_v7_request_soc_response(p_action text,p_workspace uuid,p_case uuid,p_target uuid,p_domain text,p_reason text)
returns uuid language plpgsql security definer set search_path='' as $$
declare current_actor uuid:=auth.uid(); pinned_target uuid; pinned_subject uuid; request_id uuid;
  note text:=btrim(p_reason); name text:=rtrim(lower(btrim(p_domain)),'.');
begin
  if not sectalk_private.st_v7_soc_response_verified() or
    not sectalk_private.st_v7_soc_response_role(current_actor,p_action,p_workspace,'requester') then
    raise exception 'Fresh scoped request access required' using errcode='42501'; end if;
  if note is null or char_length(note) not between 10 and 240 then
    raise exception 'Enter a response reason between 10 and 240 characters' using errcode='22023'; end if;
  case p_action
    when 'lock_room' then
      if p_case is not null or p_domain is not null or not exists(select 1 from public.st_v6_rooms r
        where r.id=p_target and r.workspace_id=p_workspace and not r.archived and not r.locked
          and sectalk_private.st_v6_room_role(r.id,current_actor) in ('owner','moderator')) then
        raise exception 'An eligible room in the assigned workspace is required' using errcode='42501'; end if;
      pinned_target:=p_target;
    when 'block_domain' then
      if p_case is not null or p_target is not null or name is null or char_length(name)>253
        or name !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
        or name !~ '[.][a-z][a-z0-9-]*$' then
        raise exception 'Enter a domain name without a scheme, path or wildcard' using errcode='22023'; end if;
    else
      if p_domain is not null or (p_action='revoke_device')<>(p_target is not null) then
        raise exception 'Choose a report and only the applicable device identifier' using errcode='22023'; end if;
      pinned_target:=sectalk_private.st_v7_soc_case_target(p_case,p_action,null,p_target,null);
      select subject into pinned_subject from public.st_reports where id=p_case;
  end case;
  perform sectalk_private.limit_action('v7_soc_response_request',12);
  insert into sectalk_private.st_v7_soc_responses(action,workspace,case_id,subject,target,domain,requester,reason)
    values(p_action,p_workspace,p_case,pinned_subject,pinned_target,name,current_actor,note)
    on conflict do nothing returning id into request_id;
  if request_id is null then raise exception 'A pending request already covers this response' using errcode='PT409'; end if;
  return request_id;
end $$;

create function public.st_v7_soc_response_queue()
returns jsonb language sql stable security definer set search_path='' as $$
  select coalesce(jsonb_agg(to_jsonb(entries)),'[]'::jsonb) from (
    select r.id,r.action,r.workspace,r.case_id,r.domain,r.target,r.reason,r.requested_at,r.decision,r.decision_reason,r.decided_at,
      r.decision is null and r.requester<>auth.uid()
        and sectalk_private.st_v7_soc_response_role(auth.uid(),r.action,r.workspace,'approver') can_decide
    from sectalk_private.st_v7_soc_responses r
    where sectalk_private.st_v7_soc_response_verified()
      and (r.action<>'lock_room' or sectalk_private.st_v6_room_role(r.target,auth.uid()) in ('owner','moderator')) and
      ((r.requester=auth.uid() and sectalk_private.st_v7_soc_response_role(auth.uid(),r.action,r.workspace,'requester'))
        or sectalk_private.st_v7_soc_response_role(auth.uid(),r.action,r.workspace,'approver'))
    order by (r.decision is null and r.requested_at>statement_timestamp()-interval '24 hours') desc,r.requested_at desc,r.id limit 60
  ) entries;
$$;

create function public.st_v7_decide_soc_response(p_id uuid,p_approve boolean,p_reason text)
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
      when 'quarantine_message' then perform sectalk_private.st_v6_case_redact(r.case_id,note);
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

revoke all on function sectalk_private.st_v7_guard_soc_response(),sectalk_private.st_v7_soc_response_verified(),
  sectalk_private.st_v7_soc_response_role(uuid,text,uuid,text),sectalk_private.st_v7_soc_case_target(uuid,text,uuid,uuid,uuid),
  public.st_v7_soc_response_catalog(),public.st_v7_soc_response_targets(uuid,uuid),
  public.st_v7_request_soc_response(text,uuid,uuid,uuid,text,text),
  public.st_v7_soc_response_queue(),public.st_v7_decide_soc_response(uuid,boolean,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_soc_response_catalog(),public.st_v7_soc_response_targets(uuid,uuid),
  public.st_v7_request_soc_response(text,uuid,uuid,uuid,text,text),
  public.st_v7_soc_response_queue(),public.st_v7_decide_soc_response(uuid,boolean,text) to authenticated;
notify pgrst,'reload schema';
commit;
