begin;

alter table sectalk_private.st_v7_soc_response_grants drop constraint st_v7_soc_response_grants_action_check,
  drop constraint st_v7_soc_response_grants_check,
  add check(action in ('quarantine_message','quarantine_file','suspend_user','force_logout','revoke_device','block_domain','block_url','lock_room','quarantine_room_post')),
  add check((action in ('lock_room','quarantine_room_post'))=(workspace is not null));
alter table sectalk_private.st_v7_soc_responses drop constraint st_v7_soc_responses_action_check,
  drop constraint st_v7_soc_responses_check2,
  add column source_digest text,
  add check(action in ('quarantine_message','quarantine_file','suspend_user','force_logout','revoke_device','block_domain','block_url','lock_room','quarantine_room_post')),
  add check((action in ('lock_room','quarantine_room_post'))=(workspace is not null)
    and (action in ('block_domain','block_url'))=(domain is not null)
    and (action='quarantine_room_post')=(source_digest is not null));

create table sectalk_private.st_v7_room_quarantine_evidence (
  response uuid primary key references sectalk_private.st_v7_soc_responses,
  report uuid not null,
  workspace uuid not null,
  room uuid not null,
  post uuid not null,
  evidence text not null,
  digest text not null,
  captured_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v7_room_quarantine_evidence enable row level security;
revoke all on sectalk_private.st_v7_room_quarantine_evidence from public,anon,authenticated,service_role;
create trigger st_v7_immutable_room_quarantine_evidence before update or delete on sectalk_private.st_v7_room_quarantine_evidence
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

create function sectalk_private.st_v7_soc_room_target(p_case uuid,p_workspace uuid,p_requester uuid,p_reviewer uuid)
returns public.st_v6_room_posts language plpgsql set search_path='' as $$
declare rr sectalk_private.st_v6_room_reports; assignment sectalk_private.st_v6_room_report_stages; post public.st_v6_room_posts;
begin
  select * into rr from sectalk_private.st_v6_room_reports r where r.id=p_case and r.workspace_id=p_workspace for update;
  if rr.id is null or not rr.share_with_workspace or rr.handed_off_at is null or rr.status not in ('open','reviewing')
    or rr.category not in ('spam','other')
    or rr.reporter=p_requester or rr.subject=p_requester or rr.reporter=p_reviewer or rr.subject=p_reviewer then
    raise exception 'An open room report shared with this workspace is required' using errcode='42501'; end if;
  select s.* into assignment from sectalk_private.st_v6_room_report_stages s where s.report_id=p_case
    order by s.stage desc limit 1 for share;
  if assignment.stage is distinct from 3 or assignment.assignee is distinct from p_requester or assignment.acknowledged_at is null then
    raise exception 'The requester must be the acknowledged workspace assignee' using errcode='42501'; end if;
  perform 1 from public.st_v6_rooms r where r.id=rr.room_id and r.workspace_id=p_workspace and not r.archived for no key update;
  if not found or not coalesce(sectalk_private.st_v6_room_role(rr.room_id,p_requester) in ('owner','moderator'),false)
    or (p_reviewer is not null and not coalesce(sectalk_private.st_v6_room_role(rr.room_id,p_reviewer) in ('owner','moderator'),false)) then
    raise exception 'Current moderation permission for the reported room is required' using errcode='42501'; end if;
  select p.* into post from public.st_v6_room_posts p where p.room_id=rr.room_id and p.id=rr.post_id
    and p.sender=rr.subject and p.removed_at is null for update;
  if post.id is null then raise exception 'The reported post is unavailable' using errcode='PT409'; end if;
  return post;
end $$;
revoke all on function sectalk_private.st_v7_soc_room_target(uuid,uuid,uuid,uuid) from public,anon,authenticated,service_role;

create function public.st_v7_read_room_quarantine_evidence(p_report uuid)
returns text language sql stable security definer set search_path='' as $$
  select e.evidence from sectalk_private.st_v7_room_quarantine_evidence e
    join sectalk_private.st_v6_room_reports r on r.id=e.report and r.workspace_id=e.workspace and r.room_id=e.room and r.post_id=e.post
    where e.report=p_report and r.share_with_workspace and r.handed_off_at is not null
      and sectalk_private.st_v7_soc_response_verified()
      and sectalk_private.st_v6_room_report_admin(e.workspace,e.room,auth.uid())
      and (sectalk_private.st_v7_soc_response_role(auth.uid(),'quarantine_room_post',e.workspace,'requester')
        or sectalk_private.st_v7_soc_response_role(auth.uid(),'quarantine_room_post',e.workspace,'approver'))
    limit 1;
$$;
revoke all on function public.st_v7_read_room_quarantine_evidence(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_read_room_quarantine_evidence(uuid) to authenticated;

create or replace function sectalk_private.st_v7_soc_response_role(p_user uuid,p_action text,p_space uuid,p_role text)
returns boolean language sql stable set search_path='' as $$
  select sectalk_private.st_v2_active(p_user) is true and exists(
    select 1 from sectalk_private.st_v7_soc_response_grants g
    where g.actor=p_user and g.action=p_action and g.workspace is not distinct from p_space and g.role=p_role
  ) and case
    when p_action in ('quarantine_message','quarantine_file','suspend_user') then
      exists(select 1 from sectalk_private.staff s where s.user_id=p_user)
    when p_action in ('force_logout','revoke_device') then
      exists(select 1 from sectalk_private.st_v7_account_operators o where o.user_id=p_user and o.capability='operator')
    when p_action in ('block_domain','block_url') then
      exists(select 1 from sectalk_private.st_v7_abuse_blocklist_operators o where o.user_id=p_user)
    when p_action in ('lock_room','quarantine_room_post') then coalesce(sectalk_private.st_v2_role(p_space,p_user) in ('owner','admin'),false)
    else false end;
$$;

create or replace function public.st_v7_request_soc_response(p_action text,p_workspace uuid,p_case uuid,p_target uuid,p_domain text,p_reason text)
returns uuid language plpgsql security definer set search_path='' as $$
declare current_actor uuid:=auth.uid(); pinned_target uuid; pinned_subject uuid; request_id uuid; selected_post public.st_v6_room_posts; content_digest text;
  note text:=btrim(p_reason); name text:=rtrim(lower(btrim(p_domain)),'.');
begin
  if not sectalk_private.st_v7_soc_response_verified() or
    not sectalk_private.st_v7_soc_response_role(current_actor,p_action,p_workspace,'requester') then
    raise exception 'Fresh scoped request access required' using errcode='42501'; end if;
  if note is null or char_length(note) not between 10 and 240 then
    raise exception 'Enter a response reason between 10 and 240 characters' using errcode='22023'; end if;
  case p_action
    when 'quarantine_room_post' then
      if p_target is not null or p_domain is not null then
        raise exception 'Select the exact reported room case' using errcode='22023'; end if;
      selected_post:=sectalk_private.st_v7_soc_room_target(p_case,p_workspace,current_actor,null);
      pinned_target:=selected_post.id;
      pinned_subject:=selected_post.sender;
      content_digest:=encode(sha256(convert_to(selected_post.body,'UTF8')),'hex');
    when 'lock_room' then
      if p_case is not null or p_domain is not null or not exists(select 1 from public.st_v6_rooms r
        where r.id=p_target and r.workspace_id=p_workspace and not r.archived and not r.locked
          and sectalk_private.st_v6_room_role(r.id,current_actor) in ('owner','moderator')) then
        raise exception 'An eligible room in the assigned workspace is required' using errcode='42501'; end if;
      pinned_target:=p_target;
    when 'block_url' then
      name:=sectalk_private.st_v7_soc_url_key(btrim(p_domain));
      if p_case is not null or p_target is not null or name is null then
        raise exception 'Enter an HTTP or HTTPS address with a valid domain and path' using errcode='22023'; end if;
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
  insert into sectalk_private.st_v7_soc_responses(action,workspace,case_id,subject,target,domain,requester,reason,source_digest)
    values(p_action,p_workspace,p_case,pinned_subject,pinned_target,name,current_actor,note,content_digest)
    on conflict do nothing returning id into request_id;
  if request_id is null then raise exception 'A pending request already covers this response' using errcode='PT409'; end if;
  return request_id;
end $$;

create or replace function public.st_v7_soc_response_queue()
returns jsonb language sql stable security definer set search_path='' as $$
  select coalesce(jsonb_agg(to_jsonb(entries)),'[]'::jsonb) from (
    select r.id,r.action,r.workspace,r.case_id,r.domain,r.target,r.reason,r.requested_at,r.decision,r.decision_reason,r.decided_at,
      r.decision is null and r.requester<>auth.uid()
        and sectalk_private.st_v7_soc_response_role(auth.uid(),r.action,r.workspace,'approver') can_decide
    from sectalk_private.st_v7_soc_responses r
    where sectalk_private.st_v7_soc_response_verified()
      and (r.action<>'lock_room' or sectalk_private.st_v6_room_role(r.target,auth.uid()) in ('owner','moderator'))
      and (r.action<>'quarantine_room_post' or exists(select 1 from sectalk_private.st_v6_room_reports item
        where item.id=r.case_id and item.workspace_id=r.workspace and item.share_with_workspace and item.handed_off_at is not null
          and sectalk_private.st_v6_room_role(item.room_id,auth.uid()) in ('owner','moderator')))
      and ((r.requester=auth.uid() and sectalk_private.st_v7_soc_response_role(auth.uid(),r.action,r.workspace,'requester'))
        or sectalk_private.st_v7_soc_response_role(auth.uid(),r.action,r.workspace,'approver'))
    order by (r.decision is null and r.requested_at>statement_timestamp()-interval '24 hours') desc,r.requested_at desc,r.id limit 60
  ) entries;
$$;

create or replace function public.st_v7_decide_soc_response(p_id uuid,p_approve boolean,p_reason text)
returns text language plpgsql security definer set search_path='' as $$
declare r sectalk_private.st_v7_soc_responses; next_decision text:='rejected'; current_actor uuid:=auth.uid();
  note text:=btrim(p_reason); stamp timestamptz:=clock_timestamp(); attachment_chat uuid; selected_post public.st_v6_room_posts;
begin
  select * into r from sectalk_private.st_v7_soc_responses where id=p_id;
  if not found or not sectalk_private.st_v7_soc_response_verified() or r.requester=current_actor
    or (r.action='lock_room' and not coalesce(sectalk_private.st_v6_room_role(r.target,current_actor) in ('owner','moderator'),false))
    or (r.action='quarantine_room_post' and not exists(select 1 from sectalk_private.st_v6_room_reports item
      where item.id=r.case_id and item.workspace_id=r.workspace and item.share_with_workspace and item.handed_off_at is not null
        and sectalk_private.st_v6_room_role(item.room_id,current_actor) in ('owner','moderator')))
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
    if r.case_id is not null and r.action<>'quarantine_room_post' then
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
      when 'block_url' then
        insert into sectalk_private.st_v7_soc_url_blocks(url_key,response,expires_at) values(r.domain,r.id,stamp+interval '7 days')
        on conflict(url_key) do update set response=excluded.response,expires_at=excluded.expires_at
          where st_v7_soc_url_blocks.expires_at<=stamp;
        if not found then raise exception 'This address is already blocked' using errcode='PT409'; end if;
      when 'block_domain' then
        perform public.st_v7_add_abuse_block('domain',r.domain,note,7);
      when 'quarantine_room_post' then
        selected_post:=sectalk_private.st_v7_soc_room_target(r.case_id,r.workspace,r.requester,current_actor);
        if selected_post.id is distinct from r.target or selected_post.sender is distinct from r.subject
          or encode(sha256(convert_to(selected_post.body,'UTF8')),'hex') is distinct from r.source_digest then
          raise exception 'The post changed since the request was created' using errcode='PT409';
        end if;
        insert into sectalk_private.st_v7_room_quarantine_evidence(response,report,workspace,room,post,evidence,digest)
          values(r.id,r.case_id,r.workspace,selected_post.room_id,selected_post.id,selected_post.body,r.source_digest);
        perform public.st_v6_room_post_action(selected_post.room_id,selected_post.id,'redact',null);
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
