begin;

create table sectalk_private.st_v6_break_glass_requests (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  report_id uuid not null references sectalk_private.st_v6_room_reports on delete cascade,
  requester uuid not null references public.st_profiles on delete cascade,
  justification text not null check(char_length(justification) between 20 and 500),
  created_at timestamptz not null default clock_timestamp(),
  approval_deadline timestamptz not null default clock_timestamp()+interval '1 hour',
  reviewer uuid,
  reviewed_at timestamptz,
  review_reason text,
  source_revision timestamptz,
  grant_expires_at timestamptz,
  reviewed_after_access timestamptz,
  state text not null default 'pending' check(state in ('pending','approved','denied','revoked','accessed','closed'))
);
create index st_v6_break_glass_workspace on sectalk_private.st_v6_break_glass_requests(workspace_id,created_at desc);
create index st_v6_break_glass_requester on sectalk_private.st_v6_break_glass_requests(requester,created_at desc);
create table sectalk_private.st_v6_break_glass_audit (
  id bigint generated always as identity primary key,
  grant_id uuid not null,
  workspace_id uuid not null,
  actor uuid not null,
  action text not null check(action in ('requested','approved','denied','revoked','accessed','closed')),
  reason text,
  recorded_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v6_break_glass_requests enable row level security;
alter table sectalk_private.st_v6_break_glass_audit enable row level security;
revoke all on sectalk_private.st_v6_break_glass_requests,sectalk_private.st_v6_break_glass_audit
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_emergency_operator()
returns boolean language sql stable set search_path='' as $$
  select public.st_v6_tenant_operations_status()='verified' and public.st_staff_status()='verified'
    and exists(select from auth.mfa_amr_claims p
      where p.session_id::text=auth.jwt()->>'session_id' and p.authentication_method='totp'
        and p.updated_at>now()-interval '10 minutes')
$$;

create function sectalk_private.st_v6_emergency_owner(p_workspace uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid())='owner'
    and sectalk_private.st_v6_holds_access(p_workspace)='verified'
    and exists(select from auth.mfa_amr_claims p
      where p.session_id::text=auth.jwt()->>'session_id' and p.authentication_method='totp'
        and p.updated_at>now()-interval '10 minutes'),false)
$$;

create function public.st_v6_break_glass_list(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare result jsonb;
begin
  if ((p_workspace is null and not sectalk_private.st_v6_emergency_operator())
    or (p_workspace is not null and not sectalk_private.st_v6_emergency_owner(p_workspace))) then
    raise exception using errcode='42501',message='Emergency review requires verified access';
  end if;
  select coalesce(jsonb_agg(jsonb_build_object('id',e.id,'workspace',w.name,'report',e.report_id,
    'reason',e.justification,'review_reason',e.review_reason,'expires',coalesce(e.grant_expires_at,e.approval_deadline),
    'state',case when (e.state='pending' and e.approval_deadline<=now()) or (e.state='approved' and e.grant_expires_at<=now())
      then 'expired' else e.state end,
    'history',(select jsonb_agg(jsonb_build_object('action',a.action,'at',a.recorded_at,'reason',a.reason) order by a.id)
      from sectalk_private.st_v6_break_glass_audit a where a.grant_id=e.id)) order by e.created_at desc),'[]'::jsonb)
  into result
  from (select * from sectalk_private.st_v6_break_glass_requests r
    where (p_workspace is null and r.requester=auth.uid())
      or (p_workspace is not null and r.workspace_id=p_workspace and r.requester<>auth.uid())
    order by r.created_at desc limit 100) e join public.st_v2_workspaces w on w.id=e.workspace_id;
  return result;
end $$;

create function public.st_v6_request_break_glass(p_report uuid,p_justification text)
returns uuid language plpgsql security definer set search_path='' as $$
declare source record; request_id uuid;
begin
  if not sectalk_private.st_v6_emergency_operator() then
    raise exception using errcode='42501',message='Fresh operator verification required';
  end if;
  if char_length(btrim(coalesce(p_justification,''))) not between 20 and 500 then
    raise exception using errcode='22023',message='Enter an emergency justification between 20 and 500 characters';
  end if;
  perform sectalk_private.limit_action('v6_emergency_request',5);
  select r.workspace_id into source
    from sectalk_private.st_v6_room_reports r join public.st_v6_rooms room on room.id=r.room_id
    join public.st_v6_room_posts p on (p.room_id,p.id)=(r.room_id,r.post_id)
    where r.id=p_report and r.share_with_workspace and r.status in ('open','reviewing') and not room.archived and p.removed_at is null
      and p.kind='message' and room.classification in ('public','internal','confidential') and not p.forwarded;
  if not found then raise exception using errcode='42501',message='The case is unavailable for an emergency request'; end if;
  perform pg_advisory_xact_lock(hashtextextended(auth.uid()::text||p_report::text,0));
  select id into request_id from sectalk_private.st_v6_break_glass_requests e
    where e.report_id=p_report and e.requester=auth.uid()
      and ((e.state='pending' and e.approval_deadline>now()) or (e.state='approved' and e.grant_expires_at>now()))
    order by e.created_at desc limit 1;
  if found then return request_id; end if;
  insert into sectalk_private.st_v6_break_glass_requests(workspace_id,report_id,requester,justification)
    values(source.workspace_id,p_report,auth.uid(),btrim(p_justification)) returning id into request_id;
  insert into sectalk_private.st_v6_break_glass_audit(grant_id,workspace_id,actor,action)
    values(request_id,source.workspace_id,auth.uid(),'requested');
  return request_id;
end $$;

create function public.st_v6_review_break_glass(p_grant uuid,p_action text,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare request sectalk_private.st_v6_break_glass_requests; revision timestamptz;
begin
  select * into request from sectalk_private.st_v6_break_glass_requests where id=p_grant for update;
  if not found or not sectalk_private.st_v6_emergency_owner(request.workspace_id) or request.requester=auth.uid() then
    raise exception using errcode='42501',message='Emergency review is unavailable';
  end if;
  if p_action is null or p_action not in ('approved','denied','revoked','closed')
    or char_length(btrim(coalesce(p_reason,''))) not between 12 and 500 then
    raise exception using errcode='22023',message='Choose a review action and enter a reason between 12 and 500 characters';
  end if;
  if (p_action in ('approved','denied') and (request.state<>'pending' or request.approval_deadline<=now()))
    or (p_action='revoked' and request.state<>'approved') or (p_action='closed' and request.state<>'accessed') then
    raise exception using errcode='40001',message='Review the current request state before proceeding';
  end if;
  if p_action='approved' then
    select coalesce(p.edited_at,p.created_at) into revision
    from sectalk_private.st_v6_room_reports r join public.st_v6_rooms room on room.id=r.room_id
      join public.st_v6_room_posts p on (p.room_id,p.id)=(r.room_id,r.post_id)
    where r.id=request.report_id and r.share_with_workspace and r.status in ('open','reviewing') and not room.archived
      and room.classification in ('public','internal','confidential') and p.kind='message'
      and p.removed_at is null and not p.forwarded
      and sectalk_private.st_v6_room_role(room.id,auth.uid()) in ('owner','moderator','member','read_only')
      and sectalk_private.open_pair(auth.uid(),p.sender)
      for share of p,room,r;
    if not found then raise exception using errcode='42501',message='Room evidence is outside your current review scope'; end if;
  end if;
  update sectalk_private.st_v6_break_glass_requests e set state=p_action,
    reviewer=case when p_action in ('approved','denied') then auth.uid() else e.reviewer end,
    reviewed_at=case when p_action in ('approved','denied') then clock_timestamp() else e.reviewed_at end,
    review_reason=btrim(p_reason),
    source_revision=coalesce(revision,e.source_revision),
    grant_expires_at=case when p_action='approved' then clock_timestamp()+interval '10 minutes' else e.grant_expires_at end,
    reviewed_after_access=case when p_action='closed' then clock_timestamp() else e.reviewed_after_access end
    where e.id=request.id;
  insert into sectalk_private.st_v6_break_glass_audit(grant_id,workspace_id,actor,action,reason)
    values(request.id,request.workspace_id,auth.uid(),p_action,btrim(p_reason));
end $$;

create function public.st_v6_read_break_glass(p_grant uuid)
returns text language plpgsql security definer set search_path='' as $$
declare request sectalk_private.st_v6_break_glass_requests; content text;
begin
  if not sectalk_private.st_v6_emergency_operator() then
    raise exception using errcode='42501',message='Fresh operator verification required';
  end if;
  select * into request from sectalk_private.st_v6_break_glass_requests
    where id=p_grant and requester=auth.uid() for update;
  if not found or request.state<>'approved' or request.grant_expires_at<=now()
    or sectalk_private.st_v2_role(request.workspace_id,request.reviewer) is distinct from 'owner'
    or sectalk_private.st_v2_active(request.reviewer) is not true then
    raise exception using errcode='42501',message='The approval is no longer available';
  end if;
  select p.body into content
  from sectalk_private.st_v6_room_reports r join public.st_v6_rooms room on room.id=r.room_id
    join public.st_v6_room_posts p on (p.room_id,p.id)=(r.room_id,r.post_id)
  where r.id=request.report_id and r.share_with_workspace and r.status in ('open','reviewing') and not room.archived
    and room.classification in ('public','internal','confidential') and p.kind='message'
    and p.removed_at is null and not p.forwarded and coalesce(p.edited_at,p.created_at)=request.source_revision
    and sectalk_private.st_v6_room_role(room.id,request.reviewer) in ('owner','moderator','member','read_only')
    and sectalk_private.open_pair(request.reviewer,p.sender)
  for share of p,room,r;
  if not found then raise exception using errcode='42501',message='The approved evidence revision is unavailable'; end if;
  update sectalk_private.st_v6_break_glass_requests set state='accessed' where id=request.id;
  insert into sectalk_private.st_v6_break_glass_audit(grant_id,workspace_id,actor,action)
    values(request.id,request.workspace_id,auth.uid(),'accessed');
  return content;
end $$;

revoke all on function sectalk_private.st_v6_emergency_operator(),sectalk_private.st_v6_emergency_owner(uuid)
  from public,anon,authenticated,service_role;
revoke all on function public.st_v6_break_glass_list(uuid),public.st_v6_request_break_glass(uuid,text),
  public.st_v6_review_break_glass(uuid,text,text),public.st_v6_read_break_glass(uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_break_glass_list(uuid),public.st_v6_request_break_glass(uuid,text),
  public.st_v6_review_break_glass(uuid,text,text),public.st_v6_read_break_glass(uuid) to authenticated;

create index st_v6_break_glass_audit_grant on sectalk_private.st_v6_break_glass_audit(grant_id,id);
notify pgrst,'reload schema';
commit;
