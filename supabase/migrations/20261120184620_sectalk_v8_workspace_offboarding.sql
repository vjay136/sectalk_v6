begin;

create table sectalk_private.st_v8_offboarding_reviewers (
  workspace uuid not null references public.st_v2_workspaces(id) on delete cascade,
  actor uuid not null references auth.users(id) on delete cascade,
  primary key(workspace,actor)
);
create table sectalk_private.st_v8_offboarding_requests (
  id uuid primary key,
  workspace uuid not null references public.st_v2_workspaces(id) on delete cascade,
  requester uuid not null,
  reviewer uuid,
  reason text not null check(char_length(reason) between 15 and 500),
  state text not null default 'requested' check(state in ('requested','approved','read_only','withdrawn')),
  snapshot jsonb not null check(jsonb_typeof(snapshot)='object'),
  snapshot_sha256 text not null check(snapshot_sha256~'^[0-9a-f]{64}$'),
  case_id uuid unique references sectalk_private.st_v7_compliance_cases(id),
  created_at timestamptz not null default statement_timestamp(),
  staged_at timestamptz,
  check(reviewer is null or reviewer<>requester),
  check(state not in ('approved','read_only') or (reviewer is not null and case_id is not null)),
  check((state='read_only')=(staged_at is not null))
);
create unique index st_v8_offboarding_open on sectalk_private.st_v8_offboarding_requests(workspace) where state<>'withdrawn';
create table sectalk_private.st_v8_offboarding_audit (
  id bigint generated always as identity primary key,
  request uuid not null,
  workspace uuid not null,
  actor uuid not null,
  action text not null check(action in ('requested','approved','read_only','withdrawn')),
  happened_at timestamptz not null default statement_timestamp()
);
create trigger st_v8_offboarding_audit_immutable before update or delete on sectalk_private.st_v8_offboarding_audit
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_offboarding_snapshot_immutable before update on sectalk_private.st_v8_offboarding_requests
  for each row when ((old.snapshot,old.snapshot_sha256,old.requester,old.workspace,old.id,old.reason,old.created_at)
    is distinct from (new.snapshot,new.snapshot_sha256,new.requester,new.workspace,new.id,new.reason,new.created_at))
  execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_offboarding_requests enable row level security;
alter table sectalk_private.st_v8_offboarding_reviewers enable row level security;
alter table sectalk_private.st_v8_offboarding_audit enable row level security;
revoke all on sectalk_private.st_v8_offboarding_requests,sectalk_private.st_v8_offboarding_reviewers,
  sectalk_private.st_v8_offboarding_audit from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_offboarding_role(p_workspace uuid,p_actor uuid)
returns text language sql stable security definer set search_path='' as $$
  select case when not sectalk_private.st_v2_active(p_actor) then 'none'
    when exists(select 1 from public.st_v2_workspaces w where w.id=p_workspace and w.owner=p_actor
      and sectalk_private.st_v2_role(p_workspace,p_actor)='owner') then 'owner'
    when sectalk_private.st_v2_role(p_workspace,p_actor)='admin' and exists(
      select 1 from sectalk_private.st_v8_offboarding_reviewers v where (v.workspace,v.actor)=(p_workspace,p_actor))
      then 'reviewer' else 'none' end;
$$;

create function sectalk_private.st_v8_offboarding_holds(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v6_workspace_holds h where h.workspace_id=p_workspace and h.released_at is null);
$$;

create function sectalk_private.st_v8_offboarding_snapshot(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' set timezone='UTC' as $$
  select jsonb_build_object('format','sectalk-workspace-inventory-v1','workspace',w.id,'name',w.name,
    'createdAt',w.created_at,'brandAccent',w.brand_accent,
    'regionPreference',coalesce(p.requested_region,'none'),
    'inventory',jsonb_build_object(
      'members',(select count(*) from public.st_v2_members m where m.workspace_id=w.id and m.suspended_at is null),
      'rooms',(select count(*) from public.st_v6_rooms r where r.workspace_id=w.id),
      'channels',(select count(*) from public.st_v2_channels c where c.workspace_id=w.id),
      'workspaceItems',(select count(*) from public.st_v2_items i where i.workspace_id=w.id)))
  from public.st_v2_workspaces w left join sectalk_private.st_v7_org_preferences p on p.workspace=w.id
  where w.id=p_workspace;
$$;

create function public.st_v8_workspace_offboarding(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); role text:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false) or role='none' then
    raise exception 'Workspace offboarding unavailable' using errcode='42501'; end if;
  if not sectalk_private.st_v7_admin_fresh() then return jsonb_build_object('access','mfa','role',role); end if;
  return jsonb_build_object('access','verified','role',role,'held',sectalk_private.st_v8_offboarding_holds(p_workspace),
    'request',(select jsonb_build_object('id',r.id,'state',r.state,'sha256',r.snapshot_sha256,'case',r.case_id,
      'artifact',c.artifact is not null and c.expires_at>statement_timestamp(),
      'expired',c.expires_at<=statement_timestamp(),
      'downloaded',exists(select 1 from sectalk_private.st_v7_compliance_audit a where a.case_id=r.case_id and a.action='downloaded'),
      'snapshot',r.snapshot,'manifestSha256',c.manifest_sha256,'reason',r.reason)
      from sectalk_private.st_v8_offboarding_requests r left join sectalk_private.st_v7_compliance_cases c on c.id=r.case_id
      where r.workspace=p_workspace and r.state<>'withdrawn'));
end $$;

create function public.st_v8_workspace_offboarding_change(p_workspace uuid,p_id uuid,p_action text,p_confirmation text,p_reason text default null)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); role text; r sectalk_private.st_v8_offboarding_requests;
  c sectalk_private.st_v7_compliance_cases; content jsonb; material jsonb; note text:=btrim(p_reason);
begin
  if p_id is null or p_workspace is null or p_confirmation is distinct from p_workspace::text
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false) or not sectalk_private.st_v7_admin_fresh() then
    raise exception 'Fresh authenticator and exact workspace confirmation required' using errcode='42501'; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
  role:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
  if role='none' then raise exception 'Workspace offboarding unavailable' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v8_workspace_offboarding',12);
  select q.* into r from sectalk_private.st_v8_offboarding_requests q where (q.workspace,q.id)=(p_workspace,p_id) for update;
  if p_action='requested' and role='owner' then
    if r.id is not null and r.requester=actor_id and r.reason=note then return r.id; end if;
    if r.id is not null or note is null or char_length(note) not between 15 and 500
      or exists(select 1 from sectalk_private.st_v8_offboarding_requests q where q.workspace=p_workspace and q.state<>'withdrawn') then
      raise exception 'Enter a valid request or withdraw the active request first' using errcode='22023'; end if;
    content:=sectalk_private.st_v8_offboarding_snapshot(p_workspace);
    insert into sectalk_private.st_v8_offboarding_requests(id,workspace,requester,reason,snapshot,snapshot_sha256)
      values(p_id,p_workspace,actor_id,note,content,encode(sha256(convert_to(content::text,'UTF8')),'hex'));
  elsif p_action='approved' and role='reviewer' and r.requester<>actor_id then
    if r.state in ('approved','read_only') and r.reviewer=actor_id then return r.id; end if;
    if r.state<>'requested' or sectalk_private.st_v8_offboarding_role(p_workspace,r.requester)<>'owner' then
      raise exception 'Offboarding request unavailable' using errcode='42501'; end if;
    insert into sectalk_private.st_v7_compliance_cases(workspace_id,requester,reviewer,case_reference,reason,sources,state,
      approved_at,expires_at)
      values(p_workspace,r.requester,actor_id,'Workspace offboarding inventory',r.reason,
        jsonb_build_array(jsonb_build_object('kind','offboarding_inventory','id',r.id,'sha256',r.snapshot_sha256,
          'label','Workspace metadata inventory')),'approved',clock_timestamp(),clock_timestamp()+interval '24 hours')
      returning * into c;
    update sectalk_private.st_v8_offboarding_requests set state='approved',reviewer=actor_id,case_id=c.id where id=r.id;
    material:=sectalk_private.st_v7_compliance_render(c);
    if material is null then raise exception 'Inventory export unavailable' using errcode='42501'; end if;
    update sectalk_private.st_v7_compliance_cases set manifest_sha256=material->>'manifest_sha256',
      bundle_sha256=material->>'sha256',bundle_bytes=(material->>'bytes')::integer where id=c.id;
    insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action)
      values(c.id,p_workspace,r.requester,'requested'),(c.id,p_workspace,actor_id,'approved');
  elsif p_action='read_only' and role='owner' and r.requester=actor_id then
    if r.state='read_only' then return r.id; end if;
    if r.state<>'approved' or sectalk_private.st_v8_offboarding_role(p_workspace,r.reviewer)<>'reviewer'
      or not exists(select 1 from sectalk_private.st_v7_compliance_cases q where q.id=r.case_id
        and q.state='approved' and q.expires_at>statement_timestamp())
      or sectalk_private.st_v8_offboarding_holds(p_workspace)
      or not exists(select 1 from sectalk_private.st_v7_compliance_audit a where a.case_id=r.case_id and a.action='downloaded'
        and a.actor=actor_id) then raise exception 'Current reviewer, downloaded export and clear preservation holds are required'
        using errcode='42501'; end if;
    update sectalk_private.st_v8_offboarding_requests set state='read_only',staged_at=clock_timestamp() where id=r.id;
  elsif p_action='withdrawn' and role='owner' and r.id is not null then
    if r.state='withdrawn' then return r.id; end if;
    if r.state not in ('requested','approved') then raise exception 'Request can no longer be withdrawn' using errcode='42501'; end if;
    if r.case_id is not null then
      update sectalk_private.st_v7_compliance_cases set state='withdrawn',ticket=null,ticket_session=null,ticket_until=null
        where id=r.case_id;
      update sectalk_private.st_v6_export_objects set expires_at=least(expires_at,clock_timestamp())
        where scope_id=r.case_id and kind='compliance';
    end if;
    update sectalk_private.st_v8_offboarding_requests set state='withdrawn' where id=r.id;
  else
    raise exception 'Workspace offboarding unavailable' using errcode='42501';
  end if;
  insert into sectalk_private.st_v8_offboarding_audit(request,workspace,actor,action)
    values(p_id,p_workspace,actor_id,p_action);
  return p_id;
end $$;

revoke all on function sectalk_private.st_v8_offboarding_role(uuid,uuid),sectalk_private.st_v8_offboarding_holds(uuid),
  sectalk_private.st_v8_offboarding_snapshot(uuid),public.st_v8_workspace_offboarding(uuid),
  public.st_v8_workspace_offboarding_change(uuid,uuid,text,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_offboarding(uuid),
  public.st_v8_workspace_offboarding_change(uuid,uuid,text,text,text) to authenticated;

create or replace function sectalk_private.st_v7_compliance_record(p_workspace uuid,p_actor uuid,p_reviewer uuid,p_kind text,p_id text)
returns jsonb language plpgsql stable set search_path='' set timezone='UTC' as $$
begin
  if p_kind='audit' and p_id~'^[1-9][0-9]{0,17}$' then
    return (select jsonb_build_object('id',a.id::text,'event',a.event,'actor',a.actor,'target',a.target,'created_at',a.created_at)
      from public.st_v2_workspace_audit a where a.workspace_id=p_workspace and a.id=p_id::bigint);
  elsif p_kind='room_report' and p_id~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' then
    return (select jsonb_build_object('id',r.id,'category',r.category,'room',r.room_id,'post',r.post_id,'author',r.author_id,
      'revision',r.revision,'body',r.body)
      from sectalk_private.st_v7_compliance_report_sources(p_workspace,p_actor,p_reviewer,p_id::uuid) r);
  elsif p_kind='managed_channel_report' and p_id~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' then
    return (select jsonb_build_object('id',r.id,'category',r.category,'channel',r.channel_id,'post',r.post_id,
      'author',r.author_id,'encrypted_revision',r.revision,'hold',r.hold_id,'body',r.body)
      from sectalk_private.st_v8_held_channel_sources(p_workspace,p_actor,p_reviewer,p_id::uuid) r);
  elsif p_kind='offboarding_inventory' and p_id~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' then
    return (select r.snapshot from sectalk_private.st_v8_offboarding_requests r
      where (r.workspace,r.id,r.requester,r.reviewer)=(p_workspace,p_id::uuid,p_actor,p_reviewer)
        and r.state in ('approved','read_only')
        and sectalk_private.st_v8_offboarding_role(p_workspace,p_actor)='owner'
        and sectalk_private.st_v8_offboarding_role(p_workspace,p_reviewer)='reviewer');
  end if;
  return null;
end $$;

create or replace function sectalk_private.st_v7_compliance_grant_live(c sectalk_private.st_v7_compliance_cases)
returns boolean language sql stable set search_path='' as $$
  select coalesce(c.state='approved' and c.expires_at>statement_timestamp() and c.reviewer<>c.requester
    and case when exists(select 1 from sectalk_private.st_v8_offboarding_requests r where r.case_id=c.id)
      then exists(select 1 from sectalk_private.st_v8_offboarding_requests r
        where (r.case_id,r.workspace,r.requester,r.reviewer)=(c.id,c.workspace_id,c.requester,c.reviewer)
          and r.state in ('approved','read_only')
          and sectalk_private.st_v8_offboarding_role(r.workspace,r.requester)='owner'
          and sectalk_private.st_v8_offboarding_role(r.workspace,r.reviewer)='reviewer')
      else sectalk_private.st_v2_role(c.workspace_id,c.requester)='admin'
        and sectalk_private.st_v2_role(c.workspace_id,c.reviewer)='owner' end
    and sectalk_private.st_v2_active(c.requester) and sectalk_private.st_v2_active(c.reviewer),false);
$$;

create or replace function public.st_v7_begin_compliance_operation(p_case uuid,p_operation text)
returns uuid language plpgsql security definer set search_path='' as $$
declare c sectalk_private.st_v7_compliance_cases; operation_ticket uuid:=gen_random_uuid();
begin
  if p_operation is null or p_operation not in ('build','download') then
    raise exception 'Invalid export operation' using errcode='22023';
  end if;
  select q.* into c from sectalk_private.st_v7_compliance_cases q where q.id=p_case and q.requester=auth.uid() for update;
  if c.id is null or (public.st_v7_compliance_access(c.workspace_id)<>'admin'
    and not (public.st_v7_compliance_access(c.workspace_id)='owner'
      and exists(select 1 from sectalk_private.st_v8_offboarding_requests r where r.case_id=c.id)))
    or sectalk_private.st_v7_compliance_revalidate(c) is null then
    raise exception 'Approved export unavailable' using errcode='42501';
  end if;
  if c.ticket_until>statement_timestamp() or (p_operation='build' and c.artifact is not null)
    or (p_operation='download' and c.artifact is null) then
    raise exception 'The requested export operation is not currently available' using errcode='PT409';
  end if;
  perform sectalk_private.limit_action('v7_compliance_operation',20);
  update sectalk_private.st_v7_compliance_cases set operation=p_operation,ticket=operation_ticket,
    ticket_session=(auth.jwt()->>'session_id')::uuid,ticket_until=clock_timestamp()+interval '45 seconds' where id=c.id;
  return operation_ticket;
end $$;

create or replace function sectalk_private.st_v7_workspace_payment_mode(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select case when exists(select 1 from sectalk_private.st_v8_offboarding_requests r
    where r.workspace=p_workspace and r.state='read_only')
    then '{"mode":"read_only","reason":"offboarding"}'::jsonb else coalesce((
    select jsonb_build_object('mode',case when g.deadline>statement_timestamp() then 'grace' else 'read_only' end,
      'grace_until',g.deadline)
    from public.st_v2_workspaces w join public.st_v2_subscriptions s on s.user_id=w.owner
    left join sectalk_private.st_v7_nonpayment_cancellations c on (c.subscription,c.account,c.customer)=(s.subscription_id,s.user_id,s.customer_id)
    cross join lateral (
      select case when s.status='past_due' then sectalk_private.st_v7_renewal_grace(s.user_id,s.subscription_id,s.period_end) else
        coalesce((select min(r.grace_until) from sectalk_private.st_v7_renewal_cases r
          where (r.recipient,r.customer,r.subscription)=(s.user_id,s.customer_id,s.subscription_id) and r.stage<>'paid'),
          s.period_end+make_interval(hours=>(select grace_hours from sectalk_private.st_v7_renewal_policy where singleton)),
          s.synced_at+make_interval(hours=>(select grace_hours from sectalk_private.st_v7_renewal_policy where singleton)))
      end deadline
    ) g
    where w.id=p_workspace and s.plan<>'free'
      and (s.status in ('past_due','unpaid') or (s.status='canceled' and c.subscription is not null))
      and g.deadline is not null
  ),'{"mode":"active"}') end
$$;

create or replace function sectalk_private.st_v7_require_workspace_write(p_workspace uuid)
returns void language plpgsql security definer set search_path='' as $$
declare state jsonb;
begin
  if p_workspace is null then return; end if;
  perform 1 from public.st_v2_subscriptions s join public.st_v2_workspaces w on w.owner=s.user_id
    where w.id=p_workspace for share of s;
  state:=sectalk_private.st_v7_workspace_payment_mode(p_workspace);
  if state->>'reason'='offboarding' then
    raise exception 'This workspace is read-only for offboarding.' using errcode='PT423';
  end if;
  if state->>'mode'='read_only' then
    raise exception 'This workspace is read-only until payment is restored.' using errcode='PT423';
  end if;
end $$;

notify pgrst,'reload schema';
commit;
