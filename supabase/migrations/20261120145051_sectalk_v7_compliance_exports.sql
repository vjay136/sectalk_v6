begin;

alter table sectalk_private.st_v6_export_objects drop constraint st_v6_export_objects_kind_check;
alter table sectalk_private.st_v6_export_objects drop constraint st_v6_export_objects_check;
alter table sectalk_private.st_v6_export_objects add constraint st_v6_export_objects_kind_check
  check(kind in ('audit','operations','security','compliance'));
alter table sectalk_private.st_v6_export_objects add constraint st_v6_export_objects_scope_check
  check ((kind in ('audit','compliance') and scope_id is not null and period is null and media_type='application/json') or
    (kind='operations' and scope_id is not null and period is null and media_type='text/csv') or
    (kind='security' and scope_id is null and period is not null and period in ('daily','weekly') and
      media_type in ('text/csv','application/pdf')));

create table sectalk_private.st_v7_compliance_cases (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  requester uuid not null,
  reviewer uuid,
  case_reference text not null check(char_length(case_reference) between 3 and 80),
  reason text not null check(char_length(reason) between 15 and 500),
  sources jsonb not null check(jsonb_typeof(sources)='array' and jsonb_array_length(sources) between 1 and 25),
  state text not null default 'pending' check(state in ('pending','approved','denied','revoked','withdrawn')),
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null default (clock_timestamp()+interval '24 hours'),
  approved_at timestamptz,
  manifest_sha256 text,
  bundle_sha256 text,
  bundle_bytes integer,
  operation text check(operation in ('build','download')),
  ticket uuid unique,
  ticket_session uuid,
  ticket_until timestamptz,
  artifact uuid unique,
  check(reviewer is distinct from requester)
);
create index st_v7_compliance_cases_workspace on sectalk_private.st_v7_compliance_cases(workspace_id,created_at desc,id);
create index st_v7_compliance_cases_requester on sectalk_private.st_v7_compliance_cases(workspace_id,requester,created_at desc);
create table sectalk_private.st_v7_compliance_audit (
  id bigint generated always as identity primary key,
  case_id uuid not null,
  workspace_id uuid not null,
  actor uuid not null,
  action text not null check(action in ('requested','approved','denied','revoked','withdrawn','built','downloaded')),
  reason text,
  occurred_at timestamptz not null default clock_timestamp()
);
create index st_v7_compliance_audit_history on sectalk_private.st_v7_compliance_audit(case_id,id desc);
alter table sectalk_private.st_v7_compliance_cases enable row level security;
alter table sectalk_private.st_v7_compliance_audit enable row level security;
revoke all on sectalk_private.st_v7_compliance_cases,sectalk_private.st_v7_compliance_audit
  from public,anon,authenticated,service_role;

create function public.st_v7_compliance_access(p_workspace uuid)
returns text language sql stable security definer set search_path='' as $$
  select case when r.kind not in ('owner','admin') or r.kind is null or not public.st_v7_current_session_valid()
       or not sectalk_private.st_v2_active(auth.uid()) then 'none'
    when not sectalk_private.st_v7_admin_fresh() then 'mfa' else r.kind end
  from (select sectalk_private.st_v2_role(p_workspace,auth.uid()) kind) r;
$$;

-- Read only the customer-shared evidence already visible to every named reviewer.
create function sectalk_private.st_v7_compliance_report_sources(p_workspace uuid,p_actor uuid,p_reviewer uuid,p_report uuid)
returns table(id uuid,category text,room_id uuid,post_id uuid,author_id uuid,revision timestamptz,body text,reported_at timestamptz)
language sql stable set search_path='' as $$
  select r.id,r.category,room.id,p.id,p.sender,coalesce(p.edited_at,p.created_at),p.body,r.created_at
  from sectalk_private.st_v6_room_reports r
  join public.st_v6_rooms room on (room.id,room.workspace_id)=(r.room_id,r.workspace_id)
  join public.st_v6_room_posts p on (p.room_id,p.id)=(r.room_id,r.post_id)
  where r.workspace_id=p_workspace and (p_report is null or r.id=p_report)
    and r.share_with_workspace and r.status in ('open','reviewing') and not room.archived
    and room.classification in ('public','internal','confidential') and p.kind='message'
    and p.removed_at is null and not p.forwarded and p.body is not null
    and sectalk_private.st_v6_room_role(room.id,p_actor) in ('owner','moderator','member','read_only')
    and sectalk_private.open_pair(p_actor,p.sender)
    and (p_reviewer is null or (sectalk_private.st_v6_room_role(room.id,p_reviewer) in ('owner','moderator','member','read_only')
      and sectalk_private.open_pair(p_reviewer,p.sender)))
  order by r.created_at desc,r.id limit 50;
$$;

create function public.st_v7_compliance_sources(p_workspace uuid)
returns table(kind text,id text,label text,occurred_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
begin
  if public.st_v7_compliance_access(p_workspace)<>'admin' then
    raise exception 'Fresh workspace administrator verification required' using errcode='42501';
  end if;
  return query select 'audit'::text,a.id::text,a.event,a.created_at
    from public.st_v2_workspace_audit a where a.workspace_id=p_workspace
    order by a.created_at desc,a.id desc limit 50;
  return query select 'room_report'::text,r.id::text,r.category,r.reported_at
    from sectalk_private.st_v7_compliance_report_sources(p_workspace,auth.uid(),null,null) r;
end $$;

create function sectalk_private.st_v7_compliance_record(p_workspace uuid,p_actor uuid,p_reviewer uuid,p_kind text,p_id text)
returns jsonb language plpgsql stable set search_path='' set timezone='UTC' as $$
begin
  if p_kind='audit' and p_id~'^[1-9][0-9]{0,17}$' then
    return (select jsonb_build_object('id',a.id::text,'event',a.event,'actor',a.actor,'target',a.target,'created_at',a.created_at)
      from public.st_v2_workspace_audit a where a.workspace_id=p_workspace and a.id=p_id::bigint);
  elsif p_kind='room_report' and p_id~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' then
    return (select jsonb_build_object('id',r.id,'category',r.category,'room',r.room_id,'post',r.post_id,'author',r.author_id,
      'revision',r.revision,'body',r.body)
      from sectalk_private.st_v7_compliance_report_sources(p_workspace,p_actor,p_reviewer,p_id::uuid) r);
  end if;
  return null;
end $$;

create function sectalk_private.st_v7_compliance_render(c sectalk_private.st_v7_compliance_cases)
returns jsonb language plpgsql stable set search_path='' set timezone='UTC' as $$
declare item jsonb; raw jsonb; manifest jsonb; manifest_text text; bundle text; payload text; fingerprint text;
  manifest_hash text; records jsonb:='[]'; entries jsonb:='[]';
begin
  for item in select s.value from jsonb_array_elements(c.sources) s order by s.value->>'kind',s.value->>'id' loop
    raw:=sectalk_private.st_v7_compliance_record(c.workspace_id,c.requester,c.reviewer,item->>'kind',item->>'id');
    if raw is null then return null; end if;
    payload:=raw::text;
    fingerprint:=encode(sha256(convert_to(payload,'UTF8')),'hex');
    if fingerprint is distinct from item->>'sha256' then return null; end if;
    item:=jsonb_build_object('kind',item->>'kind','id',item->>'id','sha256',fingerprint);
    entries:=entries||jsonb_build_array(item);
    records:=records||jsonb_build_array(item||jsonb_build_object('json',payload));
  end loop;
  manifest:=jsonb_build_object('format','sectalk-compliance-v1','case',c.id,'workspace',c.workspace_id,
    'reference',c.case_reference,'requested_by',c.requester,'approved_by',c.reviewer,'approved_at',c.approved_at,'entries',entries);
  manifest_text:=manifest::text;
  manifest_hash:=encode(sha256(convert_to(manifest_text,'UTF8')),'hex');
  bundle:=jsonb_build_object('manifest',manifest_text,'manifest_sha256',manifest_hash,'records',records)::text;
  if octet_length(bundle)>1048576 then return null; end if;
  return jsonb_build_object('bundle',bundle,'manifest_sha256',manifest_hash,
    'sha256',encode(sha256(convert_to(bundle,'UTF8')),'hex'),'bytes',octet_length(bundle));
end $$;

create function sectalk_private.st_v7_compliance_grant_live(c sectalk_private.st_v7_compliance_cases)
returns boolean language sql stable set search_path='' as $$
  select coalesce(c.state='approved' and c.expires_at>statement_timestamp() and c.reviewer<>c.requester
    and sectalk_private.st_v2_role(c.workspace_id,c.requester)='admin'
    and sectalk_private.st_v2_role(c.workspace_id,c.reviewer)='owner'
    and sectalk_private.st_v2_active(c.requester) and sectalk_private.st_v2_active(c.reviewer),false);
$$;

create function sectalk_private.st_v7_compliance_revalidate(c sectalk_private.st_v7_compliance_cases)
returns jsonb language plpgsql stable set search_path='' as $$
declare snapshot jsonb;
begin
  if not sectalk_private.st_v7_compliance_grant_live(c) then return null; end if;
  snapshot:=sectalk_private.st_v7_compliance_render(c);
  if snapshot is null or snapshot->>'sha256' is distinct from c.bundle_sha256
    or snapshot->>'manifest_sha256' is distinct from c.manifest_sha256 then return null; end if;
  return snapshot;
end $$;

create function public.st_v7_request_compliance_export(p_workspace uuid,p_reference text,p_reason text,p_sources jsonb)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); request_id uuid; item jsonb; record jsonb; selections jsonb:='[]';
  reference text:=btrim(p_reference); note text:=btrim(p_reason);
begin
  if public.st_v7_compliance_access(p_workspace)<>'admin' then
    raise exception 'Fresh workspace administrator verification required' using errcode='42501';
  end if;
  if reference is null or char_length(reference) not between 3 and 80
    or note is null or char_length(note) not between 15 and 500 or jsonb_typeof(p_sources) is distinct from 'array' then
    raise exception 'Enter a case reference, purpose and exact records' using errcode='22023';
  end if;
  if jsonb_array_length(p_sources) not between 1 and 25 then
    raise exception 'Select between 1 and 25 records' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v7_compliance_requests',8);
  for item in select s.value from jsonb_array_elements(p_sources) s loop
    if jsonb_typeof(item)<>'object' or item->>'kind' is null or item->>'id' is null
      or exists(select 1 from jsonb_array_elements(selections) e where e->>'id'=item->>'id' and e->>'kind'=item->>'kind') then
      raise exception 'Select unique records from this workspace' using errcode='22023';
    end if;
    record:=sectalk_private.st_v7_compliance_record(p_workspace,actor_id,null,item->>'kind',item->>'id');
    if record is null then raise exception 'A selected record is outside the permitted scope' using errcode='42501'; end if;
    selections:=selections||jsonb_build_array(jsonb_build_object('kind',item->>'kind','id',item->>'id',
      'label',coalesce(record->>'event',record->>'category'),
      'sha256',encode(sha256(convert_to(record::text,'UTF8')),'hex')));
  end loop;
  perform pg_advisory_xact_lock(hashtextextended('compliance-request:'||p_workspace::text||actor_id::text,0));
  if (select count(*) from sectalk_private.st_v7_compliance_cases c where c.workspace_id=p_workspace and c.requester=actor_id
      and c.state in ('pending','approved') and c.expires_at>statement_timestamp())>=15 then
    raise exception 'Resolve an existing export case before requesting another' using errcode='PT409';
  end if;
  insert into sectalk_private.st_v7_compliance_cases(workspace_id,requester,case_reference,reason,sources)
    values(p_workspace,actor_id,reference,note,selections) returning id into request_id;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action,reason)
    values(request_id,p_workspace,actor_id,'requested',note);
  return request_id;
end $$;

create function public.st_v7_compliance_cases(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare viewer text:=public.st_v7_compliance_access(p_workspace);
begin
  if viewer not in ('owner','admin') then raise exception 'Fresh workspace verification required' using errcode='42501'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id',c.id,'reference',c.case_reference,'reason',c.reason,
    'requester',c.requester,'reviewer',c.reviewer,
    'sources',(select jsonb_agg(s.value-'sha256' order by s.position) from jsonb_array_elements(c.sources) with ordinality s(value,position)),
    'created_at',c.created_at,'expires_at',c.expires_at,
    'state',case when c.state in ('pending','approved') and c.expires_at<=statement_timestamp() then 'expired' else c.state end,
    'manifest_sha256',c.manifest_sha256,'bundle_sha256',c.bundle_sha256,'has_artifact',c.artifact is not null,
    'history',(select coalesce(jsonb_agg(jsonb_build_object('action',h.action,'reason',h.reason,'occurred_at',h.occurred_at)
      order by h.id desc),'[]'::jsonb)
      from (select a.* from sectalk_private.st_v7_compliance_audit a where a.case_id=c.id order by a.id desc limit 20) h))
    order by c.created_at desc,c.id)
    from (select q.* from sectalk_private.st_v7_compliance_cases q where q.workspace_id=p_workspace
        and (viewer='owner' or q.requester=auth.uid()) order by q.created_at desc,q.id limit 50) c),'[]'::jsonb);
end $$;

create function public.st_v7_review_compliance_export(p_case uuid,p_action text,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare c sectalk_private.st_v7_compliance_cases; viewer text; snapshot jsonb;
  actor_id uuid:=auth.uid(); note text:=btrim(p_reason);
begin
  select q.* into c from sectalk_private.st_v7_compliance_cases q where q.id=p_case for update;
  viewer:=public.st_v7_compliance_access(c.workspace_id);
  if c.id is null or (p_action='withdrawn' and (viewer<>'admin' or c.requester<>actor_id))
    or (p_action is distinct from 'withdrawn' and (viewer<>'owner' or c.requester=actor_id)) then
    raise exception 'Export review is unavailable' using errcode='42501';
  end if;
  if p_action is null or p_action not in ('approved','denied','revoked','withdrawn')
    or note is null or char_length(note) not between 15 and 500 then
    raise exception 'Choose a case decision and enter a reason between 15 and 500 characters' using errcode='22023';
  end if;
  if (p_action in ('approved','denied','withdrawn') and (c.state<>'pending' or c.expires_at<=statement_timestamp()))
    or (p_action='revoked' and c.state<>'approved') then
    raise exception 'This case is no longer in the required state' using errcode='PT409';
  end if;
  if p_action='approved' then
    c.reviewer:=actor_id;
    c.approved_at:=clock_timestamp();
    c.expires_at:=c.approved_at+interval '24 hours';
    c.state:='approved';
    if sectalk_private.st_v7_compliance_grant_live(c) then snapshot:=sectalk_private.st_v7_compliance_render(c); end if;
    if snapshot is null then
      raise exception 'An exact requested revision is unavailable or outside the owner’s scope' using errcode='42501';
    end if;
  elsif p_action='denied' then c.reviewer:=actor_id;
  end if;
  update sectalk_private.st_v7_compliance_cases set state=p_action,reviewer=c.reviewer,approved_at=c.approved_at,expires_at=c.expires_at,
    manifest_sha256=coalesce(snapshot->>'manifest_sha256',c.manifest_sha256),
    bundle_sha256=coalesce(snapshot->>'sha256',c.bundle_sha256),bundle_bytes=coalesce((snapshot->>'bytes')::integer,c.bundle_bytes),
    operation=null,ticket=null,ticket_session=null,ticket_until=null where id=c.id;
  if p_action='revoked' and c.artifact is not null then
    update sectalk_private.st_v6_export_objects set expires_at=least(expires_at,clock_timestamp())
      where id=c.artifact and kind='compliance' and scope_id=c.id;
  end if;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action,reason)
    values(c.id,c.workspace_id,actor_id,p_action,note);
end $$;

create function public.st_v7_begin_compliance_operation(p_case uuid,p_operation text)
returns uuid language plpgsql security definer set search_path='' as $$
declare c sectalk_private.st_v7_compliance_cases; operation_ticket uuid:=gen_random_uuid();
begin
  if p_operation is null or p_operation not in ('build','download') then
    raise exception 'Invalid export operation' using errcode='22023';
  end if;
  select q.* into c from sectalk_private.st_v7_compliance_cases q where q.id=p_case and q.requester=auth.uid() for update;
  if c.id is null or public.st_v7_compliance_access(c.workspace_id)<>'admin'
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

create function sectalk_private.st_v7_compliance_operation_live(c sectalk_private.st_v7_compliance_cases)
returns boolean language sql stable set search_path='' as $$
  select coalesce(c.ticket is not null and c.ticket_until>statement_timestamp() and c.operation in ('build','download')
    and exists(select 1 from auth.sessions s join auth.mfa_factors f on f.id=s.factor_id and f.user_id=s.user_id
      join auth.mfa_amr_claims a on a.session_id=s.id and a.authentication_method='totp'
      where s.id=c.ticket_session and s.user_id=c.requester and s.aal='aal2'
      and f.status='verified' and f.factor_type='totp' and a.updated_at>statement_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()),false);
$$;

create function public.st_v7_read_compliance_operation(p_ticket uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare c sectalk_private.st_v7_compliance_cases; snapshot jsonb;
begin
  select q.* into c from sectalk_private.st_v7_compliance_cases q where q.ticket=p_ticket;
  if c.id is null or not sectalk_private.st_v7_compliance_operation_live(c) then return null; end if;
  snapshot:=sectalk_private.st_v7_compliance_revalidate(c);
  if snapshot is null then return null; end if;
  if c.operation='build' then
    return jsonb_build_object('case',c.id,'actor',c.requester,'bundle',snapshot->>'bundle','sha256',c.bundle_sha256,'bytes',c.bundle_bytes);
  end if;
  return (select jsonb_build_object('case',c.id,'actor',c.requester,'artifact',a.id,'sha256',a.sha256,'bytes',a.bytes)
    from sectalk_private.st_v6_export_objects a where a.id=c.artifact and a.kind='compliance' and a.scope_id=c.id
      and a.actor_id=c.requester and a.ready and a.expires_at>statement_timestamp()
      and a.sha256=c.bundle_sha256 and a.bytes=c.bundle_bytes);
end $$;

create function public.st_v7_finish_compliance_operation(p_ticket uuid,p_artifact uuid)
returns boolean language plpgsql security definer set search_path='' as $$
declare c sectalk_private.st_v7_compliance_cases;
begin
  select q.* into c from sectalk_private.st_v7_compliance_cases q where q.ticket=p_ticket for update;
  if c.id is null then return false; end if;
  if p_artifact is null then
    update sectalk_private.st_v7_compliance_cases set operation=null,ticket=null,ticket_session=null,ticket_until=null where id=c.id;
    return false;
  end if;
  if not sectalk_private.st_v7_compliance_operation_live(c) or sectalk_private.st_v7_compliance_revalidate(c) is null
    or (c.operation='build' and c.artifact is not null)
    or (c.operation='download' and c.artifact is distinct from p_artifact) then return false; end if;
  perform 1 from sectalk_private.st_v6_export_objects a where a.id=p_artifact and a.kind='compliance' and a.scope_id=c.id
    and a.actor_id=c.requester and a.ready and a.expires_at>statement_timestamp() and a.sha256=c.bundle_sha256 and a.bytes=c.bundle_bytes
    for update;
  if not found then return false; end if;
  update sectalk_private.st_v7_compliance_cases set artifact=p_artifact,operation=null,ticket=null,ticket_session=null,ticket_until=null
    where id=c.id;
  update sectalk_private.st_v6_export_objects set expires_at=least(expires_at,c.expires_at) where id=p_artifact;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action)
    values(c.id,c.workspace_id,c.requester,case when c.operation='build' then 'built' else 'downloaded' end);
  return true;
end $$;

revoke all on function public.st_v7_compliance_access(uuid),public.st_v7_compliance_sources(uuid),
  public.st_v7_request_compliance_export(uuid,text,text,jsonb),public.st_v7_compliance_cases(uuid),
  public.st_v7_review_compliance_export(uuid,text,text),public.st_v7_begin_compliance_operation(uuid,text),
  public.st_v7_read_compliance_operation(uuid),public.st_v7_finish_compliance_operation(uuid,uuid),
  sectalk_private.st_v7_compliance_report_sources(uuid,uuid,uuid,uuid),
  sectalk_private.st_v7_compliance_record(uuid,uuid,uuid,text,text),
  sectalk_private.st_v7_compliance_render(sectalk_private.st_v7_compliance_cases),
  sectalk_private.st_v7_compliance_grant_live(sectalk_private.st_v7_compliance_cases),
  sectalk_private.st_v7_compliance_revalidate(sectalk_private.st_v7_compliance_cases),
  sectalk_private.st_v7_compliance_operation_live(sectalk_private.st_v7_compliance_cases)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_compliance_access(uuid),public.st_v7_compliance_sources(uuid),
  public.st_v7_request_compliance_export(uuid,text,text,jsonb),public.st_v7_compliance_cases(uuid),
  public.st_v7_review_compliance_export(uuid,text,text),public.st_v7_begin_compliance_operation(uuid,text) to authenticated;
grant execute on function public.st_v7_read_compliance_operation(uuid),public.st_v7_finish_compliance_operation(uuid,uuid)
  to service_role;

notify pgrst,'reload schema';
commit;
