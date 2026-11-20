begin;

alter table sectalk_private.st_v6_export_objects drop constraint st_v6_export_objects_kind_check;
alter table sectalk_private.st_v6_export_objects drop constraint st_v6_export_objects_scope_check;
alter table sectalk_private.st_v6_export_objects add constraint st_v6_export_objects_kind_check
  check(kind in ('audit','operations','security','compliance','evidence'));
alter table sectalk_private.st_v6_export_objects add constraint st_v6_export_objects_scope_check
  check ((kind in ('audit','compliance','evidence') and scope_id is not null and period is null and media_type='application/json') or
    (kind='operations' and scope_id is not null and period is null and media_type='text/csv') or
    (kind='security' and scope_id is null and period is not null and period in ('daily','weekly') and
      media_type in ('text/csv','application/pdf')));

-- Held evidence can outlive transient exports, so each class has its own per-actor cap.
create or replace function public.st_v6_begin_export_object(p_actor uuid,p_kind text,p_scope uuid,p_period text,
  p_filename text,p_media text,p_bytes integer,p_sha256 text)
returns uuid language plpgsql security definer set search_path='' as $$
declare artifact uuid; item_limit integer:=case when p_kind='evidence' then 100 else 20 end;
begin
  perform pg_advisory_xact_lock(hashtextextended('export_object:'||p_actor::text,0));
  if (select count(*) from sectalk_private.st_v6_export_objects a where a.actor_id=p_actor
    and (a.kind='evidence')=(p_kind='evidence'))>=item_limit then return null; end if;
  insert into sectalk_private.st_v6_export_objects(actor_id,kind,scope_id,period,filename,media_type,bytes,sha256)
    values(p_actor,p_kind,p_scope,p_period,p_filename,p_media,p_bytes,p_sha256) returning id into artifact;
  return artifact;
end $$;

create table sectalk_private.st_v7_evidence_snapshots (
  id uuid primary key,
  workspace_id uuid not null,
  case_id uuid not null,
  report_id uuid not null,
  hold_id uuid not null,
  room_id uuid not null,
  post_id uuid not null,
  author_id uuid not null,
  post_created_at timestamptz not null,
  requester uuid not null,
  approver uuid not null,
  artifact uuid not null unique,
  sha256 text not null check(sha256~'^[0-9a-f]{64}$'),
  bytes integer not null check(bytes between 1 and 1048576),
  captured_at timestamptz not null default clock_timestamp(),
  unique(case_id,report_id,hold_id)
);
create index st_v7_evidence_workspace on sectalk_private.st_v7_evidence_snapshots(workspace_id,captured_at desc,id);
create index st_v7_evidence_hold on sectalk_private.st_v7_evidence_snapshots(hold_id,id);

create table sectalk_private.st_v7_evidence_custody (
  snapshot_id uuid not null,
  sequence integer not null check(sequence>0),
  previous_sha256 text not null check(previous_sha256~'^[0-9a-f]{64}$'),
  sha256 text not null check(sha256~'^[0-9a-f]{64}$'),
  payload text not null,
  primary key(snapshot_id,sequence)
);
create table sectalk_private.st_v7_evidence_operations (
  ticket uuid primary key default gen_random_uuid(),
  operation text not null check(operation in ('capture','download')),
  snapshot_id uuid not null,
  case_id uuid not null,
  report_id uuid not null,
  hold_id uuid not null,
  actor uuid not null,
  session_id uuid not null,
  sha256 text not null,
  reason text,
  expires_at timestamptz not null default clock_timestamp()+interval '45 seconds'
);
create index st_v7_evidence_operations_actor on sectalk_private.st_v7_evidence_operations(actor,expires_at);
create index st_v7_evidence_operations_capture on sectalk_private.st_v7_evidence_operations(case_id,report_id,hold_id,expires_at)
  where operation='capture';
alter table sectalk_private.st_v7_evidence_snapshots enable row level security;
alter table sectalk_private.st_v7_evidence_custody enable row level security;
alter table sectalk_private.st_v7_evidence_operations enable row level security;
revoke all on sectalk_private.st_v7_evidence_snapshots,sectalk_private.st_v7_evidence_custody,
  sectalk_private.st_v7_evidence_operations from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_evidence_hold_matches(
  p_hold uuid,p_workspace uuid,p_room uuid,p_author uuid,p_created timestamptz
)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v6_workspace_holds h where (h.id,h.workspace_id)=(p_hold,p_workspace)
    and h.released_at is null and (h.room_id is null or h.room_id=p_room) and (h.member_id is null or h.member_id=p_author)
    and (h.from_at is null or h.from_at<=p_created) and (h.until_at is null or h.until_at>p_created));
$$;

create function sectalk_private.st_v7_evidence_capture_source(p_case uuid,p_report uuid,p_hold uuid)
returns jsonb language plpgsql stable set search_path='' as $$
declare c sectalk_private.st_v7_compliance_cases; r record; payload text; expected text;
begin
  select q.* into c from sectalk_private.st_v7_compliance_cases q where q.id=p_case;
  if c.id is null or sectalk_private.st_v7_compliance_revalidate(c) is null then return null; end if;
  select s.value->>'sha256' into expected from jsonb_array_elements(c.sources) s
    where s.value->>'kind'='room_report' and s.value->>'id'=p_report::text;
  if expected is null then return null; end if;
  select a.room_id,a.post_id,p.sender,p.created_at into r from sectalk_private.st_v6_room_reports a
    join public.st_v6_room_posts p on (p.room_id,p.id)=(a.room_id,a.post_id)
    where a.id=p_report and a.workspace_id=c.workspace_id;
  if not found or not sectalk_private.st_v7_evidence_hold_matches(p_hold,c.workspace_id,r.room_id,r.sender,r.created_at)
    then return null; end if;
  payload:=sectalk_private.st_v7_compliance_record(c.workspace_id,c.requester,c.reviewer,'room_report',p_report::text)::text;
  if payload is null or encode(sha256(convert_to(payload,'UTF8')),'hex')<>expected then return null; end if;
  return jsonb_build_object('workspace',c.workspace_id,'actor',c.requester,'approver',c.reviewer,'room',r.room_id,
    'post',r.post_id,'author',r.sender,'post_created_at',r.created_at,'payload',payload,'sha256',expected,
    'bytes',octet_length(payload));
end $$;

create function sectalk_private.st_v7_evidence_read_live(s sectalk_private.st_v7_evidence_snapshots)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v7_compliance_cases c
    join sectalk_private.st_v6_room_reports r on (r.id,r.workspace_id,r.room_id,r.post_id)=(s.report_id,s.workspace_id,s.room_id,s.post_id)
    join public.st_v6_rooms room on (room.id,room.workspace_id)=(s.room_id,s.workspace_id)
    where (c.id,c.workspace_id,c.requester,c.reviewer)=(s.case_id,s.workspace_id,s.requester,s.approver)
      and sectalk_private.st_v7_compliance_grant_live(c) and r.share_with_workspace and r.status<>'dismissed'
      and not room.archived and room.classification in ('public','internal','confidential')
      and sectalk_private.st_v6_room_role(s.room_id,s.requester) in ('owner','moderator','member','read_only')
      and sectalk_private.st_v6_room_role(s.room_id,s.approver) in ('owner','moderator','member','read_only')
      and sectalk_private.open_pair(s.requester,s.author_id) and sectalk_private.open_pair(s.approver,s.author_id)
      and sectalk_private.st_v7_evidence_hold_matches(s.hold_id,s.workspace_id,s.room_id,s.author_id,s.post_created_at));
$$;

create function sectalk_private.st_v7_append_evidence_custody(p_snapshot uuid,p_actor uuid,p_event text,p_reason text default null)
returns void language plpgsql set search_path='' set timezone='UTC' as $$
declare s sectalk_private.st_v7_evidence_snapshots; previous text; position integer; event_text text;
begin
  select v.* into strict s from sectalk_private.st_v7_evidence_snapshots v where v.id=p_snapshot for update;
  select e.sequence,e.sha256 into position,previous from sectalk_private.st_v7_evidence_custody e
    where e.snapshot_id=p_snapshot order by e.sequence desc limit 1;
  position:=coalesce(position,0)+1;
  previous:=coalesce(previous,repeat('0',64));
  event_text:=jsonb_build_object('snapshot',p_snapshot,'sequence',position,'actor',p_actor,'event',p_event,
    'case',s.case_id,'report',s.report_id,'hold',s.hold_id,'evidence_sha256',s.sha256,
    'at',clock_timestamp(),'reason',p_reason)::text;
  insert into sectalk_private.st_v7_evidence_custody(snapshot_id,sequence,previous_sha256,sha256,payload)
    values(p_snapshot,position,previous,encode(sha256(convert_to(previous||event_text,'UTF8')),'hex'),event_text);
end $$;

create function sectalk_private.st_v7_immutable_evidence_rows()
returns trigger language plpgsql set search_path='' as $$
begin
  raise exception 'Evidence snapshots and custody records are immutable' using errcode='42501';
end $$;
create trigger st_v7_immutable_evidence_snapshot before update or delete on sectalk_private.st_v7_evidence_snapshots
  for each row execute function sectalk_private.st_v7_immutable_evidence_rows();
create trigger st_v7_immutable_evidence_custody before update or delete on sectalk_private.st_v7_evidence_custody
  for each row execute function sectalk_private.st_v7_immutable_evidence_rows();

create function sectalk_private.st_v7_keep_held_evidence_object()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if old.bucket_id='sectalk-exports' and exists(select 1 from sectalk_private.st_v7_evidence_snapshots s
    join sectalk_private.st_v6_workspace_holds h on h.id=s.hold_id and h.released_at is null
    where s.artifact=case when old.name~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' then old.name::uuid end)
  then raise exception 'This snapshot is protected by an active evidence hold' using errcode='42501'; end if;
  if tg_op='DELETE' then return old; end if;
  return new;
end $$;
create trigger st_v7_keep_held_evidence_object before update or delete on storage.objects
  for each row execute function sectalk_private.st_v7_keep_held_evidence_object();

create function sectalk_private.st_v7_end_evidence_hold()
returns trigger language plpgsql security definer set search_path='' as $$
declare s record; actor_id uuid; lifecycle text; note text;
begin
  if tg_op='UPDATE' then
    if old.released_at is not null or new.released_at is null then return new; end if;
    actor_id:=new.released_by;
    lifecycle:='hold_released';
    note:=new.release_reason;
  else
    if old.released_at is not null then return old; end if;
    actor_id:=auth.uid();
    lifecycle:='hold_removed';
  end if;
  for s in select v.id,v.artifact from sectalk_private.st_v7_evidence_snapshots v where v.hold_id=old.id order by v.id loop
    perform sectalk_private.st_v7_append_evidence_custody(s.id,actor_id,lifecycle,note);
    update sectalk_private.st_v6_export_objects set expires_at=least(expires_at,clock_timestamp()) where id=s.artifact;
  end loop;
  if tg_op='DELETE' then return old; end if;
  return new;
end $$;
create trigger st_v7_end_evidence_hold after update of released_at or delete on sectalk_private.st_v6_workspace_holds
  for each row execute function sectalk_private.st_v7_end_evidence_hold();

create function public.st_v7_evidence_vault(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare viewer text:=public.st_v7_compliance_access(p_workspace); options jsonb:='[]'; snapshots jsonb;
begin
  if viewer not in ('admin','owner') then return jsonb_build_object('access',viewer); end if;
  if viewer='admin' then
    select coalesce(jsonb_agg(to_jsonb(selected)),'[]'::jsonb) into options from (
      select c.id as case_id,c.case_reference,r.id as report_id,h.id as hold_id,h.reason as hold_reason
      from sectalk_private.st_v7_compliance_cases c cross join lateral jsonb_array_elements(c.sources) src
      join sectalk_private.st_v6_room_reports r on src->>'kind'='room_report' and r.id::text=src->>'id'
      join public.st_v6_room_posts p on (p.room_id,p.id)=(r.room_id,r.post_id)
      join sectalk_private.st_v6_workspace_holds h on h.workspace_id=c.workspace_id and h.released_at is null
      where c.workspace_id=p_workspace and c.requester=auth.uid() and r.workspace_id=p_workspace
        and r.share_with_workspace and r.status in ('open','reviewing') and p.removed_at is null
        and sectalk_private.st_v7_compliance_grant_live(c)
        and (h.room_id is null or h.room_id=p.room_id) and (h.member_id is null or h.member_id=p.sender)
        and (h.from_at is null or h.from_at<=p.created_at) and (h.until_at is null or h.until_at>p.created_at)
        and not exists(select 1 from sectalk_private.st_v7_evidence_snapshots s
          where (s.case_id,s.report_id,s.hold_id)=(c.id,r.id,h.id))
      order by c.created_at desc,r.id,h.id limit 100
    ) selected;
  end if;
  select coalesce(jsonb_agg(jsonb_build_object('id',s.id,'case_id',s.case_id,'case_reference',c.case_reference,
    'report_id',s.report_id,'hold_id',s.hold_id,'sha256',s.sha256,'captured_at',s.captured_at,
    'held',h.id is not null and h.released_at is null,
    'can_download',viewer='admin' and sectalk_private.st_v7_evidence_read_live(s),
    'custody',(select coalesce(jsonb_agg(to_jsonb(e) order by e.sequence desc),'[]'::jsonb)
      from (select a.sequence,a.previous_sha256,a.sha256,a.payload from sectalk_private.st_v7_evidence_custody a
        where a.snapshot_id=s.id order by a.sequence desc limit 30) e)) order by s.captured_at desc,s.id),'[]'::jsonb)
  into snapshots from (select v.* from sectalk_private.st_v7_evidence_snapshots v
    where v.workspace_id=p_workspace and (viewer='owner' or v.requester=auth.uid())
    order by v.captured_at desc,v.id limit 50) s
  left join sectalk_private.st_v7_compliance_cases c on c.id=s.case_id
  left join sectalk_private.st_v6_workspace_holds h on h.id=s.hold_id;
  return jsonb_build_object('access',viewer,'options',options,'snapshots',snapshots);
end $$;

create function public.st_v7_begin_evidence_operation(p_operation text,p_case uuid default null,p_report uuid default null,
  p_hold uuid default null,p_snapshot uuid default null,p_reason text default null)
returns uuid language plpgsql security definer set search_path='' as $$
declare plan jsonb; c sectalk_private.st_v7_compliance_cases; s sectalk_private.st_v7_evidence_snapshots;
  actor_id uuid:=auth.uid(); note text:=btrim(p_reason); ticket_id uuid; snapshot_id uuid;
  case_id uuid; report_id uuid; hold_id uuid; expected text;
begin
  if p_operation='capture' then
    select q.* into c from sectalk_private.st_v7_compliance_cases q where q.id=p_case and q.requester=actor_id;
    if c.id is null or public.st_v7_compliance_access(c.workspace_id)<>'admin' then
      raise exception 'Evidence preservation is unavailable' using errcode='42501'; end if;
    if note is null or char_length(note) not between 12 and 300 then
      raise exception 'Provide a preservation reason between 12 and 300 characters' using errcode='22023'; end if;
    plan:=sectalk_private.st_v7_evidence_capture_source(c.id,p_report,p_hold);
    if plan is null then raise exception 'An exact approved report and active matching hold are required' using errcode='42501'; end if;
    perform pg_advisory_xact_lock(hashtextextended('evidence:'||c.id::text||p_report::text||p_hold::text,0));
    if exists(select 1 from sectalk_private.st_v7_evidence_snapshots v where (v.case_id,v.report_id,v.hold_id)=(c.id,p_report,p_hold))
      or exists(select 1 from sectalk_private.st_v7_evidence_operations o where o.operation='capture'
        and (o.case_id,o.report_id,o.hold_id)=(c.id,p_report,p_hold) and o.expires_at>statement_timestamp()) then
      raise exception 'This hold already has a snapshot or active capture for the selected report' using errcode='PT409';
    end if;
    snapshot_id:=gen_random_uuid();
    case_id:=c.id;
    report_id:=p_report;
    hold_id:=p_hold;
    expected:=plan->>'sha256';
  elsif p_operation='download' then
    select v.* into s from sectalk_private.st_v7_evidence_snapshots v where v.id=p_snapshot and v.requester=actor_id;
    if s.id is null or public.st_v7_compliance_access(s.workspace_id)<>'admin'
      or not sectalk_private.st_v7_evidence_read_live(s) then
      raise exception 'Evidence snapshot unavailable' using errcode='42501'; end if;
    snapshot_id:=s.id;
    case_id:=s.case_id;
    report_id:=s.report_id;
    hold_id:=s.hold_id;
    expected:=s.sha256;
  else raise exception 'Choose an evidence operation' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v7_evidence_operation',15);
  delete from sectalk_private.st_v7_evidence_operations o where o.actor=actor_id and o.expires_at<=statement_timestamp();
  insert into sectalk_private.st_v7_evidence_operations(operation,snapshot_id,case_id,report_id,hold_id,actor,session_id,sha256,reason)
    values(p_operation,snapshot_id,case_id,report_id,hold_id,actor_id,(auth.jwt()->>'session_id')::uuid,expected,note)
    returning ticket into ticket_id;
  return ticket_id;
end $$;

create function sectalk_private.st_v7_evidence_operation_live(o sectalk_private.st_v7_evidence_operations)
returns boolean language sql stable set search_path='' as $$
  select coalesce(o.expires_at>statement_timestamp() and exists(
    select 1 from auth.sessions s join auth.mfa_factors f on f.id=s.factor_id and f.user_id=s.user_id
    join auth.mfa_amr_claims a on a.session_id=s.id and a.authentication_method='totp'
    where (s.id,s.user_id)=(o.session_id,o.actor) and s.aal='aal2'
      and f.status='verified' and f.factor_type='totp' and a.updated_at>statement_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()),false);
$$;

create function public.st_v7_read_evidence_operation(p_ticket uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare o sectalk_private.st_v7_evidence_operations; s sectalk_private.st_v7_evidence_snapshots; plan jsonb;
begin
  select x.* into o from sectalk_private.st_v7_evidence_operations x where x.ticket=p_ticket;
  if o.ticket is null or not sectalk_private.st_v7_evidence_operation_live(o) then return null; end if;
  if o.operation='capture' then
    plan:=sectalk_private.st_v7_evidence_capture_source(o.case_id,o.report_id,o.hold_id);
    if plan is null or plan->>'sha256'<>o.sha256 or plan->>'actor'<>o.actor::text then return null; end if;
    return plan||jsonb_build_object('snapshot',o.snapshot_id);
  end if;
  select v.* into s from sectalk_private.st_v7_evidence_snapshots v where v.id=o.snapshot_id and v.requester=o.actor;
  if s.id is null or s.sha256<>o.sha256 or not sectalk_private.st_v7_evidence_read_live(s) then return null; end if;
  return (select jsonb_build_object('snapshot',s.id,'actor',s.requester,'artifact',s.artifact,'sha256',s.sha256,'bytes',s.bytes)
    from sectalk_private.st_v6_export_objects a where a.id=s.artifact and a.kind='evidence'
      and (a.scope_id,a.actor_id,a.sha256,a.bytes)=(s.id,s.requester,s.sha256,s.bytes) and a.ready and a.expires_at>statement_timestamp());
end $$;

create function public.st_v7_finish_evidence_operation(p_ticket uuid,p_artifact uuid)
returns boolean language plpgsql security definer set search_path='' as $$
declare o sectalk_private.st_v7_evidence_operations; plan jsonb;
begin
  select x.* into o from sectalk_private.st_v7_evidence_operations x where x.ticket=p_ticket for update;
  if o.ticket is null then return false; end if;
  if p_artifact is null then delete from sectalk_private.st_v7_evidence_operations where ticket=p_ticket; return false; end if;
  perform 1 from sectalk_private.st_v6_workspace_holds h where h.id=o.hold_id and h.released_at is null for share;
  if not found then return false; end if;
  plan:=public.st_v7_read_evidence_operation(p_ticket);
  if plan is null or (o.operation='download' and plan->>'artifact'<>p_artifact::text) then return false; end if;
  perform 1 from sectalk_private.st_v6_export_objects a where a.id=p_artifact and a.kind='evidence'
    and (a.scope_id,a.actor_id,a.sha256,a.bytes)=(o.snapshot_id,o.actor,o.sha256,(plan->>'bytes')::integer)
    and a.ready and a.expires_at>statement_timestamp() for update;
  if not found then return false; end if;
  if o.operation='capture' then
    insert into sectalk_private.st_v7_evidence_snapshots(id,workspace_id,case_id,report_id,hold_id,room_id,post_id,
      author_id,post_created_at,requester,approver,artifact,sha256,bytes)
    values(o.snapshot_id,(plan->>'workspace')::uuid,o.case_id,o.report_id,o.hold_id,(plan->>'room')::uuid,(plan->>'post')::uuid,
      (plan->>'author')::uuid,(plan->>'post_created_at')::timestamptz,o.actor,(plan->>'approver')::uuid,
      p_artifact,o.sha256,(plan->>'bytes')::integer);
    update sectalk_private.st_v6_export_objects set expires_at='infinity' where id=p_artifact;
    perform sectalk_private.st_v7_append_evidence_custody(o.snapshot_id,o.actor,'captured',o.reason);
  else
    perform sectalk_private.st_v7_append_evidence_custody(o.snapshot_id,o.actor,'downloaded');
  end if;
  delete from sectalk_private.st_v7_evidence_operations where ticket=p_ticket;
  return true;
end $$;

revoke all on function public.st_v7_evidence_vault(uuid),public.st_v7_begin_evidence_operation(text,uuid,uuid,uuid,uuid,text),
  public.st_v7_read_evidence_operation(uuid),public.st_v7_finish_evidence_operation(uuid,uuid),
  sectalk_private.st_v7_evidence_hold_matches(uuid,uuid,uuid,uuid,timestamptz),
  sectalk_private.st_v7_evidence_capture_source(uuid,uuid,uuid),
  sectalk_private.st_v7_evidence_read_live(sectalk_private.st_v7_evidence_snapshots),
  sectalk_private.st_v7_append_evidence_custody(uuid,uuid,text,text),sectalk_private.st_v7_immutable_evidence_rows(),
  sectalk_private.st_v7_keep_held_evidence_object(),sectalk_private.st_v7_end_evidence_hold(),
  sectalk_private.st_v7_evidence_operation_live(sectalk_private.st_v7_evidence_operations)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_evidence_vault(uuid),public.st_v7_begin_evidence_operation(text,uuid,uuid,uuid,uuid,text) to authenticated;
grant execute on function public.st_v7_read_evidence_operation(uuid),public.st_v7_finish_evidence_operation(uuid,uuid) to service_role;

notify pgrst,'reload schema';
commit;
