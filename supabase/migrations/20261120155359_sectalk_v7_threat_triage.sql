begin;

create table sectalk_private.st_v7_threat_reviewers (
  user_id uuid not null references auth.users on delete cascade,
  signal_type text not null check(signal_type in ('detection','attachment_inspection','malware')),
  primary key(user_id,signal_type)
);
create table sectalk_private.st_v7_threat_items (
  id uuid primary key default gen_random_uuid(),
  signal_type text not null check(signal_type in ('detection','attachment_inspection','malware')),
  source_key text not null,
  severity text not null check(severity in ('low','medium','high')),
  confidence text not null check(confidence in ('supported','heuristic','confirmed')),
  details jsonb not null check(jsonb_typeof(details)='object' and octet_length(details::text)<=2048),
  detected_at timestamptz not null,
  state text not null default 'open' check(state in ('open','reviewing','confirmed','dismissed')),
  revision integer not null default 1 check(revision>0),
  unique(signal_type,source_key)
);
create index st_v7_threat_items_feed on sectalk_private.st_v7_threat_items(signal_type,detected_at desc,id desc);
create index st_v7_threat_items_state on sectalk_private.st_v7_threat_items(signal_type,state,detected_at desc,id desc);
create index st_v7_threat_items_expiry on sectalk_private.st_v7_threat_items(detected_at);
create table sectalk_private.st_v7_threat_triage_audit (
  id bigint generated always as identity primary key,
  item_id uuid not null,
  signal_type text not null,
  batch_id uuid,
  actor uuid,
  action text not null check(action in ('received','reviewing','confirmed','dismissed','reopened')),
  previous_state text,
  state text not null,
  revision integer not null,
  reason text,
  occurred_at timestamptz not null default clock_timestamp(),
  unique(item_id,revision)
);
create index st_v7_threat_audit_item on sectalk_private.st_v7_threat_triage_audit(item_id,id desc);
alter table sectalk_private.st_v7_threat_reviewers enable row level security;
alter table sectalk_private.st_v7_threat_items enable row level security;
alter table sectalk_private.st_v7_threat_triage_audit enable row level security;
revoke all on sectalk_private.st_v7_threat_reviewers,sectalk_private.st_v7_threat_items,
  sectalk_private.st_v7_threat_triage_audit from public,anon,authenticated,service_role;

create function public.st_v7_threat_triage_access()
returns jsonb language sql stable security definer set search_path='' as $$
  select case when r.scopes is null or not public.st_v7_current_session_valid()
    or not sectalk_private.st_v2_active(auth.uid()) then jsonb_build_object('status','none')
    when not sectalk_private.st_v7_admin_fresh() then jsonb_build_object('status','mfa')
    else jsonb_build_object('status','verified','scopes',r.scopes) end
  from (select jsonb_agg(s.signal_type order by s.signal_type) scopes
    from sectalk_private.st_v7_threat_reviewers s where s.user_id=auth.uid()) r;
$$;

create function sectalk_private.st_v7_enqueue_threat(p_type text,p_key text,p_severity text,p_confidence text,
  p_details jsonb,p_detected_at timestamptz)
returns void language plpgsql set search_path='' as $$
declare item_key uuid;
begin
  insert into sectalk_private.st_v7_threat_items(signal_type,source_key,severity,confidence,details,detected_at)
    values(p_type,p_key,p_severity,p_confidence,p_details,p_detected_at)
    on conflict(signal_type,source_key) do nothing returning id into item_key;
  if item_key is not null then
    insert into sectalk_private.st_v7_threat_triage_audit(item_id,signal_type,action,state,revision)
      values(item_key,p_type,'received','open',1);
  end if;
end $$;

create function sectalk_private.st_v7_enqueue_detection_threat(p_match sectalk_private.st_v7_detection_matches)
returns void language plpgsql set search_path='' as $$
declare v sectalk_private.st_v7_detection_versions; priority text;
begin
  if p_match.mode is distinct from 'enabled' then return; end if;
  select d.* into v from sectalk_private.st_v7_detection_versions d
    where (d.rule_id,d.version)=(p_match.rule_id,p_match.version);
  if v.rule_id is null then return; end if;
  priority:=case when v.source='login_anomalies' or v.metric in ('server_errors','unavailable') and p_match.observed>=v.threshold*2
    then 'high' when v.metric='requests' then 'low' else 'medium' end;
  perform sectalk_private.st_v7_enqueue_threat('detection',p_match.id::text,priority,'supported',
    jsonb_build_object('source',v.source,'scope',v.scope,'metric',v.metric,'version',v.version,'threshold',v.threshold,
      'observed',p_match.observed,'window',p_match.bucket),p_match.occurred_at);
end $$;

create function sectalk_private.st_v7_enqueue_attachment_threat(p_scan sectalk_private.st_v6_attachment_scans)
returns void language plpgsql set search_path='' as $$
begin
  if p_scan.state='malware' then
    perform sectalk_private.st_v7_enqueue_threat('malware',p_scan.file_id::text,'high','confirmed',
      jsonb_build_object('signal','scanner_verdict'),p_scan.scanned_at);
  elsif p_scan.state in ('quarantined','awaiting_release')
    and p_scan.inspection_reason in ('document_macro_marker','script_marker','embedded_document_marker',
      'embedded_link_marker','suspicious_link_format') then
    perform sectalk_private.st_v7_enqueue_threat('attachment_inspection',p_scan.file_id::text,
      case when p_scan.inspection_reason in ('embedded_link_marker','suspicious_link_format') then 'low' else 'medium' end,
      'heuristic',jsonb_build_object('signal',p_scan.inspection_reason),p_scan.scanned_at);
  end if;
end $$;

create function sectalk_private.st_v7_capture_detection_threat()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_v7_enqueue_detection_threat(new);
  return new;
end $$;
create trigger st_v7_capture_detection_threat after insert on sectalk_private.st_v7_detection_matches
  for each row when (new.mode='enabled') execute function sectalk_private.st_v7_capture_detection_threat();

create function sectalk_private.st_v7_capture_attachment_threat()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_v7_enqueue_attachment_threat(new);
  return new;
end $$;
create trigger st_v7_capture_attachment_threat after insert or update of state,inspection_reason
  on sectalk_private.st_v6_attachment_scans for each row execute function sectalk_private.st_v7_capture_attachment_threat();

do $$
declare d sectalk_private.st_v7_detection_matches; s sectalk_private.st_v6_attachment_scans;
begin
  for d in select m.* from sectalk_private.st_v7_detection_matches m
    where m.mode='enabled' and m.occurred_at>=now()-interval '7 days' order by m.occurred_at desc,m.id limit 500 loop
    perform sectalk_private.st_v7_enqueue_detection_threat(d);
  end loop;
  for s in select a.* from sectalk_private.st_v6_attachment_scans a
    where a.scanned_at>=now()-interval '24 hours' and
      (a.state='malware' or a.state in ('quarantined','awaiting_release') and a.inspection_reason is not null)
      order by a.scanned_at desc,a.file_id limit 500 loop
    perform sectalk_private.st_v7_enqueue_attachment_threat(s);
  end loop;
end $$;

select cron.schedule('sectalk-v7-prune-threat-queue','46 3 * * *',
  $job$delete from sectalk_private.st_v7_threat_items where detected_at<now()-interval '30 days';$job$);

create function public.st_v7_threat_queue(p_state text default 'open',p_type text default 'all',
  p_severity text default 'all',p_confidence text default 'all',
  p_before timestamptz default null,p_before_id uuid default null)
returns table(id uuid,signal_type text,severity text,confidence text,details jsonb,detected_at timestamptz,state text,revision integer)
language plpgsql stable security definer set search_path='' as $$
begin
  if public.st_v7_threat_triage_access()->>'status'<>'verified' then
    raise exception 'Fresh threat reviewer verification required' using errcode='42501'; end if;
  if p_state is null or p_state not in ('all','open','reviewing','confirmed','dismissed')
    or p_type is null or p_type not in ('all','detection','attachment_inspection','malware')
    or p_severity is null or p_severity not in ('all','low','medium','high')
    or p_confidence is null or p_confidence not in ('all','supported','heuristic','confirmed')
    or (p_before is null)<>(p_before_id is null) then
    raise exception 'Choose supported threat queue filters' using errcode='22023'; end if;
  return query select q.id,q.signal_type,q.severity,q.confidence,q.details,q.detected_at,q.state,q.revision
    from sectalk_private.st_v7_threat_items q join sectalk_private.st_v7_threat_reviewers r
      on r.signal_type=q.signal_type and r.user_id=auth.uid()
    where (p_state='all' or q.state=p_state) and (p_type='all' or q.signal_type=p_type)
      and (p_severity='all' or q.severity=p_severity) and (p_confidence='all' or q.confidence=p_confidence)
      and q.detected_at>=statement_timestamp()-interval '30 days'
      and (p_before is null or (q.detected_at,q.id)<(p_before,p_before_id))
    order by q.detected_at desc,q.id desc limit 41;
end $$;

create function public.st_v7_threat_triage_history(p_item uuid)
returns table(id bigint,action text,state text,revision integer,actor uuid,reason text,occurred_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
begin
  if public.st_v7_threat_triage_access()->>'status'<>'verified' then
    raise exception 'Fresh threat reviewer verification required' using errcode='42501'; end if;
  return query select a.id,a.action,a.state,a.revision,a.actor,a.reason,a.occurred_at
    from sectalk_private.st_v7_threat_triage_audit a join sectalk_private.st_v7_threat_reviewers r
      on r.signal_type=a.signal_type and r.user_id=auth.uid()
    where a.item_id=p_item order by a.id desc limit 30;
end $$;

create function public.st_v7_apply_threat_triage(p_items jsonb,p_action text,p_reason text)
returns integer language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); note text:=btrim(p_reason); event_batch uuid:=gen_random_uuid();
  processed integer:=0; entry record; next_state text;
begin
  if public.st_v7_threat_triage_access()->>'status'<>'verified' then
    raise exception 'Fresh threat reviewer verification required' using errcode='42501'; end if;
  if jsonb_typeof(p_items) is distinct from 'array' or octet_length(p_items::text)>4096
    or p_action is null or p_action not in ('reviewing','confirmed','dismissed','reopened')
    or note is null or char_length(note) not between 10 and 500 then
    raise exception 'Choose a bulk decision and enter a reason between 10 and 500 characters' using errcode='22023'; end if;
  if jsonb_array_length(p_items) not between 1 and 25 or exists(
    select 1 from jsonb_array_elements(p_items) e where jsonb_typeof(e)<>'object'
      or (e->>'id'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$') is not true
      or (e->>'revision'~'^[1-9][0-9]{0,8}$') is not true)
    or (select count(distinct e->>'id') from jsonb_array_elements(p_items) e)<>jsonb_array_length(p_items) then
    raise exception 'Select between 1 and 25 distinct queue items and their revisions' using errcode='22023'; end if;
  perform 1 from sectalk_private.st_v7_threat_reviewers r where r.user_id=actor_id for share;
  if not found then raise exception 'Threat reviewer access changed' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v7_threat_triage',12);
  next_state:=case when p_action='reopened' then 'open' else p_action end;
  for entry in
    select q.*,s.revision as expected_revision
    from jsonb_to_recordset(p_items) as s(id uuid,revision integer)
    join sectalk_private.st_v7_threat_items q on q.id=s.id
    join sectalk_private.st_v7_threat_reviewers r on r.signal_type=q.signal_type and r.user_id=actor_id
    where q.detected_at>=statement_timestamp()-interval '30 days' order by q.id for update of q
  loop
    if entry.revision<>entry.expected_revision
      or not ((p_action='reviewing' and entry.state='open')
        or (p_action in ('confirmed','dismissed') and entry.state in ('open','reviewing'))
        or (p_action='reopened' and entry.state in ('confirmed','dismissed'))) then
      raise exception 'A selected item changed or cannot receive this decision. Refresh the queue.' using errcode='PT409';
    end if;
    update sectalk_private.st_v7_threat_items q set state=next_state,revision=entry.revision+1 where q.id=entry.id;
    insert into sectalk_private.st_v7_threat_triage_audit(item_id,signal_type,batch_id,actor,action,previous_state,state,revision,reason)
      values(entry.id,entry.signal_type,event_batch,actor_id,p_action,entry.state,next_state,entry.revision+1,note);
    processed:=processed+1;
  end loop;
  if processed<>jsonb_array_length(p_items) then raise exception 'One or more selected items are outside your review scope'
    using errcode='42501'; end if;
  return processed;
end $$;

create function sectalk_private.st_v7_immutable_threat_audit()
returns trigger language plpgsql set search_path='' as $$
begin
  raise exception 'Threat triage audit history is immutable' using errcode='42501';
end $$;
create trigger st_v7_immutable_threat_audit before update or delete on sectalk_private.st_v7_threat_triage_audit
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

revoke all on function public.st_v7_threat_triage_access(),public.st_v7_threat_queue(text,text,text,text,timestamptz,uuid),
  public.st_v7_threat_triage_history(uuid),public.st_v7_apply_threat_triage(jsonb,text,text),
  sectalk_private.st_v7_enqueue_threat(text,text,text,text,jsonb,timestamptz),
  sectalk_private.st_v7_enqueue_detection_threat(sectalk_private.st_v7_detection_matches),
  sectalk_private.st_v7_enqueue_attachment_threat(sectalk_private.st_v6_attachment_scans),
  sectalk_private.st_v7_capture_detection_threat(),sectalk_private.st_v7_capture_attachment_threat(),
  sectalk_private.st_v7_immutable_threat_audit() from public,anon,authenticated,service_role;
grant execute on function public.st_v7_threat_triage_access(),public.st_v7_threat_queue(text,text,text,text,timestamptz,uuid),
  public.st_v7_threat_triage_history(uuid),public.st_v7_apply_threat_triage(jsonb,text,text) to authenticated;
notify pgrst,'reload schema';
commit;
