begin;

create table sectalk_private.st_v6_incident_responders(
  user_id uuid primary key references public.st_profiles on delete cascade,
  role text not null check(role in ('responder','lead'))
);
create table sectalk_private.st_v6_security_incidents(
  id uuid primary key,
  title text not null check(char_length(title) between 5 and 100),
  severity text not null check(severity in ('low','moderate','high','critical')),
  status text not null default 'open' check(status in ('open','investigating','contained','resolved')),
  created_by uuid not null references public.st_profiles,
  assigned_to uuid references public.st_profiles,
  postmortem text,
  created_at timestamptz not null default clock_timestamp(),
  updated_at timestamptz not null default clock_timestamp()
);
create index st_v6_incidents_assigned on sectalk_private.st_v6_security_incidents(assigned_to,updated_at desc);
create index st_v6_incidents_creator on sectalk_private.st_v6_security_incidents(created_by,updated_at desc);
create table sectalk_private.st_v6_incident_reports(
  incident_id uuid not null references sectalk_private.st_v6_security_incidents on delete cascade,
  report_id uuid not null references public.st_reports on delete cascade,
  primary key(incident_id,report_id)
);
create index st_v6_incident_reports_reverse on sectalk_private.st_v6_incident_reports(report_id);
create table sectalk_private.st_v6_incident_events(
  id bigint generated always as identity primary key,
  incident_id uuid not null references sectalk_private.st_v6_security_incidents on delete cascade,
  actor uuid not null references public.st_profiles,
  event text not null,
  subject uuid,
  note text,
  occurred_at timestamptz not null default clock_timestamp()
);
create index st_v6_incident_timeline on sectalk_private.st_v6_incident_events(incident_id,id desc);

alter table sectalk_private.st_v6_incident_responders enable row level security;
alter table sectalk_private.st_v6_security_incidents enable row level security;
alter table sectalk_private.st_v6_incident_reports enable row level security;
alter table sectalk_private.st_v6_incident_events enable row level security;
revoke all on sectalk_private.st_v6_incident_responders,sectalk_private.st_v6_security_incidents,
  sectalk_private.st_v6_incident_reports,sectalk_private.st_v6_incident_events from public,anon,authenticated,service_role;

create function public.st_v6_incident_access()
returns text language sql stable security definer set search_path='' as $$
  select coalesce((select r.role from sectalk_private.st_v6_incident_responders r
    where r.user_id=auth.uid() and sectalk_private.st_v6_case_redaction_staff()),'none')
$$;

create function public.st_v6_incident_dashboard(p_incident uuid default null)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare access text:=public.st_v6_incident_access();
declare incident sectalk_private.st_v6_security_incidents;
declare records jsonb;
declare roster jsonb;
begin
  if access='none' then raise exception 'Incident operations are unavailable' using errcode='42501'; end if;
  if p_incident is null then
    select coalesce(jsonb_agg(to_jsonb(i) order by i.updated_at desc,i.id),'[]'::jsonb) into records from (
      select id,title,severity,status,assigned_to,updated_at from sectalk_private.st_v6_security_incidents
      where access='lead' or actor in (created_by,assigned_to)
      order by updated_at desc,id limit 100
    ) i;
    return jsonb_build_object('role',access,'incidents',records);
  end if;
  select * into incident from sectalk_private.st_v6_security_incidents
    where id=p_incident and (access='lead' or actor in (created_by,assigned_to));
  if not found then raise exception 'Incident is unavailable' using errcode='42501'; end if;
  if access='lead' or incident.created_by=actor then
    select coalesce(jsonb_agg(to_jsonb(person) order by person.name,person.id),'[]'::jsonb) into roster from (
      select p.id,p.name from sectalk_private.st_v6_incident_responders r
      join sectalk_private.staff s on s.user_id=r.user_id join public.st_profiles p on p.id=r.user_id
      where sectalk_private.st_v2_active(r.user_id) order by p.name,p.id limit 250
    ) person;
  end if;
  return jsonb_build_object(
    'role',access,'incident',to_jsonb(incident),'roster',roster,
    'reports',coalesce((select jsonb_agg(r.report_id order by r.report_id) from
      sectalk_private.st_v6_incident_reports r where r.incident_id=p_incident),'[]'::jsonb),
    'timeline',coalesce((select jsonb_agg(to_jsonb(e) order by e.id desc) from (
      select h.event,h.note,h.subject,h.occurred_at,h.id,p.name as actor_name from sectalk_private.st_v6_incident_events h
      join public.st_profiles p on p.id=h.actor
      where h.incident_id=p_incident order by h.id desc limit 100
    ) e),'[]'::jsonb)
  );
end $$;

create function public.st_v6_write_incident(p_id uuid,p_action text,p_fields jsonb)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare access text:=public.st_v6_incident_access();
declare incident sectalk_private.st_v6_security_incidents;
declare label text:=btrim(p_fields->>'title');
declare severity_value text:=p_fields->>'severity';
declare desired text:=p_fields->>'status';
declare reason text:=btrim(p_fields->>'note');
declare entity uuid;
declare event_name text;
begin
  if access='none' then raise exception 'Incident operations are unavailable' using errcode='42501'; end if;
  if p_id is null or p_action is null or p_action not in ('create','assign','update','note','link','postmortem')
    or p_fields is null or jsonb_typeof(p_fields)<>'object' or octet_length(p_fields::text)>6000
  then raise exception 'Choose a valid incident action' using errcode='22023'; end if;
  perform sectalk_private.limit_action('v6_incident_actions',30);
  if p_action='create' then
    if label is null or char_length(label) not between 5 and 100 or severity_value is null
      or severity_value not in ('low','moderate','high','critical') then raise exception 'Enter a title and choose severity'; end if;
    insert into sectalk_private.st_v6_security_incidents(id,title,severity,created_by,assigned_to)
      values(p_id,label,severity_value,actor,actor) on conflict do nothing;
    if not found then
      if exists(select 1 from sectalk_private.st_v6_security_incidents i
        where i.id=p_id and i.created_by=actor and i.title=label) then return p_id; end if;
      raise exception 'Incident request ID is already in use';
    end if;
    event_name:='incident.created';
    reason:=null;
  else
    select * into incident from sectalk_private.st_v6_security_incidents
      where id=p_id and (access='lead' or actor in (created_by,assigned_to)) for update;
    if not found or public.st_v6_incident_access() is distinct from access
      then raise exception 'Incident is unavailable' using errcode='42501'; end if;
    if reason is null or char_length(reason) not between 5 and (case when p_action='postmortem' then 4000 else 1000 end)
      then raise exception 'Enter an incident reason or note'; end if;
    case p_action
      when 'assign' then
        if access<>'lead' and incident.created_by<>actor then raise exception 'Assignment is unavailable' using errcode='42501'; end if;
        entity:=(p_fields->>'entity')::uuid;
        if entity is null or not exists(select 1 from sectalk_private.st_v6_incident_responders r
          join sectalk_private.staff s on s.user_id=r.user_id where r.user_id=entity and sectalk_private.st_v2_active(entity))
        then raise exception 'Choose an active incident responder'; end if;
        if entity=incident.assigned_to then return p_id; end if;
        update sectalk_private.st_v6_security_incidents set assigned_to=entity where id=p_id;
        event_name:='incident.assigned';
      when 'update' then
        if severity_value is null or severity_value not in ('low','moderate','high','critical') or desired is null
          or desired not in ('open','investigating','contained','resolved') then raise exception 'Choose a valid status and severity'; end if;
        if desired<>incident.status and not (
          (incident.status='open' and desired='investigating')
          or (incident.status='investigating' and desired in ('contained','resolved'))
          or (incident.status='contained' and desired in ('investigating','resolved'))
          or (incident.status='resolved' and desired='investigating' and access='lead')
        ) then raise exception 'Incident status transition is unavailable'; end if;
        if desired=incident.status and severity_value=incident.severity then return p_id; end if;
        update sectalk_private.st_v6_security_incidents set status=desired,severity=severity_value where id=p_id;
        event_name:='incident.updated';
        reason:=incident.status||' → '||desired||' · '||incident.severity||' → '||severity_value||' · '||reason;
      when 'note' then event_name:='incident.note';
      when 'link' then
        entity:=(p_fields->>'entity')::uuid;
        if entity is null or not exists(select 1 from public.st_reports where id=entity) then raise exception 'Report is unavailable'; end if;
        if exists(select 1 from sectalk_private.st_v6_incident_reports where incident_id=p_id and report_id=entity)
          then return p_id; end if;
        if (select count(*) from sectalk_private.st_v6_incident_reports where incident_id=p_id)>=50
          then raise exception 'An incident can link at most 50 reports'; end if;
        insert into sectalk_private.st_v6_incident_reports values(p_id,entity) on conflict do nothing;
        if not found then return p_id; end if;
        event_name:='incident.report_linked';
      when 'postmortem' then
        if incident.status<>'resolved' then raise exception 'Resolve the incident before recording a postmortem'; end if;
        if reason=incident.postmortem then return p_id; end if;
        update sectalk_private.st_v6_security_incidents set postmortem=reason where id=p_id;
        event_name:='incident.postmortem_saved';
        reason:=null;
    end case;
  end if;
  update sectalk_private.st_v6_security_incidents set updated_at=clock_timestamp() where id=p_id;
  insert into sectalk_private.st_v6_incident_events(incident_id,actor,event,subject,note) values(p_id,actor,event_name,entity,reason);
  return p_id;
end $$;

revoke all on function public.st_v6_incident_access(),public.st_v6_incident_dashboard(uuid),
  public.st_v6_write_incident(uuid,text,jsonb) from public,anon,authenticated;
grant execute on function public.st_v6_incident_access(),public.st_v6_incident_dashboard(uuid),
  public.st_v6_write_incident(uuid,text,jsonb) to authenticated;

commit;
