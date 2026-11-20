begin;

create table sectalk_private.st_v6_guest_policy (
  meeting uuid primary key references public.st_v3_meetings on delete cascade,
  enabled boolean not null
);
create table sectalk_private.st_v6_guest_link (
  id uuid primary key default gen_random_uuid(),
  meeting uuid not null references public.st_v3_meetings on delete cascade,
  owner uuid not null references public.st_profiles on delete cascade,
  digest text not null unique,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  captcha_window timestamptz not null default clock_timestamp(),
  captcha_checks integer not null default 0
);
create index st_v6_guest_link_meeting on sectalk_private.st_v6_guest_link(meeting,owner);
create table sectalk_private.st_v6_guest_visit (
  id uuid primary key default gen_random_uuid(),
  link uuid not null references sectalk_private.st_v6_guest_link on delete cascade,
  digest text not null unique,
  captcha_digest text not null unique,
  display_name text not null check(char_length(display_name) between 1 and 60),
  state text not null default 'waiting' check(state in ('waiting','approved','denied')),
  requested_at timestamptz not null default clock_timestamp(),
  issued_at timestamptz
);
create index st_v6_guest_visit_link on sectalk_private.st_v6_guest_visit(link);
alter table sectalk_private.st_v6_guest_policy enable row level security;
alter table sectalk_private.st_v6_guest_link enable row level security;
alter table sectalk_private.st_v6_guest_visit enable row level security;
revoke all on sectalk_private.st_v6_guest_policy,sectalk_private.st_v6_guest_link,sectalk_private.st_v6_guest_visit
  from public,anon,authenticated;

create function public.st_v6_meeting_guest_command(
  p_action text, p_meeting uuid default null, p_actor uuid default null, p_link uuid default null,
  p_visitor uuid default null, p_digest text default null, p_visit_digest text default null,
  p_name text default null, p_enabled boolean default null, p_challenge_digest text default null
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  meeting_row public.st_v3_meetings;
  link_row sectalk_private.st_v6_guest_link;
  visit sectalk_private.st_v6_guest_visit;
  allowed boolean;
  live boolean;
  detached jsonb:='[]';
  links jsonb;
  visitors jsonb;
begin
  if p_action in ('probe','request') then
    select * into link_row from sectalk_private.st_v6_guest_link where digest=p_digest;
  elsif p_action in ('status','token') then
    select * into visit from sectalk_private.st_v6_guest_visit where digest=p_visit_digest;
    select * into link_row from sectalk_private.st_v6_guest_link where id=visit.link;
  end if;
  select * into meeting_row from public.st_v3_meetings where id=coalesce(p_meeting,link_row.meeting) for update;
  if not found then return null; end if;
  allowed:=coalesce((select enabled from sectalk_private.st_v6_guest_policy where meeting=meeting_row.id),false);
  live:=meeting_row.status='live' and meeting_row.ends_at>clock_timestamp()
    and sectalk_private.st_v3_is_host(meeting_row.id,meeting_row.host_id)
    and sectalk_private.st_v2_active(meeting_row.host_id);

  if p_action in ('probe','request','status','token') then
    select * into link_row from sectalk_private.st_v6_guest_link where id=link_row.id and meeting=meeting_row.id;
    if not (live and allowed) or link_row.id is null or link_row.expires_at<=clock_timestamp() or link_row.revoked_at is not null then
      return null;
    end if;
    if p_action='probe' then
      if meeting_row.meeting_locked or link_row.captcha_checks>=10 and link_row.captcha_window>clock_timestamp()-interval '2 minutes'
        or (select count(*) from sectalk_private.st_v6_guest_visit where link=link_row.id)>=12 then return null; end if;
      update sectalk_private.st_v6_guest_link set
        captcha_checks=case when captcha_window<=clock_timestamp()-interval '2 minutes' then 1 else captcha_checks+1 end,
        captcha_window=case when captcha_window<=clock_timestamp()-interval '2 minutes' then clock_timestamp() else captcha_window end
        where id=link_row.id;
      return jsonb_build_object('ok',true);
    elsif p_action='request' then
      if meeting_row.meeting_locked or char_length(trim(p_name)) not between 1 and 60
        or p_visit_digest !~ '^[a-f0-9]{64}$'
        or (select count(*) from sectalk_private.st_v6_guest_visit where link=link_row.id)>=12 then return null; end if;
      insert into sectalk_private.st_v6_guest_visit(link,digest,display_name,captcha_digest)
        values(link_row.id,p_visit_digest,trim(p_name),p_challenge_digest) on conflict(captcha_digest) do nothing;
      if not found then return null; end if;
      return jsonb_build_object('state','waiting','expiresAt',link_row.expires_at);
    end if;
    select * into visit from sectalk_private.st_v6_guest_visit where id=visit.id and link=link_row.id;
    if visit.id is null then return null; end if;
    if p_action='token' then
      if visit.state<>'approved' or visit.issued_at>clock_timestamp()-interval '5 seconds' then return null; end if;
      update sectalk_private.st_v6_guest_visit set issued_at=clock_timestamp() where id=visit.id;
    end if;
    return jsonb_build_object('state',visit.state,'expiresAt',least(link_row.expires_at,meeting_row.ends_at))
      || case when p_action='token' then jsonb_build_object('visitor',visit.id,'name',visit.display_name,'meeting',meeting_row.id)
        else '{}'::jsonb end;
  end if;

  if p_actor is distinct from meeting_row.host_id or not sectalk_private.st_v3_is_host(meeting_row.id,p_actor)
    or not sectalk_private.st_v2_active(p_actor) then return null; end if;
  if p_action='policy' then
    if p_enabled is null or (p_enabled and not live) then return null; end if;
    insert into sectalk_private.st_v6_guest_policy(meeting,enabled) values(meeting_row.id,p_enabled)
      on conflict(meeting) do update set enabled=excluded.enabled;
    allowed:=p_enabled;
    if not allowed then
      update sectalk_private.st_v6_guest_link set revoked_at=coalesce(revoked_at,clock_timestamp())
        where meeting=meeting_row.id and owner=p_actor;
      select coalesce(jsonb_agg(v.id),'[]') into detached from sectalk_private.st_v6_guest_visit v
        join sectalk_private.st_v6_guest_link l on l.id=v.link where l.meeting=meeting_row.id and l.owner=p_actor and v.state='approved';
    end if;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(meeting_row.workspace_id,p_actor,'meeting.guest_policy',meeting_row.id);
  elsif p_action='create' then
    if not (allowed and live) or meeting_row.meeting_locked or p_digest !~ '^[a-f0-9]{64}$'
      or (select count(*) from sectalk_private.st_v6_guest_link where meeting=meeting_row.id)>=16 then return null; end if;
    insert into sectalk_private.st_v6_guest_link(meeting,owner,digest,expires_at)
      values(meeting_row.id,p_actor,p_digest,least(meeting_row.ends_at,clock_timestamp()+interval '10 minutes'));
  elsif p_action='revoke' then
    update sectalk_private.st_v6_guest_link set revoked_at=coalesce(revoked_at,clock_timestamp())
      where id=p_link and meeting=meeting_row.id and owner=p_actor;
    if not found then return null; end if;
    select coalesce(jsonb_agg(id),'[]') into detached from sectalk_private.st_v6_guest_visit where link=p_link and state='approved';
  elsif p_action in ('approve','deny') then
    select l.* into link_row from sectalk_private.st_v6_guest_link l join sectalk_private.st_v6_guest_visit v on v.link=l.id
      where v.id=p_visitor and l.meeting=meeting_row.id and l.owner=p_actor;
    if link_row.id is null or link_row.expires_at<=clock_timestamp() or link_row.revoked_at is not null
      or (p_action='approve' and (not allowed or not live or meeting_row.meeting_locked)) then return null; end if;
    update sectalk_private.st_v6_guest_visit set state=case when p_action='approve' then 'approved' else 'denied' end
      where id=p_visitor and (state='waiting' or (state='approved' and p_action='deny'));
    if not found then return null; end if;
    if p_action='deny' then detached:=jsonb_build_array(p_visitor); end if;
  elsif p_action<>'view' then
    return null;
  end if;

  select coalesce(jsonb_agg(to_jsonb(row) order by row.expires_at desc),'[]') into links from (
    select id,expires_at,revoked_at from sectalk_private.st_v6_guest_link where meeting=meeting_row.id and owner=p_actor
  ) row;
  select coalesce(jsonb_agg(to_jsonb(row) order by row.requested_at),'[]') into visitors from (
    select v.id,v.display_name,v.state,v.requested_at from sectalk_private.st_v6_guest_visit v
    join sectalk_private.st_v6_guest_link l on l.id=v.link
    where l.meeting=meeting_row.id and l.owner=p_actor and l.expires_at>clock_timestamp()
      and l.revoked_at is null and v.state in ('waiting','approved')
  ) row;
  return jsonb_build_object('enabled',allowed,'live',live,'links',links,'visitors',visitors,'detach',detached);
end
$$;
revoke all on function public.st_v6_meeting_guest_command(text,uuid,uuid,uuid,uuid,text,text,text,boolean,text) from public,anon,authenticated;
grant execute on function public.st_v6_meeting_guest_command(text,uuid,uuid,uuid,uuid,text,text,text,boolean,text) to service_role;

commit;
