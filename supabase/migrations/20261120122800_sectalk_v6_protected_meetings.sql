begin;
alter table public.st_v3_meetings add column media_protection smallint not null default 0 check(media_protection in (0,1));

create table sectalk_private.st_v6_protected_meeting (
  meeting uuid primary key references public.st_v3_meetings on delete cascade,
  roster uuid[] not null,
  envelopes jsonb,
  closed boolean not null default false
);
create table sectalk_private.st_v6_protected_meeting_endpoint (
  meeting uuid not null references sectalk_private.st_v6_protected_meeting on delete cascade,
  actor uuid not null,
  device uuid not null,
  session_id text not null,
  public_key text not null check(public_key ~ '^[A-Za-z0-9_-]{87}$'),
  verified boolean not null default false,
  primary key(meeting,actor)
);
alter table sectalk_private.st_v6_protected_meeting enable row level security;
alter table sectalk_private.st_v6_protected_meeting_endpoint enable row level security;
revoke all on sectalk_private.st_v6_protected_meeting,sectalk_private.st_v6_protected_meeting_endpoint from public,anon,authenticated;

create or replace function public.st_v3_media_access(p_meeting uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v3_meetings m join public.st_v3_attendance a on m.id=a.meeting_id
    where m.id=p_meeting and m.media_protection=0 and a.user_id=auth.uid() and a.status='admitted' and m.status='live' and m.ends_at>now()
      and sectalk_private.st_v2_role(m.workspace_id,auth.uid()) is not null
      and sectalk_private.st_v2_active(auth.uid()) and sectalk_private.st_v3_is_host(m.id,m.host_id)
      and sectalk_private.st_v2_active(m.host_id) and sectalk_private.open_pair(m.host_id,auth.uid()))
$$;

create function public.st_v6_create_protected_meeting(p_meeting uuid,p_actor uuid)
returns boolean language plpgsql security definer set search_path='' as $$
declare m public.st_v3_meetings; members uuid[];
begin
  select * into m from public.st_v3_meetings where id=p_meeting for update;
  if not found or m.host_id is distinct from p_actor or m.media_protection<>0 or m.status<>'live' or m.ends_at<=clock_timestamp()
    or not sectalk_private.st_v3_is_host(m.id,p_actor) or not sectalk_private.st_v2_active(p_actor)
    or exists(select 1 from sectalk_private.st_v6_recording where meeting_id=m.id and status in ('collecting','starting','recording','stopping'))
    or exists(select 1 from sectalk_private.st_v6_caption_session where meeting=m.id and not stopped and expires_at>clock_timestamp())
    then return false; end if;
  select array_agg(user_id order by user_id) into members from public.st_v3_attendance where meeting_id=m.id and status='admitted';
  if coalesce(cardinality(members),0) not between 2 and 8 or not(p_actor=any(members)) then return false; end if;
  insert into sectalk_private.st_v6_protected_meeting(meeting,roster) values(m.id,members);
  update public.st_v3_meetings set media_protection=1,meeting_locked=true,chat_disabled=true,screen_share_disabled=true where id=m.id;
  update sectalk_private.st_v6_guest_policy set enabled=false where meeting=m.id;
  update sectalk_private.st_v6_guest_link set revoked_at=coalesce(revoked_at,clock_timestamp()) where meeting=m.id;
  return true;
end
$$;
revoke all on function public.st_v6_create_protected_meeting(uuid,uuid) from public,anon,authenticated;
grant execute on function public.st_v6_create_protected_meeting(uuid,uuid) to service_role;

create function sectalk_private.st_v6_protected_guest_policy_guard()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.enabled and exists(select 1 from public.st_v3_meetings where id=new.meeting and media_protection<>0) then
    raise exception 'Guest access is unavailable in protected meetings' using errcode='42501';
  end if;
  return new;
end
$$;
revoke all on function sectalk_private.st_v6_protected_guest_policy_guard() from public,anon,authenticated;
create trigger st_v6_protected_guest_policy_guard before insert or update of enabled on sectalk_private.st_v6_guest_policy
for each row execute function sectalk_private.st_v6_protected_guest_policy_guard();

create function sectalk_private.st_v6_end_protected_epoch_on_attendance()
returns trigger language plpgsql security definer set search_path='' as $$
declare affected_meeting uuid;
begin
  if tg_op='INSERT' then
    if new.status='admitted' then affected_meeting:=new.meeting_id; end if;
  elsif tg_op='DELETE' then
    if old.status='admitted' then affected_meeting:=old.meeting_id; end if;
  elsif old.status is distinct from new.status and (old.status='admitted' or new.status='admitted') then
    affected_meeting:=new.meeting_id;
  end if;
  if affected_meeting is not null then
    update sectalk_private.st_v6_protected_meeting set closed=true where meeting=affected_meeting and not closed;
  end if;
  return null;
end
$$;
revoke all on function sectalk_private.st_v6_end_protected_epoch_on_attendance() from public,anon,authenticated;
create trigger st_v6_end_protected_epoch_on_attendance after insert or update of status or delete on public.st_v3_attendance
for each row execute function sectalk_private.st_v6_end_protected_epoch_on_attendance();

create function sectalk_private.st_v6_protected_managed_caption_guard()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if exists(select 1 from public.st_v3_meetings where id=new.meeting and media_protection<>0) then
    raise exception 'Captions are unavailable in protected meetings' using errcode='42501';
  end if;
  return new;
end
$$;
revoke all on function sectalk_private.st_v6_protected_managed_caption_guard() from public,anon,authenticated;
create trigger st_v6_protected_managed_caption_guard before insert on sectalk_private.st_v6_caption_session
for each row execute function sectalk_private.st_v6_protected_managed_caption_guard();

create function sectalk_private.st_v6_protected_recording_guard()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.status in ('collecting','starting','recording','stopping') and exists(
    select 1 from public.st_v3_meetings where id=new.meeting_id and media_protection<>0) then
    raise exception 'Recording is unavailable in protected meetings' using errcode='42501';
  end if;
  return new;
end
$$;
revoke all on function sectalk_private.st_v6_protected_recording_guard() from public,anon,authenticated;
create trigger st_v6_protected_recording_guard before insert or update of status on sectalk_private.st_v6_recording
for each row execute function sectalk_private.st_v6_protected_recording_guard();

create function public.st_v6_protected_meeting_exchange(p_meeting uuid,p_device uuid,p_action text,p_key text default null,p_envelopes jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  m public.st_v3_meetings; epoch sectalk_private.st_v6_protected_meeting;
  endpoint sectalk_private.st_v6_protected_meeting_endpoint;
  actor_id uuid:=auth.uid(); session_key text:=auth.jwt()->>'session_id';
  members uuid[]; public_keys jsonb; all_verified boolean;
begin
  if actor_id is null or p_device is null or nullif(session_key,'') is null or p_action not in ('view','key','wrap','verify','token') then return null; end if;
  select * into m from public.st_v3_meetings where id=p_meeting and media_protection=1 for share;
  if not found then return null; end if;
  select * into epoch from sectalk_private.st_v6_protected_meeting where meeting=m.id for update;
  if not found or not(actor_id=any(epoch.roster)) then return null; end if;
  select array_agg(user_id order by user_id) into members from public.st_v3_attendance where meeting_id=m.id and status='admitted';
  if epoch.closed or m.status<>'live' or m.ends_at<=clock_timestamp() or not m.meeting_locked or members is distinct from epoch.roster
    or exists(select 1 from unnest(epoch.roster) u(id) where not coalesce(sectalk_private.st_v2_active(u.id),false)
      or sectalk_private.st_v2_role(m.workspace_id,u.id) is null or not coalesce(sectalk_private.open_pair(m.host_id,u.id),false)) then
    update sectalk_private.st_v6_protected_meeting set closed=true where meeting=m.id and not closed;
    return null;
  end if;
  if p_action='key' then
    if p_key is null or p_key !~ '^[A-Za-z0-9_-]{87}$' then return null; end if;
    insert into sectalk_private.st_v6_protected_meeting_endpoint(meeting,actor,device,session_id,public_key)
      values(m.id,actor_id,p_device,session_key,p_key) on conflict do nothing;
  end if;
  select * into endpoint from sectalk_private.st_v6_protected_meeting_endpoint e where e.meeting=m.id and e.actor=actor_id;
  if not found or endpoint.device is distinct from p_device or endpoint.session_id is distinct from session_key
    or (p_action='key' and endpoint.public_key is distinct from p_key) then return null; end if;
  select coalesce(jsonb_object_agg(e.actor::text,e.public_key),'{}'),
    count(*)=cardinality(epoch.roster) and bool_and(e.verified)
    into public_keys,all_verified from sectalk_private.st_v6_protected_meeting_endpoint e where e.meeting=m.id;
  if p_action='wrap' then
    if actor_id<>m.host_id or epoch.envelopes is not null or jsonb_typeof(p_envelopes) is distinct from 'object'
      or (select count(*) from jsonb_object_keys(public_keys))<>cardinality(epoch.roster)
      or (select count(*) from jsonb_object_keys(p_envelopes))<>cardinality(epoch.roster)-1
      or exists(select 1 from jsonb_each_text(p_envelopes) entry where not(public_keys ? entry.key)
        or entry.key=actor_id::text or entry.value !~ '^[A-Za-z0-9_-]{80}$') then return null; end if;
    update sectalk_private.st_v6_protected_meeting set envelopes=p_envelopes where meeting=m.id returning * into epoch;
  elsif p_action='verify' then
    if epoch.envelopes is null then return null; end if;
    update sectalk_private.st_v6_protected_meeting_endpoint e set verified=true where e.meeting=m.id and e.actor=actor_id;
    endpoint.verified:=true;
    all_verified:=not exists(select 1 from sectalk_private.st_v6_protected_meeting_endpoint where meeting=m.id and not verified);
  elsif p_action='token' then
    if epoch.envelopes is null or not coalesce(all_verified,false) then return null; end if;
  end if;
  return jsonb_build_object('host',m.host_id,'roster',epoch.roster,'keys',public_keys,'wrapped',epoch.envelopes is not null,
    'envelope',epoch.envelopes->>actor_id::text,'verified',endpoint.verified,'ready',coalesce(all_verified,false));
end
$$;
revoke all on function public.st_v6_protected_meeting_exchange(uuid,uuid,text,text,jsonb) from public,anon,authenticated;
grant execute on function public.st_v6_protected_meeting_exchange(uuid,uuid,text,text,jsonb) to authenticated;

commit;
