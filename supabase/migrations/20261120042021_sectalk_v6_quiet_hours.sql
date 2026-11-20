create table sectalk_private.st_v6_quiet_rules (
  user_id uuid not null references public.st_profiles on delete cascade,
  chat_id uuid references public.st_chats on delete cascade,
  muted boolean not null default false,
  snooze_until timestamptz,
  days smallint[],
  starts_at time,
  ends_at time,
  zone text,
  scheduled_status text,
  unique nulls not distinct(user_id,chat_id)
);
alter table sectalk_private.st_v6_quiet_rules enable row level security;
revoke all on sectalk_private.st_v6_quiet_rules from public,anon,authenticated;

create function sectalk_private.st_v6_quiet_window(rule sectalk_private.st_v6_quiet_rules, moment timestamptz)
returns boolean language sql stable set search_path='' as $$
  with local as (
    select moment at time zone rule.zone as stamp
  ), clock as (
    select extract(isodow from stamp)::smallint as day,stamp::time as at from local
  )
  select coalesce(
    case when rule.starts_at<rule.ends_at
      then day=any(rule.days) and at>=rule.starts_at and at<rule.ends_at
      else (day=any(rule.days) and at>=rule.starts_at)
        or (((day+5)%7+1)::smallint=any(rule.days) and at<rule.ends_at)
    end,false
  ) from clock
$$;

create function sectalk_private.st_v6_quiet_for(actor uuid, chat uuid)
returns boolean language sql stable set search_path='' as $$
  select exists(
    select 1 from sectalk_private.st_v6_quiet_rules r
    where r.user_id=actor and (r.chat_id is null or r.chat_id=chat)
      and (r.muted or r.snooze_until>now() or sectalk_private.st_v6_quiet_window(r,now()))
  ) or exists (
    select 1 from public.st_v2_chat_state s where s.chat_id=chat and s.user_id=actor and s.muted
  )
$$;

create function sectalk_private.st_v6_availability_hint(actor uuid, contacts boolean)
returns void language plpgsql set search_path='' as $$
begin
  perform realtime.send('{}'::jsonb,'availability','st:account:'||actor,true);
  if contacts then
    perform realtime.send('{}'::jsonb,'availability','st:account:'||peers.id,true)
    from (
      select case when c.member_a=actor then c.member_b else c.member_a end as id
      from public.st_chats c
      where (c.member_a=actor or c.member_b=actor) and c.status='accepted'
    ) peers where sectalk_private.open_pair(actor,peers.id);
  end if;
end
$$;

create function sectalk_private.st_v6_status_hint()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if tg_op='INSERT' or new.status_message is distinct from old.status_message then
    perform sectalk_private.st_v6_availability_hint(new.user_id,true);
  end if;
  return new;
end
$$;

create trigger st_v6_status_hint after insert or update of status_message on public.st_v5_profile_details
for each row execute function sectalk_private.st_v6_status_hint();

create function sectalk_private.st_v6_quiet_authorized(actor uuid,chat uuid)
returns boolean language sql stable set search_path='' as $$
  select actor is not null and sectalk_private.st_v2_active(actor) and (
    chat is null or sectalk_private.st_v2_chat_write(chat,actor)
  )
$$;

create function public.st_v6_quiet_active(p_chat uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select case when sectalk_private.st_v6_quiet_authorized(auth.uid(),p_chat)
    then sectalk_private.st_v6_quiet_for(auth.uid(),p_chat) else true end
$$;

create function public.st_v6_quiet_settings(p_chat uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  rule sectalk_private.st_v6_quiet_rules;
  muted boolean;
begin
  if not sectalk_private.st_v6_quiet_authorized(actor,p_chat) then
    raise exception 'Notification settings unavailable';
  end if;
  select r.* into rule from sectalk_private.st_v6_quiet_rules r
    where r.user_id=actor and r.chat_id is not distinct from p_chat;
  muted:=case when p_chat is null then coalesce(rule.muted,false) else exists(
    select 1 from public.st_v2_chat_state s where s.user_id=actor and s.chat_id=p_chat and s.muted
  ) end;
  return jsonb_build_object('muted',muted,'snooze_until',rule.snooze_until,
    'days',rule.days,'starts_at',rule.starts_at,'ends_at',rule.ends_at,'zone',rule.zone,
    'scheduled_status',rule.scheduled_status,'active',sectalk_private.st_v6_quiet_for(actor,p_chat));
end
$$;

create function public.st_v6_set_quiet_schedule(
  p_chat uuid,p_days smallint[],p_start time,p_end time,p_zone text,p_status text
)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  replacement text:=nullif(btrim(p_status),'');
begin
  if not sectalk_private.st_v6_quiet_authorized(actor,p_chat) then
    raise exception 'Notification settings unavailable';
  end if;
  perform sectalk_private.limit_action('v6_quiet_settings',20);
  if p_days is null then
    p_start:=null;
    p_end:=null;
    p_zone:=null;
    replacement:=null;
  elsif array_ndims(p_days) is distinct from 1 or cardinality(p_days) not between 1 and 7
    or array_position(p_days,null) is not null
    or not p_days<@array[1,2,3,4,5,6,7]::smallint[]
    or cardinality(p_days)<>(select count(distinct d) from unnest(p_days) d)
    or p_start is null or p_end is null or p_start=p_end or greatest(p_start,p_end)>=time '24:00'
    or p_zone is null or length(p_zone)>100
    or not exists(select 1 from pg_catalog.pg_timezone_names where name=p_zone)
    or length(replacement)>140 or (p_chat is not null and replacement is not null) then
    raise exception 'Choose valid quiet hours, days and time zone';
  end if;
  insert into sectalk_private.st_v6_quiet_rules(user_id,chat_id,days,starts_at,ends_at,zone,scheduled_status)
  values(actor,p_chat,p_days,p_start,p_end,p_zone,replacement)
  on conflict(user_id,chat_id) do update
    set days=excluded.days,starts_at=excluded.starts_at,ends_at=excluded.ends_at,zone=excluded.zone,
      scheduled_status=excluded.scheduled_status;
  perform sectalk_private.st_v6_availability_hint(actor,p_chat is null and exists(
    select 1 from public.st_v3_presence p where p.user_id=actor and p.state<>'offline' and p.expires_at>now()
  ));
end
$$;

create function public.st_v6_set_quiet_snooze(p_chat uuid,p_minutes integer)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if not sectalk_private.st_v6_quiet_authorized(actor,p_chat) or p_minutes is null or p_minutes not between 0 and 10080 then
    raise exception 'Invalid notification snooze';
  end if;
  perform sectalk_private.limit_action('v6_quiet_settings',20);
  insert into sectalk_private.st_v6_quiet_rules(user_id,chat_id,snooze_until)
  values(actor,p_chat,case when p_minutes>0 then now()+make_interval(mins=>p_minutes) end)
  on conflict(user_id,chat_id) do update set snooze_until=excluded.snooze_until;
  perform sectalk_private.st_v6_availability_hint(actor,p_chat is null and exists(
    select 1 from public.st_v3_presence p where p.user_id=actor and p.state<>'offline' and p.expires_at>now()
  ));
end
$$;

create function public.st_v6_set_quiet_mute(p_chat uuid,p_muted boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if not sectalk_private.st_v6_quiet_authorized(actor,p_chat) or p_muted is null then
    raise exception 'Notification settings unavailable';
  end if;
  if p_chat is null then
    perform sectalk_private.limit_action('v6_quiet_settings',20);
    insert into sectalk_private.st_v6_quiet_rules(user_id,muted) values(actor,p_muted)
    on conflict(user_id,chat_id) do update set muted=excluded.muted;
  else
    perform public.st_v2_mute(p_chat,p_muted);
  end if;
  perform sectalk_private.st_v6_availability_hint(actor,p_chat is null and exists(
    select 1 from public.st_v3_presence p where p.user_id=actor and p.state<>'offline' and p.expires_at>now()
  ));
end
$$;

create function public.st_v6_effective_availability(p_user uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare
  rule sectalk_private.st_v6_quiet_rules;
  custom text;
  shared boolean;
begin
  if auth.uid() is null or not sectalk_private.st_v2_active(auth.uid())
    or not sectalk_private.st_v5_profile_visible(p_user,auth.uid()) then
    return null;
  end if;
  select d.status_message into custom from public.st_v5_profile_details d where d.user_id=p_user;
  select exists(
    select 1 from public.st_v3_presence p where p.user_id=p_user and p.state<>'offline' and p.expires_at>now()
  ) into shared;
  if shared then
    select r.* into rule from sectalk_private.st_v6_quiet_rules r where r.user_id=p_user and r.chat_id is null;
    if rule.scheduled_status is not null and sectalk_private.st_v6_quiet_window(rule,now()) then
      custom:=rule.scheduled_status;
    end if;
  end if;
  return jsonb_build_object('busy',shared and sectalk_private.st_v6_quiet_for(p_user,null),'status',coalesce(custom,''));
end
$$;

revoke all on function
  sectalk_private.st_v6_quiet_window(sectalk_private.st_v6_quiet_rules,timestamptz),
  sectalk_private.st_v6_quiet_for(uuid,uuid),
  sectalk_private.st_v6_availability_hint(uuid,boolean),
  sectalk_private.st_v6_status_hint(),
  sectalk_private.st_v6_quiet_authorized(uuid,uuid)
from public,anon,authenticated;

revoke all on function public.st_v6_quiet_active(uuid),public.st_v6_quiet_settings(uuid),
  public.st_v6_set_quiet_schedule(uuid,smallint[],time,time,text,text),public.st_v6_set_quiet_snooze(uuid,integer),
  public.st_v6_set_quiet_mute(uuid,boolean),public.st_v6_effective_availability(uuid) from public,anon,authenticated;
grant execute on function public.st_v6_quiet_active(uuid),public.st_v6_quiet_settings(uuid),
  public.st_v6_set_quiet_schedule(uuid,smallint[],time,time,text,text),public.st_v6_set_quiet_snooze(uuid,integer),
  public.st_v6_set_quiet_mute(uuid,boolean),public.st_v6_effective_availability(uuid) to authenticated;
