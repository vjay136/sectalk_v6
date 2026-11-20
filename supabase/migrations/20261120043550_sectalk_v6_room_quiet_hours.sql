begin;

create table sectalk_private.st_v6_room_quiet_rules (
  room_id uuid not null references public.st_v6_rooms on delete cascade,
  user_id uuid not null references public.st_profiles on delete cascade,
  muted boolean not null default false,
  snooze_until timestamptz,
  days smallint[],
  starts_at time,
  ends_at time,
  zone text,
  primary key(room_id,user_id)
);
alter table sectalk_private.st_v6_room_quiet_rules enable row level security;
revoke all on sectalk_private.st_v6_room_quiet_rules from public,anon,authenticated;
create index st_v6_room_quiet_user on sectalk_private.st_v6_room_quiet_rules(user_id);

create function sectalk_private.st_v6_quiet_window(
  days smallint[],starts_at time,ends_at time,zone text,moment timestamptz
)
returns boolean language sql stable set search_path='' as $$
  with clock as (
    select extract(isodow from stamp)::smallint as day,stamp::time as at
    from (select moment at time zone zone as stamp) local_time
  )
  select coalesce(
    case when starts_at<ends_at
      then day=any(days) and at>=starts_at and at<ends_at
      else (day=any(days) and at>=starts_at)
        or (((day+5)%7+1)::smallint=any(days) and at<ends_at)
    end,false
  ) from clock
$$;

create or replace function sectalk_private.st_v6_quiet_window(
  rule sectalk_private.st_v6_quiet_rules,moment timestamptz
)
returns boolean language sql stable set search_path='' as $$
  select sectalk_private.st_v6_quiet_window(rule.days,rule.starts_at,rule.ends_at,rule.zone,moment)
$$;

create function sectalk_private.st_v6_room_alert_quiet(actor uuid,room uuid)
returns boolean language sql stable set search_path='' as $$
  select sectalk_private.st_v6_quiet_for(actor,null) or exists(
    select 1 from sectalk_private.st_v6_room_quiet_rules r
    where r.user_id=actor and r.room_id=room and (
      r.muted or r.snooze_until>now()
      or sectalk_private.st_v6_quiet_window(r.days,r.starts_at,r.ends_at,r.zone,now())
    )
  )
$$;

create function public.st_v6_room_quiet_settings(p_room uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare rule sectalk_private.st_v6_room_quiet_rules;
begin
  if sectalk_private.st_v6_room_role(p_room) is null then
    raise exception 'Notification settings unavailable';
  end if;
  select * into rule from sectalk_private.st_v6_room_quiet_rules
    where room_id=p_room and user_id=auth.uid();
  return jsonb_build_object('muted',coalesce(rule.muted,false),'snooze_until',rule.snooze_until,
    'days',rule.days,'starts_at',rule.starts_at,'ends_at',rule.ends_at,'zone',rule.zone,
    'active',sectalk_private.st_v6_room_alert_quiet(auth.uid(),p_room));
end
$$;

create function public.st_v6_set_room_quiet(
  p_room uuid,p_action text,p_muted boolean default null,p_minutes integer default null,
  p_days smallint[] default null,p_start time default null,p_end time default null,p_zone text default null
)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if sectalk_private.st_v6_room_role(p_room) is null then
    raise exception 'Notification settings unavailable';
  end if;
  perform sectalk_private.limit_action('v6_quiet_settings',20);
  case p_action
    when 'mute' then
      if p_muted is null then raise exception 'Choose a mute setting'; end if;
      insert into sectalk_private.st_v6_room_quiet_rules(room_id,user_id,muted)
        values(p_room,actor,p_muted) on conflict(room_id,user_id) do update set muted=excluded.muted;
    when 'snooze' then
      if p_minutes is null or p_minutes not between 0 and 10080 then
        raise exception 'Invalid notification snooze';
      end if;
      insert into sectalk_private.st_v6_room_quiet_rules(room_id,user_id,snooze_until)
        values(p_room,actor,case when p_minutes>0 then now()+make_interval(mins=>p_minutes) end)
        on conflict(room_id,user_id) do update set snooze_until=excluded.snooze_until;
    when 'schedule' then
      if p_days is null then
        p_start:=null;
        p_end:=null;
        p_zone:=null;
      elsif array_ndims(p_days) is distinct from 1 or cardinality(p_days) not between 1 and 7
        or array_position(p_days,null) is not null
        or not p_days<@array[1,2,3,4,5,6,7]::smallint[]
        or cardinality(p_days)<>(select count(distinct d) from unnest(p_days) d)
        or p_start is null or p_end is null or p_start=p_end or greatest(p_start,p_end)>=time '24:00'
        or p_zone is null or length(p_zone)>100
        or not exists(select 1 from pg_catalog.pg_timezone_names where name=p_zone) then
        raise exception 'Choose valid quiet hours, days and time zone';
      end if;
      insert into sectalk_private.st_v6_room_quiet_rules(room_id,user_id,days,starts_at,ends_at,zone)
        values(p_room,actor,p_days,p_start,p_end,p_zone) on conflict(room_id,user_id) do update
        set days=excluded.days,starts_at=excluded.starts_at,ends_at=excluded.ends_at,zone=excluded.zone;
    else raise exception 'Unknown notification setting';
  end case;
  perform sectalk_private.st_v6_availability_hint(actor,false);
end
$$;

create function sectalk_private.st_v6_room_post_alert()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform realtime.send(jsonb_build_object('room_id',new.room_id),'room_activity','st:account:'||recipients.user_id,true)
  from public.st_v6_rooms r
  cross join lateral (
    select m.user_id from public.st_v6_room_members m where r.kind<>'admin' and m.room_id=r.id
    union all
    select m.user_id from public.st_v2_members m
      where r.kind='admin' and m.workspace_id=r.workspace_id and m.role in ('owner','admin')
  ) recipients
  where r.id=new.room_id and recipients.user_id<>new.sender and not r.archived
    and sectalk_private.st_v2_active(recipients.user_id)
    and sectalk_private.st_v2_role(r.workspace_id,recipients.user_id) is not null
    and not exists(select 1 from public.st_v6_room_bans b where b.room_id=r.id and b.user_id=recipients.user_id)
    and sectalk_private.open_pair(new.sender,recipients.user_id)
    and not sectalk_private.st_v6_room_alert_quiet(recipients.user_id,r.id);
  return new;
end
$$;

create trigger st_v6_room_post_alert after insert on public.st_v6_room_posts
for each row execute function sectalk_private.st_v6_room_post_alert();
revoke all on function sectalk_private.st_v6_quiet_window(smallint[],time,time,text,timestamptz),
  sectalk_private.st_v6_room_alert_quiet(uuid,uuid),sectalk_private.st_v6_room_post_alert()
  from public,anon,authenticated;
revoke all on function public.st_v6_room_quiet_settings(uuid),
  public.st_v6_set_room_quiet(uuid,text,boolean,integer,smallint[],time,time,text)
  from public,anon,authenticated;
grant execute on function public.st_v6_room_quiet_settings(uuid),
  public.st_v6_set_room_quiet(uuid,text,boolean,integer,smallint[],time,time,text)
  to authenticated;

commit;
