begin;

alter table sectalk_private.st_v6_room_quiet_rules
  add column channel_id uuid references public.st_v2_channels on delete cascade,
  drop constraint st_v6_room_quiet_rules_pkey,
  alter column room_id drop not null,
  add constraint st_v6_conversation_quiet_scope check(num_nonnulls(room_id,channel_id)=1),
  add constraint st_v6_conversation_quiet_recipient unique nulls not distinct(room_id,channel_id,user_id);
create index st_v6_channel_quiet_read on sectalk_private.st_v6_room_quiet_rules(channel_id,user_id)
  where channel_id is not null;

-- Only the checked room and channel entry points call this common preference writer.
create function sectalk_private.st_v6_set_conversation_quiet(
  p_room uuid,p_channel uuid,p_action text,p_muted boolean,p_minutes integer,
  p_days smallint[],p_start time,p_end time,p_zone text
)
returns void language plpgsql set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_quiet_settings',20);
  case p_action
    when 'mute' then
      if p_muted is null then raise exception 'Choose a mute setting'; end if;
      insert into sectalk_private.st_v6_room_quiet_rules(room_id,channel_id,user_id,muted)
        values(p_room,p_channel,actor,p_muted)
        on conflict on constraint st_v6_conversation_quiet_recipient do update set muted=excluded.muted;
    when 'snooze' then
      if p_minutes is null or p_minutes not between 0 and 10080 then
        raise exception 'Invalid notification snooze';
      end if;
      insert into sectalk_private.st_v6_room_quiet_rules(room_id,channel_id,user_id,snooze_until)
        values(p_room,p_channel,actor,case when p_minutes>0 then now()+make_interval(mins=>p_minutes) end)
        on conflict on constraint st_v6_conversation_quiet_recipient do update set snooze_until=excluded.snooze_until;
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
      insert into sectalk_private.st_v6_room_quiet_rules(room_id,channel_id,user_id,days,starts_at,ends_at,zone)
        values(p_room,p_channel,actor,p_days,p_start,p_end,p_zone)
        on conflict on constraint st_v6_conversation_quiet_recipient do update
        set days=excluded.days,starts_at=excluded.starts_at,ends_at=excluded.ends_at,zone=excluded.zone;
    else raise exception 'Unknown notification setting';
  end case;
  perform sectalk_private.st_v6_availability_hint(actor,false);
end
$$;

create or replace function public.st_v6_set_room_quiet(
  p_room uuid,p_action text,p_muted boolean default null,p_minutes integer default null,
  p_days smallint[] default null,p_start time default null,p_end time default null,p_zone text default null
)
returns void language plpgsql security definer set search_path='' as $$
begin
  if sectalk_private.st_v6_room_role(p_room) is null then
    raise exception 'Notification settings unavailable';
  end if;
  perform sectalk_private.st_v6_set_conversation_quiet(p_room,null,p_action,p_muted,p_minutes,p_days,p_start,p_end,p_zone);
end
$$;

create function sectalk_private.st_v6_channel_alert_quiet(actor uuid,channel uuid)
returns boolean language sql stable set search_path='' as $$
  select sectalk_private.st_v6_quiet_for(actor,null) or exists(
    select 1 from sectalk_private.st_v6_room_quiet_rules r
    where r.user_id=actor and r.channel_id=channel and (
      r.muted or r.snooze_until>now()
      or sectalk_private.st_v6_quiet_window(r.days,r.starts_at,r.ends_at,r.zone,now())
    )
  )
$$;

create function sectalk_private.st_v6_channel_quiet_settings(p_channel uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare rule sectalk_private.st_v6_room_quiet_rules;
begin
  if not sectalk_private.st_v6_channel_content_access(p_channel,auth.uid()) then
    raise exception 'Notification settings unavailable';
  end if;
  select * into rule from sectalk_private.st_v6_room_quiet_rules
    where channel_id=p_channel and user_id=auth.uid();
  return jsonb_build_object('muted',coalesce(rule.muted,false),'snooze_until',rule.snooze_until,
    'days',rule.days,'starts_at',rule.starts_at,'ends_at',rule.ends_at,'zone',rule.zone,
    'active',sectalk_private.st_v6_channel_alert_quiet(auth.uid(),p_channel));
end
$$;

create function sectalk_private.st_v6_set_channel_quiet(
  p_channel uuid,p_action text,p_muted boolean,p_minutes integer,
  p_days smallint[],p_start time,p_end time,p_zone text
)
returns void language plpgsql security definer set search_path='' as $$
begin
  if not sectalk_private.st_v6_channel_content_access(p_channel,auth.uid()) then
    raise exception 'Notification settings unavailable';
  end if;
  perform sectalk_private.st_v6_set_conversation_quiet(null,p_channel,p_action,p_muted,p_minutes,p_days,p_start,p_end,p_zone);
end
$$;

create function public.st_v6_channel_quiet_settings(p_channel uuid)
returns jsonb language sql stable set search_path=''
return sectalk_private.st_v6_channel_quiet_settings(p_channel);

create function public.st_v6_set_channel_quiet(
  p_channel uuid,p_action text,p_muted boolean default null,p_minutes integer default null,
  p_days smallint[] default null,p_start time default null,p_end time default null,p_zone text default null
)
returns void language sql set search_path=''
return sectalk_private.st_v6_set_channel_quiet(p_channel,p_action,p_muted,p_minutes,p_days,p_start,p_end,p_zone);

create function sectalk_private.st_v6_channel_post_alert()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform realtime.send(jsonb_build_object('channel_id',new.channel_id),'channel_activity','st:account:'||m.user_id,true)
  from public.st_v2_channels c join public.st_v2_members m on m.workspace_id=c.workspace_id
  where c.id=new.channel_id and m.user_id<>new.sender and not c.archived
    and sectalk_private.st_v6_channel_content_access(c.id,m.user_id)
    and sectalk_private.open_pair(new.sender,m.user_id)
    and not sectalk_private.st_v6_channel_alert_quiet(m.user_id,c.id);
  return new;
end
$$;

create trigger st_v6_channel_post_alert after insert on public.st_v2_posts
for each row execute function sectalk_private.st_v6_channel_post_alert();
revoke all on function sectalk_private.st_v6_set_conversation_quiet(uuid,uuid,text,boolean,integer,smallint[],time,time,text),
  sectalk_private.st_v6_channel_alert_quiet(uuid,uuid),sectalk_private.st_v6_channel_post_alert()
  from public,anon,authenticated;
revoke all on function public.st_v6_channel_quiet_settings(uuid),
  public.st_v6_set_channel_quiet(uuid,text,boolean,integer,smallint[],time,time,text),
  sectalk_private.st_v6_channel_quiet_settings(uuid),
  sectalk_private.st_v6_set_channel_quiet(uuid,text,boolean,integer,smallint[],time,time,text)
  from public,anon,authenticated;
grant execute on function public.st_v6_channel_quiet_settings(uuid),
  public.st_v6_set_channel_quiet(uuid,text,boolean,integer,smallint[],time,time,text),
  sectalk_private.st_v6_channel_quiet_settings(uuid),
  sectalk_private.st_v6_set_channel_quiet(uuid,text,boolean,integer,smallint[],time,time,text)
  to authenticated;

commit;
