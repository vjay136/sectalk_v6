begin;

-- A future version is inert. A receipt belongs to the account, while
-- interactive writes must still use that account's current native session.
create function sectalk_private.st_v8_community_rules_agreed(p_actor uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce((
    select exists(select 1 from sectalk_private.st_v8_community_rules_acceptance a
      where (a.actor,a.version)=(p_actor,r.version))
    from sectalk_private.st_v8_community_rules r where r.effective_at<=statement_timestamp()
    order by r.effective_at desc limit 1
  ),true);
$$;

create function sectalk_private.st_v8_require_community_rules(p_actor uuid,p_current_session boolean)
returns void language plpgsql stable set search_path='' as $$
begin
  if not sectalk_private.st_v8_community_rules_agreed(p_actor) then
    raise exception 'Accept the current Community Rules before sending messages or starting calls.' using errcode='PT428';
  end if;
  if p_current_session and exists(select 1 from sectalk_private.st_v8_community_rules r
    where r.effective_at<=statement_timestamp())
    and (p_actor is null or auth.uid() is distinct from p_actor or public.st_v7_current_session_valid() is not true) then
    raise insufficient_privilege;
  end if;
end $$;

create function sectalk_private.st_v8_guard_community_action()
returns trigger language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=(to_jsonb(new)->>tg_argv[0])::uuid;
begin
  if auth.uid() is not null then
    perform sectalk_private.st_v8_require_community_rules(actor_id,true);
  elsif tg_argv[1]='service' and auth.role()='service_role' then
    -- Trusted web workers have already validated their user-bound native
    -- session or ticket. The published row captures that exact actor.
    perform sectalk_private.st_v8_require_community_rules(actor_id,false);
  end if;
  return new;
end $$;
revoke all on function sectalk_private.st_v8_community_rules_agreed(uuid),
  sectalk_private.st_v8_require_community_rules(uuid,boolean),sectalk_private.st_v8_guard_community_action()
  from public,anon,authenticated,service_role;

create trigger st_v8_community_message before insert on public.st_messages
  for each row execute function sectalk_private.st_v8_guard_community_action('sender','service');
create trigger st_v8_community_message before insert on public.st_v6_scheduled_messages
  for each row execute function sectalk_private.st_v8_guard_community_action('sender');
create trigger st_v8_community_message before insert on sectalk_private.st_v8_olm_direct_events
  for each row execute function sectalk_private.st_v8_guard_community_action('sender');
create trigger st_v8_community_message before insert on sectalk_private.st_group_messages
  for each row execute function sectalk_private.st_v8_guard_community_action('actor');
create trigger st_v8_community_message before insert on public.st_v6_room_posts
  for each row execute function sectalk_private.st_v8_guard_community_action('sender');
create trigger st_v8_community_message before insert on public.st_v2_posts
  for each row execute function sectalk_private.st_v8_guard_community_action('sender','service');
create trigger st_v8_community_message before insert on sectalk_private.st_v8_managed_room_posts
  for each row execute function sectalk_private.st_v8_guard_community_action('sender','service');

create trigger st_v8_community_call before insert on public.st_calls
  for each row execute function sectalk_private.st_v8_guard_community_action('caller');
create trigger st_v8_community_call before insert on sectalk_private.st_v6_group_call
  for each row execute function sectalk_private.st_v8_guard_community_action('owner');
create trigger st_v8_community_room_call before insert on public.st_v3_meetings
  for each row when (new.status='live') execute function sectalk_private.st_v8_guard_community_action('host_id');
create trigger st_v8_community_meeting_start before update of status on public.st_v3_meetings
  for each row when (old.status<>'live' and new.status='live')
    execute function sectalk_private.st_v8_guard_community_action('host_id');

create or replace function public.st_v8_managed_room_ticket(p_room uuid,p_post uuid default null,p_body text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
begin
  if p_post is not null then perform sectalk_private.st_v8_require_community_rules(auth.uid(),true); end if;
  if not sectalk_private.st_v8_managed_content_session_allowed(
    (select r.workspace_id from public.st_v6_rooms r where r.id=p_room and r.encryption_mode='managed'),auth.uid(),auth.jwt()->>'session_id') then
    raise exception 'Managed room unavailable' using errcode='42501';
  end if;
  return sectalk_private.st_v8_managed_room_ticket(p_room,p_post,p_body);
end $$;

create or replace function public.st_v8_managed_channel_ticket(p_channel uuid,p_purpose text,p_post uuid default null,p_body text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
begin
  if p_purpose='send' then perform sectalk_private.st_v8_require_community_rules(auth.uid(),true); end if;
  if not sectalk_private.st_v8_managed_content_session_allowed(
    (select c.workspace_id from public.st_v2_channels c where c.id=p_channel and c.encryption_mode='managed'),auth.uid(),auth.jwt()->>'session_id') then
    raise exception 'Managed channel unavailable' using errcode='42501';
  end if;
  return sectalk_private.st_v8_managed_channel_ticket(p_channel,p_purpose,p_post,p_body);
end $$;

create or replace function sectalk_private.st_v8_channel_ticket_live(t sectalk_private.st_v8_channel_key_tickets)
returns boolean language sql stable set search_path='' as $$
  select t.id is not null and t.expires_at>statement_timestamp()
    and (t.purpose is distinct from 'send' or sectalk_private.st_v8_community_rules_agreed(t.actor))
    and sectalk_private.st_v2_active(t.actor)
    and sectalk_private.st_v6_channel_content_access(t.channel,t.actor)
    and exists(select 1 from auth.sessions s where s.id=t.native_session and s.user_id=t.actor
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp())
    and exists(select 1 from public.st_v2_channels c where c.id=t.channel and c.encryption_mode='managed'
      and sectalk_private.st_v8_managed_content_session_allowed(c.workspace_id,t.actor,t.native_session::text));
$$;

create or replace function public.st_v8_managed_room_work(p_ticket uuid,p_actor uuid,p_action text,p_data jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare ticket_session uuid; workspace_id uuid; pending_post uuid;
begin
  select t.native_session,r.workspace_id,t.post into ticket_session,workspace_id,pending_post
    from sectalk_private.st_v8_managed_room_tickets t join public.st_v6_rooms r on r.id=t.room
    where t.id=p_ticket and t.actor=p_actor and r.encryption_mode='managed';
  if not found or not sectalk_private.st_v8_managed_content_session_allowed(workspace_id,p_actor,ticket_session::text) then
    return null;
  end if;
  if pending_post is not null and not sectalk_private.st_v8_community_rules_agreed(p_actor) then return null; end if;
  return sectalk_private.st_v8_managed_room_work(p_ticket,p_actor,p_action,p_data);
end $$;

create or replace function sectalk_private.st_v6_dispatch_scheduled_messages()
returns integer language plpgsql security definer set search_path='' as $$
declare queued public.st_v6_scheduled_messages; outcome text; handled integer:=0;
begin
  for queued in select * from public.st_v6_scheduled_messages
    where state='pending' and send_at<=statement_timestamp()
      and sectalk_private.st_v8_community_rules_agreed(sender)
    order by send_at,id limit 50 for update skip locked
  loop
    outcome:=sectalk_private.st_v6_write_message(queued.sender,queued.chat_id,queued.id,queued.body);
    update public.st_v6_scheduled_messages set
      state=case when outcome='sent' then 'sent' else 'failed' end,body=null,completed_at=clock_timestamp()
      where id=queued.id;
    handled:=handled+1;
  end loop;
  return handled;
end $$;

commit;
