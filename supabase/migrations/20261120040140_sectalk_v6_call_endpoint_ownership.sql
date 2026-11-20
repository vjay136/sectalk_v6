begin;

alter table public.st_calls drop constraint st_calls_check1;
alter table public.st_calls add constraint st_calls_end_reason_check
  check(end_reason is null or (status='ended' and end_reason in ('missed','declined','cancelled','busy')));

create table sectalk_private.st_v6_call_endpoints (
  call_id uuid not null references public.st_calls on delete cascade,
  actor_id uuid not null,
  auth_session text not null,
  device_id uuid,
  primary key(call_id,actor_id)
);
alter table sectalk_private.st_v6_call_endpoints enable row level security;
revoke all on sectalk_private.st_v6_call_endpoints from public,anon,authenticated;

create function public.st_v6_start_call(p_chat uuid,p_video boolean,p_device uuid)
returns uuid language plpgsql security definer set search_path='' as $$
declare
  session text:=nullif(auth.jwt()->>'session_id','');
  call_id uuid;
begin
  if p_device is null or session is null then raise exception 'Sign in to place a call'; end if;
  call_id:=public.st_place_call(p_chat,p_video);
  insert into sectalk_private.st_v6_call_endpoints values(call_id,auth.uid(),session,p_device);
  return call_id;
end $$;

create function sectalk_private.st_v6_call_action(p_call uuid,p_action text,p_device uuid)
returns text language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  session text:=nullif(auth.jwt()->>'session_id','');
  ringing public.st_calls;
  endpoint sectalk_private.st_v6_call_endpoints;
  transition_time timestamptz;
  reason text;
begin
  perform sectalk_private.limit_action('call_status',20);
  if p_action is null or p_action not in ('accept','decline','busy','end')
    or (p_device is not null and session is null) then return 'unavailable'; end if;
  select * into ringing from public.st_calls c where c.id=p_call and actor in (c.caller,c.callee) for update;
  if not found or ringing.status='ended' then return 'unavailable'; end if;
  transition_time:=case when p_device is null then now() else clock_timestamp() end;
  select * into endpoint from sectalk_private.st_v6_call_endpoints e where e.call_id=p_call and e.actor_id=actor;
  if endpoint.call_id is not null and (endpoint.auth_session is distinct from session or endpoint.device_id is distinct from p_device) then
    return case when actor=ringing.callee and ringing.status='active' then 'answered_elsewhere' else 'unavailable' end;
  end if;
  if p_action='accept' then
    if actor<>ringing.callee then return 'unavailable'; end if;
    if ringing.status='active' then
      return case when endpoint.call_id is not null then 'accepted' else 'unavailable' end;
    end if;
    if ringing.expires_at<=clock_timestamp() or not sectalk_private.open_pair(ringing.caller,ringing.callee)
      or (p_device is null and exists(select 1 from sectalk_private.st_v6_call_endpoints e where e.call_id=p_call))
      then return 'unavailable'; end if;
    if session is not null then
      insert into sectalk_private.st_v6_call_endpoints values(p_call,actor,session,p_device);
    end if;
    update public.st_calls set status='active',expires_at=transition_time+interval '2 hours'
      where id=p_call;
    return 'accepted';
  end if;
  if p_action in ('decline','busy') and (actor<>ringing.callee or ringing.status<>'ringing')
    then return 'unavailable'; end if;
  reason:=case
    when ringing.status<>'ringing' then null
    when ringing.expires_at<=transition_time then 'missed'
    when p_action='busy' then 'busy'
    when actor=ringing.callee then 'declined'
    else 'cancelled' end;
  update public.st_calls set status='ended',expires_at=transition_time,end_reason=reason where id=p_call;
  return 'ended';
end $$;

create or replace function public.st_call_status(p_call uuid,p_accept boolean)
returns void language plpgsql security definer set search_path='' as $$
declare result text;
begin
  if p_accept is null then raise exception 'Choose whether to accept the call'; end if;
  result:=sectalk_private.st_v6_call_action(p_call,case when p_accept then 'accept' else 'end' end,null);
  if p_accept and result<>'accepted' then raise exception 'This call is unavailable'; end if;
end $$;

create function public.st_v6_call_action(p_call uuid,p_action text,p_device uuid)
returns text language sql security definer set search_path='' as $$
  select case when p_device is null then 'unavailable'
    else sectalk_private.st_v6_call_action(p_call,p_action,p_device) end
$$;

create or replace function sectalk_private.call_access(cid uuid,uid uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_calls c where c.id=cid and uid in (c.caller,c.callee)
    and c.status='active' and c.expires_at>now() and sectalk_private.open_pair(c.caller,c.callee)
    and not exists(
      select 1 from sectalk_private.st_v6_call_endpoints e where e.call_id=cid and e.actor_id=uid
        and e.auth_session is distinct from auth.jwt()->>'session_id'
    ))
$$;

create function sectalk_private.st_v6_call_signal(p_call uuid,p_kind text,p_payload jsonb,p_device uuid)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('signal',180);
  if not sectalk_private.call_access(p_call,actor) or exists(
    select 1 from sectalk_private.st_v6_call_endpoints e where e.call_id=p_call and e.actor_id=actor
      and e.device_id is distinct from p_device
  ) then raise exception 'This call is unavailable'; end if;
  if not exists(select 1 from public.st_calls where id=p_call and
    (p_kind='ice' or (p_kind='offer' and caller=actor) or (p_kind='answer' and callee=actor)))
    then raise exception 'Invalid signaling role'; end if;
  insert into public.st_signals(call_id,sender,kind,payload) values(p_call,actor,p_kind,p_payload);
end $$;

create or replace function public.st_signal(p_call uuid,p_kind text,p_payload jsonb)
returns void language sql security definer set search_path='' as $$
  select sectalk_private.st_v6_call_signal(p_call,p_kind,p_payload,null)
$$;

create function public.st_v6_call_signal(p_call uuid,p_kind text,p_payload jsonb,p_device uuid)
returns void language sql security definer set search_path='' as $$
  select sectalk_private.st_v6_call_signal(p_call,p_kind,p_payload,p_device)
$$;

revoke all on function sectalk_private.st_v6_call_action(uuid,text,uuid),
  sectalk_private.st_v6_call_signal(uuid,text,jsonb,uuid) from public,anon,authenticated;
revoke all on function public.st_v6_start_call(uuid,boolean,uuid),public.st_v6_call_action(uuid,text,uuid),
  public.st_v6_call_signal(uuid,text,jsonb,uuid) from public,anon,authenticated;
grant execute on function public.st_v6_start_call(uuid,boolean,uuid),public.st_v6_call_action(uuid,text,uuid),
  public.st_v6_call_signal(uuid,text,jsonb,uuid) to authenticated;

commit;
