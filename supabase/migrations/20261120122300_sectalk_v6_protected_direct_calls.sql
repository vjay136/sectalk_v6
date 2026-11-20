begin;

alter table public.st_calls add column media_protection smallint not null default 0 check(media_protection in (0,1));

create table sectalk_private.st_v6_protected_call_keys (
  call_id uuid not null,
  actor_id uuid not null,
  public_key text not null check(public_key ~ '^[A-Za-z0-9_-]{87}$'),
  primary key(call_id,actor_id),
  foreign key(call_id,actor_id) references sectalk_private.st_v6_call_endpoints on delete cascade
);
alter table sectalk_private.st_v6_protected_call_keys enable row level security;
revoke all on sectalk_private.st_v6_protected_call_keys from public,anon,authenticated;

create function sectalk_private.place_direct_call(p_chat uuid,p_video boolean,p_protection smallint)
returns uuid language plpgsql security definer set search_path='' as $$
declare conversation public.st_chats; call_id uuid; peer uuid;
begin
  perform sectalk_private.limit_action('call',5);
  select * into conversation from public.st_chats where id=p_chat and auth.uid() in (member_a,member_b) for update;
  if not found or conversation.status<>'accepted' or not sectalk_private.open_pair(conversation.member_a,conversation.member_b)
    then raise exception 'This conversation is unavailable'; end if;
  perform id from public.st_profiles where id in (conversation.member_a,conversation.member_b) order by id for update;
  if exists(select 1 from public.st_calls where status in ('ringing','active') and expires_at>now()
    and (caller in (conversation.member_a,conversation.member_b) or callee in (conversation.member_a,conversation.member_b)))
    then raise exception 'A participant is already in a call'; end if;
  peer:=case when conversation.member_a=auth.uid() then conversation.member_b else conversation.member_a end;
  insert into public.st_calls(chat_id,caller,callee,video,media_protection)
    values(p_chat,auth.uid(),peer,p_video,p_protection) returning id into call_id;
  return call_id;
end
$$;
revoke all on function sectalk_private.place_direct_call(uuid,boolean,smallint) from public,anon,authenticated;

create or replace function public.st_place_call(p_chat uuid,p_video boolean)
returns uuid language sql security definer set search_path='' as $$
  select sectalk_private.place_direct_call(p_chat,p_video,0::smallint)
$$;

create function public.st_v6_start_protected_call(p_chat uuid,p_video boolean,p_device uuid)
returns uuid language plpgsql security definer set search_path='' as $$
declare
  session text:=nullif(auth.jwt()->>'session_id','');
  call_id uuid;
begin
  if p_device is null or session is null then raise exception 'Sign in to place a call'; end if;
  call_id:=sectalk_private.place_direct_call(p_chat,p_video,1::smallint);
  insert into sectalk_private.st_v6_call_endpoints values(call_id,auth.uid(),session,p_device);
  return call_id;
end
$$;

create or replace function public.st_v6_call_action(p_call uuid,p_action text,p_device uuid)
returns text language sql security definer set search_path='' as $$
  select case when p_device is null or (p_action='accept' and exists(
      select 1 from public.st_calls where id=p_call and media_protection<>0)) then 'unavailable'
    else sectalk_private.st_v6_call_action(p_call,p_action,p_device) end
$$;

create function public.st_v6_accept_protected_call(p_call uuid,p_device uuid)
returns text language sql security definer set search_path='' as $$
  select case when p_device is null or not exists(
      select 1 from public.st_calls where id=p_call and media_protection=1) then 'unavailable'
    else sectalk_private.st_v6_call_action(p_call,'accept',p_device) end
$$;

create function public.st_v6_protected_call_key(p_call uuid,p_device uuid,p_key text)
returns text language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  selected_call public.st_calls;
  existing text;
  peer uuid;
begin
  if p_device is null or p_key is null or p_key !~ '^[A-Za-z0-9_-]{87}$' then
    raise exception 'Protected call key exchange unavailable' using errcode='42501';
  end if;
  select * into selected_call from public.st_calls where id=p_call and media_protection=1 for update;
  if not found or not sectalk_private.call_access(p_call,actor) or not exists(
    select 1 from sectalk_private.st_v6_call_endpoints where call_id=p_call and actor_id=actor
      and device_id=p_device and auth_session=auth.jwt()->>'session_id'
  ) then raise exception 'Protected call key exchange unavailable' using errcode='42501'; end if;
  perform sectalk_private.limit_action('call_key_v1',90);
  insert into sectalk_private.st_v6_protected_call_keys values(p_call,actor,p_key) on conflict do nothing;
  select public_key into existing from sectalk_private.st_v6_protected_call_keys where call_id=p_call and actor_id=actor;
  if existing is distinct from p_key then raise exception 'Call key already established' using errcode='42501'; end if;
  peer:=case when selected_call.caller=actor then selected_call.callee else selected_call.caller end;
  return (select public_key from sectalk_private.st_v6_protected_call_keys where call_id=p_call and actor_id=peer);
end
$$;

create or replace function public.st_v6_call_signal(p_call uuid,p_kind text,p_payload jsonb,p_device uuid)
returns void language plpgsql security definer set search_path='' as $$
begin
  if exists(select 1 from public.st_calls where id=p_call and media_protection=1)
    and (select count(*) from sectalk_private.st_v6_protected_call_keys where call_id=p_call)<>2 then
    raise exception 'Protected call key exchange unavailable' using errcode='42501';
  end if;
  perform sectalk_private.st_v6_call_signal(p_call,p_kind,p_payload,p_device);
end
$$;

create function sectalk_private.st_v6_clear_protected_call_keys()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.status='ended' and old.status is distinct from new.status and new.media_protection=1 then
    delete from sectalk_private.st_v6_protected_call_keys where call_id=new.id;
  end if;
  return null;
end
$$;
revoke all on function sectalk_private.st_v6_clear_protected_call_keys() from public,anon,authenticated;
create trigger st_v6_clear_protected_call_keys after update of status on public.st_calls
for each row execute function sectalk_private.st_v6_clear_protected_call_keys();

revoke all on function public.st_v6_start_protected_call(uuid,boolean,uuid),public.st_v6_accept_protected_call(uuid,uuid),
  public.st_v6_protected_call_key(uuid,uuid,text) from public,anon,authenticated;
grant execute on function public.st_v6_start_protected_call(uuid,boolean,uuid),public.st_v6_accept_protected_call(uuid,uuid),
  public.st_v6_protected_call_key(uuid,uuid,text) to authenticated;

commit;
