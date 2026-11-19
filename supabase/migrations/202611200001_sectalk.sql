begin;

create schema sectalk_private;
revoke all on schema sectalk_private from public;

create table public.st_profiles (
  id uuid primary key references auth.users on delete cascade,
  handle text not null unique check (handle ~ '^[a-z0-9_]{3,24}$'),
  name text not null check (char_length(btrim(name)) between 1 and 50)
);
create table public.st_chats (
  id uuid primary key default gen_random_uuid(),
  member_a uuid not null references public.st_profiles,
  member_b uuid not null references public.st_profiles,
  requester uuid not null references public.st_profiles,
  status text not null default 'pending' check (status in ('pending','accepted','declined')),
  updated_at timestamptz not null default now(),
  check (member_a < member_b and requester in (member_a,member_b)),
  unique (member_a, member_b)
);
create index st_chats_a on public.st_chats(member_a,updated_at desc);
create index st_chats_b on public.st_chats(member_b,updated_at desc);
create table public.st_blocks (
  actor uuid not null references public.st_profiles,
  target uuid not null references public.st_profiles,
  primary key(actor,target),
  check(actor <> target)
);
create table public.st_messages (
  id uuid primary key,
  chat_id uuid not null references public.st_chats,
  sender uuid not null references public.st_profiles,
  body text not null check(char_length(btrim(body)) between 1 and 4000),
  created_at timestamptz not null default now()
);
create index st_messages_feed on public.st_messages(chat_id,created_at desc,id desc);

create table public.st_calls (
  id uuid primary key default gen_random_uuid(),
  chat_id uuid not null references public.st_chats,
  caller uuid not null references public.st_profiles,
  callee uuid not null references public.st_profiles,
  video boolean not null,
  status text not null default 'ringing' check(status in ('ringing','active','ended')),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '50 seconds'),
  check(caller <> callee)
);
create index st_calls_caller on public.st_calls(caller,expires_at);
create index st_calls_callee on public.st_calls(callee,expires_at);
create table public.st_signals (
  id uuid primary key default gen_random_uuid(),
  call_id uuid not null references public.st_calls on delete cascade,
  sender uuid not null references public.st_profiles,
  kind text not null check(kind in ('offer','answer','ice')),
  payload jsonb not null check(octet_length(payload::text) <= 40960),
  created_at timestamptz not null default now()
);
create index st_signals_call on public.st_signals(call_id,created_at,id);
create table public.st_reports (
  id uuid primary key default gen_random_uuid(),
  reporter uuid not null references public.st_profiles,
  subject uuid not null references public.st_profiles,
  chat_id uuid not null references public.st_chats,
  message_id uuid references public.st_messages,
  category text not null check(category in ('harassment','threat','scam','impersonation','other')),
  details text not null check(char_length(details) <= 1500),
  evidence text,
  status text not null default 'open' check(status in ('open','reviewing','resolved','dismissed')),
  created_at timestamptz not null default now()
);
create index st_reports_queue on public.st_reports(status,created_at desc);
create index st_reports_mine on public.st_reports(reporter,created_at desc);
create table sectalk_private.staff (
  user_id uuid primary key references public.st_profiles
);
create table sectalk_private.suspensions (
  user_id uuid primary key references public.st_profiles,
  until_at timestamptz not null
);
create table sectalk_private.audit (
  id bigint generated always as identity primary key,
  actor uuid not null references public.st_profiles,
  report_id uuid not null references public.st_reports,
  action text not null,
  note text not null,
  created_at timestamptz not null default now()
);
create table sectalk_private.limits (
  actor uuid not null references auth.users on delete cascade,
  action text not null,
  bucket timestamptz not null,
  hits integer not null,
  primary key (actor,action)
);

create function sectalk_private.limit_action(p_action text,p_limit integer)
returns void language plpgsql security definer set search_path='' as $$
declare count_hits integer;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  insert into sectalk_private.limits as limits values(auth.uid(),p_action,date_trunc('minute',now()),1)
  on conflict (actor,action) do update set
    hits = case when limits.bucket = excluded.bucket then limits.hits+1 else 1 end,
    bucket = excluded.bucket
  returning hits into count_hits;
  if count_hits > p_limit then raise exception 'Too many requests. Try again in a minute.' using errcode='PT429'; end if;
end $$;

create function sectalk_private.member(cid uuid, uid uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_chats where id=cid and uid in (member_a,member_b))
$$;

create function sectalk_private.related(uid uuid, other_id uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_chats where member_a=least(uid,other_id) and member_b=greatest(uid,other_id))
$$;

create function sectalk_private.open_pair(a uuid,b uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from public.st_blocks where (actor,target) in ((a,b),(b,a)))
     and not exists(select 1 from sectalk_private.suspensions where user_id in (a,b) and until_at>now())
$$;

create function sectalk_private.call_access(cid uuid,uid uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_calls where id=cid and uid in (caller,callee)
   and status='active' and expires_at>now() and sectalk_private.open_pair(caller,callee))
$$;

alter table public.st_profiles enable row level security;
alter table public.st_chats enable row level security;
alter table public.st_blocks enable row level security;
alter table public.st_messages enable row level security;
alter table public.st_calls enable row level security;
alter table public.st_signals enable row level security;
alter table public.st_reports enable row level security;
revoke all on public.st_profiles,public.st_chats,public.st_blocks,public.st_messages,public.st_calls,public.st_signals,public.st_reports from public,anon,authenticated;
grant select on public.st_profiles,public.st_chats,public.st_blocks,public.st_messages,public.st_calls,public.st_signals to authenticated;
grant select(id, reporter, category, status, created_at) on public.st_reports to authenticated;
create policy st_profile_read on public.st_profiles for select to authenticated using (id=(select auth.uid()) or sectalk_private.related((select auth.uid()),id));
create policy st_chat_read on public.st_chats for select to authenticated using ((select auth.uid()) in (member_a,member_b));
create policy st_block_read on public.st_blocks for select to authenticated using (actor=(select auth.uid()));
create policy st_message_read on public.st_messages for select to authenticated using (sectalk_private.member(chat_id,(select auth.uid())));
create policy st_call_read on public.st_calls for select to authenticated using ((select auth.uid()) in (caller,callee));
create policy st_signal_read on public.st_signals for select to authenticated using (sectalk_private.call_access(call_id,(select auth.uid())));
create policy st_report_read on public.st_reports for select to authenticated using (reporter=(select auth.uid()));

create function public.st_save_profile(p_handle text,p_name text)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('profile',6);
  insert into public.st_profiles(id,handle,name) values(auth.uid(),lower(btrim(p_handle)),btrim(p_name))
  on conflict(id) do update set name=excluded.name;
end $$;

create function public.st_request(p_handle text)
returns uuid language plpgsql security definer set search_path='' as $$
declare peer uuid; me uuid:=auth.uid(); chat uuid;
begin
  perform sectalk_private.limit_action('request',6);
  select id into peer from public.st_profiles where handle=lower(btrim(p_handle));
  if peer is null or me=peer or not sectalk_private.open_pair(me,peer)
    or not exists(select 1 from public.st_profiles where id=me) then return null; end if;
  insert into public.st_chats(member_a,member_b,requester) values(least(me,peer),greatest(me,peer),me)
  on conflict(member_a,member_b) do nothing returning id into chat;
  if chat is null then
    select id into chat from public.st_chats where member_a=least(me,peer) and member_b=greatest(me,peer);
  end if;
  return chat;
end $$;

create function public.st_respond(p_chat uuid,p_accept boolean)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('respond',20);
  update public.st_chats set status=case when p_accept then 'accepted' else 'declined' end,updated_at=now()
    where id=p_chat and auth.uid() in (member_a,member_b) and requester<>auth.uid()
      and status='pending' and sectalk_private.open_pair(member_a,member_b);
  if not found then raise exception 'This request is unavailable'; end if;
end $$;

create function public.st_send(p_chat uuid,p_id uuid,p_body text)
returns void language plpgsql security definer set search_path='' as $$
declare conversation public.st_chats;
begin
  perform sectalk_private.limit_action('message',60);
  select * into conversation from public.st_chats where id=p_chat and auth.uid() in (member_a,member_b) for update;
  if not found or conversation.status<>'accepted' or not sectalk_private.open_pair(conversation.member_a,conversation.member_b)
    then raise exception 'This conversation is unavailable'; end if;
  insert into public.st_messages values(p_id,p_chat,auth.uid(),btrim(p_body),clock_timestamp())
  on conflict(id) do nothing;
  if found then
    update public.st_chats set updated_at=clock_timestamp() where id=p_chat;
  elsif not exists(select 1 from public.st_messages where id=p_id and chat_id=p_chat and sender=auth.uid() and body=btrim(p_body)) then
    raise exception 'Message ID already in use';
  end if;
end $$;

create function public.st_set_block(p_chat uuid,p_block boolean)
returns void language plpgsql security definer set search_path='' as $$
declare peer uuid;
begin
  perform sectalk_private.limit_action('block',20);
  select case when member_a=auth.uid() then member_b else member_a end into peer
  from public.st_chats where id=p_chat and auth.uid() in (member_a,member_b) for update;
  if not found then raise exception 'This conversation is unavailable'; end if;
  if p_block then
    insert into public.st_blocks values(auth.uid(),peer) on conflict do nothing;
    update public.st_calls set status='ended',expires_at=now() where chat_id=p_chat and status<>'ended';
  else
    delete from public.st_blocks where actor=auth.uid() and target=peer;
  end if;
end $$;

create function public.st_place_call(p_chat uuid,p_video boolean)
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
  insert into public.st_calls(chat_id,caller,callee,video) values(p_chat,auth.uid(),peer,p_video) returning id into call_id;
  return call_id;
end $$;

create function public.st_call_status(p_call uuid,p_accept boolean)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('call_status',20);
  if p_accept then
    update public.st_calls set status='active',expires_at=now()+interval '2 hours'
    where id=p_call and callee=auth.uid() and status='ringing' and expires_at>now()
      and sectalk_private.open_pair(caller,callee);
    if not found then raise exception 'This call is unavailable'; end if;
  else
    update public.st_calls set status='ended',expires_at=now() where id=p_call and auth.uid() in (caller,callee) and status<>'ended';
  end if;
end $$;

create function public.st_signal(p_call uuid,p_kind text,p_payload jsonb)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('signal',180);
  if not sectalk_private.call_access(p_call,auth.uid()) then raise exception 'This call is unavailable'; end if;
  if not exists(select 1 from public.st_calls where id=p_call and
    (p_kind='ice' or (p_kind='offer' and caller=auth.uid()) or (p_kind='answer' and callee=auth.uid())))
    then raise exception 'Invalid signaling role'; end if;
  insert into public.st_signals(call_id,sender,kind,payload) values(p_call,auth.uid(),p_kind,p_payload);
end $$;

create function public.st_report(p_chat uuid,p_message uuid,p_category text,p_details text)
returns uuid language plpgsql security definer set search_path='' as $$
declare peer uuid; snapshot text; report_id uuid;
begin
  perform sectalk_private.limit_action('report',5);
  select case when member_a=auth.uid() then member_b else member_a end into peer
  from public.st_chats where id=p_chat and auth.uid() in (member_a,member_b);
  if not found then raise exception 'This conversation is unavailable'; end if;
  if p_message is not null then
    select body into snapshot from public.st_messages where id=p_message and chat_id=p_chat and sender=peer;
    if not found then raise exception 'Evidence must be a message from this contact'; end if;
  end if;
  insert into public.st_reports(reporter,subject,chat_id,message_id,category,details,evidence)
  values(auth.uid(),peer,p_chat,p_message,p_category,btrim(p_details),snapshot) returning id into report_id;
  return report_id;
end $$;

create function public.st_staff_status()
returns text language sql stable security definer set search_path='' as $$
  select case when not exists(select 1 from sectalk_private.staff where user_id=auth.uid()) then 'none'
    when auth.jwt()->>'aal'='aal2' then 'verified' else 'mfa' end
$$;

create function public.st_queue(p_offset integer default 0)
returns table(id uuid, subject_handle text, category text, status text, created_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
begin
  if public.st_staff_status()<>'verified' then raise exception 'Staff MFA required'; end if;
  return query select r.id,p.handle,r.category,r.status,r.created_at from public.st_reports r
  join public.st_profiles p on p.id=r.subject order by (r.status in ('open','reviewing')) desc,r.created_at desc,r.id
  limit 51 offset greatest(0,p_offset);
end $$;

create function public.st_case(p_report uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare result jsonb;
begin
  if public.st_staff_status()<>'verified' then raise exception 'Staff MFA required'; end if;
  perform sectalk_private.limit_action('case_view',45);
  select jsonb_build_object('id',r.id,'details',r.details,'evidence',r.evidence,'status',r.status,
    'subject_handle',p.handle,'category',r.category,'created_at',r.created_at,'suspended_until',s.until_at)
  into result from public.st_reports r join public.st_profiles p on p.id=r.subject
  left join sectalk_private.suspensions s on s.user_id=r.subject where r.id=p_report;
  if result is null then raise exception 'Report unavailable'; end if;
  insert into sectalk_private.audit(actor,report_id,action,note) values(auth.uid(),p_report,'viewed','');
  return result || jsonb_build_object('history',coalesce((select jsonb_agg(to_jsonb(logged) order by logged.id desc)
    from (select id, action, note, created_at from sectalk_private.audit
      where report_id=p_report order by id desc limit 40) logged),'[]'::jsonb));
end $$;

create function public.st_moderate(p_report uuid,p_action text,p_note text)
returns void language plpgsql security definer set search_path='' as $$
declare target public.st_reports;
begin
  if public.st_staff_status()<>'verified' then raise exception 'Staff MFA required'; end if;
  perform sectalk_private.limit_action('moderate',20);
  if p_action is null or p_action not in ('reviewing','resolved','dismissed','suspend','restore')
     or p_note is null or char_length(btrim(p_note)) not between 4 and 500 then
    raise exception 'Enter an action and a reason of 4–500 characters';
  end if;
  select * into target from public.st_reports where id=p_report for update;
  if not found then raise exception 'Report unavailable'; end if;
  if p_action='suspend' then
    if target.subject=auth.uid() or exists(select 1 from sectalk_private.staff where user_id=target.subject) then
      raise exception 'Staff restrictions require an account operator';
    end if;
    insert into sectalk_private.suspensions values(target.subject,now()+interval '24 hours')
      on conflict(user_id) do update set until_at=excluded.until_at;
    update public.st_calls set status='ended',expires_at=now()
      where target.subject in (caller,callee) and status<>'ended';
  elsif p_action='restore' then
    delete from sectalk_private.suspensions where user_id=target.subject;
  else
    update public.st_reports set status=p_action where id=p_report;
  end if;
  insert into sectalk_private.audit(actor,report_id,action,note) values(auth.uid(),p_report,p_action,btrim(p_note));
end $$;

revoke execute on all functions in schema sectalk_private from public,anon,authenticated;
grant execute on function sectalk_private.member(uuid,uuid),sectalk_private.related(uuid,uuid),sectalk_private.call_access(uuid,uuid) to authenticated;

do $$
declare signature text;
begin
  for signature in select p.oid::regprocedure::text from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and left(p.proname,3)='st_'
  loop
    execute 'revoke all on function ' || signature || ' from public,anon,authenticated';
    execute 'grant execute on function ' || signature || ' to authenticated';
  end loop;
end $$;

alter publication supabase_realtime add table public.st_chats,public.st_messages,public.st_calls,public.st_signals;
commit;
