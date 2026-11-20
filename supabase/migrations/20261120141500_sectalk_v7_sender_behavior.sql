begin;

create table sectalk_private.st_v7_behavior_counts (
  actor uuid not null references auth.users on delete cascade,
  kind text not null check(kind in ('send','invite')),
  minute timestamptz not null,
  actions integer not null check(actions between 1 and 1000),
  primary key(actor,kind,minute)
);
create index st_v7_behavior_counts_retention on sectalk_private.st_v7_behavior_counts(minute);
create table sectalk_private.st_v7_browser_link_challenge (
  id uuid primary key default gen_random_uuid(),
  session uuid not null unique references auth.sessions on delete cascade,
  actor uuid not null references auth.users on delete cascade,
  device uuid not null references sectalk_private.st_v7_devices on delete cascade,
  alias text not null check(alias ~ '^[A-Za-z0-9_-]{87}$'),
  valid_until timestamptz not null default clock_timestamp()+interval '90 seconds'
);
create table sectalk_private.st_v7_browser_link (
  actor uuid not null references auth.users on delete cascade,
  device uuid not null references sectalk_private.st_v7_devices on delete cascade,
  alias_digest bytea not null,
  verified_at timestamptz not null default clock_timestamp(),
  primary key(actor,device)
);
create index st_v7_browser_link_overlap on sectalk_private.st_v7_browser_link(alias_digest,verified_at);
alter table sectalk_private.st_v7_behavior_counts enable row level security;
alter table sectalk_private.st_v7_browser_link_challenge enable row level security;
alter table sectalk_private.st_v7_browser_link enable row level security;
revoke all on sectalk_private.st_v7_behavior_counts,sectalk_private.st_v7_browser_link_challenge,
  sectalk_private.st_v7_browser_link from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_count_behavior()
returns trigger language plpgsql security definer set search_path='' as $$
declare actor_id uuid;
begin
  if tg_argv[0]='send' then actor_id:=new.sender;
  elsif new.status='pending' and (tg_op='INSERT' or old.status is distinct from new.status) then
    if tg_table_name='st_chats' then actor_id:=new.requester; else actor_id:=new.created_by; end if;
  end if;
  if actor_id is not null then
    insert into sectalk_private.st_v7_behavior_counts as c(actor,kind,minute,actions)
      values(actor_id,tg_argv[0],date_trunc('minute',clock_timestamp()),1)
      on conflict(actor,kind,minute) do update set actions=least(1000,c.actions+1);
  end if;
  return new;
end
$$;
create trigger st_v7_count_managed_send after insert on public.st_messages
for each row execute function sectalk_private.st_v7_count_behavior('send');
create trigger st_v7_count_contact_invite after insert or update of status on public.st_chats
for each row execute function sectalk_private.st_v7_count_behavior('invite');
create trigger st_v7_count_workspace_invite after insert or update of status on public.st_v2_invites
for each row execute function sectalk_private.st_v7_count_behavior('invite');

create function public.st_v7_manage_browser_reputation_link(p_action text,p_alias text default null,p_challenge uuid default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare device_row sectalk_private.st_v7_devices; pending sectalk_private.st_v7_browser_link_challenge; current_session uuid;
begin
  if not coalesce(sectalk_private.st_v7_manage_sessions(),false) then return null; end if;
  current_session:=(auth.jwt()->>'session_id')::uuid;
  select d.* into device_row from sectalk_private.st_v7_device_sessions s
    join sectalk_private.st_v7_devices d on (d.owner,d.id)=(s.owner,s.device_id)
    where s.owner=auth.uid() and s.session_id=current_session and d.state in ('trusted','managed');
  if device_row.id is null then return null; end if;
  if p_action='begin' then
    if p_alias is null or p_alias !~ '^[A-Za-z0-9_-]{87}$' or p_alias=device_row.signing_key then return null; end if;
    perform sectalk_private.limit_action('reputation_browser_link',6);
    insert into sectalk_private.st_v7_browser_link_challenge as c(session,actor,device,alias)
      values(current_session,device_row.owner,device_row.id,p_alias)
      on conflict(session) do update set id=gen_random_uuid(),device=excluded.device,alias=excluded.alias,
        valid_until=clock_timestamp()+interval '90 seconds' returning * into pending;
  elsif p_action='proof' then
    select * into pending from sectalk_private.st_v7_browser_link_challenge c
      where c.id=p_challenge and c.session=current_session and (c.actor,c.device)=(device_row.owner,device_row.id)
        and c.valid_until>clock_timestamp();
  elsif p_action='forget' then
    delete from sectalk_private.st_v7_browser_link where (actor,device)=(device_row.owner,device_row.id);
    delete from sectalk_private.st_v7_browser_link_challenge where session=current_session;
  elsif p_action<>'status' or p_action is null then return null;
  end if;
  if p_action in ('begin','proof') then
    if pending.id is null then return null; end if;
    return jsonb_build_object('challenge',pending.id,'owner',pending.actor,'device',pending.device,
      'session',pending.session,'alias',pending.alias,'signing',device_row.signing_key);
  end if;
  return jsonb_build_object('linked',exists(select 1 from sectalk_private.st_v7_browser_link l
    where (l.actor,l.device)=(device_row.owner,device_row.id) and l.verified_at>now()-interval '30 days'));
end
$$;

create function public.st_v7_finish_browser_reputation_link(p_challenge uuid,p_actor uuid,p_session uuid)
returns boolean language plpgsql security definer set search_path='' as $$
declare c sectalk_private.st_v7_browser_link_challenge;
begin
  delete from sectalk_private.st_v7_browser_link_challenge p where p.id=p_challenge and p.actor=p_actor and p.session=p_session
    and p.valid_until>clock_timestamp() returning * into c;
  if not found or not coalesce(sectalk_private.st_v2_active(p_actor),false) or not exists(
    select 1 from sectalk_private.st_v7_device_sessions b join sectalk_private.st_v7_devices d
    on (d.owner,d.id)=(b.owner,b.device_id)
    where b.session_id=c.session and (b.owner,b.device_id)=(c.actor,c.device) and d.state in ('trusted','managed')) then return false; end if;
  insert into sectalk_private.st_v7_browser_link(actor,device,alias_digest)
    values(c.actor,c.device,extensions.digest(c.alias,'sha256'))
    on conflict(actor,device) do update set alias_digest=excluded.alias_digest,verified_at=clock_timestamp();
  return true;
end
$$;

create function public.st_v7_case_sender_behavior(p_report uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare subject_id uuid; burst integer; invites integer; flags integer; linked boolean; score integer;
begin
  if sectalk_private.st_v6_case_redaction_staff() is not true then
    raise exception using errcode='42501',message='Verified Safety access is required';
  end if;
  select r.subject into subject_id from public.st_reports r where r.id=p_report and r.chat_id is not null;
  if not found then return null; end if;
  select least(60,coalesce(max(actions),0)) into burst from sectalk_private.st_v7_behavior_counts
    where actor=subject_id and kind='send' and minute>=now()-interval '72 hours';
  select least(24,coalesce(max(hour_total),0)) into invites from (
    select sum(actions) hour_total from sectalk_private.st_v7_behavior_counts
      where actor=subject_id and kind='invite' and minute>=now()-interval '72 hours'
      group by date_trunc('hour',minute)
  ) hours;
  select least(40,coalesce(sum(case when reviewed_at>=now()-interval '7 days' then 8
    when reviewed_at>=now()-interval '30 days' then 4 else 1 end),0)) into flags from (
    select max(a.created_at) reviewed_at
    from public.st_reports r join sectalk_private.audit a on a.report_id=r.id
    where r.subject=subject_id and a.action in ('warn','suspend','restrict','remove')
      and a.created_at>=now()-interval '90 days'
      and not exists(select 1 from sectalk_private.audit changed where changed.report_id=a.report_id
        and changed.created_at>a.created_at and changed.action in ('restore','dismissed'))
    group by r.id
  ) reviewed;
  select exists(
    select 1 from auth.users u join sectalk_private.st_v7_browser_link other_link on other_link.actor=u.id
    join sectalk_private.st_v7_devices current_device on current_device.id=other_link.device and current_device.owner=u.id
    join sectalk_private.st_v7_browser_link peer on peer.alias_digest=other_link.alias_digest and peer.actor<>u.id
    join sectalk_private.st_v7_devices peer_device on peer_device.id=peer.device and peer_device.owner=peer.actor
    where u.id=subject_id and u.created_at>=now()-interval '30 days'
      and other_link.verified_at>=now()-interval '30 days' and peer.verified_at>=now()-interval '30 days'
      and current_device.state in ('trusted','managed') and peer_device.state in ('trusted','managed')
  ) into linked;
  score:=case when burst>=20 then 30 when burst>=12 then 15 else 0 end
    + case when invites>=10 then 20 when invites>=5 then 10 else 0 end
    + case when linked then 10 else 0 end + flags;
  return jsonb_build_object('score',score,'peakMinuteSend',burst,'peakHourInvites',invites,
    'reviewedFlagWeight',flags,'sharedApprovedBrowser',linked);
end
$$;

create function sectalk_private.st_v7_purge_sender_behavior()
returns void language sql security definer set search_path='' as $$
  with expired as (
    select actor,kind,minute from sectalk_private.st_v7_behavior_counts
    where minute<now()-interval '72 hours' limit 5000 for update skip locked
  )
  delete from sectalk_private.st_v7_behavior_counts b using expired e where (b.actor,b.kind,b.minute)=(e.actor,e.kind,e.minute);
  delete from sectalk_private.st_v7_browser_link_challenge where valid_until<now();
  delete from sectalk_private.st_v7_browser_link where verified_at<now()-interval '30 days';
$$;
select cron.schedule('sectalk-v7-purge-sender-behavior','*/10 * * * *','select sectalk_private.st_v7_purge_sender_behavior()');

revoke all on function sectalk_private.st_v7_count_behavior(),sectalk_private.st_v7_purge_sender_behavior(),
  public.st_v7_manage_browser_reputation_link(text,text,uuid),public.st_v7_finish_browser_reputation_link(uuid,uuid,uuid),
  public.st_v7_case_sender_behavior(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_manage_browser_reputation_link(text,text,uuid),public.st_v7_case_sender_behavior(uuid) to authenticated;
grant execute on function public.st_v7_finish_browser_reputation_link(uuid,uuid,uuid) to service_role;
commit;
