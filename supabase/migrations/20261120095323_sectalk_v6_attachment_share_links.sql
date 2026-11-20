begin;

create table sectalk_private.st_v6_file_share_links (
  id uuid primary key default gen_random_uuid(),
  file_id uuid not null references public.st_v5_files on delete cascade,
  token_hash bytea not null unique,
  password_hash text not null,
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  max_downloads integer not null check(max_downloads between 1 and 100),
  downloads integer not null default 0 check(downloads between 0 and max_downloads),
  revoked_at timestamptz,
  attempt_bucket timestamptz,
  attempts integer not null default 0
);
create index st_v6_file_share_links_file on sectalk_private.st_v6_file_share_links(file_id,created_at desc);

create table sectalk_private.st_v6_file_share_events (
  id bigint generated always as identity primary key,
  link_id uuid not null references sectalk_private.st_v6_file_share_links on delete cascade,
  event text not null check(event in ('link_created','link_revoked','link_view','link_download')),
  occurred_at timestamptz not null default clock_timestamp()
);
create index st_v6_file_share_events_link on sectalk_private.st_v6_file_share_events(link_id,occurred_at desc);
alter table sectalk_private.st_v6_file_share_links enable row level security;
alter table sectalk_private.st_v6_file_share_events enable row level security;
revoke all on sectalk_private.st_v6_file_share_links,sectalk_private.st_v6_file_share_events
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_shareable_file(p_file uuid,p_owner uuid)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from public.st_v5_files f join public.st_messages m on m.id=f.message_id
    where f.id=p_file and (p_owner is null or f.uploader=p_owner) and m.revoked_at is null
      and sectalk_private.st_v2_chat_write(f.chat_id,f.uploader))
$$;
revoke all on function sectalk_private.st_v6_shareable_file(uuid,uuid) from public,anon,authenticated,service_role;

create function public.st_v6_create_file_share(p_file uuid,p_password text,p_seconds integer,p_downloads integer)
returns text language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare token text;
declare link uuid;
begin
  if actor is null then raise exception 'Sign in first' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v6_file_share_create',10);
  perform 1 from public.st_v5_files f where f.id=p_file and f.uploader=actor for update;
  if not found or not sectalk_private.st_v6_shareable_file(p_file,actor) then
    raise exception 'Attachment cannot be shared' using errcode='42501';
  end if;
  if (octet_length(p_password) between 10 and 64) is not true or
    (p_seconds between 900 and 604800) is not true or (p_downloads between 1 and 100) is not true then
    raise exception 'Choose valid password, expiration and download limits' using errcode='22023';
  end if;
  if (select count(*) from sectalk_private.st_v6_file_share_links s where s.file_id=p_file
    and s.expires_at>now() and s.revoked_at is null and s.downloads<s.max_downloads)>=10 then
    raise exception 'Revoke an existing active link before creating another' using errcode='PT409';
  end if;
  token:=encode(extensions.gen_random_bytes(32),'hex');
  insert into sectalk_private.st_v6_file_share_links(file_id,token_hash,password_hash,expires_at,max_downloads)
    values(p_file,extensions.digest(token,'sha256'),extensions.crypt(p_password,extensions.gen_salt('bf',10)),
      clock_timestamp()+make_interval(secs=>p_seconds),p_downloads) returning id into link;
  insert into sectalk_private.st_v6_file_share_events(link_id,event) values(link,'link_created');
  return token;
end
$$;

create function public.st_v6_list_file_shares(p_file uuid)
returns table(id uuid,expires_at timestamptz,max_downloads integer,downloads integer,revoked_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_v2_active(auth.uid()) or not exists(
    select 1 from public.st_v5_files f where f.id=p_file and f.uploader=auth.uid() and f.message_id is not null
  ) then raise exception 'Attachment links are unavailable' using errcode='42501'; end if;
  return query select s.id,s.expires_at,s.max_downloads,s.downloads,s.revoked_at
    from sectalk_private.st_v6_file_share_links s where s.file_id=p_file
    order by (s.revoked_at is null and s.expires_at>now() and s.downloads<s.max_downloads) desc,s.created_at desc limit 25;
end
$$;

create function public.st_v6_revoke_file_share(p_file uuid,p_link uuid)
returns void language plpgsql security definer set search_path='' as $$
begin
  if not sectalk_private.st_v2_active(auth.uid()) or not exists(
    select 1 from public.st_v5_files f where f.id=p_file and f.uploader=auth.uid() and f.message_id is not null
  ) then raise exception 'Attachment links are unavailable' using errcode='42501'; end if;
  update sectalk_private.st_v6_file_share_links s set revoked_at=clock_timestamp()
    where s.file_id=p_file and s.id=p_link and s.revoked_at is null;
  if found then
    insert into sectalk_private.st_v6_file_share_events(link_id,event) values(p_link,'link_revoked');
  end if;
end
$$;

create function public.st_v6_access_file_share(p_token text,p_password text,p_action text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare link sectalk_private.st_v6_file_share_links;
declare file record;
declare attempt_minute timestamptz:=date_trunc('minute',clock_timestamp());
begin
  if p_token is null or length(p_token)<>64 or p_token !~ '^[0-9a-f]{64}$'
    or (octet_length(p_password) between 10 and 64) is not true
    or p_action is null or p_action not in ('view','peek','download') then return null; end if;
  select * into link from sectalk_private.st_v6_file_share_links s
    where s.token_hash=extensions.digest(p_token,'sha256') for update;
  if not found or link.revoked_at is not null or link.expires_at<=clock_timestamp()
    or link.downloads>=link.max_downloads or not sectalk_private.st_v6_shareable_file(link.file_id,null) then return null; end if;
  if p_action<>'download' then
    if link.attempt_bucket=attempt_minute and link.attempts>=12 then return null; end if;
    update sectalk_private.st_v6_file_share_links s set attempt_bucket=attempt_minute,
      attempts=case when s.attempt_bucket=attempt_minute then s.attempts+1 else 1 end where s.id=link.id;
  end if;
  if extensions.crypt(p_password,link.password_hash) is distinct from link.password_hash then return null; end if;
  if p_action='download' then
    update sectalk_private.st_v6_file_share_links s set downloads=s.downloads+1 where s.id=link.id;
    insert into sectalk_private.st_v6_file_share_events(link_id,event) values(link.id,'link_download');
  elsif p_action='view' then
    insert into sectalk_private.st_v6_file_share_events(link_id,event) values(link.id,'link_view');
  end if;
  select f.filename,f.size_bytes into file from public.st_v5_files f where f.id=link.file_id;
  return jsonb_build_object('file',link.file_id,'filename',file.filename,'size_bytes',file.size_bytes);
end
$$;

create or replace function public.st_v6_file_access_history(p_file uuid)
returns table(event text,participant text,occurred_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare context record;
begin
  if actor is null or not sectalk_private.st_v2_active(actor) then
    raise exception 'Attachment access history is unavailable' using errcode='42501';
  end if;
  select c.member_a,c.member_b,m.created_at as shared_at into context
    from public.st_v5_files f join public.st_chats c on c.id=f.chat_id
    join public.st_messages m on m.id=f.message_id
    where f.id=p_file and f.uploader=actor and actor in (c.member_a,c.member_b);
  if not found then raise exception 'Attachment access history is unavailable' using errcode='42501'; end if;

  return query
    select activity.event,activity.participant,activity.occurred_at from (
      select 'share'::text as event,'owner'::text as participant,context.shared_at as occurred_at,0::bigint as audit_order
      union all
      select d.event,case when d.actor_id=actor then 'owner' else 'recipient' end,d.requested_at,d.id
      from sectalk_private.st_v6_file_downloads d
      where d.file_id=p_file and d.actor_id in (context.member_a,context.member_b)
      union all
      select e.event,case when e.event in ('link_created','link_revoked') then 'owner' else 'link_visitor' end,e.occurred_at,e.id
      from sectalk_private.st_v6_file_share_links s join sectalk_private.st_v6_file_share_events e on e.link_id=s.id
      where s.file_id=p_file
    ) activity order by activity.occurred_at desc,activity.audit_order desc,activity.event limit 50;
end
$$;

revoke all on function public.st_v6_create_file_share(uuid,text,integer,integer),public.st_v6_list_file_shares(uuid),
  public.st_v6_revoke_file_share(uuid,uuid),public.st_v6_access_file_share(text,text,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_create_file_share(uuid,text,integer,integer),public.st_v6_list_file_shares(uuid),
  public.st_v6_revoke_file_share(uuid,uuid) to authenticated;
grant execute on function public.st_v6_access_file_share(text,text,text) to service_role;

commit;
