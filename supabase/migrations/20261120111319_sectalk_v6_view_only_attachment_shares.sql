begin;

alter table sectalk_private.st_v6_file_share_links
  add column view_only boolean not null default false,
  add column watermark boolean not null default false,
  add constraint st_v6_file_share_watermark_mode check(not watermark or view_only);
alter table sectalk_private.st_v6_file_share_events
  drop constraint st_v6_file_share_events_event_check,
  add constraint st_v6_file_share_events_event_check
    check(event in ('link_created','link_revoked','link_view','link_download','link_preview'));

create function public.st_v6_create_file_share(p_file uuid,p_password text,p_seconds integer,p_downloads integer,p_view_only boolean,p_watermark boolean)
returns text language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare token text;
declare link uuid;
begin
  if actor is null then raise exception 'Sign in first' using errcode='42501'; end if;
  if p_view_only is null or p_watermark is null or (p_watermark and not p_view_only)
    then raise exception 'Choose valid link controls' using errcode='22023'; end if;
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
  insert into sectalk_private.st_v6_file_share_links(file_id,token_hash,password_hash,expires_at,max_downloads,view_only,watermark)
    values(p_file,extensions.digest(token,'sha256'),extensions.crypt(p_password,extensions.gen_salt('bf',10)),
      clock_timestamp()+make_interval(secs=>p_seconds),p_downloads,p_view_only,p_watermark) returning id into link;
  insert into sectalk_private.st_v6_file_share_events(link_id,event) values(link,'link_created');
  return token;
end
$$;

create or replace function public.st_v6_create_file_share(p_file uuid,p_password text,p_seconds integer,p_downloads integer)
returns text language sql security definer set search_path='' as $$
  select public.st_v6_create_file_share(p_file,p_password,p_seconds,p_downloads,false,false)
$$;

drop function public.st_v6_list_file_shares(uuid);
create function public.st_v6_list_file_shares(p_file uuid)
returns table(id uuid,expires_at timestamptz,max_downloads integer,downloads integer,revoked_at timestamptz,view_only boolean,watermark boolean)
language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_v2_active(auth.uid()) or not exists(
    select 1 from public.st_v5_files f where f.id=p_file and f.uploader=auth.uid() and f.message_id is not null
  ) then raise exception 'Attachment links are unavailable' using errcode='42501'; end if;
  return query select s.id,s.expires_at,s.max_downloads,s.downloads,s.revoked_at,s.view_only,s.watermark
    from sectalk_private.st_v6_file_share_links s where s.file_id=p_file
    order by (s.revoked_at is null and s.expires_at>now() and s.downloads<s.max_downloads) desc,s.created_at desc limit 25;
end
$$;
create or replace function public.st_v6_access_file_share(p_token text,p_password text,p_action text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare link sectalk_private.st_v6_file_share_links;
declare file record;
declare attempt_minute timestamptz:=date_trunc('minute',clock_timestamp());
begin
  if p_token is null or length(p_token)<>64 or p_token !~ '^[0-9a-f]{64}$'
    or (octet_length(p_password) between 10 and 64) is not true
    or p_action is null or p_action not in ('view','peek','download','preview_peek','preview') then return null; end if;
  select * into link from sectalk_private.st_v6_file_share_links s
    where s.token_hash=extensions.digest(p_token,'sha256') for update;
  if not found or link.revoked_at is not null or link.expires_at<=clock_timestamp()
    or link.downloads>=link.max_downloads or not sectalk_private.st_v6_shareable_file(link.file_id,null) then return null; end if;
  if (link.view_only and p_action in ('peek','download'))
    or (not link.view_only and p_action in ('preview_peek','preview')) then return null; end if;
  if p_action not in ('download','preview') then
    if link.attempt_bucket=attempt_minute and link.attempts>=12 then return null; end if;
    update sectalk_private.st_v6_file_share_links s set attempt_bucket=attempt_minute,
      attempts=case when s.attempt_bucket=attempt_minute then s.attempts+1 else 1 end where s.id=link.id;
  end if;
  if extensions.crypt(p_password,link.password_hash) is distinct from link.password_hash then return null; end if;
  if p_action in ('download','preview') then
    update sectalk_private.st_v6_file_share_links s set downloads=s.downloads+1 where s.id=link.id;
    insert into sectalk_private.st_v6_file_share_events(link_id,event) values(link.id,case when p_action='preview' then 'link_preview' else 'link_download' end);
  elsif p_action='view' then
    insert into sectalk_private.st_v6_file_share_events(link_id,event) values(link.id,'link_view');
  end if;
  select f.filename,f.size_bytes into file from public.st_v5_files f where f.id=link.file_id;
  return jsonb_build_object('file',link.file_id,'filename',file.filename,'size_bytes',file.size_bytes,'view_only',link.view_only,'watermark',link.watermark);
end
$$;

revoke all on function public.st_v6_create_file_share(uuid,text,integer,integer,boolean,boolean),
  public.st_v6_list_file_shares(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_create_file_share(uuid,text,integer,integer,boolean,boolean),
  public.st_v6_list_file_shares(uuid) to authenticated;

commit;
