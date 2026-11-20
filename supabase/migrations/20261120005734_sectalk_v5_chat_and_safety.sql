begin;

alter table public.st_messages add column revoked_at timestamptz;
alter table public.st_reports drop constraint st_reports_category_check,
  add constraint st_reports_category_check check(category in
    ('harassment','threat','scam','impersonation','other','spam','sexual_content'));

create table public.st_v5_hidden_messages (
  message_id uuid not null references public.st_messages on delete cascade,
  user_id uuid not null references public.st_profiles on delete cascade,
  primary key(user_id,message_id)
);
alter table public.st_v5_hidden_messages enable row level security;
revoke all on public.st_v5_hidden_messages from public,anon,authenticated;
grant select on public.st_v5_hidden_messages to authenticated;
create policy st_v5_read_own_hidden on public.st_v5_hidden_messages for select to authenticated
  using(user_id=(select auth.uid()));

create function public.st_v5_message_action(p_message uuid,p_action text)
returns void language plpgsql security definer set search_path='' as $$
declare item public.st_messages; actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v5_message_controls',45);
  select * into item from public.st_messages where id=p_message for update;
  if not found or not sectalk_private.member(item.chat_id,actor) then raise exception 'Message unavailable'; end if;
  if p_action='hide' then
    insert into public.st_v5_hidden_messages(message_id,user_id) values(p_message,actor) on conflict do nothing;
  elsif p_action='revoke' and item.sender=actor then
    if item.revoked_at is not null then return; end if;
    delete from public.st_v2_message_edits where message_id=p_message;
    delete from public.st_v2_reactions where message_id=p_message;
    delete from public.st_v2_pins where message_id=p_message;
    update public.st_messages set body='Message removed',revoked_at=clock_timestamp(),edited_at=clock_timestamp()
      where id=p_message;
  else
    raise exception 'Message action unavailable';
  end if;
end $$;

-- Preserve the legacy edit contract while making a revoked message immutable.
create function sectalk_private.st_v5_keep_tombstone()
returns trigger language plpgsql set search_path='' as $$
begin
  if old.revoked_at is not null and (new.body is distinct from old.body or new.revoked_at is distinct from old.revoked_at)
    then raise exception 'This message was removed'; end if;
  return new;
end $$;
create trigger st_v5_keep_tombstone before update on public.st_messages for each row
  when(old.revoked_at is not null) execute function sectalk_private.st_v5_keep_tombstone();

create function public.st_v5_last_seen(p_chat uuid)
returns timestamptz language sql stable security definer set search_path='' as $$
  select p.expires_at-interval '100 seconds'
  from public.st_chats c join public.st_v3_presence p on p.user_id=
    case when c.member_a=auth.uid() then c.member_b else c.member_a end
  where c.id=p_chat and auth.uid() in(c.member_a,c.member_b) and c.status='accepted'
    and sectalk_private.open_pair(c.member_a,c.member_b) and p.state<>'offline'
    and p.expires_at>now()-interval '7 days'
$$;

create table public.st_v5_files (
  id uuid primary key,
  chat_id uuid not null references public.st_chats on delete cascade,
  uploader uuid not null references public.st_profiles,
  message_id uuid unique references public.st_messages on delete cascade,
  filename text not null check(char_length(filename) between 1 and 140),
  size_bytes integer not null check(size_bytes between 1 and 4194304),
  created_at timestamptz not null default now()
);
create index st_v5_files_chat on public.st_v5_files(chat_id,created_at desc);
create index st_v5_files_uploader on public.st_v5_files(uploader,created_at desc);
alter table public.st_v5_files enable row level security;
revoke all on public.st_v5_files from public,anon,authenticated;
grant select on public.st_v5_files to authenticated;
create policy st_v5_chat_files_read on public.st_v5_files for select to authenticated using(
  exists(select 1 from public.st_messages m where m.id=message_id and m.revoked_at is null)
);

create table sectalk_private.st_v5_attachment_reports (
  report_id uuid primary key references public.st_reports on delete cascade,
  file_id uuid not null references public.st_v5_files on delete cascade
);
create index st_v5_attachment_reports_file on sectalk_private.st_v5_attachment_reports(file_id);
alter table sectalk_private.st_v5_attachment_reports enable row level security;

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('sectalk-chat-files','sectalk-chat-files',false,4194304,array['application/octet-stream']);

create function sectalk_private.st_v5_attachment_access(p_path text,p_user uuid,p_operation text)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v5_files f where f.id=
    case when p_path ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then p_path::uuid end
    and p_user=auth.uid() and (
      (p_operation='upload' and f.uploader=p_user and f.message_id is null and f.created_at>now()-interval '15 minutes'
        and sectalk_private.st_v2_chat_write(f.chat_id,p_user))
      or (p_operation='download' and (
        (sectalk_private.member(f.chat_id,p_user) and exists(select 1 from public.st_messages m
          where m.id=f.message_id and m.revoked_at is null))
        or (public.st_staff_status()='verified' and exists(select 1 from sectalk_private.st_v5_attachment_reports e where e.file_id=f.id))
      ))
    ))
$$;
revoke all on function sectalk_private.st_v5_attachment_access(text,uuid,text) from public,anon,authenticated;
grant execute on function sectalk_private.st_v5_attachment_access(text,uuid,text) to authenticated;
create policy st_v5_attachment_insert on storage.objects for insert to authenticated with check(
  bucket_id='sectalk-chat-files' and sectalk_private.st_v5_attachment_access(name,(select auth.uid()),'upload')
);
create policy st_v5_attachment_read on storage.objects for select to authenticated using(
  bucket_id='sectalk-chat-files' and sectalk_private.st_v5_attachment_access(name,(select auth.uid()),'download')
);
create policy st_v5_attachment_guard_read on storage.objects as restrictive for select to public using(
  case when bucket_id='sectalk-chat-files' then
    case when (select auth.uid()) is null then false else sectalk_private.st_v5_attachment_access(name,(select auth.uid()),'download') end
  else true end
);
create policy st_v5_attachment_guard_insert on storage.objects as restrictive for insert to public with check(
  case when bucket_id='sectalk-chat-files' then
    case when (select auth.uid()) is null then false else sectalk_private.st_v5_attachment_access(name,(select auth.uid()),'upload') end
  else true end
);
create policy st_v5_attachment_guard_update on storage.objects as restrictive for update to public
  using(bucket_id<>'sectalk-chat-files') with check(bucket_id<>'sectalk-chat-files');
create policy st_v5_attachment_guard_delete on storage.objects as restrictive for delete to public
  using(bucket_id<>'sectalk-chat-files');

create function public.st_v5_stage_file(p_chat uuid,p_id uuid,p_filename text,p_bytes integer)
returns boolean language plpgsql security definer set search_path='' as $$
declare previous public.st_v5_files; clean_name text; actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v5_attachment_stage',8);
  if not sectalk_private.st_v2_chat_write(p_chat,actor) then raise exception 'Conversation unavailable'; end if;
  clean_name:=regexp_replace(btrim(p_filename),'[/[:cntrl:][:space:]]+',' ','g');
  if clean_name is null or char_length(clean_name) not between 1 and 140 or strpos(clean_name,chr(92))>0
    or clean_name !~* '[.](png|jpe?g|webp|gif|pdf|txt)$' or p_bytes is null or p_bytes not between 1 and 4194304
    then raise exception 'Choose a supported file up to 4 MiB'; end if;
  insert into public.st_v5_files(id,chat_id,uploader,filename,size_bytes)
    values(p_id,p_chat,actor,clean_name,p_bytes) on conflict(id) do nothing;
  select * into previous from public.st_v5_files where id=p_id;
  if previous.uploader<>actor or previous.chat_id<>p_chat or previous.filename<>clean_name or previous.size_bytes<>p_bytes
    or (previous.message_id is null and previous.created_at<=now()-interval '15 minutes')
    then raise exception 'Start a new attachment upload'; end if;
  return exists(select 1 from storage.objects where bucket_id='sectalk-chat-files' and name=p_id::text);
end $$;

create function public.st_v5_send_file(p_id uuid,p_caption text)
returns uuid language plpgsql security definer set search_path='' as $$
declare f public.st_v5_files; body_text text; object_size text;
begin
  perform sectalk_private.limit_action('v5_attachment_send',12);
  select * into f from public.st_v5_files where id=p_id and uploader=auth.uid() for update;
  if not found or not sectalk_private.st_v2_chat_write(f.chat_id,auth.uid())
    then raise exception 'Attachment unavailable'; end if;
  if f.message_id is not null then return f.message_id; end if;
  if f.created_at<=now()-interval '15 minutes' then raise exception 'Start a new attachment upload'; end if;
  select metadata->>'size' into object_size from storage.objects where bucket_id='sectalk-chat-files' and name=f.id::text;
  if object_size is distinct from f.size_bytes::text then raise exception 'Attachment upload is incomplete'; end if;
  body_text:=coalesce(nullif(btrim(p_caption),''),'Attachment: '||f.filename);
  perform public.st_send(f.chat_id,f.id,body_text);
  update public.st_v5_files set message_id=f.id where id=f.id;
  return f.id;
end $$;

create function public.st_v5_report(p_chat uuid,p_message uuid,p_category text,p_details text,p_share_file boolean default false)
returns uuid language plpgsql security definer set search_path='' as $$
declare report uuid; attachment uuid;
begin
  if p_message is not null then
    perform id from public.st_messages where id=p_message and chat_id=p_chat and revoked_at is null for update;
    if not found then raise exception 'Report the contact if the message was removed'; end if;
  end if;
  report:=public.st_report(p_chat,p_message,p_category,p_details);
  if p_share_file and p_message is not null then
    select f.id into attachment from public.st_v5_files f where f.message_id=p_message and f.chat_id=p_chat;
    if attachment is not null then
      insert into sectalk_private.st_v5_attachment_reports(report_id,file_id) values(report,attachment);
    end if;
  end if;
  return report;
end $$;

create table public.st_v5_account_notices (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.st_profiles on delete cascade,
  action text not null check(action in ('warn','suspend','restrict','remove','restore')),
  until_at timestamptz,
  created_at timestamptz not null default now()
);
create index st_v5_notices_user on public.st_v5_account_notices(user_id,id desc);
alter table public.st_v5_account_notices enable row level security;
revoke all on public.st_v5_account_notices from public,anon,authenticated;
grant select on public.st_v5_account_notices to authenticated;
create policy st_v5_notice_read on public.st_v5_account_notices for select to authenticated using(user_id=(select auth.uid()));

create function public.st_v5_report_timeline(p_report uuid)
returns table(action text,at timestamptz)
language sql stable security definer set search_path='' as $$
  select 'submitted'::text,r.created_at from public.st_reports r where r.id=p_report and r.reporter=auth.uid()
  union all
  select a.action,a.created_at from sectalk_private.audit a join public.st_reports r on r.id=a.report_id
  where r.id=p_report and r.reporter=auth.uid() and a.action in
    ('reviewing','escalated','warn','suspend','restrict','remove','restore','resolved','dismissed')
  order by 2 desc limit 100
$$;

create function public.st_v5_case(p_report uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare result jsonb; attachment jsonb;
begin
  result:=public.st_case(p_report);
  select jsonb_build_object('id',f.id,'filename',f.filename,'size_bytes',f.size_bytes) into attachment
    from sectalk_private.st_v5_attachment_reports e join public.st_v5_files f on f.id=e.file_id where e.report_id=p_report;
  return result||jsonb_build_object('attachment',attachment);
end $$;

create function public.st_v5_moderate(p_report uuid,p_action text,p_note text)
returns void language plpgsql security definer set search_path='' as $$
declare target public.st_reports; deadline timestamptz;
begin
  if public.st_staff_status()<>'verified' then raise exception 'Staff MFA required'; end if;
  if p_action in ('reviewing','resolved','dismissed') then
    perform public.st_moderate(p_report,p_action,p_note);
    return;
  end if;
  perform sectalk_private.limit_action('moderate',20);
  if p_action is null or p_action not in ('escalated','warn','suspend','restrict','remove','restore')
    or p_note is null or char_length(btrim(p_note)) not between 4 and 500 then raise exception 'Enter a moderation action and reason'; end if;
  select * into target from public.st_reports where id=p_report for update;
  if not found then raise exception 'Report unavailable'; end if;
  if p_action='escalated' then
    update public.st_reports set status='reviewing' where id=p_report;
  else
    if target.subject=auth.uid() or exists(select 1 from sectalk_private.staff where user_id=target.subject)
      then raise exception 'Staff account actions require an account operator'; end if;
    if p_action in ('suspend','restrict','remove') then
      deadline:=case p_action when 'suspend' then now()+interval '24 hours'
        when 'restrict' then now()+interval '7 days' else 'infinity'::timestamptz end;
      insert into sectalk_private.suspensions as current(user_id,until_at) values(target.subject,deadline)
        on conflict(user_id) do update set until_at=greatest(current.until_at,excluded.until_at)
        returning until_at into deadline;
      update public.st_calls set status='ended',expires_at=now() where target.subject in(caller,callee) and status<>'ended';
    elsif p_action='restore' then
      delete from sectalk_private.suspensions where user_id=target.subject;
    end if;
    insert into public.st_v5_account_notices(user_id,action,until_at) values(target.subject,p_action,deadline);
  end if;
  insert into sectalk_private.audit(actor,report_id,action,note) values(auth.uid(),p_report,p_action,btrim(p_note));
end $$;

create table public.st_v5_discovery (
  user_id uuid primary key references public.st_profiles on delete cascade,
  stage text not null check(stage in ('student','college','professional','freelancer','founder','career_change','retired','other')),
  categories text[] not null check(cardinality(categories)<=8),
  discoverable boolean not null default false
);
create index st_v5_discovery_categories on public.st_v5_discovery using gin(categories) where discoverable;
create index st_v5_discovery_stage on public.st_v5_discovery(stage,user_id) where discoverable;
alter table public.st_v5_discovery enable row level security;
revoke all on public.st_v5_discovery from public,anon,authenticated;
grant select on public.st_v5_discovery to authenticated;
create policy st_v5_discovery_self on public.st_v5_discovery for select to authenticated using(user_id=(select auth.uid()));

create function public.st_v5_save_discovery(p_stage text,p_categories text[],p_discoverable boolean,p_adult boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v5_discovery_settings',10);
  if not exists(select 1 from public.st_profiles where id=actor) then raise exception 'Create a profile first'; end if;
  if p_categories is null or cardinality(p_categories)>8 or exists(select 1 from unnest(p_categories) as value
    where value is null or value !~ '^(work-[0-9]{2}-[0-9]{4}\.[0-9]{2}|(interest|study)-[a-z0-9-]{1,55})$')
    then raise exception 'Choose up to eight categories'; end if;
  if p_discoverable and p_adult is distinct from true then raise exception 'Discovery is for adults'; end if;
  insert into public.st_v5_discovery(user_id,stage,categories,discoverable)
  values(actor,p_stage,array(select distinct value from unnest(p_categories) as value order by value),coalesce(p_discoverable,false))
  on conflict(user_id) do update set stage=excluded.stage,categories=excluded.categories,discoverable=excluded.discoverable;
end $$;

create function public.st_v5_find_friends(p_query text,p_stage text,p_category text)
returns table(handle text,name text,stage text,categories text[])
language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); needle text:=lower(btrim(coalesce(p_query,'')));
begin
  perform sectalk_private.limit_action('v5_discovery_search',12);
  if char_length(needle)>64 or (char_length(needle)<2 and p_stage is null and p_category is null) then return; end if;
  if not sectalk_private.st_v2_active(actor) or not exists(select 1 from public.st_v5_discovery where user_id=actor and discoverable)
    then raise exception 'Turn on discovery to browse public profiles'; end if;
  return query
    select p.handle,p.name,d.stage,d.categories
    from public.st_v5_discovery d join public.st_profiles p on p.id=d.user_id
    where d.discoverable and d.user_id<>actor
      and (p_stage is null or d.stage=p_stage)
      and (p_category is null or d.categories @> array[p_category])
      and (char_length(needle)<2 or strpos(lower(p.name),needle)>0 or strpos(lower(p.handle),needle)>0)
      and sectalk_private.open_pair(d.user_id,actor)
      and not exists(select 1 from public.st_chats c where c.member_a=least(d.user_id,actor) and c.member_b=greatest(d.user_id,actor))
    order by lower(p.name),p.handle limit 24;
end $$;

create table public.st_v5_profile_details (
  user_id uuid primary key references public.st_profiles on delete cascade,
  status_message text not null default '' check(char_length(status_message)<=140),
  photo_revision uuid
);
alter table public.st_v5_profile_details enable row level security;
revoke all on public.st_v5_profile_details from public,anon,authenticated;
grant select on public.st_v5_profile_details to authenticated;

create function sectalk_private.st_v5_profile_visible(p_target uuid,p_actor uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select p_actor is not null and p_actor=auth.uid() and
    (p_target=p_actor or exists(select 1 from public.st_chats where member_a=least(p_target,p_actor)
      and member_b=greatest(p_target,p_actor) and status='accepted' and sectalk_private.open_pair(p_target,p_actor)))
$$;
revoke all on function sectalk_private.st_v5_profile_visible(uuid,uuid) from public,anon,authenticated;
grant execute on function sectalk_private.st_v5_profile_visible(uuid,uuid) to authenticated;
create policy st_v5_profile_details_read on public.st_v5_profile_details for select to authenticated
  using(sectalk_private.st_v5_profile_visible(user_id,(select auth.uid())));

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('sectalk-avatars','sectalk-avatars',false,262144,array['image/jpeg']);
create function sectalk_private.st_v5_avatar_read(p_path text,p_actor uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select case when p_path ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[.]jpg$'
    then sectalk_private.st_v5_profile_visible(left(p_path,36)::uuid,p_actor)
    else false end
$$;
revoke all on function sectalk_private.st_v5_avatar_read(text,uuid) from public,anon,authenticated;
grant execute on function sectalk_private.st_v5_avatar_read(text,uuid) to authenticated;
create policy st_v5_avatar_read on storage.objects for select to authenticated using(
  bucket_id='sectalk-avatars' and sectalk_private.st_v5_avatar_read(name,(select auth.uid()))
);
create policy st_v5_avatar_restrict_read on storage.objects as restrictive for select to public using(
  case when bucket_id='sectalk-avatars' then
    case when (select auth.uid()) is null then false else sectalk_private.st_v5_avatar_read(name,(select auth.uid())) end
  else true end
);
create policy st_v5_avatar_restrict_write on storage.objects as restrictive for insert to public with check(
  bucket_id<>'sectalk-avatars' or name=(select auth.uid())::text||'.jpg'
);
create policy st_v5_avatar_guard_update on storage.objects as restrictive for update to public
  using(bucket_id<>'sectalk-avatars' or name=(select auth.uid())::text||'.jpg')
  with check(bucket_id<>'sectalk-avatars' or name=(select auth.uid())::text||'.jpg');
create policy st_v5_avatar_guard_delete on storage.objects as restrictive for delete to public
  using(bucket_id<>'sectalk-avatars' or name=(select auth.uid())::text||'.jpg');
create policy st_v5_avatar_insert on storage.objects for insert to authenticated with check(
  bucket_id='sectalk-avatars' and name=(select auth.uid())::text||'.jpg'
);
create policy st_v5_avatar_update on storage.objects for update to authenticated
  using(bucket_id='sectalk-avatars' and name=(select auth.uid())::text||'.jpg')
  with check(bucket_id='sectalk-avatars' and name=(select auth.uid())::text||'.jpg');
create policy st_v5_avatar_delete on storage.objects for delete to authenticated
  using(bucket_id='sectalk-avatars' and name=(select auth.uid())::text||'.jpg');

create function public.st_v5_profile_details_save(p_status text,p_refresh_photo boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); status_text text:=btrim(p_status); revision uuid;
begin
  perform sectalk_private.limit_action('v5_profile_details',12);
  if not exists(select 1 from public.st_profiles where id=actor) then raise exception 'Create a profile first'; end if;
  if p_status is not null and char_length(status_text)>140 then raise exception 'Use 140 characters or fewer'; end if;
  if p_refresh_photo and exists(select 1 from storage.objects where bucket_id='sectalk-avatars' and name=actor::text||'.jpg') then
    revision:=gen_random_uuid();
  end if;
  insert into public.st_v5_profile_details as profile(user_id,status_message,photo_revision) values(actor,coalesce(status_text,''),revision)
    on conflict(user_id) do update set
      status_message=coalesce(status_text,profile.status_message),
      photo_revision=case when p_refresh_photo then revision else profile.photo_revision end;
end $$;

create function public.st_v5_profile_activity()
returns jsonb language sql stable security invoker set search_path='' as $$
  select jsonb_build_object('sent',count(*) filter(where sender=auth.uid()),
    'received',count(*) filter(where sender<>auth.uid()),
    'reports',(select count(*) from public.st_reports where reporter=auth.uid()),
    'open_reports',(select count(*) from public.st_reports where reporter=auth.uid() and status in('open','reviewing')))
  from public.st_messages m where m.revoked_at is null and not exists(
    select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=auth.uid())
$$;

do $$
declare signature text;
begin
  for signature in select p.oid::regprocedure::text from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and left(p.proname,6)='st_v5_'
  loop
    execute 'revoke all on function '||signature||' from public,anon,authenticated';
    execute 'grant execute on function '||signature||' to authenticated';
  end loop;
end $$;
commit;
