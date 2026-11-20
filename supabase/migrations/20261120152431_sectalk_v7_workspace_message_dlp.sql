begin;

select vault.create_secret(encode(extensions.gen_random_bytes(32),'hex'),
  'sectalk_v7_dlp_receipt_hmac','Binds confirmations and retries to exact managed text without retaining a second copy');

create table sectalk_private.st_v7_workspace_dlp (
  workspace_id uuid primary key references public.st_v2_workspaces on delete cascade,
  revision integer not null check(revision>0),
  rules jsonb not null,
  updated_at timestamptz not null default clock_timestamp()
);
create table sectalk_private.st_v7_dlp_acknowledgements (
  actor uuid not null references auth.users on delete cascade,
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  scope_type text not null check(scope_type in ('room','channel')),
  scope_id uuid not null,
  message_id uuid not null,
  revision integer not null,
  fingerprint bytea not null check(octet_length(fingerprint)=32),
  expires_at timestamptz not null,
  primary key(actor,scope_type,scope_id,message_id)
);
create index st_v7_dlp_ack_expiry on sectalk_private.st_v7_dlp_acknowledgements(expires_at);
create table sectalk_private.st_v7_dlp_delivery_receipts (
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  scope_type text not null check(scope_type in ('room','channel')),
  scope_id uuid not null,
  message_id uuid not null,
  actor uuid not null references auth.users on delete cascade,
  fingerprint bytea not null check(octet_length(fingerprint)=32),
  primary key(scope_type,scope_id,message_id)
);
alter table sectalk_private.st_v7_workspace_dlp enable row level security;
alter table sectalk_private.st_v7_dlp_acknowledgements enable row level security;
alter table sectalk_private.st_v7_dlp_delivery_receipts enable row level security;
revoke all on sectalk_private.st_v7_workspace_dlp,sectalk_private.st_v7_dlp_acknowledgements,
  sectalk_private.st_v7_dlp_delivery_receipts from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_dlp_luhn(candidate text)
returns boolean language plpgsql immutable strict set search_path='' as $$
declare digits text:=regexp_replace(candidate,'\D','','g'); total integer:=0; value integer; i integer;
begin
  if length(digits) not between 13 and 19 or digits=repeat(left(digits,1),length(digits)) then return false; end if;
  for i in 1..length(digits) loop
    value:=substr(digits,i,1)::integer;
    if (length(digits)-i)%2=1 then value:=case when value>4 then value*2-9 else value*2 end; end if;
    total:=total+value;
  end loop;
  return total%10=0;
end $$;

create function sectalk_private.st_v7_dlp_matches(body text)
returns table(category text,token text)
language sql immutable strict set search_path='' as $$
  select 'payment_card',m[1] from regexp_matches(body,'(?<![0-9])([0-9](?:[ -]?[0-9]){12,18})(?![ -]?[0-9])','g') m
    where sectalk_private.st_v7_dlp_luhn(m[1])
  union all
  select 'pii',m[1] from regexp_matches(body,'([a-z0-9.!#$%&''*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+)','gi') m
  union all
  select 'phi',m[1] from regexp_matches(body,'\m((?:medical record(?: number)?|patient id|mrn)[[:space:]]*[:#=][[:space:]]*[a-z0-9-]{4,40})','gi') m
  union all
  select 'credential',m[1] from regexp_matches(body,'\m((?:authorization[[:space:]]*:[[:space:]]*bearer[[:space:]]+|(?:api[ _-]?key|password|secret[ _-]?key)[[:space:]]*[:=][[:space:]]*)[a-z0-9_./+~=-]{7,180})','gi') m
$$;

create function sectalk_private.st_v7_dlp_digest(body text)
returns bytea language sql stable strict security definer set search_path='' as $$
  select extensions.hmac(btrim(body),s.decrypted_secret,'sha256')
  from vault.decrypted_secrets s where s.name='sectalk_v7_dlp_receipt_hmac';
$$;

create function public.st_v7_workspace_dlp(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare access text:=sectalk_private.st_v6_holds_access(p_workspace);
begin
  if access='none' then raise exception 'Workspace data loss controls are unavailable' using errcode='42501'; end if;
  if access<>'verified' or not coalesce(sectalk_private.st_v7_admin_fresh(),false) then return jsonb_build_object('access','mfa'); end if;
  return jsonb_build_object('access','verified','revision',coalesce((select p.revision from sectalk_private.st_v7_workspace_dlp p
    where p.workspace_id=p_workspace),0),'rules',coalesce((select p.rules from sectalk_private.st_v7_workspace_dlp p
    where p.workspace_id=p_workspace),'{"pii":"allow","phi":"allow","payment_card":"allow","credential":"allow"}'::jsonb));
end $$;

create function public.st_v7_set_workspace_dlp(p_workspace uuid,p_revision integer,p_rules jsonb)
returns integer language plpgsql security definer set search_path='' as $$
declare prior integer; installed integer;
begin
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' or not coalesce(sectalk_private.st_v7_admin_fresh(),false) then
    raise exception 'Fresh authenticator verification required' using errcode='42501';
  end if;
  if jsonb_typeof(p_rules) is distinct from 'object' or p_revision is null or p_revision<0 then
    raise exception 'Invalid data loss policy' using errcode='22023';
  end if;
  if (select count(*) from jsonb_each_text(p_rules) e where e.key in ('pii','phi','payment_card','credential')
    and e.value in ('allow','warn','block','redact'))<>4 or (select count(*) from jsonb_object_keys(p_rules))<>4 then
    raise exception 'Choose an action for each sensitive pattern' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v7_workspace_dlp',15);
  perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
  if not found or sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Workspace data loss controls are unavailable' using errcode='42501';
  end if;
  select revision into prior from sectalk_private.st_v7_workspace_dlp where workspace_id=p_workspace;
  if coalesce(prior,0)<>p_revision then raise exception 'Workspace policy changed. Reload before saving' using errcode='PT409'; end if;
  insert into sectalk_private.st_v7_workspace_dlp as d(workspace_id,revision,rules)
    values(p_workspace,1,p_rules) on conflict(workspace_id) do update
    set revision=d.revision+1,rules=excluded.rules,updated_at=clock_timestamp()
    returning revision into installed;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,auth.uid(),'workspace.data_loss_policy_changed',p_workspace);
  return installed;
end $$;

create function public.st_v7_acknowledge_dlp(p_scope_type text,p_scope uuid,p_message uuid,p_body text)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); tenant uuid; policy sectalk_private.st_v7_workspace_dlp;
begin
  if actor is null or p_message is null or p_body is null or char_length(p_body) not between 1 and 4000 then
    raise exception 'Message confirmation unavailable' using errcode='42501'; end if;
  if p_scope_type='room' then
    select r.workspace_id into tenant from public.st_v6_rooms r where r.id=p_scope and not r.archived
      and sectalk_private.st_v6_room_role(r.id) in ('owner','moderator','member','guest');
  elsif p_scope_type='channel' then
    select c.workspace_id into tenant from public.st_v2_channels c where c.id=p_scope and not c.archived
      and sectalk_private.st_v6_channel_content_access(c.id,actor);
  end if;
  if tenant is null then raise exception 'Message confirmation unavailable' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v7_dlp_confirm',30);
  select * into policy from sectalk_private.st_v7_workspace_dlp where workspace_id=tenant for share;
  if not found or not exists(select 1 from sectalk_private.st_v7_dlp_matches(p_body) m where policy.rules->>m.category='warn') then
    raise exception 'Workspace policy changed. Review the message again' using errcode='PT409';
  end if;
  insert into sectalk_private.st_v7_dlp_acknowledgements(actor,workspace_id,scope_type,scope_id,message_id,revision,fingerprint,expires_at)
    values(actor,tenant,p_scope_type,p_scope,p_message,policy.revision,sectalk_private.st_v7_dlp_digest(p_body),clock_timestamp()+interval '2 minutes')
    on conflict on constraint st_v7_dlp_acknowledgements_pkey do update set revision=excluded.revision,
      fingerprint=excluded.fingerprint,expires_at=excluded.expires_at;
end $$;

create function sectalk_private.st_v7_apply_message_dlp()
returns trigger language plpgsql security definer set search_path='' as $$
declare source text; scope uuid; tenant uuid; policy sectalk_private.st_v7_workspace_dlp;
  original text:=new.body; entry record; warnings text[]:='{}'; blocked text[]:='{}'; signature bytea;
begin
  if tg_table_name='st_v6_room_posts' then
    source:='room'; scope:=new.room_id;
    if tg_op='UPDATE' and (new.removed_at is not null or old.body is not distinct from new.body) then
      if new.removed_at is not null then
        delete from sectalk_private.st_v7_dlp_delivery_receipts r where r.scope_type=source and r.scope_id=scope and r.message_id=new.id;
      end if;
      return new;
    end if;
    select x.workspace_id into tenant from public.st_v6_rooms x where x.id=scope;
  else
    source:='channel'; scope:=new.channel_id;
    if tg_op='UPDATE' and old.body is not distinct from new.body then return new; end if;
    select x.workspace_id into tenant from public.st_v2_channels x where x.id=scope;
  end if;
  if tg_op='UPDATE' then
    delete from sectalk_private.st_v7_dlp_delivery_receipts r where r.scope_type=source and r.scope_id=scope and r.message_id=new.id;
  end if;
  select * into policy from sectalk_private.st_v7_workspace_dlp where workspace_id=tenant for share;
  if not found or new.body is null or char_length(new.body)>4000 then return new; end if;
  for entry in select m.* from sectalk_private.st_v7_dlp_matches(original) m order by length(m.token) desc loop
    case policy.rules->>entry.category
      when 'block' then blocked:=array_append(blocked,entry.category);
      when 'warn' then warnings:=array_append(warnings,entry.category);
      when 'redact' then new.body:=replace(new.body,entry.token,'[…]');
      else null;
    end case;
  end loop;
  if cardinality(blocked)>0 then raise exception 'Workspace policy blocked sensitive information'
    using errcode='PT422',detail=(select string_agg(distinct category,',') from unnest(blocked) category); end if;
  if cardinality(warnings)>0 then
    signature:=sectalk_private.st_v7_dlp_digest(original);
    delete from sectalk_private.st_v7_dlp_acknowledgements a where a.actor=auth.uid() and a.scope_type=source
      and a.scope_id=scope and a.message_id=new.id and a.workspace_id=tenant and a.revision=policy.revision
      and a.fingerprint=signature and a.expires_at>clock_timestamp();
    if not found then raise exception 'Confirm the workspace sensitive information warning'
      using errcode='PT428',detail=(select string_agg(distinct category,',') from unnest(warnings) category); end if;
  end if;
  if new.body is distinct from original then
    insert into sectalk_private.st_v7_dlp_delivery_receipts(workspace_id,scope_type,scope_id,message_id,actor,fingerprint)
      values(tenant,source,scope,new.id,new.sender,coalesce(signature,sectalk_private.st_v7_dlp_digest(original)))
      on conflict(scope_type,scope_id,message_id) do update set actor=excluded.actor,fingerprint=excluded.fingerprint;
  end if;
  return new;
end $$;

create trigger st_v7_room_message_dlp before insert or update of body on public.st_v6_room_posts
  for each row execute function sectalk_private.st_v7_apply_message_dlp();
create trigger st_v7_channel_message_dlp before insert or update of body on public.st_v2_posts
  for each row execute function sectalk_private.st_v7_apply_message_dlp();

create function sectalk_private.st_v7_dlp_is_retry(source text,scope uuid,message uuid,sender uuid,body text)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v7_dlp_delivery_receipts r where r.scope_type=source and r.scope_id=scope
    and r.message_id=message and r.actor=sender and r.fingerprint=sectalk_private.st_v7_dlp_digest(body));
$$;

create or replace function sectalk_private.st_v6_write_room_post(p_room uuid,p_id uuid,p_body text,p_kind text,p_parent uuid,p_forwarded boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); r public.st_v6_rooms; actor_room_role text;
begin
  select * into r from public.st_v6_rooms where id=p_room for update;
  actor_room_role:=sectalk_private.st_v6_room_role(p_room);
  if not found or r.archived or actor_room_role is null or actor_room_role='read_only'
    or (r.locked and actor_room_role not in ('owner','moderator'))
    or ((r.kind in ('announcement','broadcast') or p_kind='announcement') and actor_room_role not in ('owner','moderator'))
    or (r.kind='announcement' and p_kind is distinct from 'announcement')
    or (p_kind='announcement' and p_parent is not null)
    or exists(select 1 from public.st_v6_room_timeouts where room_id=p_room and user_id=actor and until_at>now())
    then raise exception 'Posting is unavailable'; end if;
  if exists(select 1 from public.st_v6_room_posts where room_id=p_room and id=p_id) then
    if exists(select 1 from public.st_v6_room_posts where room_id=p_room and id=p_id and sender=actor and removed_at is null
      and (body=btrim(p_body) or sectalk_private.st_v7_dlp_is_retry('room',p_room,p_id,actor,p_body))
      and kind=p_kind and parent_id is not distinct from p_parent and forwarded=p_forwarded) then return; end if;
    raise exception 'Message ID already in use';
  end if;
  if p_parent is not null and not exists(select 1 from public.st_v6_room_posts where room_id=p_room and id=p_parent and parent_id is null)
    then raise exception 'Thread unavailable'; end if;
  if r.slow_seconds>0 and actor_room_role not in ('owner','moderator')
    and exists(select 1 from public.st_v6_room_posts where room_id=p_room and sender=actor and created_at>clock_timestamp()-make_interval(secs=>r.slow_seconds))
    then raise exception 'Slow mode is on. Wait before posting again.'; end if;
  insert into public.st_v6_room_posts(room_id,id,sender,body,kind,parent_id,forwarded)
    values(p_room,p_id,actor,btrim(p_body),p_kind,p_parent,p_forwarded);
  if p_kind='announcement' then
    insert into public.st_v6_room_audit(room_id,actor,action,target) values(p_room,actor,'post.announcement',p_id);
  end if;
end $$;

create or replace function public.st_v2_post(p_channel uuid,p_id uuid,p_body text)
returns void language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); is_archived boolean;
begin
  perform sectalk_private.limit_action('v2_post',60);
  select archived into is_archived from public.st_v2_channels where id=p_channel for update;
  if not found or is_archived or not sectalk_private.st_v6_channel_content_access(p_channel,me)
    then raise exception 'Channel unavailable'; end if;
  if exists(select 1 from public.st_v2_posts where id=p_id and channel_id=p_channel and sender=me
    and (body=btrim(p_body) or sectalk_private.st_v7_dlp_is_retry('channel',p_channel,p_id,me,p_body))) then return; end if;
  insert into public.st_v2_posts(id,channel_id,sender,body) values(p_id,p_channel,me,btrim(p_body)) on conflict(id) do nothing;
  if not found then raise exception 'Message ID already in use'; end if;
end $$;

create function sectalk_private.st_v7_delete_dlp_receipt()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if tg_table_name='st_v6_room_posts' then
    delete from sectalk_private.st_v7_dlp_delivery_receipts where scope_type='room' and scope_id=old.room_id and message_id=old.id;
  else
    delete from sectalk_private.st_v7_dlp_delivery_receipts where scope_type='channel' and scope_id=old.channel_id and message_id=old.id;
  end if;
  return old;
end $$;
create trigger st_v7_delete_room_dlp_receipt after delete on public.st_v6_room_posts
  for each row execute function sectalk_private.st_v7_delete_dlp_receipt();
create trigger st_v7_delete_channel_dlp_receipt after delete on public.st_v2_posts
  for each row execute function sectalk_private.st_v7_delete_dlp_receipt();

create function sectalk_private.st_v7_expire_dlp_confirmations()
returns void language sql set search_path='' as $$
  delete from sectalk_private.st_v7_dlp_acknowledgements where expires_at<=now();
$$;
select cron.schedule('sectalk-v7-expire-dlp-confirmations','*/10 * * * *',
  'select sectalk_private.st_v7_expire_dlp_confirmations()');

revoke all on function sectalk_private.st_v7_dlp_luhn(text),sectalk_private.st_v7_dlp_matches(text),
  sectalk_private.st_v7_dlp_digest(text),sectalk_private.st_v7_apply_message_dlp(),
  sectalk_private.st_v7_delete_dlp_receipt(),sectalk_private.st_v7_expire_dlp_confirmations(),
  sectalk_private.st_v7_dlp_is_retry(text,uuid,uuid,uuid,text),public.st_v7_workspace_dlp(uuid),
  public.st_v7_set_workspace_dlp(uuid,integer,jsonb),public.st_v7_acknowledge_dlp(text,uuid,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_workspace_dlp(uuid),public.st_v7_set_workspace_dlp(uuid,integer,jsonb),
  public.st_v7_acknowledge_dlp(text,uuid,uuid,text) to authenticated;

commit;
