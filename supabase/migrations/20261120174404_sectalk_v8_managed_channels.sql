begin;

create table sectalk_private.st_v8_channel_encryption_policy (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  managed boolean not null default false
);
alter table public.st_v2_channels add column encryption_mode text not null default 'standard'
  check(encryption_mode in ('standard','managed'));
create table sectalk_private.st_v8_channel_payloads (
  post uuid primary key references public.st_v2_posts on delete cascade,
  workspace uuid not null,
  key_version integer not null,
  body text not null check(char_length(body) between 2 and 24000 and body~'^[A-Za-z0-9_-]+$'),
  nonce text not null check(nonce~'^[A-Za-z0-9_-]{16}$'),
  tag text not null check(tag~'^[A-Za-z0-9_-]{22}$'),
  wrapped_dek text not null check(wrapped_dek~'^[A-Za-z0-9_-]{80}$'),
  foreign key(workspace,key_version) references sectalk_private.st_v7_tenant_key_versions
);
create table sectalk_private.st_v8_channel_key_tickets (
  id uuid primary key default gen_random_uuid(),
  channel uuid not null references public.st_v2_channels on delete cascade,
  actor uuid not null,
  native_session uuid not null,
  purpose text not null check(purpose in ('send','read')),
  post uuid,
  policy_revision integer,
  message_digest bytea,
  acknowledgement bytea,
  expires_at timestamptz not null default clock_timestamp()+interval '30 seconds'
);
create index st_v8_channel_ticket_expiry on sectalk_private.st_v8_channel_key_tickets(expires_at);
alter table sectalk_private.st_v8_channel_encryption_policy enable row level security;
alter table sectalk_private.st_v8_channel_payloads enable row level security;
alter table sectalk_private.st_v8_channel_key_tickets enable row level security;
revoke all on sectalk_private.st_v8_channel_encryption_policy,sectalk_private.st_v8_channel_payloads,
  sectalk_private.st_v8_channel_key_tickets from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_channel_mode_at_creation()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if tg_op='UPDATE' then
    if new.encryption_mode is distinct from old.encryption_mode then
      raise exception 'Channel encryption mode is immutable' using errcode='42501'; end if;
  else
    perform pg_advisory_xact_lock(hashtextextended('sectalk-channel-mode:'||new.workspace_id::text,0));
    new.encryption_mode:=case when exists(select 1 from sectalk_private.st_v8_channel_encryption_policy p
      where p.workspace=new.workspace_id and p.managed) then 'managed' else 'standard' end;
  end if;
  return new;
end $$;
create trigger st_v8_channel_mode_at_creation before insert or update of encryption_mode on public.st_v2_channels
  for each row execute function sectalk_private.st_v8_channel_mode_at_creation();

create function public.st_v8_channel_mode_policy(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select case when sectalk_private.st_v2_role(p_workspace,auth.uid())='owner'
    and sectalk_private.st_v2_active(auth.uid())
    and public.st_v7_current_session_valid() and public.st_v7_account_under_lockdown() is false
    then jsonb_build_object('verified',sectalk_private.st_v7_admin_fresh(),
      'managed',exists(select 1 from sectalk_private.st_v8_channel_encryption_policy p where p.workspace=p_workspace and p.managed))
    end;
$$;

create function public.st_v8_set_channel_mode_policy(p_workspace uuid,p_managed boolean)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  if p_managed is null or (public.st_v8_channel_mode_policy(p_workspace)->>'verified')::boolean is not true then
    raise exception 'Fresh workspace owner verification required' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v8_channel_mode_policy',8);
  perform pg_advisory_xact_lock(hashtextextended('sectalk-channel-mode:'||p_workspace::text,0));
  insert into sectalk_private.st_v8_channel_encryption_policy(workspace,managed) values(p_workspace,p_managed)
    on conflict(workspace) do update set managed=excluded.managed;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,auth.uid(),case when p_managed then 'workspace.managed_channels_on' else 'workspace.managed_channels_off' end,p_workspace);
  return p_managed;
end $$;

create function sectalk_private.st_v8_channel_ticket_live(t sectalk_private.st_v8_channel_key_tickets)
returns boolean language sql stable set search_path='' as $$
  select t.id is not null and t.expires_at>statement_timestamp()
    and sectalk_private.st_v2_active(t.actor)
    and sectalk_private.st_v6_channel_content_access(t.channel,t.actor)
    and exists(select 1 from auth.sessions s where s.id=t.native_session and s.user_id=t.actor
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp());
$$;

create function public.st_v8_managed_channel_ticket(p_channel uuid,p_purpose text,p_post uuid default null,p_body text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); channel_row public.st_v2_channels; policy sectalk_private.st_v7_workspace_dlp;
  prepared text:=btrim(p_body); blocked text[]:='{}'; warnings text[]:='{}';
  original bytea; fingerprint bytea; entry record; key_ticket uuid;
begin
  select * into channel_row from public.st_v2_channels c where c.id=p_channel and c.encryption_mode='managed';
  if channel_row.id is null or p_purpose is null or p_purpose not in ('send','read')
    or public.st_v7_current_session_valid() is not true or public.st_v7_account_under_lockdown()
    or not sectalk_private.st_v2_active(actor_id) or not sectalk_private.st_v6_channel_content_access(p_channel,actor_id) then
    raise exception 'Managed channel unavailable' using errcode='42501'; end if;
  if p_purpose='send' then
    if channel_row.archived or p_post is null or char_length(coalesce(prepared,'')) not between 1 and 4000 then
      raise exception 'Enter a message for an active managed channel' using errcode='22023'; end if;
    perform sectalk_private.limit_action('v2_post',60);
    fingerprint:=sectalk_private.st_v7_dlp_digest(prepared);
    if fingerprint is null then raise exception 'Managed message policy is unavailable' using errcode='PT503'; end if;
    if exists(select 1 from public.st_v2_posts p where p.id=p_post) then
      if exists(select 1 from public.st_v2_posts p where p.id=p_post and p.channel_id=p_channel
          and p.sender=actor_id and p.quarantined_at is null)
        and sectalk_private.st_v7_dlp_is_retry('channel',p_channel,p_post,actor_id,prepared) then
        return jsonb_build_object('already_sent',true);
      end if;
      raise exception 'Message ID already in use' using errcode='PT409';
    end if;
    select * into policy from sectalk_private.st_v7_workspace_dlp p where p.workspace_id=channel_row.workspace_id;
    if policy.workspace_id is not null then
      for entry in select m.* from sectalk_private.st_v7_dlp_matches(prepared) m order by length(m.token) desc loop
        case policy.rules->>entry.category
          when 'block' then blocked:=array_append(blocked,entry.category);
          when 'warn' then warnings:=array_append(warnings,entry.category);
          when 'redact' then prepared:=replace(prepared,entry.token,'[…]');
          else null;
        end case;
      end loop;
      if cardinality(blocked)>0 then raise exception 'Workspace policy blocked sensitive information' using errcode='PT422'; end if;
      if cardinality(warnings)>0 then
        original:=sectalk_private.st_v7_dlp_digest(btrim(p_body));
        if not exists(select 1 from sectalk_private.st_v7_dlp_acknowledgements a where a.actor=actor_id and a.scope_type='channel'
          and a.scope_id=p_channel and a.message_id=p_post and a.workspace_id=channel_row.workspace_id
          and a.revision=policy.revision and a.fingerprint=original and a.expires_at>statement_timestamp()) then
          raise exception 'Confirm the workspace sensitive information warning' using errcode='PT428',
            detail=(select string_agg(distinct category,',') from unnest(warnings) category); end if;
      end if;
    end if;
  else
    perform sectalk_private.limit_action('v8_channel_page',90);
  end if;
  delete from sectalk_private.st_v8_channel_key_tickets where expires_at<statement_timestamp();
  insert into sectalk_private.st_v8_channel_key_tickets(channel,actor,native_session,purpose,post,policy_revision,message_digest,acknowledgement)
    values(p_channel,actor_id,(auth.jwt()->>'session_id')::uuid,p_purpose,p_post,coalesce(policy.revision,0),fingerprint,original)
    returning id into key_ticket;
  return jsonb_build_object('ticket',key_ticket,'workspace',channel_row.workspace_id,'body',prepared);
end $$;

create function public.st_v8_channel_write_key(p_ticket uuid,p_actor uuid,p_wrapped text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare t sectalk_private.st_v8_channel_key_tickets; space uuid; state sectalk_private.st_v7_tenant_key_state;
  key_row sectalk_private.st_v7_tenant_key_versions;
begin
  select * into t from sectalk_private.st_v8_channel_key_tickets where id=p_ticket and actor=p_actor and purpose='send';
  if sectalk_private.st_v8_channel_ticket_live(t) is not true then return null; end if;
  select c.workspace_id into space from public.st_v2_channels c where c.id=t.channel and c.encryption_mode='managed' and not c.archived;
  if space is null then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||space::text,0));
  select * into state from sectalk_private.st_v7_tenant_key_state where workspace=space;
  if state.destroyed_at is not null then return null; end if;
  if state.workspace is null and p_wrapped is not null then
    insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values(space,1);
    insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,wrapped) values(space,1,'managed',p_wrapped);
    insert into sectalk_private.st_v7_tenant_key_audit(workspace,actor,event,version) values(space,p_actor,'provisioned',1);
    state.current_version:=1;
  end if;
  select * into key_row from sectalk_private.st_v7_tenant_key_versions where workspace=space and version=state.current_version;
  return jsonb_build_object('workspace',space,'version',key_row.version,'custody',key_row.custody,
    'ref',key_row.provider_ref,'wrapped',key_row.wrapped);
end $$;

create function public.st_v8_finish_managed_channel_send(p_ticket uuid,p_actor uuid,p_version integer,p_payload jsonb)
returns boolean language plpgsql security definer set search_path='' as $$
declare t sectalk_private.st_v8_channel_key_tickets; space uuid; policy_version integer;
begin
  delete from sectalk_private.st_v8_channel_key_tickets where id=p_ticket and actor=p_actor and purpose='send'
    returning * into t;
  if sectalk_private.st_v8_channel_ticket_live(t) is not true then return false; end if;
  select c.workspace_id into space from public.st_v2_channels c where c.id=t.channel and c.encryption_mode='managed'
    and not c.archived for update;
  if space is null or not sectalk_private.st_v6_channel_content_access(t.channel,t.actor) then return false; end if;
  if exists(select 1 from public.st_v2_posts p join sectalk_private.st_v7_dlp_delivery_receipts r
    on r.scope_type='channel' and r.scope_id=p.channel_id and r.message_id=p.id and r.actor=p.sender and r.workspace_id=space
    where p.id=t.post and p.channel_id=t.channel and p.sender=t.actor and p.quarantined_at is null
      and r.fingerprint=t.message_digest) then return true; end if;
  if t.message_digest is null then return false; end if;
  perform 1 from public.st_v2_workspaces w where w.id=space for share;
  select p.revision into policy_version from sectalk_private.st_v7_workspace_dlp p where p.workspace_id=space for share;
  if coalesce(policy_version,0)<>t.policy_revision then raise exception 'Workspace policy changed' using errcode='PT409'; end if;
  if t.acknowledgement is not null then
    delete from sectalk_private.st_v7_dlp_acknowledgements a where a.actor=t.actor and a.scope_type='channel'
      and a.scope_id=t.channel and a.message_id=t.post and a.workspace_id=space and a.revision=t.policy_revision
      and a.fingerprint=t.acknowledgement and a.expires_at>statement_timestamp();
    if not found then raise exception 'Workspace confirmation expired' using errcode='PT409'; end if;
  end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||space::text,0));
  if not exists(select 1 from sectalk_private.st_v7_tenant_key_versions k where k.workspace=space and k.version=p_version)
    then return false; end if;
  insert into public.st_v2_posts(id,channel_id,sender,body) values(t.post,t.channel,t.actor,'Managed encrypted message')
    on conflict(id) do nothing;
  if not found then raise exception 'Message ID already in use' using errcode='PT409'; end if;
  insert into sectalk_private.st_v8_channel_payloads(post,workspace,key_version,body,nonce,tag,wrapped_dek)
    values(t.post,space,p_version,p_payload->>'body',p_payload->>'nonce',p_payload->>'tag',p_payload->>'wrapped_dek');
  insert into sectalk_private.st_v7_dlp_delivery_receipts(workspace_id,scope_type,scope_id,message_id,actor,fingerprint)
    values(space,'channel',t.channel,t.post,t.actor,t.message_digest);
  return true;
end $$;

create function sectalk_private.st_v8_guard_managed_channel_post()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if exists(select 1 from public.st_v2_channels c where c.id=new.channel_id and c.encryption_mode='managed')
    and (new.body<>case when new.quarantined_at is not null then 'Message quarantined' else 'Managed encrypted message' end
      or not exists(select 1 from sectalk_private.st_v8_channel_payloads e join public.st_v2_channels c
        on c.id=new.channel_id and c.workspace_id=e.workspace where e.post=new.id)) then
    raise exception 'A managed channel post requires a scoped ciphertext envelope' using errcode='42501';
  end if;
  return null;
end $$;
create constraint trigger st_v8_guard_managed_channel_post after insert or update on public.st_v2_posts
  deferrable initially deferred for each row execute function sectalk_private.st_v8_guard_managed_channel_post();

create function sectalk_private.st_v8_guard_managed_channel_report()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if exists(select 1 from public.st_v2_channels c where c.id=new.channel_id and c.encryption_mode='managed') then
    raise exception 'Managed channel reports require an approved evidence capture source' using errcode='42501';
  end if;
  return new;
end $$;
create trigger st_v8_guard_managed_channel_report before insert on sectalk_private.st_v7_channel_reports
  for each row execute function sectalk_private.st_v8_guard_managed_channel_report();

create or replace view sectalk_private.st_v7_search_sources as
  select 'direct'::text kind,id,body first_field,''::text second_field from public.st_messages where revoked_at is null and expires_at is null
  union all select 'channel',p.id,p.body,'' from public.st_v2_posts p join public.st_v2_channels c on c.id=p.channel_id
    where c.encryption_mode='standard'
  union all select 'room',id,body,'' from public.st_v6_room_posts where removed_at is null
  union all select 'board',id,title,details from public.st_v2_items
  union all select 'task',id,title,'' from public.st_v6_tasks
  union all select 'meeting',id,title,agenda from public.st_v3_meetings
  union all select 'room_name',id,name,'' from public.st_v6_rooms where not archived
  union all select 'file',id,filename,'' from public.st_v5_files
  union all select 'person',id,name||' '||handle,'' from public.st_profiles;

create function public.st_v8_read_managed_channel(p_ticket uuid,p_actor uuid,p_before timestamptz,p_before_id uuid,p_limit integer)
returns jsonb language plpgsql security definer set search_path='' as $$
declare t sectalk_private.st_v8_channel_key_tickets;
begin
  delete from sectalk_private.st_v8_channel_key_tickets where id=p_ticket and actor=p_actor and purpose='read'
    returning * into t;
  if sectalk_private.st_v8_channel_ticket_live(t) is not true or (p_before is null)<>(p_before_id is null) then return null; end if;
  return coalesce((select jsonb_agg(to_jsonb(posts) order by posts.created_at desc,posts.id desc) from (
    select p.id,p.channel_id,p.sender,p.created_at,p.quarantined_at,e.workspace,e.key_version,
      case when p.quarantined_at is null then jsonb_build_object('body',e.body,'nonce',e.nonce,'tag',e.tag,'wrapped_dek',e.wrapped_dek) end as envelope,
      case when p.quarantined_at is null then jsonb_build_object('workspace',e.workspace,'version',k.version,'custody',k.custody,
        'ref',k.provider_ref,'wrapped',k.wrapped) end as key
    from public.st_v2_posts p join sectalk_private.st_v8_channel_payloads e on e.post=p.id
    join sectalk_private.st_v7_tenant_key_versions k on (k.workspace,k.version)=(e.workspace,e.key_version)
    join public.st_v2_channels c on c.id=p.channel_id and c.workspace_id=e.workspace and c.encryption_mode='managed'
    where p.channel_id=t.channel and sectalk_private.st_v2_post_read(p.channel_id,p.sender,t.actor)
      and (p_before is null or (p.created_at,p.id)<(p_before,p_before_id))
    order by p.created_at desc,p.id desc limit greatest(1,least(100,coalesce(p_limit,51)))
  ) posts),'[]'::jsonb);
end $$;

create function public.st_v8_managed_channel_still_readable(p_channel uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select public.st_v7_current_session_valid() and public.st_v7_account_under_lockdown() is false
    and sectalk_private.st_v2_active(auth.uid()) and sectalk_private.st_v6_channel_content_access(p_channel,auth.uid())
    and exists(select 1 from public.st_v2_channels where id=p_channel and encryption_mode='managed');
$$;

alter function public.st_v2_post(uuid,uuid,text) set schema sectalk_private;
revoke all on function sectalk_private.st_v2_post(uuid,uuid,text) from public,anon,authenticated,service_role;
create function public.st_v2_post(p_channel uuid,p_id uuid,p_body text)
returns void language plpgsql security definer set search_path='' as $$
begin
  if exists(select 1 from public.st_v2_channels where id=p_channel and encryption_mode='managed') then
    if sectalk_private.st_v6_channel_content_access(p_channel,auth.uid()) then
      raise exception 'Use authenticated managed channel publishing' using errcode='42501'; end if;
    raise exception 'Channel unavailable' using errcode='42501';
  end if;
  perform sectalk_private.st_v2_post(p_channel,p_id,p_body);
end $$;

revoke all on function sectalk_private.st_v8_channel_mode_at_creation(),sectalk_private.st_v8_channel_ticket_live(sectalk_private.st_v8_channel_key_tickets),
  sectalk_private.st_v8_guard_managed_channel_post(),sectalk_private.st_v8_guard_managed_channel_report(),
  public.st_v8_channel_mode_policy(uuid),public.st_v8_set_channel_mode_policy(uuid,boolean),
  public.st_v8_managed_channel_ticket(uuid,text,uuid,text),public.st_v8_channel_write_key(uuid,uuid,text),
  public.st_v8_finish_managed_channel_send(uuid,uuid,integer,jsonb),public.st_v8_read_managed_channel(uuid,uuid,timestamptz,uuid,integer),
  public.st_v8_managed_channel_still_readable(uuid),public.st_v2_post(uuid,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_channel_mode_policy(uuid),public.st_v8_set_channel_mode_policy(uuid,boolean),
  public.st_v8_managed_channel_ticket(uuid,text,uuid,text),public.st_v8_managed_channel_still_readable(uuid),
  public.st_v2_post(uuid,uuid,text) to authenticated;
grant execute on function public.st_v8_channel_write_key(uuid,uuid,text),public.st_v8_finish_managed_channel_send(uuid,uuid,integer,jsonb),
  public.st_v8_read_managed_channel(uuid,uuid,timestamptz,uuid,integer) to service_role;

notify pgrst,'reload schema';
commit;
