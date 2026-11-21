begin;
alter table public.st_v6_rooms add column encryption_mode text not null default 'standard' check(encryption_mode in ('standard','managed'));
create table sectalk_private.st_v8_room_encryption_policy (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  managed boolean not null
);
create table sectalk_private.st_v8_managed_room_posts (
  room uuid not null references public.st_v6_rooms on delete cascade,
  id uuid not null,
  workspace uuid not null,
  sender uuid not null,
  key_version integer not null,
  fingerprint bytea not null,
  body text not null check(length(body) between 2 and 24000 and body~'^[A-Za-z0-9_-]+$'),
  nonce text not null check(nonce~'^[A-Za-z0-9_-]{16}$'),
  tag text not null check(tag~'^[A-Za-z0-9_-]{22}$'),
  wrapped_dek text not null check(wrapped_dek~'^[A-Za-z0-9_-]{80}$'),
  created_at timestamptz not null default clock_timestamp(),
  primary key(room,id),
  foreign key(workspace,key_version) references sectalk_private.st_v7_tenant_key_versions
);
create index on sectalk_private.st_v8_managed_room_posts(room,created_at desc,id desc);
create index on sectalk_private.st_v8_managed_room_posts(room,sender,created_at desc);
create table sectalk_private.st_v8_managed_room_tickets (
  id uuid primary key default gen_random_uuid(),
  actor uuid not null,
  native_session uuid not null,
  room uuid not null references public.st_v6_rooms on delete cascade,
  post uuid,
  policy_revision integer,
  fingerprint bytea,
  expires_at timestamptz not null default clock_timestamp()+interval '30 seconds'
);
create index on sectalk_private.st_v8_managed_room_tickets(expires_at);
alter table sectalk_private.st_v8_room_encryption_policy enable row level security;
alter table sectalk_private.st_v8_managed_room_posts enable row level security;
alter table sectalk_private.st_v8_managed_room_tickets enable row level security;
revoke all on sectalk_private.st_v8_room_encryption_policy,sectalk_private.st_v8_managed_room_posts,
  sectalk_private.st_v8_managed_room_tickets from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_room_pin_encryption()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if tg_op='UPDATE' then
    if old.encryption_mode is distinct from new.encryption_mode or
      (old.encryption_mode='managed' and (old.workspace_id,old.kind,old.template) is distinct from (new.workspace_id,new.kind,new.template)) then
      raise exception 'Room encryption mode and managed room type are immutable' using errcode='42501';
    end if;
  else
    perform pg_advisory_xact_lock(hashtextextended('sectalk-room-mode:'||new.workspace_id::text,0));
    new.encryption_mode:=case when new.kind='private' and new.template='blank' and exists(select 1
      from sectalk_private.st_v8_room_encryption_policy where workspace=new.workspace_id and managed) then 'managed' else 'standard' end;
  end if;
  return new;
end $$;
create trigger st_v8_room_pin_encryption before insert or update of encryption_mode,workspace_id,kind,template on public.st_v6_rooms
  for each row execute function sectalk_private.st_v8_room_pin_encryption();

create function sectalk_private.st_v8_no_legacy_managed_room()
returns trigger language plpgsql security definer set search_path='' as $$
declare room_id uuid;
begin
  if tg_table_name='st_v6_room_files' then room_id:=new.room; else room_id:=new.room_id; end if;
  if exists(select 1 from public.st_v6_rooms where id=room_id and encryption_mode='managed') then
    raise exception 'Use the managed room message route' using errcode='42501';
  end if;
  return new;
end $$;
create trigger aa_st_v8_no_managed_room_post before insert or update of room_id,body on public.st_v6_room_posts
  for each row execute function sectalk_private.st_v8_no_legacy_managed_room();
create trigger aa_st_v8_no_managed_room_file before insert on sectalk_private.st_v6_room_files
  for each row execute function sectalk_private.st_v8_no_legacy_managed_room();

create function public.st_v8_managed_room_policy(p_workspace uuid,p_enabled boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
begin
  if sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner'
    or public.st_v7_current_session_valid() is not true or public.st_v7_account_under_lockdown() then return null; end if;
  if p_enabled is not null then
    if sectalk_private.st_v7_admin_fresh() is not true then raise exception 'Fresh workspace owner verification required' using errcode='42501'; end if;
    perform sectalk_private.st_v7_require_workspace_write(p_workspace);
    perform sectalk_private.limit_action('v8_room_mode_policy',8);
    perform pg_advisory_xact_lock(hashtextextended('sectalk-room-mode:'||p_workspace::text,0));
    insert into sectalk_private.st_v8_room_encryption_policy values(p_workspace,p_enabled)
      on conflict(workspace) do update set managed=excluded.managed;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,auth.uid(),case when p_enabled then 'workspace.managed_rooms_on' else 'workspace.managed_rooms_off' end,p_workspace);
  end if;
  return jsonb_build_object('enabled',exists(select 1 from sectalk_private.st_v8_room_encryption_policy
    where workspace=p_workspace and managed));
end $$;

create function sectalk_private.st_v8_managed_room_allowed(r public.st_v6_rooms,p_actor uuid,p_write boolean)
returns boolean language sql stable set search_path='' as $$
  select coalesce(r.encryption_mode='managed' and case when p_write
    then sectalk_private.st_v6_room_role(r.id,p_actor) in ('owner','moderator','member') and not r.archived
      and (not r.locked or sectalk_private.st_v6_room_role(r.id,p_actor) in ('owner','moderator'))
      and sectalk_private.st_v6_room_role_rule(r.id,p_actor,'post')<>'deny'
      and not exists(select 1 from public.st_v6_room_timeouts where room_id=r.id and user_id=p_actor and until_at>now())
    else sectalk_private.st_v6_room_role(r.id,p_actor) in ('owner','moderator','member','read_only') end,false)
$$;

create function public.st_v8_managed_room_ticket(p_room uuid,p_post uuid default null,p_body text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare r public.st_v6_rooms; current_policy sectalk_private.st_v7_workspace_dlp; actor uuid:=auth.uid(); ticket uuid; message_signature bytea;
begin
  select * into r from public.st_v6_rooms where id=p_room;
  if public.st_v7_current_session_valid() is not true or public.st_v7_account_under_lockdown()
    or public.st_v7_login_risk_status() is distinct from 'clear' or
    not sectalk_private.st_v8_managed_room_allowed(r,actor,p_post is not null) then
    raise exception 'Managed room unavailable' using errcode='42501'; end if;
  perform sectalk_private.limit_action(case when p_post is null then 'v8_managed_room_read' else 'v6_room_post' end,60);
  delete from sectalk_private.st_v8_managed_room_tickets where expires_at<=clock_timestamp();
  if p_post is not null then
    perform sectalk_private.st_v7_require_workspace_write(r.workspace_id);
    if length(coalesce(btrim(p_body),'')) not between 1 and 4000 then
      raise exception 'Enter a message for this managed room' using errcode='22023'; end if;
    message_signature:=sectalk_private.st_v7_dlp_digest(btrim(p_body));
    if message_signature is null then raise exception 'Managed room message verification unavailable' using errcode='PT503'; end if;
    if exists(select 1 from sectalk_private.st_v8_managed_room_posts where room=r.id and id=p_post) then
      if exists(select 1 from sectalk_private.st_v8_managed_room_posts m where m.room=r.id and m.id=p_post
        and m.sender=actor and m.fingerprint=message_signature) then return jsonb_build_object('already_sent',true); end if;
      raise exception 'Message identifier in use' using errcode='PT409';
    end if;
    select * into current_policy from sectalk_private.st_v7_workspace_dlp where workspace_id=r.workspace_id;
    if exists(select 1 from sectalk_private.st_v7_dlp_matches(btrim(p_body)) m
      where current_policy.rules->>m.category in ('warn','redact','block')) then
      raise exception 'Managed room policy could not accept this message' using errcode='PT422'; end if;
  end if;
  insert into sectalk_private.st_v8_managed_room_tickets(actor,native_session,room,post,policy_revision,fingerprint)
    values(actor,(auth.jwt()->>'session_id')::uuid,r.id,p_post,current_policy.revision,message_signature) returning id into ticket;
  return jsonb_build_object('ticket',ticket,'workspace',r.workspace_id);
end $$;

create function public.st_v8_managed_room_readable(p_room uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce(public.st_v7_current_session_valid() and public.st_v7_account_under_lockdown() is false
    and public.st_v7_login_risk_status()='clear' and exists(select 1 from public.st_v6_rooms r where r.id=p_room
      and sectalk_private.st_v8_managed_room_allowed(r,auth.uid(),false)),false)
$$;

create function public.st_v8_managed_room_work(p_ticket uuid,p_actor uuid,p_action text,p_data jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare t sectalk_private.st_v8_managed_room_tickets; r public.st_v6_rooms; state sectalk_private.st_v7_tenant_key_state;
declare k sectalk_private.st_v7_tenant_key_versions; who text; before_at timestamptz; before_id uuid;
begin
  select * into t from sectalk_private.st_v8_managed_room_tickets where id=p_ticket and actor=p_actor
    and expires_at>clock_timestamp() for update;
  if not found or not exists(select 1 from auth.sessions s where s.id=t.native_session and s.user_id=p_actor
    and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()) then return null; end if;
  if t.post is not null then
    perform 1 from public.st_v2_workspaces w where w.id=(select workspace_id from public.st_v6_rooms where id=t.room) for share;
  end if;
  select * into r from public.st_v6_rooms where id=t.room for update;
  if not sectalk_private.st_v8_managed_room_allowed(r,p_actor,t.post is not null) then return null; end if;
  if p_action='read' and t.post is null then
    before_at:=(p_data->>'before')::timestamptz;
    before_id:=(p_data->>'id')::uuid;
    if (before_at is null)<>(before_id is null) then return null; end if;
    delete from sectalk_private.st_v8_managed_room_tickets where id=t.id;
    return coalesce((select jsonb_agg(to_jsonb(rows) order by rows.created_at desc,rows.id desc) from (
      select m.room,m.id,m.sender,m.created_at,
        jsonb_build_object('body',m.body,'nonce',m.nonce,'tag',m.tag,'wrapped_dek',m.wrapped_dek) envelope,
        jsonb_build_object('workspace',m.workspace,'version',v.version,'custody',v.custody,'ref',v.provider_ref,'wrapped',v.wrapped) key
      from sectalk_private.st_v8_managed_room_posts m
      join sectalk_private.st_v7_tenant_key_versions v on (v.workspace,v.version)=(m.workspace,m.key_version)
      join sectalk_private.st_v7_tenant_key_state s on s.workspace=m.workspace and s.destroyed_at is null
      where m.room=r.id and m.workspace=r.workspace_id and (before_at is null or (m.created_at,m.id)<(before_at,before_id))
      order by m.created_at desc,m.id desc limit 51
    ) rows),'[]');
  end if;
  if t.post is null or p_action not in ('key','finish') then return null; end if;
  perform sectalk_private.st_v7_require_workspace_write(r.workspace_id);
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||r.workspace_id::text,0));
  select * into state from sectalk_private.st_v7_tenant_key_state where workspace=r.workspace_id;
  if state.destroyed_at is not null then return null; end if;
  if p_action='key' then
    if state.workspace is null and p_data->>'wrapped' is not null then
      insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values(r.workspace_id,1);
      insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,wrapped)
        values(r.workspace_id,1,'managed',p_data->>'wrapped');
      insert into sectalk_private.st_v7_tenant_key_audit(workspace,actor,event,version) values(r.workspace_id,p_actor,'provisioned',1);
      state.current_version:=1;
    end if;
    select * into k from sectalk_private.st_v7_tenant_key_versions where workspace=r.workspace_id and version=state.current_version;
    return jsonb_build_object('workspace',r.workspace_id,'version',k.version,'custody',k.custody,'ref',k.provider_ref,'wrapped',k.wrapped);
  end if;
  if t.policy_revision is distinct from (select revision from sectalk_private.st_v7_workspace_dlp where workspace_id=r.workspace_id) then
    raise exception 'Workspace policy changed. Send the message again.' using errcode='PT409';
  end if;
  if state.current_version is null or state.current_version is distinct from (p_data->>'version')::integer then
    return null;
  end if;
  who:=sectalk_private.st_v6_room_role(r.id,p_actor);
  delete from sectalk_private.st_v8_managed_room_tickets where id=t.id;
  if exists(select 1 from sectalk_private.st_v8_managed_room_posts where room=r.id and id=t.post) then
    return to_jsonb(exists(select 1 from sectalk_private.st_v8_managed_room_posts where room=r.id and id=t.post
      and sender=p_actor and fingerprint=t.fingerprint));
  end if;
  if r.slow_seconds>0 and who not in ('owner','moderator') and exists(
    select 1 from sectalk_private.st_v8_managed_room_posts where room=r.id and sender=p_actor
    and created_at>clock_timestamp()-make_interval(secs=>r.slow_seconds)) then
    raise exception 'Slow mode is on. Wait before posting again.' using errcode='PT409';
  end if;
  insert into sectalk_private.st_v8_managed_room_posts(room,id,workspace,sender,key_version,fingerprint,body,nonce,tag,wrapped_dek)
    values(r.id,t.post,r.workspace_id,p_actor,state.current_version,t.fingerprint,p_data->>'body',p_data->>'nonce',p_data->>'tag',p_data->>'wrapped_dek');
  return 'true'::jsonb;
end $$;
revoke all on function sectalk_private.st_v8_room_pin_encryption(),sectalk_private.st_v8_no_legacy_managed_room(),
  sectalk_private.st_v8_managed_room_allowed(public.st_v6_rooms,uuid,boolean),public.st_v8_managed_room_policy(uuid,boolean),
  public.st_v8_managed_room_ticket(uuid,uuid,text),public.st_v8_managed_room_readable(uuid),
  public.st_v8_managed_room_work(uuid,uuid,text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_managed_room_policy(uuid,boolean),public.st_v8_managed_room_ticket(uuid,uuid,text),
  public.st_v8_managed_room_readable(uuid) to authenticated;
grant execute on function public.st_v8_managed_room_work(uuid,uuid,text,jsonb) to service_role;
commit;
