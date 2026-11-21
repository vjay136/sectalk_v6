begin;

create table sectalk_private.st_v8_managed_room_wraps (
  room uuid not null,
  post uuid not null,
  workspace uuid not null,
  source_revision text not null check(source_revision~'^[a-f0-9]{64}$'),
  wrapping_version integer not null,
  wrapped_dek text not null check(wrapped_dek~'^[A-Za-z0-9_-]{80}$'),
  primary key(room,post),
  foreign key(room,post) references sectalk_private.st_v8_managed_room_posts on delete cascade,
  foreign key(workspace,wrapping_version) references sectalk_private.st_v7_tenant_key_versions on delete cascade
);
create table sectalk_private.st_v8_managed_room_rewrap_audit (
  room uuid not null,
  post uuid not null,
  workspace uuid not null,
  source_revision text not null check(source_revision~'^[a-f0-9]{64}$'),
  previous_version integer not null,
  wrapping_version integer not null check(wrapping_version>previous_version),
  authorized_by uuid not null,
  occurred_at timestamptz not null default clock_timestamp(),
  primary key(room,post,wrapping_version)
);
create trigger st_v8_immutable_managed_room_rewrap_audit before update or delete
  on sectalk_private.st_v8_managed_room_rewrap_audit
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_managed_room_wraps enable row level security;
alter table sectalk_private.st_v8_managed_room_rewrap_audit enable row level security;
revoke all on sectalk_private.st_v8_managed_room_wraps,sectalk_private.st_v8_managed_room_rewrap_audit
  from public,anon,authenticated,service_role;

create index st_v8_rewrap_room_post_workspace on sectalk_private.st_v8_managed_room_posts(workspace,room,id);
create index st_v8_rewrap_room_report_post on sectalk_private.st_v6_room_reports(room_id,post_id);
create index st_v8_rewrap_room_evidence_post on sectalk_private.st_v8_managed_room_evidence(room,post);

-- Use the original report revision algorithm so rotating a capsule cannot rename the source revision.
create function sectalk_private.st_v8_managed_room_revision(m sectalk_private.st_v8_managed_room_posts)
returns text language sql immutable strict set search_path='' as $$
  select encode(sha256(convert_to(concat_ws(':',m.room,m.id,m.workspace,m.sender,
    m.key_version,m.body,m.nonce,m.tag,m.wrapped_dek),'UTF8')),'hex');
$$;

create function sectalk_private.st_v8_managed_room_rewrap_candidates(p_workspace uuid,p_room uuid,p_post uuid)
returns table(workspace uuid,room uuid,post uuid,actor uuid,policy_revision uuid,authorized_by uuid,
  source_revision text,source_key jsonb,target_key jsonb,payload jsonb)
language sql stable set search_path='' as $$
  select m.workspace,m.room,m.id,m.sender,s.revision,s.authorized_by,
    sectalk_private.st_v8_managed_room_revision(m),
    jsonb_build_object('workspace',m.workspace,'version',src.version,'custody',src.custody,'ref',src.provider_ref,'wrapped',src.wrapped),
    jsonb_build_object('workspace',m.workspace,'version',dst.version,'custody',dst.custody,'ref',dst.provider_ref,'wrapped',dst.wrapped),
    jsonb_build_object('body',m.body,'nonce',m.nonce,'tag',m.tag,'data_version',m.key_version,
      'wrapped_dek',coalesce(w.wrapped_dek,m.wrapped_dek))
  from sectalk_private.st_v8_tenant_rotation_schedules s
  join sectalk_private.st_v7_tenant_key_state k on k.workspace=s.workspace and k.destroyed_at is null
  join sectalk_private.st_v7_tenant_key_versions dst on (dst.workspace,dst.version)=(k.workspace,k.current_version)
    and dst.custody='managed'
  join sectalk_private.st_v8_managed_room_posts m on m.workspace=s.workspace and m.key_version<dst.version
  join sectalk_private.st_v7_tenant_key_versions original on (original.workspace,original.version)=(m.workspace,m.key_version)
    and original.custody='managed'
  join public.st_v6_rooms r on (r.workspace_id,r.id)=(m.workspace,m.room) and r.encryption_mode='managed' and not r.archived
  left join sectalk_private.st_v8_managed_room_wraps w on (w.workspace,w.room,w.post)=(m.workspace,m.room,m.id)
    and w.source_revision=sectalk_private.st_v8_managed_room_revision(m)
  join sectalk_private.st_v7_tenant_key_versions src on (src.workspace,src.version)=(m.workspace,coalesce(w.wrapping_version,m.key_version))
    and src.custody='managed' and src.version<dst.version
  where s.workspace=p_workspace and (p_room is null or (m.room,m.id)=(p_room,p_post))
    and sectalk_private.st_v8_scheduled_rotation_allowed(s.workspace,s.authorized_by)
    and not exists(select 1 from sectalk_private.st_v6_workspace_holds h where h.workspace_id=m.workspace and h.released_at is null)
    and not exists(select 1 from sectalk_private.st_v6_room_reports q where (q.room_id,q.post_id)=(m.room,m.id))
    and not exists(select 1 from sectalk_private.st_v8_managed_room_evidence q where (q.room,q.post)=(m.room,m.id));
$$;

create function public.st_v8_due_managed_room_rewrap(p_workspace uuid,p_after_room uuid,p_after_post uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select coalesce(jsonb_agg(to_jsonb(jobs) order by jobs.room,jobs.post),'[]'::jsonb) from (
    select workspace,room,post,actor,policy_revision,source_revision,source_key,target_key,payload
    from sectalk_private.st_v8_managed_room_rewrap_candidates(p_workspace,null,null)
    where (p_after_room is null and p_after_post is null) or (room,post)>(p_after_room,p_after_post)
    order by room,post limit 16
  ) jobs;
$$;

create function public.st_v8_due_managed_channel_rewrap_after(p_workspace uuid,p_after_post uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select coalesce(jsonb_agg(to_jsonb(jobs) order by jobs.post),'[]'::jsonb) from (
    select workspace,post,channel,actor,policy_revision,source_revision,source_key,target_key,payload
    from sectalk_private.st_v8_managed_channel_rewrap_candidates(p_workspace,null)
    where p_after_post is null or post>p_after_post
    order by post limit 16
  ) jobs;
$$;

create function public.st_v8_commit_managed_room_rewrap(p_workspace uuid,p_room uuid,p_post uuid,p_policy_revision uuid,
  p_source_revision text,p_previous integer,p_target integer,p_wrapped_dek text)
returns boolean language plpgsql security definer set search_path='' as $$
declare candidate record;
begin
  if p_workspace is null or p_room is null or p_post is null or p_policy_revision is null or p_previous is null or p_target is null
    or p_previous>=p_target or (p_source_revision~'^[a-f0-9]{64}$') is not true
    or (p_wrapped_dek~'^[A-Za-z0-9_-]{80}$') is not true then return false; end if;
  perform 1 from public.st_v2_workspaces where id=p_workspace for share;
  if not found then return false; end if;
  -- Keep the workspace, room, and tenant advisory lock order used by room writes.
  perform 1 from public.st_v6_rooms where id=p_room and workspace_id=p_workspace and not archived for update;
  if not found then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
  perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform 1 from sectalk_private.st_v8_managed_room_posts where (workspace,room,id)=(p_workspace,p_room,p_post) for update;
  if not found then return false; end if;
  select * into candidate from sectalk_private.st_v8_managed_room_rewrap_candidates(p_workspace,p_room,p_post);
  if not found or (candidate.source_revision,candidate.policy_revision,(candidate.source_key->>'version')::integer,
    (candidate.target_key->>'version')::integer) is distinct from (p_source_revision,p_policy_revision,p_previous,p_target)
    or p_wrapped_dek=candidate.payload->>'wrapped_dek' then return false; end if;
  insert into sectalk_private.st_v8_managed_room_wraps(room,post,workspace,source_revision,wrapping_version,wrapped_dek)
    values(p_room,p_post,p_workspace,p_source_revision,p_target,p_wrapped_dek)
    on conflict(room,post) do update set source_revision=excluded.source_revision,
      wrapping_version=excluded.wrapping_version,wrapped_dek=excluded.wrapped_dek;
  insert into sectalk_private.st_v8_managed_room_rewrap_audit(room,post,workspace,source_revision,previous_version,wrapping_version,authorized_by)
    values(p_room,p_post,p_workspace,p_source_revision,p_previous,p_target,candidate.authorized_by);
  return true;
end $$;

revoke all on function sectalk_private.st_v8_managed_room_revision(sectalk_private.st_v8_managed_room_posts),
  sectalk_private.st_v8_managed_room_rewrap_candidates(uuid,uuid,uuid),
  public.st_v8_due_managed_room_rewrap(uuid,uuid,uuid),public.st_v8_due_managed_channel_rewrap_after(uuid,uuid),
  public.st_v8_commit_managed_room_rewrap(uuid,uuid,uuid,uuid,text,integer,integer,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_due_managed_room_rewrap(uuid,uuid,uuid),public.st_v8_due_managed_channel_rewrap_after(uuid,uuid),
  public.st_v8_commit_managed_room_rewrap(uuid,uuid,uuid,uuid,text,integer,integer,text) to service_role;

create or replace function sectalk_private.st_v8_managed_room_work(p_ticket uuid,p_actor uuid,p_action text,p_data jsonb default null)
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
        jsonb_build_object('body',m.body,'nonce',m.nonce,'tag',m.tag,'data_version',m.key_version,
          'wrapped_dek',coalesce(w.wrapped_dek,m.wrapped_dek)) envelope,
        sectalk_private.st_v8_managed_room_revision(m) source_revision,
        jsonb_build_object('workspace',m.workspace,'version',v.version,'custody',v.custody,'ref',v.provider_ref,'wrapped',v.wrapped) key
      from sectalk_private.st_v8_managed_room_posts m
      left join sectalk_private.st_v8_managed_room_wraps w on (w.workspace,w.room,w.post)=(m.workspace,m.room,m.id)
        and w.source_revision=sectalk_private.st_v8_managed_room_revision(m)
      join sectalk_private.st_v7_tenant_key_versions v on (v.workspace,v.version)=(m.workspace,coalesce(w.wrapping_version,m.key_version))
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

commit;
