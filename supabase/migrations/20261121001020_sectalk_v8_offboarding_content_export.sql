begin;
create table sectalk_private.st_v8_content_exports (
  id uuid primary key,
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  requester uuid not null,
  reviewer uuid,
  created_at timestamptz not null default statement_timestamp(),
  approved_at timestamptz,
  expires_at timestamptz,
  withdrawn_at timestamptz,
  manifest_sha256 text,
  record_count integer,
  check(reviewer is null or reviewer<>requester)
);
create unique index on sectalk_private.st_v8_content_exports(workspace) where withdrawn_at is null;
create table sectalk_private.st_v8_content_export_entries (
  export_id uuid not null references sectalk_private.st_v8_content_exports on delete cascade,
  position integer not null,
  kind text not null,
  scope_id uuid not null,
  record_id uuid not null,
  sha256 text not null check(sha256~'^[0-9a-f]{64}$'),
  primary key(export_id,position),
  unique(export_id,kind,scope_id,record_id)
);
create trigger st_v8_content_manifest_immutable before update or delete on sectalk_private.st_v8_content_export_entries
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
create trigger st_v8_content_manifest_header_immutable before update on sectalk_private.st_v8_content_exports
  for each row when (old.approved_at is not null and
    (old.id,old.workspace,old.requester,old.reviewer,old.created_at,old.approved_at,old.expires_at,old.manifest_sha256,old.record_count)
    is distinct from (new.id,new.workspace,new.requester,new.reviewer,new.created_at,new.approved_at,new.expires_at,new.manifest_sha256,new.record_count))
  execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_content_exports enable row level security;
alter table sectalk_private.st_v8_content_export_entries enable row level security;
revoke all on sectalk_private.st_v8_content_exports,sectalk_private.st_v8_content_export_entries
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_content_export_records(p_workspace uuid,p_owner uuid,p_reviewer uuid,
  p_kind text default null,p_scope uuid default null,p_record uuid default null)
returns table(kind text,scope_id uuid,record_id uuid,item jsonb)
language sql stable security definer set search_path='' set timezone='UTC' as $$
  select 'room_message',r.id,p.id,jsonb_build_object('room',r.id,'name',r.name,'message',p.id,'parent',p.parent_id,
    'body',p.body,'kind',p.kind,'createdAt',p.created_at,'editedAt',p.edited_at)
  from public.st_v6_rooms r join public.st_v6_room_posts p on p.room_id=r.id
  where (p_kind is null or p_kind='room_message') and (p_scope is null or r.id=p_scope) and (p_record is null or p.id=p_record)
    and r.workspace_id=p_workspace and r.kind='public' and r.classification in ('public','internal') and not r.archived
    and p.removed_at is null and not p.forwarded
    and (p.parent_id is null or exists(select 1 from public.st_v6_room_posts root
      where (root.room_id,root.id)=(p.room_id,p.parent_id) and root.parent_id is null
        and root.removed_at is null and not root.forwarded
        and (root.sender=p_owner or sectalk_private.open_pair(root.sender,p_owner))
        and (root.sender=p_reviewer or sectalk_private.open_pair(root.sender,p_reviewer))))
    and sectalk_private.st_v6_room_role(r.id,p_owner) is not null
    and sectalk_private.st_v6_room_role(r.id,p_reviewer) is not null
    and (p.sender=p_owner or sectalk_private.open_pair(p.sender,p_owner))
    and (p.sender=p_reviewer or sectalk_private.open_pair(p.sender,p_reviewer))
  union all
  select 'channel_message',c.id,p.id,jsonb_build_object('channel',c.id,'name',c.name,'message',p.id,
    'body',p.body,'createdAt',p.created_at)
  from public.st_v2_channels c join public.st_v2_posts p on p.channel_id=c.id
  where (p_kind is null or p_kind='channel_message') and (p_scope is null or c.id=p_scope) and (p_record is null or p.id=p_record)
    and c.workspace_id=p_workspace and c.visibility='workspace' and c.encryption_mode='standard' and not c.archived
    and p.quarantined_at is null
    and sectalk_private.st_v2_post_read(c.id,p.sender,p_owner)
    and sectalk_private.st_v2_post_read(c.id,p.sender,p_reviewer)
  union all
  select 'workspace_task',i.workspace_id,i.id,jsonb_build_object('task',i.id,'title',i.title,'details',i.details,
    'dueAt',i.due_at,'completed',i.completed,'createdAt',i.created_at)
  from public.st_v2_items i
  where (p_kind is null or p_kind='workspace_task') and (p_scope is null or i.workspace_id=p_scope) and (p_record is null or i.id=p_record)
    and i.workspace_id=p_workspace and i.kind='task'
    and (i.created_by=p_owner or sectalk_private.open_pair(i.created_by,p_owner))
    and (i.created_by=p_reviewer or sectalk_private.open_pair(i.created_by,p_reviewer))
  union all
  select 'room_task',r.id,t.id,jsonb_build_object('room',r.id,'task',t.id,'title',t.title,'status',t.status,
    'priority',t.priority,'labels',t.labels,'dueAt',t.due_at,'createdAt',t.created_at,'updatedAt',t.updated_at)
  from public.st_v6_rooms r join public.st_v6_tasks t on t.room_id=r.id
  where (p_kind is null or p_kind='room_task') and (p_scope is null or r.id=p_scope) and (p_record is null or t.id=p_record)
    and r.workspace_id=p_workspace and r.kind='public' and r.classification in ('public','internal') and not r.archived
    and not exists(select 1 from sectalk_private.st_v6_task_sources x where x.task_id=t.id)
    and sectalk_private.st_v6_room_role(r.id,p_owner) is not null
    and sectalk_private.st_v6_room_role(r.id,p_reviewer) is not null
    and sectalk_private.st_v6_task_audience(r.id,null,p_owner)
    and sectalk_private.st_v6_task_audience(r.id,null,p_reviewer)
    and (t.author_id=p_owner or sectalk_private.open_pair(t.author_id,p_owner))
    and (t.author_id=p_reviewer or sectalk_private.open_pair(t.author_id,p_reviewer));
$$;

create function public.st_v8_offboarding_content(p_workspace uuid,p_action text default 'status',
  p_id uuid default null,p_confirmation text default null,p_after integer default 0)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); access_kind text:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
  export_row sectalk_private.st_v8_content_exports; entries jsonb; total integer; fingerprint text;
  after_position integer; end_position integer; fresh jsonb;
begin
  if access_kind='none' or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not sectalk_private.st_v7_admin_fresh() then
    raise exception 'Verified content export access unavailable' using errcode='42501'; end if;
  if p_action='status' then
    select * into export_row from sectalk_private.st_v8_content_exports where workspace=p_workspace and withdrawn_at is null;
    return jsonb_build_object('role',access_kind,'id',export_row.id,'records',export_row.record_count,
      'manifestSha256',export_row.manifest_sha256,'expiresAt',export_row.expires_at);
  end if;
  if p_id is null or p_confirmation is distinct from p_workspace::text then
    raise exception 'Confirm the workspace for this content export' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v8_offboarding_content',30);
  if p_action='page' then
    select * into export_row from sectalk_private.st_v8_content_exports where workspace=p_workspace and id=p_id for share;
  else
    perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
    select * into export_row from sectalk_private.st_v8_content_exports where workspace=p_workspace and id=p_id for update;
    access_kind:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
  end if;
  if p_action='export_content' and access_kind='owner' then
    if export_row.id is null then
      if exists(select 1 from sectalk_private.st_v8_content_exports e where e.workspace=p_workspace and e.withdrawn_at is null) then
        raise exception 'Withdraw the existing content approval before starting another' using errcode='PT409';
      end if;
      insert into sectalk_private.st_v8_content_exports(id,workspace,requester) values(p_id,p_workspace,actor_id);
    elsif export_row.requester<>actor_id or export_row.withdrawn_at is not null then
      raise exception 'Content export unavailable' using errcode='42501'; end if;
  elsif p_action='approve' and access_kind='reviewer' and export_row.requester<>actor_id
    and export_row.withdrawn_at is null
    and sectalk_private.st_v8_offboarding_role(p_workspace,export_row.requester)='owner' then
    if export_row.reviewer=actor_id then return jsonb_build_object('id',p_id); end if;
    if export_row.reviewer is not null or export_row.created_at<statement_timestamp()-interval '24 hours' then
      raise exception 'Content approval unavailable' using errcode='42501'; end if;
    with picked as (
      select s.kind,s.scope_id,s.record_id,encode(sha256(convert_to(s.item::text,'UTF8')),'hex') as sha
      from sectalk_private.st_v8_content_export_records(p_workspace,export_row.requester,actor_id) s
      order by s.kind,s.scope_id,s.record_id limit 501
    )
    insert into sectalk_private.st_v8_content_export_entries(export_id,position,kind,scope_id,record_id,sha256)
      select p_id,row_number() over(order by s.kind,s.scope_id,s.record_id),s.kind,s.scope_id,s.record_id,s.sha from picked s;
    get diagnostics total=row_count;
    if total>500 then raise exception 'Content export exceeds the 500-record approval limit' using errcode='22023'; end if;
    select encode(sha256(convert_to(jsonb_build_object('format','sectalk-workspace-content-v1','workspace',p_workspace,
      'approval',p_id,'entries',coalesce(jsonb_agg(jsonb_build_array(m.position,m.kind,m.scope_id,m.record_id,m.sha256)
      order by m.position),'[]'))::text,'UTF8')),'hex')
      into fingerprint from sectalk_private.st_v8_content_export_entries m where m.export_id=p_id;
    update sectalk_private.st_v8_content_exports set reviewer=actor_id,approved_at=statement_timestamp(),
      expires_at=statement_timestamp()+interval '24 hours',record_count=total,manifest_sha256=fingerprint where id=p_id;
  elsif p_action='page' and access_kind='owner' and export_row.requester=actor_id and export_row.withdrawn_at is null
    and export_row.expires_at>statement_timestamp()
    and sectalk_private.st_v8_offboarding_role(p_workspace,export_row.reviewer)='reviewer' then
    if p_after is null or p_after<0 or p_after>export_row.record_count or p_after%25<>0 then
      raise exception 'Invalid content page cursor' using errcode='22023'; end if;
    after_position:=p_after;
    end_position:=least(p_after+25,export_row.record_count);
    select jsonb_agg(jsonb_build_object('position',m.position,'kind',m.kind,'scope',m.scope_id,'id',m.record_id,
      'sha256',m.sha256,'json',s.item::text) order by m.position),count(s.item)
      into fresh,total from sectalk_private.st_v8_content_export_entries m
      left join lateral sectalk_private.st_v8_content_export_records(p_workspace,actor_id,export_row.reviewer,m.kind,m.scope_id,m.record_id) s
        on encode(sha256(convert_to(s.item::text,'UTF8')),'hex')=m.sha256
      where m.export_id=p_id and m.position>after_position and m.position<=end_position;
    if total<>end_position-after_position then
      raise exception 'An approved record changed or access ended' using errcode='42501'; end if;
    return jsonb_build_object('id',p_id,'manifestSha256',export_row.manifest_sha256,'records',coalesce(fresh,'[]'),
      'next',case when end_position<export_row.record_count then end_position end);
  elsif p_action='withdraw' and access_kind='owner' and export_row.id is not null then
    update sectalk_private.st_v8_content_exports set withdrawn_at=coalesce(withdrawn_at,statement_timestamp()) where id=p_id;
  else raise exception 'Content export unavailable' using errcode='42501';
  end if;
  return jsonb_build_object('id',p_id);
end $$;

revoke all on function sectalk_private.st_v8_content_export_records(uuid,uuid,uuid,text,uuid,uuid),
  public.st_v8_offboarding_content(uuid,text,uuid,text,integer) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_content(uuid,text,uuid,text,integer) to authenticated;
notify pgrst,'reload schema';
commit;
