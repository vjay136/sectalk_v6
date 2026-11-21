begin;

create table sectalk_private.st_v8_managed_channel_wraps (
  post uuid primary key references sectalk_private.st_v8_channel_payloads on delete cascade,
  workspace uuid not null,
  source_revision text not null check(source_revision~'^[a-f0-9]{64}$'),
  wrapping_version integer not null,
  wrapped_dek text not null check(wrapped_dek~'^[A-Za-z0-9_-]{80}$'),
  foreign key(workspace,wrapping_version) references sectalk_private.st_v7_tenant_key_versions on delete cascade
);
create table sectalk_private.st_v8_managed_channel_rewrap_audit (
  post uuid not null,
  workspace uuid not null,
  source_revision text not null check(source_revision~'^[a-f0-9]{64}$'),
  previous_version integer not null,
  wrapping_version integer not null check(wrapping_version>previous_version),
  authorized_by uuid not null,
  occurred_at timestamptz not null default clock_timestamp(),
  primary key(post,wrapping_version)
);
create trigger st_v8_immutable_managed_channel_rewrap_audit before update or delete
  on sectalk_private.st_v8_managed_channel_rewrap_audit
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_managed_channel_wraps enable row level security;
alter table sectalk_private.st_v8_managed_channel_rewrap_audit enable row level security;
revoke all on sectalk_private.st_v8_managed_channel_wraps,sectalk_private.st_v8_managed_channel_rewrap_audit
  from public,anon,authenticated,service_role;

create index st_v8_rewrap_payload_workspace on sectalk_private.st_v8_channel_payloads(workspace,key_version,post);
create index st_v8_rewrap_report_post on sectalk_private.st_v7_channel_reports(post_id);
create index st_v8_rewrap_report_ticket_post on sectalk_private.st_v8_managed_report_tickets(post,expires_at);

create function sectalk_private.st_v8_managed_channel_rewrap_candidates(p_workspace uuid,p_post uuid)
returns table(workspace uuid,post uuid,channel uuid,actor uuid,policy_revision uuid,authorized_by uuid,
  source_revision text,source_key jsonb,target_key jsonb,payload jsonb)
language sql stable set search_path='' as $$
  select e.workspace,e.post,p.channel_id,p.sender,s.revision,s.authorized_by,
    sectalk_private.st_v8_managed_revision(e),
    jsonb_build_object('workspace',e.workspace,'version',src.version,'custody',src.custody,'ref',src.provider_ref,'wrapped',src.wrapped),
    jsonb_build_object('workspace',e.workspace,'version',dst.version,'custody',dst.custody,'ref',dst.provider_ref,'wrapped',dst.wrapped),
    jsonb_build_object('body',e.body,'nonce',e.nonce,'tag',e.tag,'data_version',e.key_version,
      'wrapped_dek',coalesce(w.wrapped_dek,e.wrapped_dek))
  from sectalk_private.st_v8_tenant_rotation_schedules s
  join sectalk_private.st_v7_tenant_key_state k on k.workspace=s.workspace and k.destroyed_at is null
  join sectalk_private.st_v7_tenant_key_versions dst on (dst.workspace,dst.version)=(k.workspace,k.current_version)
    and dst.custody='managed'
  join sectalk_private.st_v8_channel_payloads e on e.workspace=s.workspace and e.key_version<dst.version
  join sectalk_private.st_v7_tenant_key_versions original on (original.workspace,original.version)=(e.workspace,e.key_version)
    and original.custody='managed'
  join public.st_v2_posts p on p.id=e.post and p.quarantined_at is null
  join public.st_v2_channels c on (c.workspace_id,c.id)=(e.workspace,p.channel_id) and c.encryption_mode='managed'
  left join sectalk_private.st_v8_managed_channel_wraps w on (w.workspace,w.post)=(e.workspace,e.post)
    and w.source_revision=sectalk_private.st_v8_managed_revision(e)
  join sectalk_private.st_v7_tenant_key_versions src on (src.workspace,src.version)=(e.workspace,coalesce(w.wrapping_version,e.key_version))
    and src.custody='managed' and src.version<dst.version
  where s.workspace=p_workspace and (p_post is null or e.post=p_post)
    and sectalk_private.st_v8_scheduled_rotation_allowed(s.workspace,s.authorized_by)
    and not exists(select 1 from sectalk_private.st_v6_workspace_holds h where h.workspace_id=e.workspace and h.released_at is null)
    and not exists(select 1 from sectalk_private.st_v7_channel_reports r where r.post_id=e.post)
    and not exists(select 1 from sectalk_private.st_v8_managed_report_tickets t where t.post=e.post and t.expires_at>statement_timestamp());
$$;

create function public.st_v8_due_managed_channel_rewrap(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select coalesce(jsonb_agg(to_jsonb(jobs)),'[]'::jsonb) from (
    select workspace,post,channel,actor,policy_revision,source_revision,source_key,target_key,payload
    from sectalk_private.st_v8_managed_channel_rewrap_candidates(p_workspace,null)
    order by post limit 16
  ) jobs;
$$;

create function public.st_v8_commit_managed_channel_rewrap(p_workspace uuid,p_post uuid,p_policy_revision uuid,
  p_source_revision text,p_previous integer,p_target integer,p_wrapped_dek text)
returns boolean language plpgsql security definer set search_path='' as $$
declare candidate record;
begin
  if p_workspace is null or p_post is null or p_policy_revision is null or p_previous is null or p_target is null
    or p_previous>=p_target or (p_source_revision~'^[a-f0-9]{64}$') is not true
    or (p_wrapped_dek~'^[A-Za-z0-9_-]{80}$') is not true then return false; end if;
  perform 1 from public.st_v2_workspaces where id=p_workspace for share;
  if not found then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
  perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform 1 from sectalk_private.st_v8_channel_payloads e join public.st_v2_posts p on p.id=e.post
    where (e.workspace,e.post)=(p_workspace,p_post) for update of e,p;
  if not found then return false; end if;
  select * into candidate from sectalk_private.st_v8_managed_channel_rewrap_candidates(p_workspace,p_post);
  if not found or (candidate.source_revision,candidate.policy_revision,(candidate.source_key->>'version')::integer,
    (candidate.target_key->>'version')::integer) is distinct from (p_source_revision,p_policy_revision,p_previous,p_target)
    or p_wrapped_dek=candidate.payload->>'wrapped_dek' then return false; end if;
  insert into sectalk_private.st_v8_managed_channel_wraps(post,workspace,source_revision,wrapping_version,wrapped_dek)
    values(p_post,p_workspace,p_source_revision,p_target,p_wrapped_dek)
    on conflict(post) do update set source_revision=excluded.source_revision,
      wrapping_version=excluded.wrapping_version,wrapped_dek=excluded.wrapped_dek;
  insert into sectalk_private.st_v8_managed_channel_rewrap_audit(post,workspace,source_revision,previous_version,wrapping_version,authorized_by)
    values(p_post,p_workspace,p_source_revision,p_previous,p_target,candidate.authorized_by);
  return true;
end $$;

create or replace function public.st_v8_read_managed_channel(p_ticket uuid,p_actor uuid,p_before timestamptz,p_before_id uuid,p_limit integer)
returns jsonb language plpgsql security definer set search_path='' as $$
declare t sectalk_private.st_v8_channel_key_tickets;
begin
  delete from sectalk_private.st_v8_channel_key_tickets where id=p_ticket and actor=p_actor and purpose='read'
    returning * into t;
  if sectalk_private.st_v8_channel_ticket_live(t) is not true or (p_before is null)<>(p_before_id is null) then return null; end if;
  return coalesce((select jsonb_agg(to_jsonb(posts) order by posts.created_at desc,posts.id desc) from (
    select p.id,p.channel_id,p.sender,p.created_at,p.quarantined_at,e.workspace,e.key_version,
      case when p.quarantined_at is null then jsonb_build_object('body',e.body,'nonce',e.nonce,'tag',e.tag,
        'data_version',e.key_version,'wrapped_dek',coalesce(w.wrapped_dek,e.wrapped_dek)) end as envelope,
      case when p.quarantined_at is null then jsonb_build_object('workspace',e.workspace,'version',k.version,'custody',k.custody,
        'ref',k.provider_ref,'wrapped',k.wrapped) end as key
    from public.st_v2_posts p join sectalk_private.st_v8_channel_payloads e on e.post=p.id
    left join sectalk_private.st_v8_managed_channel_wraps w on (w.workspace,w.post)=(e.workspace,e.post)
      and w.source_revision=sectalk_private.st_v8_managed_revision(e)
    join sectalk_private.st_v7_tenant_key_versions k on (k.workspace,k.version)=(e.workspace,coalesce(w.wrapping_version,e.key_version))
    join public.st_v2_channels c on c.id=p.channel_id and c.workspace_id=e.workspace and c.encryption_mode='managed'
    where p.channel_id=t.channel and sectalk_private.st_v2_post_read(p.channel_id,p.sender,t.actor)
      and (p_before is null or (p.created_at,p.id)<(p_before,p_before_id))
    order by p.created_at desc,p.id desc limit greatest(1,least(100,coalesce(p_limit,51)))
  ) posts),'[]'::jsonb);
end $$;

revoke all on function sectalk_private.st_v8_managed_channel_rewrap_candidates(uuid,uuid),
  public.st_v8_due_managed_channel_rewrap(uuid),public.st_v8_commit_managed_channel_rewrap(uuid,uuid,uuid,text,integer,integer,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_due_managed_channel_rewrap(uuid),
  public.st_v8_commit_managed_channel_rewrap(uuid,uuid,uuid,text,integer,integer,text) to service_role;

commit;
