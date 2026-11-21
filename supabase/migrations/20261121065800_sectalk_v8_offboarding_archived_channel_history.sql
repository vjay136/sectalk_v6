begin;

alter table sectalk_private.st_v8_offboarding_archived_channel_plans add column message_manifest jsonb not null default '[]'
  check(jsonb_typeof(message_manifest)='array' and jsonb_array_length(message_manifest)<=16);

create table sectalk_private.st_v8_offboarding_retired_channel_posts (
  post uuid primary key,
  plan uuid not null references sectalk_private.st_v8_offboarding_archived_channel_plans,
  channel uuid not null,
  sha256 text not null check(sha256~'^[a-f0-9]{64}$')
);
alter table sectalk_private.st_v8_offboarding_retired_channel_posts enable row level security;
revoke all on sectalk_private.st_v8_offboarding_retired_channel_posts from public,anon,authenticated,service_role;
create trigger st_v8_retired_channel_post_immutable before update or delete on sectalk_private.st_v8_offboarding_retired_channel_posts
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

create function sectalk_private.st_v8_prevent_archived_channel_post_id_reuse()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform pg_advisory_xact_lock(hashtextextended('sectalk-channel-post-identifier:'||new.id::text,0));
  if exists(select 1 from sectalk_private.st_v8_offboarding_retired_channel_posts x where x.post=new.id) then
    raise exception 'This archived message identifier is permanently retired' using errcode='PT409';
  end if;
  return new;
end $$;
create trigger st_v8_prevent_archived_channel_post_id_reuse before insert or update of id on public.st_v2_posts
  for each row execute function sectalk_private.st_v8_prevent_archived_channel_post_id_reuse();
revoke all on function sectalk_private.st_v8_prevent_archived_channel_post_id_reuse() from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v8_offboarding_archived_channel_source(
  r sectalk_private.st_v8_offboarding_requests,p_channel uuid
) returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  select jsonb_build_object('channel',to_jsonb(c),'archiveAudit',to_jsonb(a)) ||
    case when messages.total=0 then '{}'::jsonb else jsonb_build_object('messages',messages.rows) end
  from public.st_v2_channels c join sectalk_private.st_v6_channel_audit a on a.channel_id=c.id
  cross join lateral (
    select count(*) as total,jsonb_agg(to_jsonb(p) order by p.id) as rows,
      coalesce(bool_and(p.sender=r.requester and p.quarantined_at is null
        and sectalk_private.st_v2_post_read(c.id,p.sender,r.requester)
        and sectalk_private.st_v2_post_read(c.id,p.sender,r.reviewer)
        and not exists(select 1 from sectalk_private.st_v8_channel_payloads k where k.post=p.id)
        and not exists(select 1 from sectalk_private.st_v8_offboarding_post_deletions z where z.post=p.id)),true) as eligible
    from (select x.* from public.st_v2_posts x where x.channel_id=c.id order by x.id limit 17) p
  ) messages
  where (c.workspace_id,c.id,c.owner)=(r.workspace,p_channel,r.requester)
    and c.name<>'general' and c.visibility='workspace' and c.encryption_mode='standard' and c.archived
    and sectalk_private.st_v6_channel_can_manage(c.id,r.requester)
    and sectalk_private.st_v6_channel_can_manage(c.id,r.reviewer)
    and sectalk_private.st_v8_standard_channel_session_allowed(c.id)
    and a.actor=r.requester and a.action='archive' and a.target is null and a.detail is null
    and not exists(select 1 from sectalk_private.st_v6_channel_audit x where x.channel_id=c.id and x.id<>a.id)
    and exists(select 1 from sectalk_private.st_v6_audit_chain j
      where (j.source,j.source_id,j.operation,j.row_hash)=
        ('sectalk_private.st_v6_channel_audit',a.id,'INSERT',sectalk_private.st_v6_audit_row_hash(to_jsonb(a))))
    and not exists(select 1 from sectalk_private.st_v6_audit_chain j
      where (j.source,j.source_id)=('sectalk_private.st_v6_channel_audit',a.id) and j.operation<>'INSERT')
    and messages.total<=16 and messages.eligible
    and (messages.total=0 or not exists(select 1 from pg_constraint f
      where f.contype='f' and f.confrelid='public.st_v2_posts'::regclass
        and f.conrelid<>'sectalk_private.st_v8_channel_payloads'::regclass))
    and not exists(select 1 from sectalk_private.st_v7_dlp_acknowledgements x where (x.scope_type,x.scope_id)=('channel',c.id))
    and not exists(select 1 from sectalk_private.st_v6_channel_members x where x.channel_id=c.id)
    and not exists(select 1 from sectalk_private.st_v6_room_quiet_rules x where x.channel_id=c.id)
    and not exists(select 1 from sectalk_private.st_v8_channel_key_tickets x where x.channel=c.id)
    and not exists(select 1 from sectalk_private.st_v8_managed_report_tickets x where x.channel=c.id)
    and not exists(select 1 from sectalk_private.st_v7_channel_reports x where x.channel_id=c.id)
    and not exists(select 1 from sectalk_private.st_v6_preserved_post_versions x where (x.source,x.scope_id)=('channel',c.id))
    and not exists(select 1 from sectalk_private.st_v7_dlp_delivery_receipts x where (x.scope_type,x.scope_id)=('channel',c.id));
$$;

create or replace function public.st_v8_offboarding_archived_channel_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare r sectalk_private.st_v8_offboarding_requests:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
begin
  if not sectalk_private.st_v8_channel_structure_sso_allows(p_workspace) then raise insufficient_privilege; end if;
  return jsonb_build_object('held',sectalk_private.st_v8_offboarding_holds(p_workspace),
    'channels',case when auth.uid()=r.requester then coalesce((select jsonb_agg(to_jsonb(x) order by x.name,x.id) from (
      select c.id,c.name,coalesce(jsonb_array_length(s.source->'messages'),0) as "messageCount",exists(select 1 from sectalk_private.st_v8_offboarding_archived_channel_copies a
        where (a.request_id,a.channel,a.owner_id,a.sha256)=(r.id,c.id,r.requester,
          encode(sha256(convert_to(s.source::text,'UTF8')),'hex'))) as copied
      from public.st_v2_channels c cross join lateral (select sectalk_private.st_v8_offboarding_archived_channel_source(r,c.id)
        as source offset 0) s
      where c.workspace_id=p_workspace and c.archived and s.source is not null order by c.name,c.id limit 100
    ) x),'[]') else '[]'::jsonb end,
    'plans',coalesce((select jsonb_agg(to_jsonb(p) order by p."createdAt" desc,p.plan) from (
      select x.id as plan,x.channel,x.channel_name as name,x.sha256,x.copy_sha256 as "copySha256",x.archive_sha256 as "archiveSha256",
        x.message_manifest as messages,x.created_at as "createdAt",d.happened_at as "approvedAt",z.happened_at as "deletedAt"
      from sectalk_private.st_v8_offboarding_archived_channel_plans x
      left join sectalk_private.st_v8_offboarding_archived_channel_decisions d on (d.plan,d.action)=(x.id,'approved')
      left join sectalk_private.st_v8_offboarding_archived_channel_decisions z on (z.plan,z.action)=(x.id,'removed')
      where (x.request_id,x.workspace)=(r.id,p_workspace) and (x.expires_at>statement_timestamp() or z.happened_at is not null)
      order by x.created_at desc,x.id limit 50
    ) p),'[]'));
end $$;

create or replace function public.st_v8_offboarding_archived_channel(
  p_workspace uuid,p_channel uuid,p_action text,p_confirmation text,p_plan uuid default null,p_sha256 text default null
) returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  caller uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  plan sectalk_private.st_v8_offboarding_archived_channel_plans;
  source jsonb; audit_row jsonb; metadata_sha text; event_sha text; key_sha text; fingerprint text;
  inventory_until timestamptz; approved_at timestamptz; deleted_at timestamptz;
  message_manifest jsonb; message_id uuid; message_count integer; removed_count integer;
begin
  if p_workspace is null or p_channel is null or p_action is null or p_action not in ('copy','capture','approve','delete')
    or p_confirmation is distinct from p_workspace::text then raise insufficient_privilege; end if;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if not sectalk_private.st_v8_channel_structure_sso_allows(p_workspace)
    or caller is distinct from (case when p_action='approve' then r.reviewer else r.requester end) then raise insufficient_privilege; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-tenant-key:'||p_workspace::text,0));
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform 1 from public.st_v2_workspaces w where w.id=p_workspace for no key update;
  select x.* into r from sectalk_private.st_v8_offboarding_requests x
    where x.workspace=p_workspace and x.state='read_only' and x.integration_shutdown is not null for update;
  perform 1 from sectalk_private.st_v8_offboarding_reviewers x where (x.workspace,x.actor)=(p_workspace,r.reviewer) for share;
  if not found then raise insufficient_privilege; end if;
  perform 1 from public.st_v2_members x where x.workspace_id=p_workspace and x.user_id in (r.requester,r.reviewer)
    order by x.user_id for share;
  r:=sectalk_private.st_v8_offboarding_task_request(p_workspace);
  if not sectalk_private.st_v8_channel_structure_sso_allows(p_workspace)
    or caller is distinct from (case when p_action='approve' then r.reviewer else r.requester end)
    or sectalk_private.st_v8_offboarding_holds(p_workspace) then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_offboarding_archived_channel',12);

  if p_action in ('approve','delete') then
    select p.* into plan from sectalk_private.st_v8_offboarding_archived_channel_plans p
      where (p.id,p.workspace,p.request_id,p.channel,p.sha256)=(p_plan,p_workspace,r.id,p_channel,p_sha256);
    if plan.id is null then raise exception 'Confirm the exact channel deletion digest' using errcode='PT409'; end if;
    select x.happened_at into approved_at from sectalk_private.st_v8_offboarding_archived_channel_decisions x
      where (x.plan,x.action,x.actor)=(plan.id,'approved',r.reviewer);
    select x.happened_at into deleted_at from sectalk_private.st_v8_offboarding_archived_channel_decisions x
      where (x.plan,x.action,x.actor)=(plan.id,'removed',r.requester);
    if deleted_at is not null then
      return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'approvedAt',approved_at,'deletedAt',deleted_at);
    end if;
  end if;

  select c.expires_at into inventory_until from sectalk_private.st_v7_compliance_cases c
    where (c.id,c.workspace_id,c.requester,c.reviewer)=(r.case_id,p_workspace,r.requester,r.reviewer)
      and c.state='approved' and c.expires_at>clock_timestamp() and c.manifest_sha256~'^[a-f0-9]{64}$' and c.ticket is null for share;
  if inventory_until is null or not exists(select 1 from sectalk_private.st_v7_compliance_audit a
    where (a.case_id,a.workspace_id,a.actor,a.action)=(r.case_id,p_workspace,r.requester,'downloaded'))
    or exists(select 1 from sectalk_private.st_v7_compliance_cases c where c.workspace_id=p_workspace and c.id<>r.case_id
      and c.state in ('pending','approved') and c.expires_at>clock_timestamp())
    or exists(select 1 from sectalk_private.st_v7_evidence_operations o
      join sectalk_private.st_v7_compliance_cases c on c.id=o.case_id where c.workspace_id=p_workspace and o.expires_at>clock_timestamp())
    then raise exception 'Live inventory and clear evidence retention are required' using errcode='PT409'; end if;
  perform 1 from public.st_v2_channels c where (c.workspace_id,c.id)=(p_workspace,p_channel) for update nowait;
  if not found then raise insufficient_privilege; end if;
  perform 1 from sectalk_private.st_v6_channel_audit a where a.channel_id=p_channel order by a.id limit 2 for update nowait;
  perform 1 from public.st_v2_posts p where p.channel_id=p_channel order by p.id limit 17 for update nowait;
  source:=sectalk_private.st_v8_offboarding_archived_channel_source(r,p_channel);
  if source is null then raise exception 'The archived channel, message history or archive evidence is ineligible' using errcode='PT409'; end if;
  audit_row:=source->'archiveAudit';
  select coalesce(jsonb_agg(jsonb_build_object('id',p->>'id',
    'sha256',encode(sha256(convert_to(p::text,'UTF8')),'hex')) order by p->>'id'),'[]'::jsonb)
    into message_manifest from jsonb_array_elements(coalesce(source->'messages','[]'::jsonb)) p;
  message_count:=jsonb_array_length(message_manifest);
  metadata_sha:=encode(sha256(convert_to(source::text,'UTF8')),'hex');
  event_sha:=encode(sectalk_private.st_v6_audit_row_hash(audit_row),'hex');
  select encode(sha256(convert_to(jsonb_build_array(s.current_version,
    coalesce((select jsonb_agg(jsonb_build_array(k.version,k.custody,k.provider_ref,k.wrapped) order by k.version)
      from sectalk_private.st_v7_tenant_key_versions k where k.workspace=s.workspace),'[]'))::text,'UTF8')),'hex')
    into key_sha from sectalk_private.st_v7_tenant_key_state s where s.workspace=p_workspace and s.destroyed_at is null
      and exists(select 1 from sectalk_private.st_v7_tenant_key_versions k where (k.workspace,k.version)=(s.workspace,s.current_version));
  if key_sha is null
    or exists(select 1 from sectalk_private.st_v7_tenant_key_destroy k where k.workspace=p_workspace and k.result is null)
    or exists(select 1 from sectalk_private.st_v7_tenant_rotation_tickets k where k.workspace=p_workspace and k.expires_at>clock_timestamp())
    then raise exception 'Live stable key custody is required' using errcode='PT409'; end if;
  perform 1 from auth.sessions n join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
    join auth.mfa_amr_claims a on a.session_id=n.id and a.authentication_method='totp'
    where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',caller) and n.aal='aal2' and f.status='verified' and f.factor_type='totp'
      and a.updated_at>clock_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp() for share of n,f,a;
  if not found or inventory_until<=clock_timestamp() then raise insufficient_privilege; end if;

  if p_action='copy' then
    insert into sectalk_private.st_v8_offboarding_archived_channel_copies(request_id,channel,owner_id,sha256)
      values(r.id,p_channel,caller,metadata_sha) on conflict do nothing;
    return jsonb_build_object('format',case when message_count=0 then 'sectalk-offboarding-archived-channel-copy-v1'
      else 'sectalk-offboarding-archived-channel-history-copy-v1' end,'channel',p_channel,
      'sha256',metadata_sha,'json',source::text);
  end if;
  if not exists(select 1 from sectalk_private.st_v8_offboarding_archived_channel_copies a
    where (a.request_id,a.channel,a.owner_id,a.sha256)=(r.id,p_channel,r.requester,metadata_sha)) then
    raise exception 'Download the exact approved channel copy first' using errcode='PT409'; end if;
  fingerprint:=encode(sha256(convert_to(jsonb_build_array('sectalk-offboarding-archived-channel-v1',p_workspace,r.id,
    r.snapshot_sha256,p_channel,metadata_sha,event_sha,key_sha)::text,'UTF8')),'hex');
  if p_action='capture' then
    insert into sectalk_private.st_v8_offboarding_archived_channel_plans(request_id,workspace,channel,channel_name,
      owner_id,reviewer_id,copy_sha256,archive_sha256,sha256,expires_at,message_manifest)
      values(r.id,p_workspace,p_channel,source#>>'{channel,name}',r.requester,r.reviewer,metadata_sha,event_sha,fingerprint,inventory_until,message_manifest)
      on conflict do nothing;
    select x.* into strict plan from sectalk_private.st_v8_offboarding_archived_channel_plans x
      where (x.request_id,x.workspace,x.channel,x.sha256)=(r.id,p_workspace,p_channel,fingerprint);
  elsif plan.sha256 is distinct from fingerprint or plan.message_manifest is distinct from message_manifest or plan.expires_at<=clock_timestamp() then
    raise exception 'The exact channel approval changed or expired' using errcode='PT409';
  elsif p_action='approve' and approved_at is null then
    insert into sectalk_private.st_v8_offboarding_archived_channel_decisions(plan,action,actor)
      values(plan.id,'approved',caller) returning happened_at into approved_at;
  elsif p_action='delete' then
    if approved_at is null then raise insufficient_privilege; end if;
    -- Lock the search jobs before removing source data. The worker skips locked jobs.
    for message_id in select (p->>'id')::uuid from jsonb_array_elements(message_manifest) p order by 1 loop
      perform pg_advisory_xact_lock(hashtextextended('sectalk-channel-post-identifier:'||message_id::text,0));
      loop
        insert into sectalk_private.st_v7_search_pending(kind,object_id) values('channel',message_id) on conflict do nothing;
        perform 1 from sectalk_private.st_v7_search_pending d
          where (d.kind,d.object_id)=('channel',message_id) for update;
        exit when found;
      end loop;
    end loop;
    if inventory_until<=clock_timestamp() or plan.expires_at<=clock_timestamp()
      or not sectalk_private.st_v7_admin_fresh()
      or not sectalk_private.st_v8_channel_structure_sso_allows(p_workspace)
      or sectalk_private.st_v8_offboarding_archived_channel_source(r,p_channel) is distinct from source
      then raise insufficient_privilege; end if;
    insert into sectalk_private.st_v8_offboarding_retired_channel_posts(post,plan,channel,sha256)
      select (p->>'id')::uuid,plan.id,p_channel,p->>'sha256' from jsonb_array_elements(message_manifest) p;
    delete from public.st_v2_posts p where p.channel_id=p_channel and exists(
      select 1 from jsonb_array_elements(message_manifest) x where (x->>'id')::uuid=p.id);
    get diagnostics removed_count=row_count;
    if removed_count<>message_count then
      raise exception 'An approved archived message could not be removed' using errcode='PT409';
    end if;
    delete from sectalk_private.st_v7_search_document d where d.kind='channel' and exists(
      select 1 from jsonb_array_elements(message_manifest) x where (x->>'id')::uuid=d.object_id);
    insert into sectalk_private.st_v8_offboarding_retained_channel_archive(plan,audit_id,audit_row,sha256)
      values(plan.id,(audit_row->>'id')::bigint,audit_row,event_sha);
    delete from public.st_v2_channels c where (c.workspace_id,c.id)=(p_workspace,p_channel);
    if not found then raise exception 'The exact channel could not be removed' using errcode='PT409'; end if;
    insert into sectalk_private.st_v8_offboarding_archived_channel_decisions(plan,action,actor)
      values(plan.id,'removed',caller) returning happened_at into deleted_at;
  end if;
  return jsonb_build_object('plan',plan.id,'sha256',plan.sha256,'approvedAt',approved_at,'deletedAt',deleted_at);
end $$;

revoke all on function sectalk_private.st_v8_offboarding_archived_channel_source(sectalk_private.st_v8_offboarding_requests,uuid),
  public.st_v8_offboarding_archived_channel_status(uuid),public.st_v8_offboarding_archived_channel(uuid,uuid,text,text,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_offboarding_archived_channel_status(uuid),
  public.st_v8_offboarding_archived_channel(uuid,uuid,text,text,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
