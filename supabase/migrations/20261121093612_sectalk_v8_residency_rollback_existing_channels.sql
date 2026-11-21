begin;

create function sectalk_private.st_v8_residency_source_channel_matches(
  p_workspace uuid,p_approval uuid,p_owner uuid,p_reviewer uuid,p_channel uuid,p_name text
) returns boolean language sql stable set search_path='' set timezone='UTC' as $$
  select exists(
    select 1 from public.st_v2_channels c where (c.id,c.workspace_id,c.name)=(p_channel,p_workspace,p_name)
      and c.visibility='workspace' and c.encryption_mode='standard' and not c.archived
  ) and exists(
    select 1 from sectalk_private.st_v8_content_export_entries e
    join lateral sectalk_private.st_v8_content_export_records(p_workspace,p_owner,p_reviewer,
      'channel_message',p_channel,e.record_id) s on
      e.sha256=encode(sha256(convert_to(s.item::text,'UTF8')),'hex') and s.item->>'name'=p_name
    where (e.export_id,e.kind,e.scope_id)=(p_approval,'channel_message',p_channel)
  )
$$;
revoke all on function sectalk_private.st_v8_residency_source_channel_matches(uuid,uuid,uuid,uuid,uuid,text)
 from public,anon,authenticated,service_role;

create or replace function public.st_v8_residency_source_replay_review(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  actor_id uuid:=auth.uid();
  actor_role text;
  transfer sectalk_private.st_v8_residency_write_handoffs;
  approval sectalk_private.st_v8_content_exports;
  manifest sectalk_private.st_v8_residency_rollback_manifests;
  results jsonb;
begin
  actor_role:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
  if p_workspace is null or actor_id is null or actor_role not in ('owner','reviewer')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false) then
    raise insufficient_privilege;
  end if;
  if sectalk_private.st_v8_residency_rollback_side(p_workspace) is distinct from 'source' then
    return '{"state":"inactive"}'::jsonb;
  end if;
  select f.* into strict transfer from sectalk_private.st_v8_residency_write_handoffs f where f.workspace=p_workspace;
  select c.* into approval from sectalk_private.st_v8_content_exports c
    where (c.id,c.workspace)=(transfer.approval,p_workspace)
      and c.approved_at is not null and c.withdrawn_at is null
      and sectalk_private.st_v8_offboarding_role(p_workspace,c.requester)='owner'
      and sectalk_private.st_v8_offboarding_role(p_workspace,c.reviewer)='reviewer';
  if not found or actor_id is distinct from (case actor_role when 'owner' then approval.requester else approval.reviewer end) then
    raise insufficient_privilege;
  end if;
  select m.* into manifest from sectalk_private.st_v8_residency_rollback_manifests m
    where m.handoff=transfer.handoff and m.workspace=p_workspace;
  if not found then return '{"state":"awaiting_manifest"}'::jsonb; end if;

  with board as (
    select (e->>'id')::uuid as id,e
    from sectalk_private.st_v8_residency_rollback_board_batches b
    cross join lateral jsonb_array_elements(b.tasks) e
    where b.handoff=transfer.handoff and b.applied_at is not null
      and (b.staged_by,b.applied_by)=(approval.requester,approval.reviewer)
  ), chat as (
    select (e->>'id')::uuid as id,e
    from sectalk_private.st_v8_residency_rollback_channel_batches b
    cross join lateral jsonb_array_elements(b.records) e
    where b.handoff=transfer.handoff and b.applied_at is not null
      and (b.staged_by,b.applied_by)=(approval.requester,approval.reviewer)
  ), evidence as (
    select e->>'kind' as kind,(e->>'id')::uuid as id,e->>'state' as change,e->>'after' as revision
    from jsonb_array_elements(manifest.changes) e
  ), checked as (
    select d.kind,d.id,d.change,d.revision,
      case
        when b.id is not null then case when coalesce(
          case when d.change='added' then
            to_jsonb(i)=to_jsonb(sectalk_private.st_v8_rollback_board_added_row(
              p_workspace,coalesce((b.e->>'sourceAuthor')::uuid,approval.requester),b.e))
          else i.completed=(b.e->>'completed')::boolean and exists(
            select 1 from sectalk_private.st_v8_content_export_entries c
            join lateral sectalk_private.st_v8_content_export_records(p_workspace,approval.requester,approval.reviewer,
              'workspace_task',p_workspace,i.id) s on c.sha256=encode(sha256(convert_to(
                jsonb_set(s.item,'{completed}',to_jsonb(not i.completed))::text,'UTF8')),'hex')
            where (c.export_id,c.kind,c.scope_id,c.record_id)=(approval.id,'workspace_task',p_workspace,i.id))
          end,false) then 'matched' else 'source_changed' end
        when a.id is not null then case when coalesce(
          (case d.kind when 'channel' then to_jsonb(c) else to_jsonb(p) end)=
          sectalk_private.st_v8_rollback_channel_row(p_workspace,
            coalesce((a.e->>'sourceAuthor')::uuid,approval.requester),a.e)
          and (d.kind='channel' or p.channel_id=parent.id and parent.workspace_id=p_workspace
            and parent.visibility='workspace' and parent.encryption_mode='standard' and not parent.archived
            and not exists(select 1 from sectalk_private.st_v7_channel_reports r where r.post_id=p.id)
            and (not (a.e ? 'existingChannelName') or sectalk_private.st_v8_residency_source_channel_matches(
              p_workspace,approval.id,approval.requester,approval.reviewer,parent.id,a.e->>'existingChannelName'))),
          false) then 'matched' else 'source_changed' end
        else 'not_replayed'
      end as result
    from evidence d
    left join board b on d.kind='workspace_task' and d.id=b.id and d.revision=b.e->>'after'
      and d.change=(case when b.e->>'kind'='added' then 'added' else 'changed' end)
    left join public.st_v2_items i on i.id=b.id and i.workspace_id=p_workspace and i.kind='task'
    left join chat a on d.kind=a.e->>'kind' and d.id=a.id and d.revision=a.e->>'digest' and d.change='added'
    left join public.st_v2_channels c on d.kind='channel' and c.id=a.id and c.workspace_id=p_workspace
    left join public.st_v2_posts p on d.kind='channel_message' and p.id=a.id
    left join public.st_v2_channels parent on parent.id=p.channel_id
  )
  select coalesce(jsonb_agg(jsonb_build_object('kind',kind,'id',id,'change',change,'revision',revision,'result',result)
    order by kind,id),'[]'::jsonb) into results from checked;

  return jsonb_build_object('state','held','reviewDigest',manifest.review_sha256,'records',results);
end $$;

create or replace function public.st_v8_residency_rollback_channels(p_workspace uuid,p_action text default 'status',
  p_confirmation text default null,p_packet jsonb default null)
returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare actor_id uuid:=auth.uid(); actor_role text; side text;
  transfer sectalk_private.st_v8_residency_write_handoffs;
  admission sectalk_private.st_v8_residency_rollback_manifest_admissions;
  manifest sectalk_private.st_v8_residency_rollback_manifests;
  batch sectalk_private.st_v8_residency_rollback_channel_batches;
  approval sectalk_private.st_v8_content_exports;
  review jsonb; claim jsonb; records jsonb; item jsonb; channels jsonb; posts jsonb; inserted jsonb;
  source_records jsonb; dest_author uuid; source_author uuid;
  signing_key bytea; wire text; digest text; owner_tag text; email text; expiry bigint; current_epoch bigint;
  dest_owner uuid; replay_id uuid; relation_id oid;
begin
  if p_workspace is null or p_action is null or p_action not in ('status','issue','stage','apply')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false) then raise insufficient_privilege; end if;
  actor_role:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
  if actor_role not in ('owner','reviewer') or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    or not coalesce(sectalk_private.st_v8_channel_structure_sso_allows(p_workspace),false)
    or exists(select 1 from sectalk_private.st_v8_workspace_standard_channel_sso p where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true)
    then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if p_confirmation is distinct from p_workspace::text or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
      or actor_role is distinct from (case when p_action='apply' then 'reviewer' else 'owner' end)
      then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    if p_action='apply' then
      perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
    end if;
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for share;
    if not found or actor_role is distinct from sectalk_private.st_v8_offboarding_role(p_workspace,actor_id)
      then raise insufficient_privilege; end if;
  end if;
  side:=sectalk_private.st_v8_residency_rollback_side(p_workspace);
  if side is null or side='destination' and actor_role<>'owner' then
    if p_action='status' then return '{"state":"inactive"}'::jsonb; end if;
    raise insufficient_privilege;
  end if;
  if p_action<>'status' and (p_action='issue') is distinct from (side='destination') then raise insufficient_privilege; end if;
  select * into transfer from sectalk_private.st_v8_residency_write_handoffs f where f.workspace=p_workspace;
  select * into admission from sectalk_private.st_v8_residency_rollback_manifest_admissions a
    where a.handoff=transfer.handoff and a.expires_at>statement_timestamp();
  if side='source' then
    select * into approval from sectalk_private.st_v8_content_exports c
      where (c.id,c.workspace)=(transfer.approval,p_workspace) and c.approved_at is not null and c.withdrawn_at is null
        and sectalk_private.st_v8_offboarding_role(p_workspace,c.requester)='owner'
        and sectalk_private.st_v8_offboarding_role(p_workspace,c.reviewer)='reviewer';
    if not found or actor_id is distinct from
      (case when actor_role='owner' then approval.requester else approval.reviewer end) then
      if p_action='status' then return '{"state":"inactive"}'::jsonb; end if;
      raise insufficient_privilege;
    end if;
    select * into manifest from sectalk_private.st_v8_residency_rollback_manifests m where m.handoff=transfer.handoff;
    select * into batch from sectalk_private.st_v8_residency_rollback_channel_batches b where b.handoff=transfer.handoff;
  end if;
  if p_action='status' then
    return jsonb_build_object('state',case when batch.applied_at is not null then 'applied' when batch.handoff is not null then 'staged'
      when admission.handoff is not null and (side='destination' or manifest.handoff is not null) then 'ready' else 'inactive' end,
      'side',side,'role',actor_role,'records',coalesce(batch.records,'[]'::jsonb));
  end if;
  perform sectalk_private.limit_action('v8_residency_channel_replay',12);
  if p_action='stage' then
    if manifest.handoff is null or not coalesce(jsonb_typeof(p_packet)='object' and octet_length(p_packet::text)<=8388608
      and p_packet->>'signature'~'^[0-9a-f]{64}$' and jsonb_typeof(p_packet->'payload')='string'
      and p_packet-array['payload','signature']='{}'::jsonb,false) then raise insufficient_privilege; end if;
    digest:=encode(sha256(convert_to(p_packet::text,'UTF8')),'hex');
    if batch.handoff is not null then
      if batch.packet_sha256 is distinct from digest then raise exception 'A different channel batch is already staged.' using errcode='PT409'; end if;
      return jsonb_build_object('state',case when batch.applied_at is null then 'staged' else 'applied' end,
        'side',side,'role',actor_role,'records',batch.records);
    end if;
  end if;
  if p_action in ('issue','stage') then
    select decode(v.decrypted_secret,'hex') into signing_key from vault.decrypted_secrets v
      where v.id=admission.vault_id and v.decrypted_secret~'^[0-9a-f]{64}$';
    if not found then raise insufficient_privilege; end if;
    select lower(btrim(u.email)) into email from auth.users u
      where u.id=actor_id and u.email_confirmed_at is not null and nullif(btrim(u.email),'') is not null
        and nullif(btrim(u.email_change),'') is null;
    if not found then raise insufficient_privilege; end if;
    owner_tag:=encode(extensions.hmac(convert_to('sectalk-channel-replay-owner-v1:'||transfer.handoff::text||':'||email,'UTF8'),
      signing_key,'sha256'),'hex');
  end if;
  if p_action='issue' then
    review:=public.st_v8_residency_rollback_reconcile(p_workspace);
    if review->>'state' is distinct from 'reviewed' then
      raise exception 'A current independent destination review is required.' using errcode='PT409'; end if;
    select coalesce(jsonb_agg(jsonb_build_object('kind','channel','id',c.id,'name',c.name,'createdAt',c.created_at,
        'digest',e->>'after') order by c.id),'[]'::jsonb) into channels
      from jsonb_array_elements(review->'changes') e join public.st_v2_channels c on c.id=(e->>'id')::uuid
      where (e->>'kind',e->>'state')=('channel','added') and c.workspace_id=p_workspace
        and c.owner=actor_id and c.created_at>=transfer.changed_at and c.visibility='workspace' and not c.archived
        and c.encryption_mode='standard' and e->>'after'=encode(sha256(convert_to(to_jsonb(c)::text,'UTF8')),'hex');
    select coalesce(jsonb_agg(jsonb_build_object('kind','channel_message','id',p.id,'channel',p.channel_id,'body',p.body,
        'createdAt',p.created_at,'digest',e->>'after') || case when p.sender<>actor_id then
          jsonb_build_object('destinationAuthor',p.sender,'authorTag',c.email_tag) else '{}'::jsonb end ||
        case when imported.channel is not null then jsonb_build_object('existingChannelName',imported.channel_name)
          else '{}'::jsonb end
        order by p.id),'[]'::jsonb) into posts
      from jsonb_array_elements(review->'changes') e join public.st_v2_posts p on p.id=(e->>'id')::uuid
      left join sectalk_private.st_v8_residency_channel_author_consents c on (c.handoff,c.actor)=(transfer.handoff,p.sender)
      left join lateral (
        select i.channel,i.channel_name from sectalk_private.st_v8_residency_channel_imports i
        join public.st_v2_channels current_channel on (current_channel.id,current_channel.workspace_id,current_channel.name)=
          (i.channel,i.workspace,i.channel_name)
        where (i.workspace,i.source_project,i.approval,i.channel)=
          (p_workspace,transfer.source_project,transfer.approval,p.channel_id)
          and i.imported_at<=transfer.changed_at
          and current_channel.visibility='workspace' and current_channel.encryption_mode='standard' and not current_channel.archived
          and not exists(select 1 from jsonb_array_elements(review->'changes') changed
            where (changed->>'kind',changed->>'id')=('channel',i.channel::text))
        limit 1
      ) imported on true
      where (e->>'kind',e->>'state')=('channel_message','added') and p.created_at>=transfer.changed_at
        and (p.sender=actor_id or (c.revoked_at is null and c.local_identity=
          sectalk_private.st_v8_residency_board_author_local_identity(p_workspace,transfer.handoff,p.sender)))
        and p.quarantined_at is null and e->>'after'=encode(sha256(convert_to(to_jsonb(p)::text,'UTF8')),'hex')
        and (imported.channel is not null or exists(select 1 from jsonb_array_elements(channels) c where c->>'id'=p.channel_id::text))
        and not exists(select 1 from sectalk_private.st_v7_channel_reports r where r.post_id=p.id);
    records:=channels||posts;
    if jsonb_array_length(records) not between 1 and 500 then
      raise exception 'The review has no eligible standard channels or messages, or exceeds the replay limit.' using errcode='PT409'; end if;
    wire:=jsonb_build_object('format','sectalk-residency-channel-replay-v1','workspace',p_workspace,'handoff',transfer.handoff,
      'source',transfer.source_project,'destination',transfer.destination_project,'review',review->>'id','digest',review->>'digest',
      'plan',admission.plan_sha256,'records',records,'ownerTag',owner_tag,'destinationOwner',actor_id,
      'expires',floor(extract(epoch from least(admission.expires_at,statement_timestamp()+interval '5 minutes'))))::text;
    claim:=jsonb_build_object('payload',wire,'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),'hex'));
    if octet_length(claim::text)>8388608 then raise exception 'The channel batch exceeds the transfer limit.' using errcode='PT409'; end if;
    return jsonb_build_object('state','ready','side',side,'role',actor_role,'packet',claim);
  end if;
  if manifest.handoff is null then raise insufficient_privilege; end if;
  if p_action='stage' then
    wire:=p_packet->>'payload';
    if extensions.hmac(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),signing_key,'sha256')
      <>extensions.hmac(decode(p_packet->>'signature','hex'),signing_key,'sha256') then raise insufficient_privilege; end if;
    claim:=wire::jsonb; records:=claim->'records'; expiry:=(claim->>'expires')::bigint;
    current_epoch:=floor(extract(epoch from clock_timestamp()));
    if (claim->>'format',claim->>'workspace',claim->>'handoff',claim->>'source',claim->>'destination',
        claim->>'review',claim->>'digest',claim->>'plan')
       is distinct from ('sectalk-residency-channel-replay-v1',p_workspace::text,transfer.handoff::text,
         transfer.source_project,transfer.destination_project,manifest.review::text,manifest.review_sha256,manifest.plan_sha256)
      or admission.plan_sha256 is distinct from manifest.plan_sha256 or expiry is null or expiry<=current_epoch or expiry>current_epoch+303
      or jsonb_typeof(records) is distinct from 'array' or jsonb_array_length(records) not between 1 and 500
      or not coalesce(claim->>'ownerTag'~'^[0-9a-f]{64}$'
        and claim->>'destinationOwner'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$',false)
      or extensions.hmac(convert_to(claim->>'ownerTag','UTF8'),signing_key,'sha256')
         <>extensions.hmac(convert_to(owner_tag,'UTF8'),signing_key,'sha256') then raise insufficient_privilege; end if;
    dest_owner:=(claim->>'destinationOwner')::uuid;
    if (select count(distinct (e->>'kind',e->>'id')) from jsonb_array_elements(records) e)<>jsonb_array_length(records)
      then raise insufficient_privilege; end if;
    source_records:='[]'::jsonb;
    for item in select e from jsonb_array_elements(records) e
    loop
      if not coalesce(case item->>'kind'
        when 'channel' then item-array['kind','id','name','digest','createdAt']='{}'::jsonb and item->>'name'~'^[a-z0-9][a-z0-9-]{0,39}$'
        when 'channel_message' then item-array['kind','id','channel','body','digest','createdAt','destinationAuthor','authorTag','existingChannelName']='{}'::jsonb
          and jsonb_typeof(item->'body')='string' and char_length(btrim(item->>'body')) between 1 and 4000
          and (not (item ?| array['destinationAuthor','authorTag']) or coalesce(
            item->>'destinationAuthor'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
            and item->>'authorTag'~'^[0-9a-f]{64}$',false))
          and case when item ? 'existingChannelName' then
            item->>'existingChannelName'~'^[a-z0-9][a-z0-9-]{0,39}$'
            and not exists(select 1 from jsonb_array_elements(records) a where (a->>'kind',a->>'id')=('channel',item->>'channel'))
            and sectalk_private.st_v8_residency_source_channel_matches(p_workspace,approval.id,approval.requester,
              approval.reviewer,(item->>'channel')::uuid,item->>'existingChannelName')
          else exists(select 1 from jsonb_array_elements(records) a where (a->>'kind',a->>'id')=('channel',item->>'channel')) end
        else false end,false)
        or not exists(select 1 from jsonb_array_elements(manifest.changes) c
          where (c->>'kind',c->>'state',c->>'id',c->>'after')=(item->>'kind','added',item->>'id',item->>'digest'))
        then raise insufficient_privilege; end if;
      dest_author:=coalesce((item->>'destinationAuthor')::uuid,dest_owner);
      if encode(sha256(convert_to(sectalk_private.st_v8_rollback_channel_row(p_workspace,dest_author,item)::text,'UTF8')),'hex')
        is distinct from item->>'digest' then raise insufficient_privilege; end if;
      if item ? 'destinationAuthor' then
        select c.actor into source_author from sectalk_private.st_v8_residency_channel_author_consents c
          where c.handoff=transfer.handoff and c.email_tag=item->>'authorTag' and c.revoked_at is null
            and c.local_identity=sectalk_private.st_v8_residency_board_author_local_identity(p_workspace,transfer.handoff,c.actor);
        if not found then raise exception 'The matching source member has not approved chat recovery.' using errcode='42501'; end if;
        item:=(item-'authorTag'-'destinationAuthor')||jsonb_build_object('sourceAuthor',source_author,'sourceAuthorTag',item->>'authorTag');
      end if;
      source_records:=source_records||jsonb_build_array(item);
    end loop;
    insert into sectalk_private.st_v8_residency_rollback_channel_batches(handoff,packet_sha256,records,staged_by)
      values(transfer.handoff,digest,source_records,actor_id) returning * into batch;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor_id,'workspace.residency_channel_replay_staged',transfer.handoff);
    return jsonb_build_object('state','staged','side',side,'role',actor_role,'records',batch.records);
  end if;

  if batch.handoff is null or actor_id is distinct from approval.reviewer or batch.staged_by is distinct from approval.requester
    then raise insufficient_privilege; end if;
  if batch.applied_at is not null then
    return jsonb_build_object('state','applied','side',side,'role',actor_role,'records',batch.records); end if;
  perform 1 from sectalk_private.st_v8_offboarding_reviewers r join public.st_v2_members m
    on (r.workspace,r.actor)=(m.workspace_id,m.user_id)
    where (r.workspace,r.actor)=(p_workspace,actor_id) and m.role='admin' and m.suspended_at is null for share of r,m;
  if not found then raise insufficient_privilege; end if;
  if sectalk_private.st_v8_offboarding_holds(p_workspace)
    or sectalk_private.st_v7_workspace_payment_mode(p_workspace)->>'reason' is distinct from 'residency'
    or exists(select 1 from sectalk_private.st_v8_channel_encryption_policy p where p.workspace=p_workspace and p.managed)
    then raise exception 'A preservation or workspace policy blocks standard channel replay.' using errcode='PT423'; end if;
  for item in select e from jsonb_array_elements(batch.records) e order by e->>'kind',e->>'id'
  loop
    replay_id:=(item->>'id')::uuid;
    if item->>'kind'='channel' then
      relation_id:='public.st_v2_channels'::regclass;
      if exists(select 1 from public.st_v2_channels c where c.id=replay_id or (c.workspace_id,c.name)=(p_workspace,item->>'name'))
        or exists(select 1 from sectalk_private.st_v8_offboarding_retained_channel_archive a
          join sectalk_private.st_v8_offboarding_archived_channel_plans p on p.id=a.plan where p.channel=replay_id)
        then raise exception 'A verified channel ID or name is already in use or retained.' using errcode='PT409'; end if;
    else
      relation_id:='public.st_v2_posts'::regclass;
      if item ? 'existingChannelName' then
        perform 1 from public.st_v2_channels c
          where (c.id,c.workspace_id)=((item->>'channel')::uuid,p_workspace) for share;
        if not found or not sectalk_private.st_v8_residency_source_channel_matches(p_workspace,approval.id,
          approval.requester,approval.reviewer,(item->>'channel')::uuid,item->>'existingChannelName')
          then raise exception 'The approved source channel no longer matches.' using errcode='PT409'; end if;
      end if;
      if exists(select 1 from public.st_v2_posts p where p.id=replay_id)
        or exists(select 1 from sectalk_private.st_v7_channel_reports r where r.post_id=replay_id)
        then raise exception 'A verified message ID is already in use or has a retained report.' using errcode='PT409'; end if;
    end if;
    source_author:=approval.requester;
    if item ? 'sourceAuthor' then
      source_author:=(item->>'sourceAuthor')::uuid;
      perform 1 from sectalk_private.st_v8_residency_channel_author_consents c
        join public.st_v2_members m on (m.workspace_id,m.user_id)=(p_workspace,c.actor)
        join auth.users u on u.id=c.actor
        where (c.handoff,c.actor,c.email_tag)=(transfer.handoff,source_author,item->>'sourceAuthorTag')
          and c.revoked_at is null and m.role='member' and m.suspended_at is null
          and c.local_identity=sectalk_private.st_v8_residency_board_author_local_identity(p_workspace,transfer.handoff,c.actor)
        for share of c,m,u;
      if not found then raise exception 'The source member chat recovery approval is no longer current.' using errcode='PT409'; end if;
    end if;
    inserted:=sectalk_private.st_v8_rollback_channel_row(p_workspace,source_author,item);
    insert into sectalk_private.st_v8_residency_channel_write_permits values(pg_current_xact_id(),relation_id,replay_id,
      encode(sha256(convert_to(inserted::text,'UTF8')),'hex'));
    if item->>'kind'='channel' then
      insert into public.st_v2_channels select * from jsonb_populate_record(null::public.st_v2_channels,inserted);
      if not exists(select 1 from public.st_v2_channels c where c.id=replay_id and to_jsonb(c)=inserted)
        then raise exception 'The recovered channel was changed by a local policy.' using errcode='PT409'; end if;
    else
      insert into public.st_v2_posts select * from jsonb_populate_record(null::public.st_v2_posts,inserted);
      if not exists(select 1 from public.st_v2_posts p where p.id=replay_id and to_jsonb(p)=inserted)
        then raise exception 'The recovered message was changed by a local policy.' using errcode='PT409'; end if;
    end if;
    delete from sectalk_private.st_v8_residency_channel_write_permits p
      where (p.tx,p.relation,p.row_id)=(pg_current_xact_id(),relation_id,replay_id);
  end loop;
  update sectalk_private.st_v8_residency_rollback_channel_batches set applied_by=actor_id,applied_at=clock_timestamp()
    where handoff=transfer.handoff;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor_id,'workspace.residency_channel_replay_applied',transfer.handoff);
  return jsonb_build_object('state','applied','side',side,'role',actor_role,'records',batch.records);
end $$;

notify pgrst,'reload schema';
commit;
