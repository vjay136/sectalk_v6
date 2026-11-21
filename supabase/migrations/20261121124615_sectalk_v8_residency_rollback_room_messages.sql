begin;

create table sectalk_private.st_v8_residency_rollback_room_batches (
  handoff uuid primary key references sectalk_private.st_v8_residency_rollback_manifests on delete cascade,
  packet_sha256 text not null check(packet_sha256~'^[0-9a-f]{64}$'),
  records jsonb not null check(jsonb_typeof(records)='array'),
  staged_by uuid not null,
  applied_by uuid,
  applied_at timestamptz,
  check(applied_by is distinct from staged_by),
  check((applied_by is null)=(applied_at is null))
);
alter table sectalk_private.st_v8_residency_rollback_room_batches enable row level security;
revoke all on sectalk_private.st_v8_residency_rollback_room_batches from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v7_guard_workspace_write()
returns trigger language plpgsql security definer set search_path='' as $$
declare current_row jsonb:=to_jsonb(new); prior_row jsonb; tenant uuid; previous uuid;
begin
  if tg_op='INSERT' and tg_relid in ('public.st_v2_channels'::regclass,'public.st_v2_posts'::regclass,'public.st_v6_room_posts'::regclass)
    and exists(select 1 from sectalk_private.st_v8_residency_channel_write_permits p
      where (p.tx,p.relation,p.row_id)=(pg_current_xact_id_if_assigned(),tg_relid,(current_row->>'id')::uuid)
        and p.revision=encode(sha256(convert_to(current_row::text,'UTF8')),'hex')) then return new; end if;
  if tg_op='INSERT' and tg_relid='public.st_v2_items'::regclass and current_row->>'kind'='task'
    and exists(select 1 from sectalk_private.st_v8_residency_board_write_permits p
      where (p.tx,p.workspace,p.task)=(pg_current_xact_id_if_assigned(),(current_row->>'workspace_id')::uuid,(current_row->>'id')::uuid)
        and p.before_sha256 is null
        and p.after_sha256=encode(sha256(convert_to(current_row::text,'UTF8')),'hex')) then return new; end if;
  if tg_op='UPDATE' then
    prior_row:=to_jsonb(old);
    if tg_relid='public.st_v2_items'::regclass and current_row-'completed'=prior_row-'completed'
      and current_row->'completed' is distinct from prior_row->'completed' and current_row->>'kind'='task'
      and exists(select 1 from sectalk_private.st_v8_residency_board_write_permits p
        where (p.tx,p.workspace,p.task)=(pg_current_xact_id_if_assigned(),(current_row->>'workspace_id')::uuid,(current_row->>'id')::uuid)
          and p.before_sha256=encode(sha256(convert_to(prior_row::text,'UTF8')),'hex')
          and p.after_sha256=encode(sha256(convert_to(current_row::text,'UTF8')),'hex')) then return new; end if;
    if tg_argv[2]='room_post' and prior_row->>'removed_at' is null and current_row->>'removed_at' is not null
      and current_row->>'body'='Message removed' and current_row->>tg_argv[0]=prior_row->>tg_argv[0] then return new; end if;
    if tg_argv[2]='channel_post' and prior_row->>'quarantined_at' is null and current_row->>'quarantined_at' is not null
      and current_row->>'body'='Message quarantined' and current_row->>tg_argv[0]=prior_row->>tg_argv[0] then return new; end if;
    if tg_argv[2]='workspace_member' and current_row->>tg_argv[0]=prior_row->>tg_argv[0]
      and (current_row->>'suspended_at' is not null or (current_row->>'role'='member' and prior_row->>'role'='admin'))
      then return new; end if;
    if tg_argv[2]='file' and current_row->>'published_at' is not distinct from prior_row->>'published_at'
      and current_row->>tg_argv[0]=prior_row->>tg_argv[0] then return new; end if;
    if tg_argv[2]='recording' and current_row->>'status'<>'collecting' then return new; end if;
    previous:=sectalk_private.st_v7_workspace_write_scope((prior_row->>tg_argv[0])::uuid,tg_argv[1]);
  end if;
  tenant:=sectalk_private.st_v7_workspace_write_scope((current_row->>tg_argv[0])::uuid,tg_argv[1]);
  perform sectalk_private.st_v7_require_workspace_write(least(tenant,previous));
  if tenant is not null and previous is not null and tenant is distinct from previous then
    perform sectalk_private.st_v7_require_workspace_write(greatest(tenant,previous));
  end if;
  return new;
end $$;

create function sectalk_private.st_v8_rollback_room_message(p_author uuid,p_record jsonb)
returns public.st_v6_room_posts language sql stable set search_path='' as $$
  select jsonb_populate_record(null::public.st_v6_room_posts,jsonb_build_object(
    'room_id',p_record->>'room','id',p_record->>'id','sender',p_author,
    'body',p_record->>'body','kind','message','parent_id',null,'created_at',p_record->>'createdAt',
    'edited_at',null,'removed_at',null,'forwarded',false));
$$;

create function sectalk_private.st_v8_residency_source_room_matches(
  p_workspace uuid,p_approval uuid,p_owner uuid,p_reviewer uuid,p_room uuid,p_name text
) returns boolean language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  select exists(select 1 from public.st_v6_rooms r
    where (r.id,r.workspace_id,r.name)=(p_room,p_workspace,p_name)
      and r.kind='public' and r.classification in ('public','internal')
      and r.encryption_mode='standard' and not r.archived and not r.locked
      and sectalk_private.st_v8_standard_room_session_allowed(r.id)
      and sectalk_private.st_v6_room_role(r.id,p_owner) in ('owner','moderator','member')
      and sectalk_private.st_v6_room_role(r.id,p_reviewer) is not null
      and sectalk_private.open_pair(p_owner,p_reviewer)
  ) and exists(
    select 1 from sectalk_private.st_v8_content_export_entries e
    join lateral sectalk_private.st_v8_content_export_records(p_workspace,p_owner,p_reviewer,
      'room_message',p_room,e.record_id) s on
      e.sha256=encode(sha256(convert_to(s.item::text,'UTF8')),'hex') and s.item->>'name'=p_name
    where (e.export_id,e.kind,e.scope_id)=(p_approval,'room_message',p_room)
  );
$$;

revoke all on function sectalk_private.st_v8_rollback_room_message(uuid,jsonb),
  sectalk_private.st_v8_residency_source_room_matches(uuid,uuid,uuid,uuid,uuid,text)
  from public,anon,authenticated,service_role;

create function public.st_v8_residency_rollback_rooms(p_workspace uuid,p_action text default 'status',
  p_confirmation text default null,p_packet jsonb default null)
returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  actor_id uuid:=auth.uid(); access_kind text; side text;
  transfer sectalk_private.st_v8_residency_write_handoffs;
  admission sectalk_private.st_v8_residency_rollback_manifest_admissions;
  manifest sectalk_private.st_v8_residency_rollback_manifests;
  batch sectalk_private.st_v8_residency_rollback_room_batches;
  approval sectalk_private.st_v8_content_exports;
  review jsonb; claim jsonb; records jsonb; item jsonb; restored public.st_v6_room_posts;
  signing_key bytea; wire text; packet_digest text; owner_tag text; email text; expiry bigint; current_epoch bigint;
  post_table oid:='public.st_v6_room_posts'::regclass;
begin
  if p_workspace is null or p_action is null or p_action not in ('status','issue','stage','apply')
    or sectalk_private.st_v7_billing_admin_session() is not true then raise insufficient_privilege; end if;
  access_kind:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
  if access_kind not in ('owner','reviewer') or sectalk_private.st_v8_organization_sso_allows(p_workspace) is not true
    or sectalk_private.st_v8_room_structure_sso_allows(p_workspace) is not true
    or exists(select 1 from sectalk_private.st_v8_workspace_standard_room_sso s where s.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(s.workspace,s.protocol,s.provider) is not true)
    then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if p_confirmation is distinct from p_workspace::text or sectalk_private.st_v7_admin_fresh() is not true
      or access_kind is distinct from (case when p_action='apply' then 'reviewer' else 'owner' end)
      then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    if p_action='apply' then
      perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
      perform pg_advisory_xact_lock(hashtextextended('sectalk-room-mode:'||p_workspace::text,0));
    end if;
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for share;
    if not found or access_kind is distinct from sectalk_private.st_v8_offboarding_role(p_workspace,actor_id)
      then raise insufficient_privilege; end if;
  end if;
  side:=sectalk_private.st_v8_residency_rollback_side(p_workspace);
  if side is null or side='destination' and access_kind<>'owner' then
    if p_action='status' then return '{"state":"inactive"}'::jsonb; end if;
    raise insufficient_privilege;
  end if;
  if p_action<>'status' and (p_action='issue') is distinct from (side='destination') then raise insufficient_privilege; end if;
  select * into strict transfer from sectalk_private.st_v8_residency_write_handoffs t where t.workspace=p_workspace;
  select * into admission from sectalk_private.st_v8_residency_rollback_manifest_admissions a
    where a.handoff=transfer.handoff and a.expires_at>statement_timestamp();
  if side='source' then
    select * into approval from sectalk_private.st_v8_content_exports c
      where (c.id,c.workspace)=(transfer.approval,p_workspace) and c.approved_at is not null and c.withdrawn_at is null
        and sectalk_private.st_v8_offboarding_role(p_workspace,c.requester)='owner'
        and sectalk_private.st_v8_offboarding_role(p_workspace,c.reviewer)='reviewer';
    if not found or actor_id is distinct from (case when access_kind='owner' then approval.requester else approval.reviewer end) then
      if p_action='status' then return '{"state":"inactive"}'::jsonb; end if;
      raise insufficient_privilege;
    end if;
    select * into manifest from sectalk_private.st_v8_residency_rollback_manifests m
      where (m.handoff,m.workspace)=(transfer.handoff,p_workspace);
    select * into batch from sectalk_private.st_v8_residency_rollback_room_batches b where b.handoff=transfer.handoff;
    if batch.handoff is not null and (batch.staged_by is distinct from approval.requester or exists(
      select 1 from jsonb_array_elements(batch.records) r
      where not sectalk_private.st_v8_residency_source_room_matches(p_workspace,approval.id,approval.requester,
        approval.reviewer,(r->>'room')::uuid,r->>'roomName'))) then
      if p_action='status' then return '{"state":"inactive"}'::jsonb; end if;
      raise exception 'The approved source room or reviewer access changed.' using errcode='PT409';
    end if;
  end if;
  if p_action='status' then
    return jsonb_build_object('state',case when batch.applied_at is not null then 'applied' when batch.handoff is not null then 'staged'
      when admission.handoff is not null and (side='destination' or manifest.handoff is not null) then 'ready' else 'inactive' end,
      'side',side,'role',access_kind,'records',case when batch.applied_at is null then batch.records else null end);
  end if;
  perform sectalk_private.limit_action('v8_residency_room_replay',12);
  if p_action='stage' then
    if manifest.handoff is null or not coalesce(jsonb_typeof(p_packet)='object' and octet_length(p_packet::text)<=8388608
      and p_packet->>'signature'~'^[0-9a-f]{64}$' and jsonb_typeof(p_packet->'payload')='string'
      and p_packet-array['payload','signature']='{}'::jsonb,false) then raise insufficient_privilege; end if;
    packet_digest:=encode(sha256(convert_to(p_packet::text,'UTF8')),'hex');
    if batch.handoff is not null then
      if batch.packet_sha256 is distinct from packet_digest then
        raise exception 'A different room message batch is already staged.' using errcode='PT409'; end if;
      return jsonb_build_object('state',case when batch.applied_at is null then 'staged' else 'applied' end,
        'side',side,'role',access_kind,'records',case when batch.applied_at is null then batch.records else null end);
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
    owner_tag:=encode(extensions.hmac(convert_to('sectalk-room-replay-owner-v1:'||transfer.handoff::text||':'||email,'UTF8'),
      signing_key,'sha256'),'hex');
  end if;
  if p_action='issue' then
    review:=public.st_v8_residency_rollback_reconcile(p_workspace);
    if review->>'state' is distinct from 'reviewed' then
      raise exception 'A current independent destination review is required.' using errcode='PT409'; end if;
    select coalesce(jsonb_agg(jsonb_build_object('kind','room_message','id',p.id,'room',p.room_id,'roomName',r.name,
      'body',p.body,'createdAt',p.created_at,'digest',e->>'after') order by p.room_id,p.id),'[]'::jsonb) into records
    from jsonb_array_elements(review->'changes') e
    join public.st_v6_room_posts p on p.id=(e->>'id')::uuid
    join public.st_v6_rooms r on r.id=p.room_id
    where (e->>'kind',e->>'state')=('room_message','added') and (p.sender,r.creator,r.workspace_id)=(actor_id,actor_id,p_workspace)
      and p.created_at>=transfer.changed_at and p.kind='message' and p.parent_id is null and p.edited_at is null
      and p.removed_at is null and not p.forwarded and r.kind='private' and r.classification='confidential'
      and r.encryption_mode='standard' and not r.archived and not r.locked
      and sectalk_private.st_v6_room_role(r.id,actor_id)='owner'
      and e->>'after'=encode(sha256(convert_to(to_jsonb(p)::text,'UTF8')),'hex')
      and not exists(select 1 from jsonb_array_elements(review->'changes') diff
        where (diff->>'kind',diff->>'id')=('room',r.id::text))
      and exists(select 1 from sectalk_private.st_v8_residency_room_imports i
        where (i.workspace,i.source_project,i.approval,i.room,i.room_name,i.actor)=
          (p_workspace,transfer.source_project,transfer.approval,r.id,r.name,actor_id) and i.imported_at<=transfer.changed_at)
      and not exists(select 1 from sectalk_private.st_v6_room_reports report where (report.room_id,report.post_id)=(p.room_id,p.id))
      and not exists(select 1 from public.st_v6_room_posts duplicate where duplicate.id=p.id and duplicate.room_id<>p.room_id);
    if jsonb_array_length(records) not between 1 and 500 then
      raise exception 'The reviewed changes contain no eligible owner-authored room messages, or exceed the replay limit.'
        using errcode='PT409'; end if;
    wire:=jsonb_build_object('format','sectalk-residency-room-replay-v1','workspace',p_workspace,'handoff',transfer.handoff,
      'source',transfer.source_project,'destination',transfer.destination_project,'review',review->>'id','digest',review->>'digest',
      'plan',admission.plan_sha256,'records',records,'ownerTag',owner_tag,'destinationOwner',actor_id,
      'expires',floor(extract(epoch from least(admission.expires_at,statement_timestamp()+interval '5 minutes'))))::text;
    claim:=jsonb_build_object('payload',wire,'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),'hex'));
    if octet_length(claim::text)>8388608 then raise exception 'The room message batch exceeds the transfer limit.' using errcode='PT409'; end if;
    return jsonb_build_object('state','ready','side',side,'role',access_kind,'packet',claim);
  end if;
  if manifest.handoff is null then raise insufficient_privilege; end if;
  if p_action='stage' then
    wire:=p_packet->>'payload';
    if extensions.hmac(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),signing_key,'sha256')
      <>extensions.hmac(decode(p_packet->>'signature','hex'),signing_key,'sha256') then raise insufficient_privilege; end if;
    claim:=wire::jsonb; records:=claim->'records'; expiry:=(claim->>'expires')::bigint;
    current_epoch:=floor(extract(epoch from clock_timestamp()));
    if (claim->>'format',claim->>'workspace',claim->>'handoff',claim->>'source',claim->>'destination',
        claim->>'review',claim->>'digest',claim->>'plan') is distinct from
      ('sectalk-residency-room-replay-v1',p_workspace::text,transfer.handoff::text,transfer.source_project,
        transfer.destination_project,manifest.review::text,manifest.review_sha256,manifest.plan_sha256)
      or admission.plan_sha256 is distinct from manifest.plan_sha256 or expiry is null or expiry<=current_epoch or expiry>current_epoch+303
      or jsonb_typeof(records) is distinct from 'array' or jsonb_array_length(records) not between 1 and 500
      or not coalesce(claim->>'ownerTag'~'^[0-9a-f]{64}$'
        and claim->>'destinationOwner'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$',false)
      or extensions.hmac(convert_to(claim->>'ownerTag','UTF8'),signing_key,'sha256')
         <>extensions.hmac(convert_to(owner_tag,'UTF8'),signing_key,'sha256') then raise insufficient_privilege; end if;
    if (select count(distinct e->>'id') from jsonb_array_elements(records) e)<>jsonb_array_length(records)
      then raise insufficient_privilege; end if;
    for item in select e from jsonb_array_elements(records) e loop
      if not coalesce(jsonb_typeof(item)='object' and item->>'kind'='room_message'
        and item-array['kind','id','room','roomName','body','createdAt','digest']='{}'::jsonb
        and item->>'room'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
        and char_length(item->>'roomName') between 1 and 64 and jsonb_typeof(item->'body')='string'
        and char_length(btrim(item->>'body')) between 1 and 4000 and jsonb_typeof(item->'createdAt')='string',false)
        or not exists(select 1 from jsonb_array_elements(manifest.changes) c where
          (c->>'kind',c->>'state',c->>'id',c->>'after')=('room_message','added',item->>'id',item->>'digest'))
        or encode(sha256(convert_to(to_jsonb(sectalk_private.st_v8_rollback_room_message(
          (claim->>'destinationOwner')::uuid,item))::text,'UTF8')),'hex') is distinct from item->>'digest'
        or not sectalk_private.st_v8_residency_source_room_matches(p_workspace,approval.id,approval.requester,
          approval.reviewer,(item->>'room')::uuid,item->>'roomName') then raise insufficient_privilege; end if;
    end loop;
    insert into sectalk_private.st_v8_residency_rollback_room_batches(handoff,packet_sha256,records,staged_by)
      values(transfer.handoff,packet_digest,records,actor_id);
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor_id,'workspace.residency_room_replay_staged',transfer.handoff);
    return jsonb_build_object('state','staged','side',side,'role',access_kind,'records',records);
  end if;

  if batch.handoff is null or actor_id is distinct from approval.reviewer then raise insufficient_privilege; end if;
  if batch.applied_at is not null then return jsonb_build_object('state','applied','side',side,'role',access_kind); end if;
  perform 1 from sectalk_private.st_v8_offboarding_reviewers r
    join public.st_v2_members m on (r.workspace,r.actor)=(m.workspace_id,m.user_id)
    where (r.workspace,r.actor)=(p_workspace,actor_id) and m.role='admin' and m.suspended_at is null for share of r,m;
  if not found then raise insufficient_privilege; end if;
  if sectalk_private.st_v8_offboarding_holds(p_workspace)
    or sectalk_private.st_v7_workspace_payment_mode(p_workspace)->>'reason' is distinct from 'residency'
    or exists(select 1 from sectalk_private.st_v8_room_encryption_policy p where p.workspace=p_workspace and p.managed)
    then raise exception 'A preservation or workspace policy blocks standard room replay.' using errcode='PT423'; end if;
  for item in select e from jsonb_array_elements(batch.records) e order by e->>'room',e->>'id' loop
    restored:=sectalk_private.st_v8_rollback_room_message(approval.requester,item);
    perform 1 from public.st_v6_rooms r where (r.id,r.workspace_id)=(restored.room_id,p_workspace) for update;
    if not found or not sectalk_private.st_v8_residency_source_room_matches(p_workspace,approval.id,approval.requester,
      approval.reviewer,restored.room_id,item->>'roomName') then
      raise exception 'The approved source room no longer matches.' using errcode='PT409'; end if;
    if sectalk_private.st_v6_room_role_rule(restored.room_id,approval.requester,'post')='deny'
      or exists(select 1 from public.st_v6_room_timeouts t where (t.room_id,t.user_id)=(restored.room_id,approval.requester)
        and t.until_at>statement_timestamp())
      then raise exception 'The source author cannot post under the current room policy.' using errcode='PT423'; end if;
    if exists(select 1 from public.st_v6_room_posts p where p.id=restored.id)
      or exists(select 1 from sectalk_private.st_v6_room_reports r where (r.room_id,r.post_id)=(restored.room_id,restored.id))
      then raise exception 'A reviewed room message ID is already in use or has a retained report.' using errcode='PT409'; end if;
    insert into sectalk_private.st_v8_residency_channel_write_permits values(pg_current_xact_id(),post_table,restored.id,
      encode(sha256(convert_to(to_jsonb(restored)::text,'UTF8')),'hex'));
    insert into public.st_v6_room_posts select (restored).*;
    if not exists(select 1 from public.st_v6_room_posts p where (p.room_id,p.id)=(restored.room_id,restored.id)
      and to_jsonb(p)=to_jsonb(restored)) then
      raise exception 'A local policy altered the recovered room message.' using errcode='PT409'; end if;
    delete from sectalk_private.st_v8_residency_channel_write_permits p
      where (p.tx,p.relation,p.row_id)=(pg_current_xact_id(),post_table,restored.id);
  end loop;
  update sectalk_private.st_v8_residency_rollback_room_batches b set applied_by=actor_id,applied_at=clock_timestamp()
    where b.handoff=transfer.handoff;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor_id,'workspace.residency_room_replay_applied',transfer.handoff);
  return jsonb_build_object('state','applied','side',side,'role',access_kind);
end $$;

revoke all on function public.st_v8_residency_rollback_rooms(uuid,text,text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_rollback_rooms(uuid,text,text,jsonb) to authenticated;

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
  ), rooms as (
    select (e->>'id')::uuid as id,e
    from sectalk_private.st_v8_residency_rollback_room_batches b
    cross join lateral jsonb_array_elements(b.records) e
    where b.handoff=transfer.handoff and b.applied_at is not null
      and (b.staged_by,b.applied_by)=(approval.requester,approval.reviewer)
  ), recovered_files as (
    select * from sectalk_private.st_v8_restored_file_evidence(p_workspace,transfer.handoff,manifest.review,
      approval.requester,approval.reviewer)
  ), evidence as (
    select e->>'kind' as kind,(e->>'id')::uuid as id,e->>'state' as change,e->>'after' as revision
    from jsonb_array_elements(manifest.changes) e
  ), checked as (
    select d.kind,d.id,d.change,d.revision,r.receipt,
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
        when rp.id is not null then case when coalesce(
          to_jsonb(post)=to_jsonb(sectalk_private.st_v8_rollback_room_message(approval.requester,rp.e))
          and sectalk_private.st_v8_residency_source_room_matches(p_workspace,approval.id,approval.requester,
            approval.reviewer,post.room_id,rp.e->>'roomName')
          and not exists(select 1 from sectalk_private.st_v6_room_reports report
            where (report.room_id,report.post_id)=(post.room_id,post.id))
          and not exists(select 1 from public.st_v6_room_posts duplicate where duplicate.id=post.id and duplicate.room_id<>post.room_id),
          false) then 'matched' else 'source_changed' end
        when r.id is not null then case when r.matched then 'matched' else 'source_changed' end
        else 'not_replayed'
      end as result
    from evidence d
    left join rooms rp on d.kind='room_message' and d.id=rp.id and d.revision=rp.e->>'digest' and d.change='added'
    left join public.st_v6_room_posts post on (post.room_id,post.id)=((rp.e->>'room')::uuid,rp.id)
    left join recovered_files r on (r.kind,r.id,r.revision)=(d.kind,d.id,d.revision) and d.change='added'
    left join board b on d.kind='workspace_task' and d.id=b.id and d.revision=b.e->>'after'
      and d.change=(case when b.e->>'kind'='added' then 'added' else 'changed' end)
    left join public.st_v2_items i on i.id=b.id and i.workspace_id=p_workspace and i.kind='task'
    left join chat a on d.kind=a.e->>'kind' and d.id=a.id and d.revision=a.e->>'digest' and d.change='added'
    left join public.st_v2_channels c on d.kind='channel' and c.id=a.id and c.workspace_id=p_workspace
    left join public.st_v2_posts p on d.kind='channel_message' and p.id=a.id
    left join public.st_v2_channels parent on parent.id=p.channel_id
  )
  select coalesce(jsonb_agg(jsonb_build_object('kind',kind,'id',id,'change',change,'revision',revision,'result',result)
    ||case when receipt is null then '{}'::jsonb else jsonb_build_object('sourceReceipt',receipt) end
    order by kind,id),'[]'::jsonb) into results from checked;

  return jsonb_build_object('state','held','reviewDigest',manifest.review_sha256,'records',results);
end $$;

create or replace function sectalk_private.st_v8_offboarding_reconcile_workspace_root(r sectalk_private.st_v8_offboarding_requests)
returns jsonb language sql stable set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
  with base as materialized (select sectalk_private.st_v8_offboarding_reconcile_archives(r) as snapshot),
    root as materialized (select sectalk_private.st_v8_offboarding_workspace_root_snapshot(r.workspace) as snapshot),
    families(name,section) as (values
      ('residencyRecoveryPaths','storage'),('residencyRecoveryFileReceipts','native'),
      ('residencyDestinationRetirements','native'),('residencySourceReactivations','native'),
      ('residencyRecoveryRoomBatches','native')
    ), scoped(name,row_data) as (
      (select 'residencyRecoveryPaths',to_jsonb(o)-'last_accessed_at' from storage.objects o
        where o.bucket_id='sectalk-residency-recovery' and o.name like r.workspace::text||'/%'
        order by o.name,o.id limit 501)
      union all (select 'residencyRecoveryFileReceipts',to_jsonb(c)
        from sectalk_private.st_v8_residency_source_file_copies c
        join sectalk_private.st_v8_residency_write_handoffs h on h.handoff=c.handoff
        where h.workspace=r.workspace order by c.handoff,c.file limit 501)
      union all (select 'residencyRecoveryRoomBatches',to_jsonb(b)
        from sectalk_private.st_v8_residency_rollback_room_batches b
        join sectalk_private.st_v8_residency_write_handoffs h on h.handoff=b.handoff
        where h.workspace=r.workspace order by b.handoff limit 501)
      union all (select 'residencyDestinationRetirements',to_jsonb(d)
        from sectalk_private.st_v8_residency_retired_destinations d where d.workspace=r.workspace
        order by d.receipt limit 501)
      union all (select 'residencySourceReactivations',to_jsonb(a)
        from sectalk_private.st_v8_residency_source_reactivations a where a.workspace=r.workspace
        order by a.handoff limit 501)
    ), digests as (
      select name,encode(sha256(convert_to(row_data::text,'UTF8')),'hex') as digest from scoped
    ), counts as (
      select f.name,f.section,count(d.digest) as rows,
        encode(sha256(convert_to(coalesce(string_agg(d.digest,'' order by d.digest),''),'UTF8')),'hex') as digest
      from families f left join digests d using(name) group by f.name,f.section
    )
  select jsonb_build_object('summary',(base.snapshot->'summary')||jsonb_build_object(
    'workspaceRootDependencies',root.snapshot->'summary',
    'nativeRows',(base.snapshot#>'{summary,nativeRows}')||
      (select jsonb_object_agg(name,rows) from counts where section='native'),
    'storageMetadata',(base.snapshot#>'{summary,storageMetadata}')||
      (select jsonb_object_agg(name,rows) from counts where section='storage'),
    'overflow',(base.snapshot#>'{summary,overflow}')||case when (root.snapshot#>>'{summary,overflowFamilies}')::integer>0
      then '["workspaceRootReferences"]'::jsonb else '[]'::jsonb end||
      (select coalesce(jsonb_agg(name order by name),'[]') from counts where rows>500)),
    'revision',encode(sha256(convert_to(jsonb_build_array('sectalk-workspace-root-reconciliation-v2',
      base.snapshot->>'revision',root.snapshot->>'revision',(select jsonb_object_agg(name,digest) from counts))::text,'UTF8')),'hex'))
  from base cross join root;
$$;

notify pgrst,'reload schema';
commit;
