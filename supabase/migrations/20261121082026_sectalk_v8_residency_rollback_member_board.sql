begin;

create table sectalk_private.st_v8_residency_board_author_consents (
  handoff uuid not null references sectalk_private.st_v8_residency_write_handoffs(handoff) on delete cascade,
  actor uuid not null references auth.users on delete cascade,
  email_tag text not null check(email_tag~'^[0-9a-f]{64}$'),
  local_identity text not null check(local_identity~'^[0-9a-f]{64}$'),
  approved_at timestamptz not null default clock_timestamp(),
  revoked_at timestamptz,
  primary key(handoff,actor)
);
create unique index st_v8_residency_board_author_active_tag
  on sectalk_private.st_v8_residency_board_author_consents(handoff,email_tag) where revoked_at is null;
alter table sectalk_private.st_v8_residency_board_author_consents enable row level security;
revoke all on sectalk_private.st_v8_residency_board_author_consents from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_residency_board_author_email(p_workspace uuid,p_actor uuid)
returns text language sql stable set search_path='' as $$
  select lower(btrim(u.email)) from auth.users u
  where u.id=p_actor and u.email_confirmed_at is not null and nullif(btrim(u.email),'') is not null
    and nullif(btrim(u.email_change),'') is null
    and sectalk_private.st_v2_role(p_workspace,p_actor)='member' and sectalk_private.st_v2_active(p_actor)
$$;
create function sectalk_private.st_v8_residency_board_author_local_identity(p_workspace uuid,p_handoff uuid,p_actor uuid)
returns text language sql stable set search_path='' as $$
  select encode(sha256(convert_to('sectalk-board-author-local-v1:'||p_handoff::text||':'||p_actor::text||':'||
    sectalk_private.st_v8_residency_board_author_email(p_workspace,p_actor),'UTF8')),'hex')
$$;
revoke all on function sectalk_private.st_v8_residency_board_author_email(uuid,uuid),
  sectalk_private.st_v8_residency_board_author_local_identity(uuid,uuid,uuid) from public,anon,authenticated,service_role;

create function public.st_v8_residency_board_author_consent(p_workspace uuid,p_action text default 'status',
  p_confirmation text default null)
returns text language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); handoff_id uuid; approval sectalk_private.st_v8_residency_board_author_consents;
  email text; identity text; key_bytes bytea; tag text;
begin
  if p_workspace is null or p_action is null or p_action not in ('status','approve','revoke')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or sectalk_private.st_v2_role(p_workspace,actor_id) is distinct from 'member'
    or (p_action<>'revoke' and not coalesce(sectalk_private.st_v8_planner_sso_allows(p_workspace),false))
    then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if p_confirmation is distinct from p_workspace::text or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
      then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    if sectalk_private.st_v2_role(p_workspace,actor_id) is distinct from 'member' then raise insufficient_privilege; end if;
  end if;

  select f.handoff into handoff_id from sectalk_private.st_v8_residency_write_handoffs f where f.workspace=p_workspace
    and (f.phase='held' or sectalk_private.st_v8_residency_rollback_side(p_workspace)='destination');
  if not found then
    if p_action='status' then return 'inactive'; end if;
    raise insufficient_privilege;
  end if;
  select * into approval from sectalk_private.st_v8_residency_board_author_consents c
    where (c.handoff,c.actor)=(handoff_id,actor_id);
  if p_action='revoke' then
    update sectalk_private.st_v8_residency_board_author_consents c set revoked_at=clock_timestamp()
      where (c.handoff,c.actor)=(handoff_id,actor_id) and c.revoked_at is null;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(p_workspace,actor_id,'workspace.residency_board_author_revoked',handoff_id);
    end if;
    return 'ready';
  end if;
  identity:=sectalk_private.st_v8_residency_board_author_local_identity(p_workspace,handoff_id,actor_id);
  if p_action='status' then
    if approval.actor is not null and approval.revoked_at is null and approval.local_identity=identity then return 'approved'; end if;
    if exists(select 1 from sectalk_private.st_v8_residency_rollback_manifest_admissions a
      where a.handoff=handoff_id and a.expires_at>statement_timestamp()) then return 'ready'; end if;
    return 'inactive';
  end if;
  perform sectalk_private.limit_action('v8_residency_board_author',10);
  email:=sectalk_private.st_v8_residency_board_author_email(p_workspace,actor_id);
  select decode(v.decrypted_secret,'hex') into key_bytes
    from sectalk_private.st_v8_residency_rollback_manifest_admissions a join vault.decrypted_secrets v on v.id=a.vault_id
    where a.handoff=handoff_id and a.expires_at>statement_timestamp() and v.decrypted_secret~'^[0-9a-f]{64}$';
  if not found or email is null or identity is null then raise insufficient_privilege; end if;
  tag:=encode(extensions.hmac(convert_to('sectalk-board-member-v1:'||handoff_id::text||':'||email,'UTF8'),key_bytes,'sha256'),'hex');
  insert into sectalk_private.st_v8_residency_board_author_consents as c(handoff,actor,email_tag,local_identity)
    values(handoff_id,actor_id,tag,identity)
    on conflict(handoff,actor) do update set email_tag=excluded.email_tag,local_identity=excluded.local_identity,
      approved_at=clock_timestamp(),revoked_at=null
    where (c.email_tag,c.local_identity,c.revoked_at) is distinct from (excluded.email_tag,excluded.local_identity,null::timestamptz);
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor_id,'workspace.residency_board_author_approved',handoff_id);
  end if;
  return 'approved';
end $$;
revoke all on function public.st_v8_residency_board_author_consent(uuid,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_board_author_consent(uuid,text,text) to authenticated;

create or replace function public.st_v8_residency_rollback_board_replay(p_workspace uuid,p_action text default 'status',
  p_confirmation text default null,p_packet jsonb default null)
returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare actor_id uuid:=auth.uid(); actor_role text; side text; ready boolean;
  transfer sectalk_private.st_v8_residency_write_handoffs;
  admission sectalk_private.st_v8_residency_rollback_manifest_admissions;
  manifest sectalk_private.st_v8_residency_rollback_manifests;
  batch sectalk_private.st_v8_residency_rollback_board_batches;
  approval sectalk_private.st_v8_content_exports;
  review jsonb; claim jsonb; tasks jsonb; added_tasks jsonb; item jsonb; before_row jsonb; after_row jsonb;
  owner_tag text; owner_email text; restored_task public.st_v2_items;
  member_tasks jsonb; task_creator uuid; destination_author uuid;
  signing_key bytea; wire text; packet_digest text; task_id uuid; current_done boolean; wanted boolean; expiry bigint; now_epoch bigint;
begin
  if p_workspace is null or p_action is null or p_action not in ('status','issue','stage','apply')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false) then raise insufficient_privilege; end if;
  actor_role:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
  if actor_role not in ('owner','reviewer') or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    or not coalesce(sectalk_private.st_v8_planner_sso_allows(p_workspace),false) then raise insufficient_privilege; end if;
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
    select * into batch from sectalk_private.st_v8_residency_rollback_board_batches b where b.handoff=transfer.handoff;
  end if;
  if p_action='status' then
    ready:=admission.handoff is not null and (side='destination' or manifest.handoff is not null);
    return jsonb_build_object('state',case when batch.applied_at is not null then 'applied' when batch.handoff is not null then 'staged'
      when ready then 'ready' else 'inactive' end,'side',side,'role',actor_role,'tasks',coalesce(batch.tasks,'[]'::jsonb));
  end if;
  perform sectalk_private.limit_action('v8_residency_board_replay',12);
  if p_action='stage' then
    if manifest.handoff is null or not coalesce(jsonb_typeof(p_packet)='object' and octet_length(p_packet::text)<=8388608
      and p_packet->>'signature'~'^[0-9a-f]{64}$' and jsonb_typeof(p_packet->'payload')='string'
      and p_packet-array['payload','signature']='{}'::jsonb,false) then raise insufficient_privilege; end if;
    packet_digest:=encode(sha256(convert_to(p_packet::text,'UTF8')),'hex');
    if batch.handoff is not null then
      if batch.packet_sha256 is distinct from packet_digest then raise exception 'A different task batch is already staged.' using errcode='PT409'; end if;
      return jsonb_build_object('state',case when batch.applied_at is null then 'staged' else 'applied' end,
        'side','source','role',actor_role,'tasks',batch.tasks);
    end if;
  end if;
  if p_action in ('issue','stage') then
    if admission.vault_id is null then raise insufficient_privilege; end if;
    select decode(v.decrypted_secret,'hex') into signing_key from vault.decrypted_secrets v
      where v.id=admission.vault_id and v.decrypted_secret~'^[0-9a-f]{64}$';
    if not found then raise insufficient_privilege; end if;
  end if;
  if p_action='issue' then
    review:=public.st_v8_residency_rollback_reconcile(p_workspace);
    if review->>'state' is distinct from 'reviewed' then
      raise exception 'A current independent destination review is required.' using errcode='PT409'; end if;
    select coalesce(jsonb_agg(jsonb_build_object('id',i.id,'completed',i.completed,'before',e->>'before','after',e->>'after') order by i.id),'[]'::jsonb)
      into tasks from jsonb_array_elements(review->'changes') e
      join public.st_v2_items i on (i.workspace_id,i.id)=(p_workspace,(e->>'id')::uuid) and i.kind='task'
      where e->>'kind'='workspace_task' and e->>'state'='changed'
        and e->>'after'=encode(sha256(convert_to(to_jsonb(i)::text,'UTF8')),'hex')
        and e->>'before'=encode(sha256(convert_to(jsonb_set(to_jsonb(i),'{completed}',to_jsonb(not i.completed))::text,'UTF8')),'hex');
    select coalesce(jsonb_agg(jsonb_build_object('id',i.id,'completed',i.completed,'before',null,
      'after',e->>'after','kind','added','title',i.title,'details',i.details,'dueAt',i.due_at,'createdAt',i.created_at)
      order by i.id),'[]'::jsonb) into added_tasks
      from jsonb_array_elements(review->'changes') e
      join public.st_v2_items i on (i.workspace_id,i.id,i.kind,i.created_by)=(p_workspace,(e->>'id')::uuid,'task',actor_id)
      where (e->>'kind',e->>'state')=('workspace_task','added') and i.created_at>=transfer.changed_at
        and e->>'after'=encode(sha256(convert_to(to_jsonb(i)::text,'UTF8')),'hex');
    if jsonb_array_length(added_tasks)>0 then
      select lower(btrim(u.email)) into owner_email from auth.users u
        where u.id=actor_id and u.email_confirmed_at is not null and nullif(btrim(u.email),'') is not null;
      if not found then raise exception 'Verify the destination owner account before exporting new tasks.' using errcode='PT409'; end if;
      owner_tag:=encode(extensions.hmac(convert_to('sectalk-board-replay-owner-v1:'||p_workspace::text||':'||
        transfer.handoff::text||':'||owner_email,'UTF8'),signing_key,'sha256'),'hex');
      tasks:=tasks||added_tasks;
    end if;
    select coalesce(jsonb_agg(jsonb_build_object('id',i.id,'completed',i.completed,'before',null,
      'after',e->>'after','kind','added','title',i.title,'details',i.details,'dueAt',i.due_at,'createdAt',i.created_at,
      'destinationAuthor',i.created_by,'authorTag',c.email_tag) order by i.id),'[]'::jsonb) into member_tasks
      from jsonb_array_elements(review->'changes') e
      join public.st_v2_items i on (i.workspace_id,i.id,i.kind)=(p_workspace,(e->>'id')::uuid,'task')
      join sectalk_private.st_v8_residency_board_author_consents c on (c.handoff,c.actor)=(transfer.handoff,i.created_by)
      where (e->>'kind',e->>'state')=('workspace_task','added') and i.created_at>=transfer.changed_at
        and c.revoked_at is null and c.local_identity=
          sectalk_private.st_v8_residency_board_author_local_identity(p_workspace,transfer.handoff,i.created_by)
        and e->>'after'=encode(sha256(convert_to(to_jsonb(i)::text,'UTF8')),'hex');
    tasks:=tasks||member_tasks;
    if jsonb_array_length(tasks) not between 1 and 500 then
      raise exception 'The review has no eligible Board changes or exceeds the replay limit.' using errcode='PT409'; end if;
    wire:=jsonb_build_object('format','sectalk-residency-board-replay-v1','workspace',p_workspace,'handoff',transfer.handoff,
      'source',transfer.source_project,'destination',transfer.destination_project,'review',review->>'id','digest',review->>'digest',
      'plan',admission.plan_sha256,'tasks',tasks,'ownerTag',owner_tag,
      'destinationOwner',case when owner_tag is not null then actor_id end,
      'expires',floor(extract(epoch from least(admission.expires_at,statement_timestamp()+interval '5 minutes'))))::text;
    claim:=jsonb_build_object('payload',wire,'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),'hex'));
    if octet_length(claim::text)>8388608 then raise exception 'The signed task batch exceeds the transfer limit.' using errcode='PT409'; end if;
    return jsonb_build_object('state','ready','side','destination','role',actor_role,'packet',claim);
  end if;
  if manifest.handoff is null then raise insufficient_privilege; end if;
  if p_action='stage' then
    wire:=p_packet->>'payload';
    if extensions.hmac(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),signing_key,'sha256')
      <>extensions.hmac(decode(p_packet->>'signature','hex'),signing_key,'sha256') then raise insufficient_privilege; end if;
    claim:=wire::jsonb; tasks:=claim->'tasks';
    expiry:=(claim->>'expires')::bigint; now_epoch:=floor(extract(epoch from clock_timestamp()));
    if (claim->>'format',claim->>'workspace',claim->>'handoff',claim->>'source',claim->>'destination',
        claim->>'review',claim->>'digest',claim->>'plan')
       is distinct from ('sectalk-residency-board-replay-v1',p_workspace::text,transfer.handoff::text,
         transfer.source_project,transfer.destination_project,manifest.review::text,manifest.review_sha256,manifest.plan_sha256)
      or admission.plan_sha256 is distinct from manifest.plan_sha256 or expiry is null or expiry<=now_epoch or expiry>now_epoch+303
      or jsonb_typeof(tasks) is distinct from 'array' or jsonb_array_length(tasks) not between 1 and 500 then raise insufficient_privilege; end if;
    if exists(select 1 from jsonb_array_elements(tasks) e where not coalesce(
        jsonb_typeof(e)='object' and e ?& array['id','completed','before','after']
        and jsonb_typeof(e->'completed')='boolean'
        and (case when e->>'kind'='added' then
          e ?& array['title','details','dueAt','createdAt']
          and e-array['id','completed','before','after','kind','title','details','dueAt','createdAt','destinationAuthor','authorTag']='{}'::jsonb
          and (not (e ?| array['destinationAuthor','authorTag']) or coalesce(
            e->>'destinationAuthor'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' and e->>'authorTag'~'^[0-9a-f]{64}$',false))
          and jsonb_typeof(e->'title')='string' and char_length(btrim(e->>'title')) between 1 and 120
          and jsonb_typeof(e->'details')='string' and char_length(e->>'details')<=3000
          and jsonb_typeof(e->'dueAt') in ('string','null') and jsonb_typeof(e->'createdAt')='string'
          and e->'before'='null'::jsonb
          else e-array['id','completed','before','after']='{}'::jsonb end)
        and exists(select 1 from jsonb_array_elements(manifest.changes) c
          where (c->>'kind',c->>'state',c->>'id',c->>'before',c->>'after') is not distinct from
            ('workspace_task',case when e->>'kind'='added' then 'added' else 'changed' end,
              e->>'id',e->>'before',e->>'after')),false))
      or (select count(distinct e->>'id') from jsonb_array_elements(tasks) e)<>jsonb_array_length(tasks)
      then raise insufficient_privilege; end if;
    if exists(select 1 from jsonb_array_elements(tasks) e where e->>'kind'='added' and not (e ? 'destinationAuthor')) then
      select lower(btrim(u.email)) into owner_email from auth.users u
        where u.id=actor_id and u.email_confirmed_at is not null and nullif(btrim(u.email),'') is not null;
      if not found or actor_id is distinct from approval.requester then raise insufficient_privilege; end if;
      owner_tag:=encode(extensions.hmac(convert_to('sectalk-board-replay-owner-v1:'||p_workspace::text||':'||
        transfer.handoff::text||':'||owner_email,'UTF8'),signing_key,'sha256'),'hex');
      if not coalesce(claim->>'ownerTag'~'^[0-9a-f]{64}$',false)
        or extensions.hmac(convert_to(claim->>'ownerTag','UTF8'),signing_key,'sha256')
          <>extensions.hmac(convert_to(owner_tag,'UTF8'),signing_key,'sha256') then
        raise exception 'The verified source and destination owner accounts do not match.' using errcode='42501'; end if;
      if not coalesce(claim->>'destinationOwner'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$',false)
        then raise insufficient_privilege; end if;
      for item in select e from jsonb_array_elements(tasks) e where e->>'kind'='added' and not (e ? 'destinationAuthor')
      loop
        restored_task:=sectalk_private.st_v8_rollback_board_added_row(p_workspace,(claim->>'destinationOwner')::uuid,item);
        if encode(sha256(convert_to(to_jsonb(restored_task)::text,'UTF8')),'hex') is distinct from item->>'after'
          then raise insufficient_privilege; end if;
      end loop;
    end if;
    member_tasks:='[]'::jsonb;
    for item in select e from jsonb_array_elements(tasks) e order by e->>'id'
    loop
      if item ? 'destinationAuthor' then
        destination_author:=(item->>'destinationAuthor')::uuid;
        restored_task:=sectalk_private.st_v8_rollback_board_added_row(p_workspace,destination_author,item);
        if encode(sha256(convert_to(to_jsonb(restored_task)::text,'UTF8')),'hex') is distinct from item->>'after'
          then raise insufficient_privilege; end if;
        select c.actor into task_creator from sectalk_private.st_v8_residency_board_author_consents c
          where c.handoff=transfer.handoff and c.email_tag=item->>'authorTag' and c.revoked_at is null
            and c.local_identity=sectalk_private.st_v8_residency_board_author_local_identity(p_workspace,transfer.handoff,c.actor);
        if not found then raise exception 'The matching source member has not approved task recovery.' using errcode='42501'; end if;
        item:=(item-'authorTag'-'destinationAuthor')||jsonb_build_object('sourceAuthor',task_creator,'sourceAuthorTag',item->>'authorTag');
      end if;
      member_tasks:=member_tasks||jsonb_build_array(item);
    end loop;
    tasks:=member_tasks;
    insert into sectalk_private.st_v8_residency_rollback_board_batches(handoff,packet_sha256,tasks,staged_by)
      values(transfer.handoff,packet_digest,tasks,actor_id) returning * into batch;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor_id,'workspace.residency_board_replay_staged',transfer.handoff);
    return jsonb_build_object('state','staged','side','source','role',actor_role,'tasks',batch.tasks);
  end if;

  if batch.handoff is null or actor_id is distinct from approval.reviewer or actor_id=batch.staged_by
    or batch.staged_by is distinct from approval.requester then raise insufficient_privilege; end if;
  if batch.applied_at is not null then
    return jsonb_build_object('state','applied','side','source','role',actor_role,'tasks',batch.tasks);
  end if;
  perform 1 from sectalk_private.st_v8_offboarding_reviewers r join public.st_v2_members m
    on (r.workspace,r.actor)=(m.workspace_id,m.user_id)
    where (r.workspace,r.actor)=(p_workspace,actor_id) and m.role='admin' and m.suspended_at is null for share of r,m;
  if not found then raise insufficient_privilege; end if;
  if sectalk_private.st_v8_offboarding_holds(p_workspace)
    or sectalk_private.st_v7_workspace_payment_mode(p_workspace)->>'reason' is distinct from 'residency'
    then raise exception 'A preservation or workspace restriction blocks the task replay.' using errcode='PT423'; end if;
  for item in select e from jsonb_array_elements(batch.tasks) e order by e->>'id'
  loop
    task_id:=(item->>'id')::uuid; wanted:=(item->>'completed')::boolean;
    if item->>'kind'='added' then
      if exists(select 1 from public.st_v2_items i where i.id=task_id) then
        raise exception 'A recovered task ID is already present on the source.' using errcode='PT409'; end if;
      task_creator:=approval.requester;
      if item ? 'sourceAuthor' then
        task_creator:=(item->>'sourceAuthor')::uuid;
        perform 1 from sectalk_private.st_v8_residency_board_author_consents c
          join public.st_v2_members m on (m.workspace_id,m.user_id)=(p_workspace,c.actor)
          join auth.users u on u.id=c.actor
          where (c.handoff,c.actor,c.email_tag)=(transfer.handoff,task_creator,item->>'sourceAuthorTag')
            and c.revoked_at is null and m.role='member' and m.suspended_at is null
            and c.local_identity=sectalk_private.st_v8_residency_board_author_local_identity(p_workspace,transfer.handoff,c.actor)
          for share of c,m,u;
        if not found then raise exception 'The source member recovery approval is no longer current.' using errcode='PT409'; end if;
      end if;
      restored_task:=sectalk_private.st_v8_rollback_board_added_row(p_workspace,task_creator,item);
      insert into sectalk_private.st_v8_residency_board_write_permits values(pg_current_xact_id(),p_workspace,task_id,null,
        encode(sha256(convert_to(to_jsonb(restored_task)::text,'UTF8')),'hex'));
      insert into public.st_v2_items values(restored_task.*);
      delete from sectalk_private.st_v8_residency_board_write_permits p where (p.tx,p.task)=(pg_current_xact_id(),task_id);
      continue;
    end if;
    select to_jsonb(i),i.completed into before_row,current_done from public.st_v2_items i
      where (i.workspace_id,i.id,i.kind)=(p_workspace,task_id,'task') for update nowait;
    if not found or current_done is not distinct from wanted or not exists(
      select 1 from sectalk_private.st_v8_content_export_entries c
      join lateral sectalk_private.st_v8_content_export_records(p_workspace,approval.requester,approval.reviewer,
        'workspace_task',p_workspace,task_id) s on c.sha256=encode(sha256(convert_to(s.item::text,'UTF8')),'hex')
      where (c.export_id,c.kind,c.scope_id,c.record_id)=(approval.id,'workspace_task',p_workspace,task_id)
      ) then raise exception 'A source task differs from its original approved revision.' using errcode='PT409'; end if;
    after_row:=jsonb_set(before_row,'{completed}',to_jsonb(wanted));
    insert into sectalk_private.st_v8_residency_board_write_permits values(pg_current_xact_id(),p_workspace,task_id,
      encode(sha256(convert_to(before_row::text,'UTF8')),'hex'),encode(sha256(convert_to(after_row::text,'UTF8')),'hex'));
    update public.st_v2_items set completed=wanted where (workspace_id,id)=(p_workspace,task_id);
    if not found then raise exception 'A source task became unavailable.' using errcode='PT409'; end if;
    delete from sectalk_private.st_v8_residency_board_write_permits p where (p.tx,p.task)=(pg_current_xact_id(),task_id);
  end loop;
  update sectalk_private.st_v8_residency_rollback_board_batches set applied_by=actor_id,applied_at=clock_timestamp()
    where handoff=transfer.handoff;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor_id,'workspace.residency_board_replay_applied',transfer.handoff);
  return jsonb_build_object('state','applied','side','source','role',actor_role,'tasks',batch.tasks);
end $$;

notify pgrst,'reload schema';
commit;
