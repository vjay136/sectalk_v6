begin;

create table sectalk_private.st_v8_residency_room_history (
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  approval uuid not null,
  room uuid not null,
  post uuid not null,
  actor uuid not null,
  record_digest text not null check(record_digest~'^[0-9a-f]{64}$'),
  imported_at timestamptz not null default clock_timestamp(),
  primary key(room,post)
);
create index st_v8_residency_room_history_workspace on sectalk_private.st_v8_residency_room_history(workspace);
alter table sectalk_private.st_v8_residency_room_history enable row level security;
revoke all on sectalk_private.st_v8_residency_room_history from public,anon,authenticated,service_role;

create function public.st_v8_residency_room_author_proof(p_workspace uuid,p_approval uuid,p_room uuid,p_post uuid,p_challenge text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); person jsonb; approved record; wire text;
begin
  if p_workspace is null or not coalesce(sectalk_private.st_v2_active(actor_id),false) then raise insufficient_privilege; end if;
  person:=public.st_v8_residency_member_proof(p_challenge,p_workspace);
  if not coalesce(sectalk_private.st_v8_standard_room_session_allowed(p_room),false)
    or sectalk_private.st_v6_room_role(p_room,actor_id) is distinct from 'member' then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_residency_room_author_proof',20);
  select e.sha256,c.requester,c.reviewer,h.source_project,h.destination_project,
    least(c.expires_at,h.expires_at,statement_timestamp()+interval '5 minutes') expires_at,v.decrypted_secret as shared_key
    into approved from sectalk_private.st_v8_content_exports c
    join sectalk_private.st_v8_content_export_entries e on e.export_id=c.id
    join sectalk_private.st_v8_residency_history_links h on (h.workspace,h.approval)=(c.workspace,c.id) and h.side='source'
    join vault.decrypted_secrets v on v.id=h.vault_id
    join public.st_v6_rooms r on (r.workspace_id,r.id)=(c.workspace,e.scope_id)
    join public.st_v6_room_posts p on (p.room_id,p.id)=(r.id,e.record_id)
    where (c.workspace,c.id,e.kind,e.scope_id,e.record_id)=(p_workspace,p_approval,'room_message',p_room,p_post)
      and c.withdrawn_at is null and c.approved_at is not null and least(c.expires_at,h.expires_at)>statement_timestamp()
      and sectalk_private.st_v8_offboarding_role(c.workspace,c.requester)='owner'
      and sectalk_private.st_v8_offboarding_role(c.workspace,c.reviewer)='reviewer'
      and v.decrypted_secret~'^[0-9a-f]{64}$' and r.encryption_mode='standard'
      and p.sender=actor_id and p.kind='message' and p.removed_at is null and not p.forwarded
      and not exists(select 1 from sectalk_private.st_v6_room_reports q where (q.room_id,q.post_id)=(p_room,p_post))
    for share of c,e,h,r,p;
  if not found or not exists(select 1 from sectalk_private.st_v8_content_export_records(
      p_workspace,approved.requester,approved.reviewer,'room_message',p_room,p_post) current
      where encode(sha256(convert_to(current.item::text,'UTF8')),'hex')=approved.sha256) then raise insufficient_privilege; end if;
  wire:=jsonb_build_object('format','sectalk-room-author-v1','source',approved.source_project,'destination',approved.destination_project,
    'workspace',p_workspace,'approval',p_approval,'room',p_room,'post',p_post,'digest',approved.sha256,
    'identity',person->>'identity','challenge',p_challenge,'expires',floor(extract(epoch from approved.expires_at))::bigint)::text;
  return jsonb_build_object('payload',wire,'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),decode(approved.shared_key,'hex'),'sha256'),'hex'));
end $$;

create function public.st_v8_residency_publish_room_history(p_workspace uuid,p_approval uuid,p_room uuid,p_post uuid,
  p_payload text,p_signature text)
returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' as $$
declare actor_id uuid:=auth.uid(); claims jsonb; admission record; shared_key bytea; expected bytea;
  evidence jsonb; message jsonb; source_parent uuid; prior sectalk_private.st_v8_residency_room_history; published_at timestamptz;
begin
  if p_workspace is null or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
    or not coalesce(sectalk_private.st_v2_active(actor_id),false)
    or not coalesce(p_signature~'^[0-9a-f]{64}$' and octet_length(p_payload) between 10 and 1600,false)
    then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_residency_publish_room_history',20);
  if not coalesce(sectalk_private.st_v8_standard_room_session_allowed(p_room),false)
    or sectalk_private.st_v6_room_role(p_room,actor_id) is distinct from 'member' then raise insufficient_privilege; end if;
  select c.source_project,t.project_reference,s.records,v.decrypted_secret as secret into admission
    from sectalk_private.st_v8_residency_workspace_claims c
    join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
    join sectalk_private.st_v8_residency_cells t on t.id=c.cell and t.retired_at is null
    join sectalk_private.st_v8_residency_content_admissions a on (a.cell,a.workspace,a.source_project,a.approval)=
      (c.cell,c.workspace,c.source_project,c.approval)
    join sectalk_private.st_v8_residency_staged_content s on (s.cell,s.workspace,s.source_project,s.approval)=
      (c.cell,c.workspace,c.source_project,c.approval)
    join sectalk_private.st_v8_residency_room_imports r on (r.cell,r.workspace,r.source_project,r.approval,r.room)=
      (c.cell,c.workspace,c.source_project,c.approval,p_room)
    join sectalk_private.st_v8_residency_history_links h on (h.workspace,h.approval,h.source_project,h.destination_project)=
      (c.workspace,c.approval,c.source_project,t.project_reference) and h.side='destination'
    join vault.decrypted_secrets v on v.id=h.vault_id
    join public.st_v6_rooms room on (room.id,room.workspace_id)=(r.room,c.workspace)
    where (c.workspace,c.approval)=(p_workspace,p_approval) and c.claimed_at is not null
      and sectalk_private.st_v8_offboarding_role(c.workspace,c.owner_id)='owner'
      and c.manifest_sha256=a.manifest_sha256 and least(c.expires_at,a.expires_at,h.expires_at)>statement_timestamp()
      and v.decrypted_secret~'^[0-9a-f]{64}$' and (room.kind,room.classification,room.encryption_mode)=('private','confidential','standard')
      and not room.archived and not room.locked
    for share of c,i,t,a,s,r,h for update of room;
  if not found then raise insufficient_privilege; end if;
  shared_key:=decode(admission.secret,'hex');
  expected:=extensions.hmac(convert_to(p_payload,'UTF8'),shared_key,'sha256');
  if extensions.hmac(expected,shared_key,'sha256')<>extensions.hmac(decode(p_signature,'hex'),shared_key,'sha256')
    then raise insufficient_privilege; end if;
  claims:=p_payload::jsonb;
  if (claims->>'format',claims->>'workspace',claims->>'approval',claims->>'room',claims->>'post',claims->>'source',claims->>'destination')
    is distinct from ('sectalk-room-author-v1',p_workspace::text,p_approval::text,p_room::text,p_post::text,
      admission.source_project,admission.project_reference)
    or coalesce((claims->>'expires')::bigint,0)<=extract(epoch from clock_timestamp())
    or claims->>'identity' is distinct from (public.st_v8_residency_member_proof(claims->>'challenge',p_workspace)->>'identity')
    then raise insufficient_privilege; end if;

  select item into evidence from jsonb_array_elements(admission.records) item
    where (item->>'kind',item->>'scope',item->>'id',item->>'sha256')=('room_message',p_room::text,p_post::text,claims->>'digest');
  if evidence is null or encode(sha256(convert_to(evidence->>'json','UTF8')),'hex') is distinct from claims->>'digest'
    then raise insufficient_privilege; end if;
  message:=(evidence->>'json')::jsonb;
  if (message->>'room',message->>'message',message->>'kind') is distinct from (p_room::text,p_post::text,'message')
    or not coalesce(message ?& array['body','parent','createdAt','editedAt'],false) then raise insufficient_privilege; end if;
  perform sectalk_private.st_v7_require_workspace_write(p_workspace);
  select * into prior from sectalk_private.st_v8_residency_room_history r where (r.room,r.post)=(p_room,p_post);
  if found then
    if (prior.workspace,prior.approval,prior.actor,prior.record_digest) is distinct from
      (p_workspace,p_approval,actor_id,claims->>'digest') then raise insufficient_privilege; end if;
    return jsonb_build_object('post',p_post,'importedAt',prior.imported_at);
  end if;
  source_parent:=(message->>'parent')::uuid;
  if source_parent is not null and not exists(
    select 1 from sectalk_private.st_v8_residency_room_history h
    join public.st_v6_room_posts p on (p.room_id,p.id,p.sender)=(h.room,h.post,h.actor)
    cross join lateral jsonb_array_elements(admission.records) e
    cross join lateral (select (e->>'json')::jsonb as original) item
    where (h.workspace,h.approval,h.room,h.post)=(p_workspace,p_approval,p_room,source_parent)
      and (e->>'kind',e->>'scope',e->>'id',e->>'sha256')=('room_message',p_room::text,source_parent::text,h.record_digest)
      and encode(sha256(convert_to(e->>'json','UTF8')),'hex')=h.record_digest
      and p.kind='message' and not p.forwarded and p.parent_id is null and p.removed_at is null
      and (p.body,p.created_at,p.edited_at) is not distinct from
        (item.original->>'body',(item.original->>'createdAt')::timestamptz,(item.original->>'editedAt')::timestamptz)
  ) then raise exception 'Restore the exact approved thread root before its replies.' using errcode='PT409'; end if;
  if exists(select 1 from public.st_v6_room_posts p where (p.room_id,p.id)=(p_room,p_post)) then
    raise exception 'The room message ID already exists.' using errcode='PT409'; end if;
  perform public.st_v6_room_post(p_room,p_post,message->>'body','message',source_parent);
  update public.st_v6_room_posts p set created_at=(message->>'createdAt')::timestamptz,edited_at=(message->>'editedAt')::timestamptz
    where (p.room_id,p.id,p.sender,p.body)=(p_room,p_post,actor_id,message->>'body');
  if not found then raise exception 'Destination policy changed the message.' using errcode='PT409'; end if;
  insert into sectalk_private.st_v8_residency_room_history(workspace,approval,room,post,actor,record_digest)
    values(p_workspace,p_approval,p_room,p_post,actor_id,claims->>'digest') returning imported_at into published_at;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor_id,'room.message_residency_imported',p_post);
  return jsonb_build_object('post',p_post,'importedAt',published_at);
end $$;

revoke all on function public.st_v8_residency_room_author_proof(uuid,uuid,uuid,uuid,text),
  public.st_v8_residency_publish_room_history(uuid,uuid,uuid,uuid,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_room_author_proof(uuid,uuid,uuid,uuid,text),
  public.st_v8_residency_publish_room_history(uuid,uuid,uuid,uuid,text,text) to authenticated;
notify pgrst,'reload schema';
commit;
