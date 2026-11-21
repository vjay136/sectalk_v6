begin;

create table sectalk_private.st_v8_residency_room_member_invites (
  id uuid not null unique default gen_random_uuid(),
  cell uuid not null,
  workspace uuid not null,
  source_project text not null,
  approval uuid not null,
  room uuid not null,
  member uuid not null references auth.users on delete cascade,
  challenge text check(challenge~'^[0-9a-f]{64}$'),
  identity text check(identity~'^[0-9a-f]{64}$'),
  expires_at timestamptz not null,
  invited_at timestamptz,
  primary key(cell,workspace,source_project,approval,room,member),
  foreign key(cell,workspace,source_project,approval,room)
    references sectalk_private.st_v8_residency_room_imports on delete cascade,
  check((invited_at is null and challenge is not null and identity is not null)
    or (invited_at is not null and challenge is null and identity is null))
);
alter table sectalk_private.st_v8_residency_room_member_invites enable row level security;
revoke all on sectalk_private.st_v8_residency_room_member_invites from public,anon,authenticated,service_role;

create function public.st_v8_residency_room_member_proof(p_workspace uuid,p_approval uuid,p_room uuid,p_challenge text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); person jsonb; approved record; wire text;
begin
  if p_workspace is null or p_approval is null or p_room is null then raise insufficient_privilege; end if;
  person:=public.st_v8_residency_member_proof(p_challenge,p_workspace);
  perform sectalk_private.limit_action('v8_residency_room_member_proof',20);
  perform 1 from public.st_v2_workspaces where id=p_workspace for key share;
  if not found then raise insufficient_privilege; end if;
  select c.manifest_sha256,c.requester,c.reviewer,h.source_project,h.destination_project,
    least(c.expires_at,h.expires_at,statement_timestamp()+interval '5 minutes') expires_at,v.decrypted_secret secret
    into approved
  from sectalk_private.st_v8_content_exports c
  join sectalk_private.st_v8_residency_history_links h on (h.workspace,h.approval,h.side)=(c.workspace,c.id,'source')
  join vault.decrypted_secrets v on v.id=h.vault_id
  join public.st_v6_rooms r on (r.workspace_id,r.id)=(c.workspace,p_room)
  where (c.workspace,c.id)=(p_workspace,p_approval) and c.approved_at is not null and c.withdrawn_at is null
    and least(c.expires_at,h.expires_at)>statement_timestamp() and v.decrypted_secret~'^[0-9a-f]{64}$'
    and (r.kind,r.encryption_mode)=('public','standard') and r.classification in ('public','internal') and not r.archived
    and sectalk_private.st_v8_offboarding_role(c.workspace,c.requester)='owner'
    and sectalk_private.st_v8_offboarding_role(c.workspace,c.reviewer)='reviewer'
    and sectalk_private.open_pair(actor_id,c.requester) and sectalk_private.open_pair(actor_id,c.reviewer)
  for share of c,h,r;
  if not found or sectalk_private.st_v6_room_role(p_room,actor_id) is distinct from 'member'
    or not exists(select 1
    from sectalk_private.st_v8_content_export_entries e
    join public.st_v6_room_posts m on (m.room_id,m.id)=(e.scope_id,e.record_id)
    cross join lateral sectalk_private.st_v8_content_export_records(
      p_workspace,approved.requester,approved.reviewer,'room_message',p_room,e.record_id) live
    where (e.export_id,e.kind,e.scope_id)=(p_approval,'room_message',p_room)
      and m.removed_at is null and not m.forwarded and (m.sender=actor_id or sectalk_private.open_pair(actor_id,m.sender))
      and encode(sha256(convert_to(live.item::text,'UTF8')),'hex')=e.sha256) then raise insufficient_privilege; end if;
  wire:=jsonb_build_object('format','sectalk-room-member-v1','workspace',p_workspace,'approval',p_approval,'room',p_room,
    'manifest',approved.manifest_sha256,'source',approved.source_project,'destination',approved.destination_project,
    'identity',person->>'identity','challenge',p_challenge,'expires',floor(extract(epoch from approved.expires_at))::bigint)::text;
  return jsonb_build_object('payload',wire,'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),
    decode(approved.secret,'hex'),'sha256'),'hex'));
end $$;

create function public.st_v8_residency_room_member_claim(p_workspace uuid,p_approval uuid,p_room uuid,
  p_payload text,p_signature text)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); claims jsonb; admission record; key_bytes bytea; expected bytea;
  proof jsonb; deadline timestamptz; claim_id uuid;
begin
  if p_workspace is null or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
    or not coalesce(p_signature~'^[0-9a-f]{64}$' and octet_length(p_payload) between 10 and 1600,false)
    then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_residency_room_member_claim',20);
  perform 1 from public.st_v2_workspaces where id=p_workspace for key share;
  if not found or not sectalk_private.st_v8_standard_room_session_allowed(p_room) then raise insufficient_privilege; end if;
  select c.cell,c.owner_id,c.manifest_sha256,c.source_project,t.project_reference,
    least(c.expires_at,a.expires_at,h.expires_at) expires_at,v.decrypted_secret secret into admission
  from sectalk_private.st_v8_residency_workspace_claims c
  join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
  join sectalk_private.st_v8_residency_cells t on t.id=c.cell and t.retired_at is null
  join sectalk_private.st_v8_residency_content_admissions a
    on (a.cell,a.workspace,a.source_project,a.approval)=(c.cell,c.workspace,c.source_project,c.approval)
  join sectalk_private.st_v8_residency_room_imports j
    on (j.cell,j.workspace,j.source_project,j.approval,j.room,j.actor)=(c.cell,c.workspace,c.source_project,c.approval,p_room,c.owner_id)
  join sectalk_private.st_v8_residency_history_links h
    on (h.workspace,h.approval,h.source_project,h.destination_project,h.side)=
    (c.workspace,c.approval,c.source_project,t.project_reference,'destination')
  join vault.decrypted_secrets v on v.id=h.vault_id
  join public.st_v6_rooms r on (r.workspace_id,r.id)=(c.workspace,j.room)
  where (c.workspace,c.approval)=(p_workspace,p_approval) and c.claimed_at is not null
    and c.manifest_sha256=a.manifest_sha256 and least(c.expires_at,a.expires_at,h.expires_at)>statement_timestamp()
    and (r.kind,r.encryption_mode,r.classification,r.creator)=('private','standard','confidential',c.owner_id)
    and not r.archived and not r.locked and v.decrypted_secret~'^[0-9a-f]{64}$'
    and sectalk_private.st_v8_offboarding_role(c.workspace,c.owner_id)='owner'
    and sectalk_private.st_v6_room_role(r.id,c.owner_id)='owner'
    and sectalk_private.open_pair(c.owner_id,actor_id)
    and not exists(select 1 from public.st_v6_room_bans b where (b.room_id,b.user_id)=(p_room,actor_id))
  for share of c,i,t,a,j,h,r;
  if not found then raise insufficient_privilege; end if;
  key_bytes:=decode(admission.secret,'hex');
  expected:=extensions.hmac(convert_to(p_payload,'UTF8'),key_bytes,'sha256');
  if extensions.hmac(expected,key_bytes,'sha256')<>extensions.hmac(decode(p_signature,'hex'),key_bytes,'sha256')
    then raise insufficient_privilege; end if;
  claims:=p_payload::jsonb;
  if (claims->>'format',claims->>'workspace',claims->>'approval',claims->>'room',claims->>'manifest',
      claims->>'source',claims->>'destination') is distinct from
    ('sectalk-room-member-v1',p_workspace::text,p_approval::text,p_room::text,admission.manifest_sha256,
      admission.source_project,admission.project_reference) then raise insufficient_privilege; end if;
  deadline:=least(admission.expires_at,to_timestamp(coalesce((claims->>'expires')::bigint,0)));
  if deadline<=statement_timestamp() then raise insufficient_privilege; end if;
  proof:=public.st_v8_residency_member_proof(claims->>'challenge',p_workspace);
  if claims->>'identity' is distinct from proof->>'identity' then raise insufficient_privilege; end if;
  insert into sectalk_private.st_v8_residency_room_member_invites as current_invite(
    cell,workspace,source_project,approval,room,member,challenge,identity,expires_at)
    values(admission.cell,p_workspace,admission.source_project,p_approval,p_room,actor_id,
      claims->>'challenge',claims->>'identity',deadline)
    on conflict(cell,workspace,source_project,approval,room,member) do update
      set challenge=excluded.challenge,identity=excluded.identity,expires_at=excluded.expires_at
      where current_invite.invited_at is null returning id into claim_id;
  if claim_id is null then
    select id into claim_id from sectalk_private.st_v8_residency_room_member_invites
      where (cell,workspace,source_project,approval,room,member)=
        (admission.cell,p_workspace,admission.source_project,p_approval,p_room,actor_id);
  end if;
  return claim_id;
end $$;

create function public.st_v8_residency_room_member_invite(p_workspace uuid,p_claim uuid,p_confirmation text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); prepared sectalk_private.st_v8_residency_room_member_invites; expiry timestamptz;
  issued timestamptz;
begin
  if p_workspace is null or p_claim is null or p_confirmation is distinct from p_workspace::text
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
    then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_residency_room_member_invite',20);
  perform 1 from public.st_v2_workspaces where id=p_workspace and owner=actor_id for no key update;
  if not found or sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'owner'
    or not sectalk_private.st_v8_directory_sso_allows(p_workspace)
    or not sectalk_private.st_v8_organization_sso_allows(p_workspace) then raise insufficient_privilege; end if;
  select * into prepared from sectalk_private.st_v8_residency_room_member_invites
    where id=p_claim and workspace=p_workspace;
  if not found or prepared.member=actor_id then raise insufficient_privilege; end if;
  select least(c.expires_at,a.expires_at,h.expires_at) into expiry
  from sectalk_private.st_v8_residency_workspace_claims c
  join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
  join sectalk_private.st_v8_residency_cells t on t.id=c.cell and t.retired_at is null
  join sectalk_private.st_v8_residency_content_admissions a
    on (a.cell,a.workspace,a.source_project,a.approval)=(c.cell,c.workspace,c.source_project,c.approval)
  join sectalk_private.st_v8_residency_history_links h
    on (h.workspace,h.approval,h.source_project,h.destination_project,h.side)=
    (c.workspace,c.approval,c.source_project,t.project_reference,'destination')
  join public.st_v6_rooms r on (r.workspace_id,r.id)=(c.workspace,prepared.room)
  where (c.cell,c.workspace,c.source_project,c.approval,c.owner_id)=
    (prepared.cell,prepared.workspace,prepared.source_project,prepared.approval,actor_id)
    and c.claimed_at is not null and c.manifest_sha256=a.manifest_sha256
    and (r.kind,r.encryption_mode,r.classification,r.creator)=('private','standard','confidential',actor_id)
    and not r.archived and not r.locked and sectalk_private.st_v6_room_role(r.id,actor_id)='owner'
  for share of c,i,t,a,h for update of r;
  if not found then raise insufficient_privilege; end if;
  select * into prepared from sectalk_private.st_v8_residency_room_member_invites
    where id=p_claim and workspace=p_workspace for update;
  if not found or not sectalk_private.st_v2_active(prepared.member)
    or sectalk_private.st_v2_role(p_workspace,prepared.member) is distinct from 'member'
    or not sectalk_private.open_pair(actor_id,prepared.member)
    or exists(select 1 from public.st_v6_room_bans b where (b.room_id,b.user_id)=(prepared.room,prepared.member))
    then raise insufficient_privilege; end if;
  expiry:=least(expiry,prepared.expires_at);
  if prepared.invited_at is not null then
    if sectalk_private.st_v6_room_role(prepared.room,prepared.member)='member' then
      return jsonb_build_object('claim',p_claim,'room',prepared.room,'status','accepted','invitedAt',prepared.invited_at);
    end if;
    if exists(select 1 from public.st_v6_room_entries e where (e.room_id,e.user_id,e.kind,e.invited_role,e.expires_at)=
        (prepared.room,prepared.member,'invite','member',prepared.expires_at) and e.expires_at>statement_timestamp())
      then return jsonb_build_object('claim',p_claim,'room',prepared.room,'status','pending','invitedAt',prepared.invited_at); end if;
    raise exception 'That approved invitation is no longer pending' using errcode='PT409';
  end if;
  if expiry<=statement_timestamp() or not exists(select 1 from auth.users u where u.id=prepared.member
    and u.email_confirmed_at is not null and nullif(btrim(u.email),'') is not null and nullif(btrim(u.email_change),'') is null
    and encode(sha256(convert_to('sectalk-residency-member-v1:'||prepared.challenge||':'||lower(btrim(u.email)),'UTF8')),'hex')=prepared.identity)
    then raise insufficient_privilege; end if;
  if exists(select 1 from public.st_v6_room_members m where (m.room_id,m.user_id)=(prepared.room,prepared.member))
    or exists(select 1 from public.st_v6_room_entries e where (e.room_id,e.user_id)=(prepared.room,prepared.member))
    then raise exception 'An existing room request, invitation or membership is already in use' using errcode='PT409'; end if;
  perform sectalk_private.st_v7_require_workspace_write(p_workspace);
  perform public.st_v6_room_membership(prepared.room,'invite',prepared.member,'member');
  update public.st_v6_room_entries set expires_at=expiry
    where (room_id,user_id,kind,invited_role)=(prepared.room,prepared.member,'invite','member');
  if not found then raise exception 'A native room invitation could not be issued' using errcode='PT409'; end if;
  update sectalk_private.st_v8_residency_room_member_invites set invited_at=clock_timestamp(),
    identity=null,challenge=null,expires_at=expiry where id=p_claim returning invited_at into issued;
  return jsonb_build_object('claim',p_claim,'room',prepared.room,'status','pending','invitedAt',issued);
end $$;

revoke all on function public.st_v8_residency_room_member_proof(uuid,uuid,uuid,text),
  public.st_v8_residency_room_member_claim(uuid,uuid,uuid,text,text),
  public.st_v8_residency_room_member_invite(uuid,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_room_member_proof(uuid,uuid,uuid,text),
  public.st_v8_residency_room_member_claim(uuid,uuid,uuid,text,text),
  public.st_v8_residency_room_member_invite(uuid,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
