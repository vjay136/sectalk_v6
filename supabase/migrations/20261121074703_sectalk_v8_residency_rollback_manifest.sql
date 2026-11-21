begin;

create table sectalk_private.st_v8_residency_rollback_manifest_admissions (
  handoff uuid primary key references sectalk_private.st_v8_residency_write_handoffs(handoff) on delete cascade,
  vault_id uuid not null,
  plan_sha256 text not null check (plan_sha256~'^[0-9a-f]{64}$'),
  expires_at timestamptz not null
);
create table sectalk_private.st_v8_residency_rollback_manifests (
  handoff uuid primary key references sectalk_private.st_v8_residency_write_handoffs(handoff) on delete cascade,
  workspace uuid not null,
  review uuid not null,
  review_sha256 text not null,
  packet_sha256 text not null,
  plan_sha256 text not null,
  changes jsonb not null check (jsonb_typeof(changes)='array'),
  received_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v8_residency_rollback_manifest_admissions enable row level security;
alter table sectalk_private.st_v8_residency_rollback_manifests enable row level security;
revoke all on sectalk_private.st_v8_residency_rollback_manifest_admissions,
  sectalk_private.st_v8_residency_rollback_manifests from public,anon,authenticated,service_role;

create function public.st_v8_residency_rollback_manifest(p_workspace uuid,p_action text default 'status',
  p_confirmation text default null,p_packet jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid();
  transfer sectalk_private.st_v8_residency_write_handoffs;
  admitted sectalk_private.st_v8_residency_rollback_manifest_admissions;
  known sectalk_private.st_v8_residency_rollback_manifests;
  review jsonb;
  claim jsonb;
  side text;
  wire text;
  signing_key bytea;
  received_digest text;
  now_epoch bigint;
  expires bigint;
begin
  if p_workspace is null or p_action is null or p_action not in ('status','issue','receive')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'owner'
    or not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false)
    then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if p_confirmation is distinct from p_workspace::text or not coalesce(sectalk_private.st_v7_admin_fresh(),false)
      then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces w where (w.id,w.owner)=(p_workspace,actor_id) for share;
    if not found then raise insufficient_privilege; end if;
  end if;

  side:=sectalk_private.st_v8_residency_rollback_side(p_workspace);
  if side is null then
    if p_action='status' then return '{"state":"inactive"}'::jsonb; end if;
    raise insufficient_privilege;
  end if;
  if p_action<>'status' and (p_action='issue') is distinct from (side='destination')
    then raise insufficient_privilege; end if;
  select f.* into transfer from sectalk_private.st_v8_residency_write_handoffs f where f.workspace=p_workspace;

  if p_action='receive' then
    if not coalesce(jsonb_typeof(p_packet)='object' and octet_length(p_packet::text)<=4194304,false)
      or not coalesce(p_packet->>'signature'~'^[0-9a-f]{64}$' and octet_length(p_packet->>'payload') between 50 and 4000000,false)
      or p_packet-array['payload','signature']<>'{}'::jsonb then raise insufficient_privilege; end if;
    received_digest:=encode(sha256(convert_to(p_packet::text,'UTF8')),'hex');
  end if;
  if side='source' then
    select k.* into known from sectalk_private.st_v8_residency_rollback_manifests k where k.handoff=transfer.handoff;
    if found then
      if p_action='receive' and received_digest is distinct from known.packet_sha256 then
        raise exception 'The rollback handoff already has a different verified manifest.' using errcode='PT409'; end if;
      return jsonb_build_object('state','received','side','source','review',known.review,'digest',known.review_sha256,
        'packetSha256',known.packet_sha256,'receivedAt',known.received_at,'changeCount',jsonb_array_length(known.changes));
    end if;
  end if;
  select a.* into admitted from sectalk_private.st_v8_residency_rollback_manifest_admissions a
    where a.handoff=transfer.handoff and a.expires_at>statement_timestamp();
  if not found then
    if p_action='status' then return jsonb_build_object('state','admission_required','side',side); end if;
    raise insufficient_privilege;
  end if;
  if side='destination' then
    review:=public.st_v8_residency_rollback_reconcile(p_workspace);
    if review->>'state' is distinct from 'reviewed' then
      if p_action='status' then return '{"state":"review_required","side":"destination"}'::jsonb; end if;
      raise exception 'The destination needs a current independent change review.' using errcode='PT409';
    end if;
  end if;
  if p_action='status' then return jsonb_build_object('state','ready','side',side); end if;
  perform sectalk_private.limit_action('v8_residency_rollback_manifest',12);
  select decode(v.decrypted_secret,'hex') into signing_key from vault.decrypted_secrets v
    where v.id=admitted.vault_id and v.decrypted_secret~'^[0-9a-f]{64}$';
  if not found then raise insufficient_privilege; end if;
  if p_action='issue' then
    wire:=jsonb_build_object('format','sectalk-residency-recovery-manifest-v1','workspace',p_workspace,
      'handoff',transfer.handoff,'approval',transfer.approval,'source',transfer.source_project,'destination',transfer.destination_project,
      'plan',admitted.plan_sha256,'review',review->>'id','digest',review->>'digest','changes',review->'changes',
      'expires',floor(extract(epoch from least(admitted.expires_at,statement_timestamp()+interval '5 minutes'))))::text;
    if octet_length(wire)>4000000 then raise exception 'The reviewed manifest exceeds the transfer limit.' using errcode='PT409'; end if;
    return jsonb_build_object('state','ready','side','destination','packet',jsonb_build_object('payload',wire,
      'signature',encode(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),'hex')));
  end if;
  wire:=p_packet->>'payload';
  if extensions.hmac(extensions.hmac(convert_to(wire,'UTF8'),signing_key,'sha256'),signing_key,'sha256')
    <>extensions.hmac(decode(p_packet->>'signature','hex'),signing_key,'sha256') then raise insufficient_privilege; end if;
  claim:=wire::jsonb;
  now_epoch:=floor(extract(epoch from clock_timestamp()));
  expires:=(claim->>'expires')::bigint;
  if (claim->>'format',claim->>'workspace',claim->>'handoff',claim->>'approval',claim->>'source',claim->>'destination',claim->>'plan')
    is distinct from ('sectalk-residency-recovery-manifest-v1',p_workspace::text,transfer.handoff::text,
      transfer.approval::text,transfer.source_project,transfer.destination_project,admitted.plan_sha256)
    or expires is null or expires<=now_epoch or expires>now_epoch+303
    or not coalesce(claim->>'digest'~'^[0-9a-f]{64}$' and claim->>'review'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$',false)
    or jsonb_typeof(claim->'changes') is distinct from 'array' then raise insufficient_privilege; end if;
  if jsonb_array_length(claim->'changes')>9000 or exists(
    select 1 from jsonb_array_elements(claim->'changes') entry
    where jsonb_typeof(entry) is distinct from 'object'
      or not coalesce(entry ?& array['kind','id','state','before','after'] and
        entry-array['kind','id','state','before','after']='{}'::jsonb
        and entry->>'kind' in ('channel','channel_message','workspace_task','room','room_message','room_task',
          'workspace_file','room_file','storage_object') and entry->>'id'~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
        and case entry->>'state'
          when 'added' then entry->'before'='null'::jsonb and entry->>'after'~'^[0-9a-f]{64}$'
          when 'removed' then entry->>'before'~'^[0-9a-f]{64}$' and entry->'after'='null'::jsonb
          when 'changed' then entry->>'before'~'^[0-9a-f]{64}$' and entry->>'after'~'^[0-9a-f]{64}$'
            and entry->>'before'<>entry->>'after'
          else false end,false)
  ) then raise insufficient_privilege; end if;
  insert into sectalk_private.st_v8_residency_rollback_manifests
    (handoff,workspace,review,review_sha256,packet_sha256,plan_sha256,changes)
    values(transfer.handoff,p_workspace,(claim->>'review')::uuid,claim->>'digest',received_digest,admitted.plan_sha256,claim->'changes')
    returning * into known;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor_id,'workspace.residency_rollback_manifest_received',transfer.handoff);
  return jsonb_build_object('state','received','side','source','review',known.review,'digest',known.review_sha256,
    'packetSha256',known.packet_sha256,'receivedAt',known.received_at,'changeCount',jsonb_array_length(known.changes));
end $$;
revoke all on function public.st_v8_residency_rollback_manifest(uuid,text,text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_rollback_manifest(uuid,text,text,jsonb) to authenticated;

notify pgrst,'reload schema';
commit;
