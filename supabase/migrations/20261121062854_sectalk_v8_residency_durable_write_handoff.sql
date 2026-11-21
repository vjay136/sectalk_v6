begin;

create table sectalk_private.st_v8_residency_write_handoffs (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  approval uuid not null,
  handoff uuid not null unique,
  source_project text not null,
  destination_project text not null,
  phase text not null check(phase in ('standby','cancelled','held','restored')),
  changed_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v8_residency_write_handoffs enable row level security;
revoke all on sectalk_private.st_v8_residency_write_handoffs from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v7_workspace_payment_mode(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select case when exists(select 1 from sectalk_private.st_v8_offboarding_requests r
    where r.workspace=p_workspace and r.state='read_only')
    then '{"mode":"read_only","reason":"offboarding"}'::jsonb
    when exists(select 1 from sectalk_private.st_v8_residency_write_handoffs h
      where h.workspace=p_workspace and h.phase in ('standby','cancelled','held'))
    then '{"mode":"read_only","reason":"residency","handoff":true}'::jsonb
    when exists(select 1 from sectalk_private.st_v8_residency_source_pauses p
      join sectalk_private.st_v8_residency_requests r on (r.id,r.workspace)=(p.request,p.workspace)
      where p.workspace=p_workspace and p.resumed_at is null and p.ends_at>statement_timestamp() and r.withdrawn_at is null)
    then '{"mode":"read_only","reason":"residency"}'::jsonb else coalesce((
    select jsonb_build_object('mode',case when g.deadline>statement_timestamp() then 'grace' else 'read_only' end,
      'grace_until',g.deadline)
    from public.st_v2_workspaces w join public.st_v2_subscriptions s on s.user_id=w.owner
    left join sectalk_private.st_v7_nonpayment_cancellations c on (c.subscription,c.account,c.customer)=(s.subscription_id,s.user_id,s.customer_id)
    cross join lateral (
      select case when s.status='past_due' then sectalk_private.st_v7_renewal_grace(s.user_id,s.subscription_id,s.period_end) else
        coalesce((select min(r.grace_until) from sectalk_private.st_v7_renewal_cases r
          where (r.recipient,r.customer,r.subscription)=(s.user_id,s.customer_id,s.subscription_id) and r.stage<>'paid'),
          s.period_end+make_interval(hours=>(select grace_hours from sectalk_private.st_v7_renewal_policy where singleton)),
          s.synced_at+make_interval(hours=>(select grace_hours from sectalk_private.st_v7_renewal_policy where singleton)))
      end deadline
    ) g
    where w.id=p_workspace and s.plan<>'free'
      and (s.status in ('past_due','unpaid') or (s.status='canceled' and c.subscription is not null))
      and g.deadline is not null
  ),'{"mode":"active"}') end
$$;

create function public.st_v8_residency_write_handoff(p_workspace uuid,p_action text default 'status',
  p_approval uuid default null,p_confirmation text default null,p_proof jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); known sectalk_private.st_v8_residency_write_handoffs; link record; selected uuid; new_approval uuid;
  proof_wire text; incoming jsonb; proof_key bytea; expected bytea; state text; transfer_id uuid; result jsonb;
  now_epoch bigint; expires bigint;
begin
  if p_workspace is null or p_action is null or p_action not in ('status','prepare','cancel','hold','restore')
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or sectalk_private.st_v8_offboarding_role(p_workspace,actor) is distinct from 'owner' then raise insufficient_privilege; end if;
  if p_action<>'status' then
    if not coalesce(sectalk_private.st_v7_admin_fresh(),false) or p_approval is null
      or p_confirmation is distinct from p_workspace::text
      or (p_action in ('prepare','hold') and not coalesce(sectalk_private.st_v8_organization_sso_allows(p_workspace),false))
      then raise insufficient_privilege; end if;
    perform pg_advisory_xact_lock(hashtextextended('sectalk-residency-source-writes:'||p_workspace::text,0));
    perform 1 from public.st_v2_workspaces w where (w.id,w.owner)=(p_workspace,actor) for share;
    if not found then raise insufficient_privilege; end if;
  end if;
  select * into known from sectalk_private.st_v8_residency_write_handoffs h where h.workspace=p_workspace;
  if known.phase='restored' and p_approval is distinct from known.approval and p_action in ('status','hold') then
    select c.id into new_approval from sectalk_private.st_v8_content_exports c
    join sectalk_private.st_v8_residency_history_links h on (h.workspace,h.approval,h.side)=(c.workspace,c.id,'source')
    where c.workspace=p_workspace and c.id<>known.approval and (p_approval is null or c.id=p_approval) and c.requester=actor
      and c.approved_at is not null and c.withdrawn_at is null and least(c.expires_at,h.expires_at)>statement_timestamp()
      and sectalk_private.st_v8_offboarding_role(c.workspace,c.reviewer)='reviewer';
    if new_approval is not null then known:=null; end if;
  end if;
  if p_approval is not null and known.approval is not null and p_approval<>known.approval then raise insufficient_privilege; end if;
  selected:=coalesce(p_approval,known.approval,new_approval);
  select h.approval,h.side,h.source_project,h.destination_project,h.expires_at,v.decrypted_secret as secret
    into link from sectalk_private.st_v8_residency_history_links h join vault.decrypted_secrets v on v.id=h.vault_id
    where h.workspace=p_workspace and h.expires_at>statement_timestamp() and v.decrypted_secret~'^[0-9a-f]{64}$'
      and (selected is null or h.approval=selected)
      and ((h.side='source' and (known.phase in ('held','restored') or exists(
        select 1 from sectalk_private.st_v8_content_exports c where (c.workspace,c.id,c.requester)=(p_workspace,h.approval,actor)
          and c.approved_at is not null and c.withdrawn_at is null and c.expires_at>statement_timestamp()
          and sectalk_private.st_v8_offboarding_role(p_workspace,c.reviewer)='reviewer')))
        or (h.side='destination' and (known.phase in ('standby','cancelled') or exists(
        select 1 from sectalk_private.st_v8_residency_workspace_claims c
          join sectalk_private.st_v8_residency_content_admissions a on (a.cell,a.workspace,a.source_project,a.approval)=
            (c.cell,c.workspace,c.source_project,c.approval)
          join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
          join sectalk_private.st_v8_residency_cells t on (t.id,t.project_reference)=(c.cell,h.destination_project) and t.retired_at is null
          where (c.workspace,c.approval,c.owner_id,c.source_project)=(p_workspace,h.approval,actor,h.source_project)
            and c.claimed_at is not null and c.manifest_sha256=a.manifest_sha256
            and least(c.expires_at,a.expires_at)>statement_timestamp()))))
    order by h.expires_at desc limit 1;
  if not found then
    if p_action='status' then return jsonb_build_object('phase',coalesce(known.phase,'inactive'),'linkCurrent',false); end if;
    raise insufficient_privilege;
  end if;
  if known.handoff is not null and (known.source_project,known.destination_project) is distinct from
    (link.source_project,link.destination_project) then raise insufficient_privilege; end if;
  if p_action='status' then
    return jsonb_build_object('phase',coalesce(known.phase,'ready'),'side',link.side,'approval',link.approval,'linkCurrent',true);
  end if;
  if (p_action in ('prepare','cancel')) is distinct from (link.side='destination') then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_residency_write_handoff',16);
  proof_key:=decode(link.secret,'hex');

  if link.side='destination' then
    if p_action='cancel' and known.handoff is null then raise insufficient_privilege; end if;
    if p_action='prepare' and known.phase='cancelled' then
      raise exception 'This destination handoff has been cancelled.' using errcode='PT409'; end if;
    state:=case when p_action='cancel' then 'cancelled' else 'standby' end;
    transfer_id:=coalesce(known.handoff,gen_random_uuid());
  else
    if not coalesce(jsonb_typeof(p_proof)='object' and octet_length(p_proof::text)<=1800,false)
      or not coalesce(p_proof->>'signature'~'^[0-9a-f]{64}$' and octet_length(p_proof->>'payload') between 60 and 1200,false)
      then raise insufficient_privilege; end if;
    proof_wire:=p_proof->>'payload';
    expected:=extensions.hmac(convert_to(proof_wire,'UTF8'),proof_key,'sha256');
    if extensions.hmac(expected,proof_key,'sha256')<>extensions.hmac(decode(p_proof->>'signature','hex'),proof_key,'sha256')
      then raise insufficient_privilege; end if;
    incoming:=proof_wire::jsonb;
    state:=case when p_action='hold' then 'held' else 'restored' end;
    now_epoch:=floor(extract(epoch from clock_timestamp()));
    expires:=(incoming->>'expires')::bigint;
    if (incoming->>'format',incoming->>'workspace',incoming->>'approval',incoming->>'source',incoming->>'destination',incoming->>'phase')
      is distinct from ('sectalk-write-handoff-v1',p_workspace::text,link.approval::text,link.source_project,link.destination_project,
        case when p_action='hold' then 'standby' else 'cancelled' end)
      or expires is null or expires<=now_epoch or expires>now_epoch+300 or incoming->>'handoff' is null then raise insufficient_privilege; end if;
    transfer_id:=(incoming->>'handoff')::uuid;
    if known.handoff is not null and known.handoff<>transfer_id then raise insufficient_privilege; end if;
    if (p_action='restore' and known.phase is distinct from 'held' and known.phase is distinct from 'restored')
      or (p_action='hold' and known.phase='restored') then raise insufficient_privilege; end if;
    if p_action='hold' and known.handoff is null and (not exists(
      select 1 from sectalk_private.st_v8_residency_source_pauses l
      join sectalk_private.st_v8_residency_requests r on (r.id,r.workspace)=(l.request,l.workspace)
      join sectalk_private.st_v8_residency_cells c on c.id=r.cell and c.project_reference=link.destination_project
      where l.workspace=p_workspace and l.resumed_at is null and l.ends_at>clock_timestamp() and r.withdrawn_at is null
        and (c.environment='deployment' or exists(select 1 from sectalk_private.st_v8_residency_verifiers v
          where (v.workspace,v.actor)=(p_workspace,r.reviewed_by) and sectalk_private.st_v2_active(v.actor)))
      ) or not coalesce((public.st_v8_workspace_residency(p_workspace)#>>'{request,state}') in
        ('provider_target_verified','fixture_target_verified'),false)) then
      raise exception 'Pause source writes against the independently verified destination first.' using errcode='PT409'; end if;
  end if;

  if state is distinct from known.phase then
    insert into sectalk_private.st_v8_residency_write_handoffs(workspace,approval,handoff,source_project,destination_project,phase)
    values(p_workspace,link.approval,transfer_id,link.source_project,link.destination_project,state)
    on conflict(workspace) do update set approval=excluded.approval,handoff=excluded.handoff,source_project=excluded.source_project,
      destination_project=excluded.destination_project,phase=excluded.phase,changed_at=clock_timestamp();
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,'workspace.residency_write_'||state,transfer_id);
  end if;
  result:=jsonb_build_object('phase',state,'side',link.side,'approval',link.approval,'linkCurrent',true);
  if link.side='destination' then
    proof_wire:=jsonb_build_object('format','sectalk-write-handoff-v1','workspace',p_workspace,'approval',link.approval,
      'source',link.source_project,'destination',link.destination_project,'handoff',transfer_id,'phase',state,
      'expires',floor(extract(epoch from least(link.expires_at,statement_timestamp()+interval '5 minutes'))))::text;
    result:=result||jsonb_build_object('proof',jsonb_build_object('payload',proof_wire,
      'signature',encode(extensions.hmac(convert_to(proof_wire,'UTF8'),proof_key,'sha256'),'hex')));
  end if;
  return result;
end $$;

revoke all on function public.st_v8_residency_write_handoff(uuid,text,uuid,text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_write_handoff(uuid,text,uuid,text,jsonb) to authenticated;
notify pgrst,'reload schema';
commit;
