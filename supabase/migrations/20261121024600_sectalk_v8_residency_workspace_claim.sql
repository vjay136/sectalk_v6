begin;

create table sectalk_private.st_v8_residency_workspace_claims (
  id uuid primary key default gen_random_uuid(),
  cell uuid not null,
  workspace uuid not null unique,
  source_project text not null,
  approval uuid not null,
  owner_id uuid not null references auth.users on delete cascade,
  name text not null check(char_length(btrim(name)) between 1 and 64),
  manifest_sha256 text not null check(manifest_sha256~'^[0-9a-f]{64}$'),
  installation_nonce uuid not null,
  expires_at timestamptz not null,
  claimed_at timestamptz,
  foreign key (cell,workspace,source_project,approval)
    references sectalk_private.st_v8_residency_staged_content on delete restrict
);
create index st_v8_workspace_claim_owner on sectalk_private.st_v8_residency_workspace_claims(owner_id,expires_at)
  where claimed_at is null;
alter table sectalk_private.st_v8_residency_workspace_claims enable row level security;
revoke all on sectalk_private.st_v8_residency_workspace_claims from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_create_owned_workspace(p_id uuid,p_name text,p_event text)
returns uuid language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); cap integer;
begin
  if not sectalk_private.st_v2_active(me) then raise exception 'Workspace access is restricted'; end if;
  perform id from public.st_profiles where id=me for update;
  if not found then raise exception 'Create a profile first'; end if;
  cap:=coalesce((sectalk_private.st_v7_account_entitlements(me)).workspace_limit,0);
  if (select count(*) from public.st_v2_workspaces where owner=me)>=cap then
    raise exception 'Your plan’s workspace limit has been reached';
  end if;
  insert into public.st_v2_workspaces(id,name,owner) values(p_id,btrim(p_name),me);
  insert into public.st_v2_members(workspace_id,user_id,role) values(p_id,me,'owner');
  insert into public.st_v2_channels(workspace_id,name) values(p_id,'general');
  insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(p_id,me,p_event);
  return p_id;
end $$;
revoke all on function sectalk_private.st_v8_create_owned_workspace(uuid,text,text) from public,anon,authenticated,service_role;

create or replace function public.st_v2_create_workspace(p_name text)
returns uuid language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('v2_workspace',4);
  return sectalk_private.st_v8_create_owned_workspace(gen_random_uuid(),p_name,'workspace.created');
end $$;

create function public.st_v8_residency_workspace_claim(p_claim uuid default null,p_confirmation text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); claim sectalk_private.st_v8_residency_workspace_claims; available jsonb;
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false) then raise insufficient_privilege; end if;
  if p_claim is null then
    select coalesce(jsonb_agg(jsonb_build_object('id',q.id,'workspace',q.workspace,'name',q.name,
      'manifestSha256',q.manifest_sha256,'expiresAt',q.expires_at) order by q.expires_at,q.id),'[]') into available
    from (
      select c.* from sectalk_private.st_v8_residency_workspace_claims c
      join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
      join sectalk_private.st_v8_residency_cells t on t.id=c.cell and t.retired_at is null
      join sectalk_private.st_v8_residency_content_admissions a
        on (a.cell,a.workspace,a.source_project,a.approval)=(c.cell,c.workspace,c.source_project,c.approval)
      where c.owner_id=actor_id and c.claimed_at is null and least(c.expires_at,a.expires_at)>statement_timestamp()
        and c.manifest_sha256=a.manifest_sha256
      order by c.expires_at,c.id limit 10
    ) q;
    return jsonb_build_object('claims',available,'access',case when sectalk_private.st_v7_admin_fresh() then 'verified' else 'mfa' end);
  end if;
  if not sectalk_private.st_v7_admin_fresh() then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_residency_claim',8);
  select c.* into claim from sectalk_private.st_v8_residency_workspace_claims c
    join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
    join sectalk_private.st_v8_residency_cells t on t.id=c.cell and t.retired_at is null
    join sectalk_private.st_v8_residency_content_admissions a
      on (a.cell,a.workspace,a.source_project,a.approval)=(c.cell,c.workspace,c.source_project,c.approval)
    where c.id=p_claim and c.owner_id=actor_id and c.workspace::text=p_confirmation
      and c.manifest_sha256=a.manifest_sha256
      and (c.claimed_at is not null or least(c.expires_at,a.expires_at)>statement_timestamp())
    for update of c for share of i,t,a;
  if not found then raise insufficient_privilege; end if;
  if claim.claimed_at is not null then
    if sectalk_private.st_v8_offboarding_role(claim.workspace,actor_id) is distinct from 'owner' then
      raise insufficient_privilege; end if;
    return jsonb_build_object('workspace',claim.workspace);
  end if;
  begin
    perform sectalk_private.st_v8_create_owned_workspace(claim.workspace,claim.name,'workspace.residency_claimed');
  exception when unique_violation then
    raise exception 'The approved workspace ID is already in use' using errcode='PT409';
  end;
  update sectalk_private.st_v8_residency_workspace_claims set claimed_at=clock_timestamp() where id=claim.id;
  return jsonb_build_object('workspace',claim.workspace);
end $$;
revoke all on function public.st_v8_residency_workspace_claim(uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_workspace_claim(uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
