begin;

create function sectalk_private.st_v8_create_owned_workspace(p_id uuid,p_name text,p_event text,p_general uuid)
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
  insert into public.st_v2_channels(id,workspace_id,name) values(coalesce(p_general,gen_random_uuid()),p_id,'general');
  insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(p_id,me,p_event);
  return p_id;
end $$;

revoke all on function sectalk_private.st_v8_create_owned_workspace(uuid,text,text,uuid) from public,anon,authenticated,service_role;

create or replace function sectalk_private.st_v8_create_owned_workspace(p_id uuid,p_name text,p_event text)
returns uuid language sql security definer set search_path='' as $$
  select sectalk_private.st_v8_create_owned_workspace(p_id,p_name,p_event,null)
$$;

create or replace function public.st_v8_residency_workspace_claim(p_claim uuid default null,p_confirmation text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor_id uuid:=auth.uid();
  claim sectalk_private.st_v8_residency_workspace_claims;
  available jsonb;
  archive jsonb;
  expected_count integer;
  archive_digest text;
  default_channel uuid;
  channel_count integer;
  evidence_count integer;
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
      raise insufficient_privilege;
    end if;
    return jsonb_build_object('workspace',claim.workspace);
  end if;

  select s.records,a.record_count into strict archive,expected_count
    from sectalk_private.st_v8_residency_staged_content s
    join sectalk_private.st_v8_residency_content_admissions a using(cell,workspace,source_project,approval)
    where (s.cell,s.workspace,s.source_project,s.approval)=(claim.cell,claim.workspace,claim.source_project,claim.approval)
    for share of s;
  if jsonb_typeof(archive) is distinct from 'array' or jsonb_array_length(archive) is distinct from expected_count then
    raise exception 'The admitted workspace archive changed.' using errcode='PT409';
  end if;
  select encode(sha256(convert_to(jsonb_build_object('format','sectalk-workspace-content-v1','workspace',claim.workspace,
    'approval',claim.approval,'entries',jsonb_agg(jsonb_build_array(position,e->>'kind',e->>'scope',e->>'id',e->>'sha256')
      order by position))::text,'UTF8')),'hex') into archive_digest
    from jsonb_array_elements(archive) with ordinality item(e,position);
  if archive_digest is distinct from claim.manifest_sha256 or exists(
    select 1 from jsonb_array_elements(archive) e
    where encode(sha256(convert_to(e->>'json','UTF8')),'hex') is distinct from e->>'sha256'
  ) then
    raise exception 'The admitted workspace archive changed.' using errcode='PT409';
  end if;
  select count(*)::integer,(array_agg(x.channel))[1],(array_agg(x.evidence_count))[1]
    into channel_count,default_channel,evidence_count
    from sectalk_private.st_v8_residency_channel_candidates(archive) x where x.name='general';
  if channel_count>1 then
    raise exception 'More than one approved general channel was found.' using errcode='PT409';
  end if;

  begin
    perform sectalk_private.st_v8_create_owned_workspace(claim.workspace,claim.name,'workspace.residency_claimed',default_channel);
    if default_channel is not null then
      insert into sectalk_private.st_v8_residency_channel_imports(cell,workspace,source_project,approval,channel,channel_name,actor,evidence_count)
        values(claim.cell,claim.workspace,claim.source_project,claim.approval,default_channel,'general',actor_id,evidence_count);
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(claim.workspace,actor_id,'channel.residency_imported',default_channel);
    end if;
  exception when unique_violation then
    raise exception 'The approved workspace or default channel ID is already in use.' using errcode='PT409';
  end;
  update sectalk_private.st_v8_residency_workspace_claims set claimed_at=clock_timestamp() where id=claim.id;
  return jsonb_build_object('workspace',claim.workspace);
end $$;

notify pgrst,'reload schema';
commit;
