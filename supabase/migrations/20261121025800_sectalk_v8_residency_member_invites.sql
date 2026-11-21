begin;

create function public.st_v8_residency_member_proof(p_challenge text,p_workspace uuid default null)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); verified_email text;
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not sectalk_private.st_v7_admin_fresh() or p_challenge is null or p_challenge!~'^[0-9a-f]{64}$'
    or (p_workspace is not null and (
      sectalk_private.st_v2_role(p_workspace,actor_id) is distinct from 'member'
      or not sectalk_private.st_v8_directory_sso_allows(p_workspace))) then raise insufficient_privilege; end if;
  select lower(btrim(u.email)) into verified_email from auth.users u join public.st_profiles p on p.id=u.id
    where u.id=actor_id and u.email_confirmed_at is not null and nullif(btrim(u.email),'') is not null
      and nullif(btrim(u.email_change),'') is null;
  if not found then raise insufficient_privilege; end if;
  return jsonb_build_object('account',actor_id,'identity',encode(sha256(convert_to(
    'sectalk-residency-member-v1:'||p_challenge||':'||verified_email,'UTF8')),'hex'));
end $$;

create function public.st_v8_residency_member_invite(p_workspace uuid,p_approval uuid,p_source text,p_destination uuid,
  p_challenge text,p_identity text)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); destination_handle text; invitation uuid;
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false)
    or not sectalk_private.st_v7_admin_fresh() or p_destination is null or p_destination=actor_id
    or not coalesce(p_challenge~'^[0-9a-f]{64}$' and p_identity~'^[0-9a-f]{64}$',false) then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_residency_member_invite',10);
  perform 1 from public.st_v2_workspaces w where w.id=p_workspace and w.owner=actor_id for update;
  if not found or sectalk_private.st_v8_offboarding_role(p_workspace,actor_id) is distinct from 'owner'
    or not sectalk_private.st_v8_directory_sso_allows(p_workspace) then raise insufficient_privilege; end if;
  perform sectalk_private.st_v7_require_workspace_write(p_workspace);
  perform 1 from sectalk_private.st_v8_residency_workspace_claims c
    join sectalk_private.st_v8_residency_installation i on (i.cell,i.installation_nonce)=(c.cell,c.installation_nonce)
    join sectalk_private.st_v8_residency_cells t on t.id=c.cell and t.retired_at is null
    join sectalk_private.st_v8_residency_content_admissions a
      on (a.cell,a.workspace,a.source_project,a.approval)=(c.cell,c.workspace,c.source_project,c.approval)
    where (c.workspace,c.approval,c.source_project,c.owner_id)=(p_workspace,p_approval,p_source,actor_id)
      and c.claimed_at is not null and c.manifest_sha256=a.manifest_sha256
      and least(c.expires_at,a.expires_at)>statement_timestamp() for share of c,i,t,a;
  if not found then raise insufficient_privilege; end if;
  select p.handle into destination_handle from public.st_profiles p join auth.users u on u.id=p.id
    where p.id=p_destination and u.email_confirmed_at is not null and nullif(btrim(u.email),'') is not null
      and nullif(btrim(u.email_change),'') is null
      and encode(sha256(convert_to('sectalk-residency-member-v1:'||p_challenge||':'||lower(btrim(u.email)),'UTF8')),'hex')=p_identity
    for share of p,u;
  if not found or not sectalk_private.st_v2_active(p_destination)
    or not sectalk_private.open_pair(actor_id,p_destination) then raise insufficient_privilege; end if;
  perform public.st_v2_invite(p_workspace,destination_handle);
  select id into invitation from public.st_v2_invites where workspace_id=p_workspace and invitee=p_destination
    and created_by=actor_id and status='pending';
  if not found then raise exception 'A new destination invitation is unavailable for this account' using errcode='PT409'; end if;
  return invitation;
end $$;

revoke all on function public.st_v8_residency_member_proof(text,uuid),
  public.st_v8_residency_member_invite(uuid,uuid,text,uuid,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_member_proof(text,uuid),
  public.st_v8_residency_member_invite(uuid,uuid,text,uuid,text,text) to authenticated;
notify pgrst,'reload schema';
commit;
