begin;

create function public.st_v8_export_provider_key_evidence(p_workspace uuid,p_version integer,p_confirmation text)
returns jsonb language plpgsql security definer set search_path='' set timezone='UTC' set datestyle='ISO, YMD' as $$
declare
  caller uuid:=auth.uid(); r sectalk_private.st_v8_offboarding_requests;
  evidence sectalk_private.st_v8_provider_erasure_receipts; result text; pin_commitment text;
begin
  if p_workspace is null or p_version is null or p_version<1 or p_confirmation is distinct from p_workspace::text
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false) or not sectalk_private.st_v7_admin_fresh()
    then raise insufficient_privilege; end if;
  select x.* into r from sectalk_private.st_v8_offboarding_requests x where x.workspace=p_workspace and x.state='read_only';
  if not sectalk_private.st_v8_provider_erasure_reviewer(r,caller) then raise insufficient_privilege; end if;
  perform pg_advisory_xact_lock_shared(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform 1 from public.st_v2_workspaces x where x.id=p_workspace for share;
  perform 1 from sectalk_private.st_v7_tenant_destroy_reviewers x where (x.workspace,x.actor)=(p_workspace,caller) for share;
  perform 1 from sectalk_private.st_v8_offboarding_reviewers x where (x.workspace,x.actor)=(p_workspace,caller) for share;
  perform 1 from public.st_v2_members x where x.workspace_id=p_workspace and x.user_id in (r.requester,r.reviewer)
    order by x.user_id for share;
  if not sectalk_private.st_v8_provider_erasure_reviewer(r,caller) then raise insufficient_privilege; end if;
  perform 1 from auth.sessions n
    join auth.mfa_factors f on (f.id,f.user_id)=(n.factor_id,n.user_id)
    join auth.mfa_amr_claims proof on proof.session_id=n.id and proof.authentication_method='totp'
    where (n.id::text,n.user_id)=(auth.jwt()->>'session_id',caller) and n.aal='aal2'
      and f.status='verified' and f.factor_type='totp' and proof.updated_at>clock_timestamp()-interval '5 minutes'
      and sectalk_private.st_v7_session_deadline(n.created_at,n.refreshed_at,n.not_after)>clock_timestamp()
    for share of n,f,proof;
  if not found then raise insufficient_privilege; end if;
  perform sectalk_private.limit_action('v8_export_provider_key_evidence',12);
  select x.* into evidence from sectalk_private.st_v8_provider_erasure_receipts x
    where (x.request,x.workspace,x.version)=(r.id,p_workspace,p_version);
  if evidence.request is null then raise exception 'Exact provider evidence is unavailable' using errcode='PT409'; end if;
  pin_commitment:=encode(sha256(convert_to('sectalk-provider-pin-commitment-v1:'||p_workspace::text||':'||
    p_version::text||':'||evidence.provider_pin,'UTF8')),'hex');
  result:=jsonb_build_object('format','sectalk-provider-key-evidence-v1','workspace',p_workspace,'version',p_version,
    'eventTime',evidence.provider_event_time,'eventSha256',evidence.provider_event_sha256,
    'recordedAt',evidence.recorded_at,'pinCommitment',pin_commitment)::text;
  return jsonb_build_object('json',result,'sha256',encode(sha256(convert_to(result,'UTF8')),'hex'));
end $$;

revoke all on function public.st_v8_export_provider_key_evidence(uuid,integer,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_export_provider_key_evidence(uuid,integer,text) to authenticated;
notify pgrst,'reload schema';
commit;
