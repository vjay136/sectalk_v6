begin;
insert into auth.users(id,email) values
  ('39c4a3a6-8d36-482a-a216-d44e6ed65501','audit-signer@example.invalid'),
  ('39c4a3a6-8d36-482a-a216-d44e6ed65502','audit-outsider@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('39c4a3a6-8d36-482a-a216-d44e6ed65501','sign_audit_owner','Audit signer'),
  ('39c4a3a6-8d36-482a-a216-d44e6ed65502','sign_audit_outside','Audit outsider');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
  ('39c4a3a6-8d36-482a-a216-d44e6ed65511','39c4a3a6-8d36-482a-a216-d44e6ed65501','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
  ('39c4a3a6-8d36-482a-a216-d44e6ed65521','39c4a3a6-8d36-482a-a216-d44e6ed65501','aal2','39c4a3a6-8d36-482a-a216-d44e6ed65511');
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
  (gen_random_uuid(),'39c4a3a6-8d36-482a-a216-d44e6ed65521','totp',now(),now());

do $$
declare
  owner_id uuid:='39c4a3a6-8d36-482a-a216-d44e6ed65501';
  other_id uuid:='39c4a3a6-8d36-482a-a216-d44e6ed65502';
  session_id uuid:='39c4a3a6-8d36-482a-a216-d44e6ed65521';
  workspace uuid;
  room uuid:=gen_random_uuid();
  audit_id bigint;
  refs jsonb;
  status jsonb;
begin
  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  workspace:=public.st_v2_create_workspace('Signed audit fixture');
  perform public.st_v6_room_create(room,workspace,'Signed audit room','private','blank');
  select id into audit_id from public.st_v2_workspace_audit where workspace_id=workspace and event='workspace.created';
  select jsonb_agg(jsonb_build_object('source',e.source,'id',e.id)) into refs
    from public.st_v6_audit_search(workspace) e;
  status:=public.st_v6_audit_integrity_status(workspace,refs);
  if status->>'state'<>'matched' or (status->>'can_export')::boolean is not false then
    raise exception 'Visible workspace and room rows did not match the local journal'; end if;
  begin
    perform public.st_v6_record_audit_export(workspace);
    raise exception 'Unverified workspace owner triggered signed export';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',other_id,'role','authenticated','aal','aal2','session_id',session_id)::text,true);
  begin
    perform public.st_v6_audit_integrity_status(workspace,refs);
    raise exception 'Cross-tenant actor queried journal integrity';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated','aal','aal2','session_id',session_id)::text,true);
  if (public.st_v6_audit_integrity_status(workspace,refs)->>'can_export')::boolean is not true then
    raise exception 'Live verified owner was denied'; end if;
  perform public.st_v6_record_audit_export(workspace);
  if not exists(select 1 from public.st_v2_workspace_audit where workspace_id=workspace and event='workspace.audit_export_requested') then
    raise exception 'Export authorization was not audited'; end if;

  reset role;
  update auth.mfa_amr_claims set updated_at=now()-interval '6 minutes'
    where auth.mfa_amr_claims.session_id='39c4a3a6-8d36-482a-a216-d44e6ed65521';
  set local role authenticated;
  begin
    perform public.st_v6_record_audit_export(workspace);
    raise exception 'An expired TOTP step could still authorize an export';
  exception when insufficient_privilege then null; end;
  reset role;
  alter table public.st_v2_workspace_audit disable trigger st_v6_audit_capture;
  update public.st_v2_workspace_audit set target=gen_random_uuid() where id=audit_id;
  alter table public.st_v2_workspace_audit enable trigger st_v6_audit_capture;
  set local role authenticated;
  if public.st_v6_audit_integrity_status(workspace,refs)->>'state'<>'unavailable' then
    raise exception 'The verification accepted a changed source row'; end if;
end $$;
select 'passed: existing audit scopes, native MFA, authorization logging and source integrity failure' as result;
rollback;
