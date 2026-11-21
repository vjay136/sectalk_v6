begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  declined_recipient uuid:=gen_random_uuid(); late_recipient uuid:=gen_random_uuid();
  pending_recipient uuid:=gen_random_uuid(); accepted_recipient uuid:=gen_random_uuid();
  claims jsonb:='{}'; w uuid; separate_workspace uuid; request_id uuid:=gen_random_uuid(); case_id uuid; hold_id uuid:=gen_random_uuid();
  declined_invite uuid; late_invite uuid; pending_invite uuid; accepted_invite uuid;
  copy jsonb; selected_plan jsonb; late_plan jsonb; receipt jsonb; status jsonb; baseline integer;
begin
  foreach actor in array array[owner_id,reviewer_id,declined_recipient,late_recipient,pending_recipient,accepted_recipient] loop
    session_id:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'batch_'||left(actor::text,8),'Disposable batch actor');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,jsonb_build_object('sub',actor,'role','authenticated','session_id',session_id,'aal','aal2'));
  end loop;
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  separate_workspace:=public.st_v2_create_workspace('Disposable invitation ID control');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  w:=public.st_v2_create_workspace('Disposable declined invitation source');
  foreach actor in array array[declined_recipient,late_recipient,pending_recipient,accepted_recipient] loop
    if not public.st_v2_invite(w,'batch_'||left(actor::text,8)) then raise exception 'Native invite fixture was not created'; end if;
  end loop;
  select id into strict declined_invite from public.st_v2_invites i where (i.workspace_id,i.invitee)=(w,declined_recipient);
  select id into strict late_invite from public.st_v2_invites i where (i.workspace_id,i.invitee)=(w,late_recipient);
  select id into strict pending_invite from public.st_v2_invites i where (i.workspace_id,i.invitee)=(w,pending_recipient);
  select id into strict accepted_invite from public.st_v2_invites i where (i.workspace_id,i.invitee)=(w,accepted_recipient);
  perform set_config('request.jwt.claims',claims->>declined_recipient::text,true);
  perform public.st_v2_reply_invite(declined_invite,false);
  perform set_config('request.jwt.claims',claims->>late_recipient::text,true);
  perform public.st_v2_reply_invite(late_invite,false);
  perform set_config('request.jwt.claims',claims->>accepted_recipient::text,true);
  perform public.st_v2_reply_invite(accepted_invite,true);
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(w,reviewer_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Review exact declined identity requests.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  case_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(case_id,w,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  begin
    perform public.st_v8_offboarding_declined_invite(w,declined_invite,'capture',w::text);
    raise exception 'Captured before issuing the exact invitation copy';
  exception when sqlstate 'PT409' then null; end;
  status:=public.st_v8_offboarding_declined_invite_status(w);
  if jsonb_array_length(status->'invitations')<>2
    or not exists(select 1 from jsonb_array_elements(status->'invitations') x where x->>'id'=declined_invite::text)
    or exists(select 1 from jsonb_array_elements(status->'invitations') x where x->>'id' in (pending_invite::text,accepted_invite::text))
    then raise exception 'Pending or accepted invitations were treated as removable'; end if;
  copy:=public.st_v8_offboarding_declined_invite(w,declined_invite,'copy',w::text);
  if copy->>'sha256' is distinct from encode(sha256(convert_to(copy->>'json','UTF8')),'hex')
    or (copy->>'json')::jsonb#>>'{invitation,recipient}' is distinct from declined_recipient::text
    or (copy->>'json')::jsonb#>>'{invitation,status}' is distinct from 'declined'
    or (copy->>'json')::jsonb#>>'{workspaceAudit,event}' is distinct from 'member.invited'
    or copy::text like '%@example.invalid%' or copy::text like '%Disposable batch actor%'
    then raise exception 'Exact invitation custody did not preserve declined and native audit state or exposed profile text'; end if;
  selected_plan:=public.st_v8_offboarding_declined_invite(w,declined_invite,'capture',w::text);
  perform public.st_v8_offboarding_declined_invite(w,late_invite,'copy',w::text);
  late_plan:=public.st_v8_offboarding_declined_invite(w,late_invite,'capture',w::text);
  begin
    perform public.st_v8_offboarding_declined_invite(w,declined_invite,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner self-approved the roster record';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_offboarding_declined_invite(w,declined_invite,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner removed a declined invitation before review';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  status:=public.st_v8_offboarding_declined_invite_status(w);
  if jsonb_array_length(status->'invitations')<>0 or not exists(select 1 from jsonb_array_elements(status->'plans') x
    where x->>'plan'=selected_plan->>'plan' and x->>'copySha256'=copy->>'sha256')
    then raise exception 'Wrong reviewer visibility or exact copy fingerprint'; end if;
  perform public.st_v8_offboarding_declined_invite(w,declined_invite,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  perform public.st_v8_offboarding_declined_invite(w,late_invite,'approve',w::text,(late_plan->>'plan')::uuid,late_plan->>'sha256');
  reset role;
  insert into sectalk_private.st_v7_managed_accounts(workspace,supervisor,participant)
    values(w,owner_id,late_recipient);
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,w,declined_recipient,'Preserve disposable invitation evidence during review.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_declined_invite(w,declined_invite,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Removed the invitation under an active preservation hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release this disposable invitation hold.' where h.id=hold_id;
  set local role authenticated;
  baseline:=(public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,categories,access}')::integer;
  begin
    perform public.st_v8_offboarding_declined_invite(w,late_invite,'delete',w::text,(late_plan->>'plan')::uuid,late_plan->>'sha256');
    raise exception 'Removed the invitation despite a late managed roster relationship';
  exception when sqlstate 'PT409' then null; end;
  receipt:=public.st_v8_offboarding_declined_invite(w,declined_invite,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  if receipt->>'deletedAt' is null or receipt is distinct from
    public.st_v8_offboarding_declined_invite(w,declined_invite,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256')
    or (public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,categories,access}')::integer<>baseline-1
    then raise exception 'No exact retirement receipt or identity root reference was reduced'; end if;
  reset role;
  insert into public.st_v2_invites(id,workspace_id,invitee,created_by,workspace_name)
    values(declined_invite,separate_workspace,declined_recipient,reviewer_id,'Disposable unrelated workspace');
  if found then raise exception 'Retired invitation UUID was reassigned to another workspace'; end if;
  if exists(select 1 from public.st_v2_invites i where i.id=declined_invite)
    or not exists(select 1 from sectalk_private.st_v8_offboarding_retired_declined_invite t where
      (t.plan,t.invitation,t.workspace,t.invitee,t.custody,t.sha256)=((selected_plan->>'plan')::uuid,
        declined_invite,w,declined_recipient,(copy->>'json')::jsonb,copy->>'sha256'))
    or not exists(select 1 from public.st_v2_invites i where (i.id,i.status)=(pending_invite,'pending'))
    or not exists(select 1 from public.st_v2_invites i where (i.id,i.status)=(accepted_invite,'accepted'))
    or not exists(select 1 from public.st_v2_members m where (m.workspace_id,m.user_id)=(w,accepted_recipient))
    or not exists(select 1 from public.st_v2_invites i where (i.id,i.status)=(late_invite,'declined'))
    or not exists(select 1 from public.st_v2_workspace_audit a
      where (a.workspace_id,a.target,a.event)=(w,declined_recipient,'member.invited'))
    then raise exception 'Declined invite retirement altered protected audit, roster or unrelated records'; end if;
end $$;

select 'passed: exact declined invitation removal, audit and recipient reservation, no active roster or pending invitation removal';
rollback;