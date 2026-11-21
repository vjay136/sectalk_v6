begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  eligible_member uuid:=gen_random_uuid(); staffed_member uuid:=gen_random_uuid(); late_member uuid:=gen_random_uuid(); active_member uuid:=gen_random_uuid();
  claims jsonb:='{}'; w uuid; other_workspace uuid; request_id uuid:=gen_random_uuid(); case_id uuid; hold_id uuid:=gen_random_uuid();
  invitation_id uuid; eligible_invite uuid; team uuid:=gen_random_uuid();
  copy jsonb; selected_plan jsonb; late_plan jsonb; receipt jsonb; status jsonb; initial_access integer;
begin
  foreach actor in array array[owner_id,reviewer_id,eligible_member,staffed_member,late_member,active_member] loop
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
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values(owner_id,'business','active',now()+interval '1 day');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  other_workspace:=public.st_v2_create_workspace('Disposable ordinary member removal control');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id) values(other_workspace,eligible_member);
  set local role authenticated;
  perform public.st_v2_set_member(other_workspace,eligible_member,'remove');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  w:=public.st_v2_create_workspace('Disposable suspended membership source');
  foreach actor in array array[eligible_member,staffed_member,late_member,active_member] loop
    perform set_config('request.jwt.claims',claims->>owner_id::text,true);
    if not public.st_v2_invite(w,'batch_'||left(actor::text,8)) then raise exception 'Native roster invitation failed'; end if;
    select i.id into strict invitation_id from public.st_v2_invites i where (i.workspace_id,i.invitee)=(w,actor);
    if actor=eligible_member then eligible_invite:=invitation_id; end if;
    perform set_config('request.jwt.claims',claims->>actor::text,true);
    if public.st_v2_reply_invite(invitation_id,true) is distinct from w then raise exception 'Native acceptance failed'; end if;
  end loop;
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(w,reviewer_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v6_workspace_group_create(w,team,'team','Disposable roster dependency','Synthetic access dependency.');
  perform public.st_v6_workspace_group_change(w,team,'member_added',p_user=>staffed_member);
  foreach actor in array array[eligible_member,staffed_member,late_member] loop
    perform public.st_v2_set_member(w,actor,'suspend');
  end loop;
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Review one exact suspended roster membership.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  case_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(case_id,w,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  begin
    perform public.st_v2_set_member(w,staffed_member,'remove');
    raise exception 'Ordinary staged roster DELETE bypassed independent custody';
  exception when sqlstate 'PT423' then
    if sqlerrm<>'Reviewed roster custody is required during workspace offboarding' then raise; end if;
  end;
  status:=public.st_v8_offboarding_suspended_member_status(w);
  if jsonb_array_length(status->'members')<>2
    or not exists(select 1 from jsonb_array_elements(status->'members') x where x->>'id'=eligible_member::text)
    or exists(select 1 from jsonb_array_elements(status->'members') x where x->>'id' in (active_member::text,staffed_member::text))
    then raise exception 'Dependent or active roster membership was offered, or pristine suspended source was missing'; end if;
  copy:=public.st_v8_offboarding_suspended_member(w,eligible_member,'copy',w::text);
  if copy->>'sha256' is distinct from encode(sha256(convert_to(copy->>'json','UTF8')),'hex')
    or (copy->>'json')::jsonb#>>'{membership,user_id}' is distinct from eligible_member::text
    or (copy->>'json')::jsonb->>'acceptedInvitation' is distinct from eligible_invite::text
    or (copy->>'json')::jsonb#>>'{workspaceAudit,0,event}' is distinct from 'member.invited'
    or (copy->>'json')::jsonb#>>'{workspaceAudit,1,event}' is distinct from 'member.joined'
    or (copy->>'json')::jsonb#>>'{workspaceAudit,2,event}' is distinct from 'member.suspend'
    or copy::text like '%@example.invalid%'
    then raise exception 'Exact member custody copy lost identity proof or exposed an email'; end if;
  selected_plan:=public.st_v8_offboarding_suspended_member(w,eligible_member,'capture',w::text);
  perform public.st_v8_offboarding_suspended_member(w,late_member,'copy',w::text);
  late_plan:=public.st_v8_offboarding_suspended_member(w,late_member,'capture',w::text);
  begin
    perform public.st_v8_offboarding_suspended_member(w,eligible_member,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner removed the membership before independent approval';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  status:=public.st_v8_offboarding_suspended_member_status(w);
  if jsonb_array_length(status->'members')<>0 or not exists(select 1 from jsonb_array_elements(status->'plans') x
    where x->>'member'=eligible_member::text and x->>'copySha256'=copy->>'sha256')
    then raise exception 'Independent reviewer listing could not prove the selected copy'; end if;
  perform public.st_v8_offboarding_suspended_member(w,eligible_member,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  perform public.st_v8_offboarding_suspended_member(w,late_member,'approve',w::text,(late_plan->>'plan')::uuid,late_plan->>'sha256');
  reset role;
  insert into sectalk_private.st_v6_impersonation_watch(workspace_id,member_id,tier) values(w,late_member,'vip');
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,w,owner_id,'Preserve disposable roster evidence during the active hold.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_suspended_member(w,eligible_member,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Retired membership despite active preservation hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release this disposable roster evidence hold.' where h.id=hold_id;
  set local role authenticated;
  initial_access:=(public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,categories,access}')::integer;
  begin
    perform public.st_v8_offboarding_suspended_member(w,late_member,'delete',w::text,(late_plan->>'plan')::uuid,late_plan->>'sha256');
    raise exception 'Retired membership despite late native identity-alert evidence';
  exception when sqlstate 'PT409' then null; end;
  receipt:=public.st_v8_offboarding_suspended_member(w,eligible_member,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  if receipt->>'deletedAt' is null or receipt is distinct from
    public.st_v8_offboarding_suspended_member(w,eligible_member,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256')
    or (public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,categories,access}')::integer<>initial_access-1
    then raise exception 'Exact retirement or direct membership count was not verified'; end if;
  reset role;
  if exists(select 1 from public.st_v2_members m where (m.workspace_id,m.user_id) in ((w,eligible_member),(other_workspace,eligible_member)))
    or not exists(select 1 from auth.users u where u.id=eligible_member)
    or not exists(select 1 from public.st_v2_invites i where (i.id,i.status)=(eligible_invite,'accepted'))
    or not exists(select 1 from public.st_v2_members m where (m.workspace_id,m.user_id)=(w,active_member) and m.suspended_at is null)
    or not exists(select 1 from public.st_v6_workspace_group_members g where (g.workspace_id,g.group_id,g.user_id)=(w,team,staffed_member))
    or not exists(select 1 from sectalk_private.st_v6_impersonation_watch t where (t.workspace_id,t.member_id,t.tier)=(w,late_member,'vip'))
    or (select count(*) from public.st_v2_workspace_audit a where (a.workspace_id,a.target)=(w,eligible_member))<>3
    or not exists(select 1 from sectalk_private.st_v8_offboarding_retired_suspended_member t where
      (t.plan,t.member_id,t.workspace,t.custody,t.sha256)=((selected_plan->>'plan')::uuid,eligible_member,w,(copy->>'json')::jsonb,copy->>'sha256'))
    then raise exception 'Ordinary removal, retained identity/audit, or protected roster dependencies changed'; end if;
end $$;

select 'passed: exact suspended membership retirement, blocked ordinary staged delete, preserved user/invite/audit, hold and late dependency denial';
rollback;