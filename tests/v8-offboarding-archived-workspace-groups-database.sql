begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); actor uuid; session_id uuid; factor_id uuid;
  claims jsonb:='{}'; w uuid; separate_workspace uuid; request_id uuid:=gen_random_uuid(); case_id uuid; hold_id uuid:=gen_random_uuid();
  archived_group uuid:=gen_random_uuid(); roster_group uuid:=gen_random_uuid(); live_group uuid:=gen_random_uuid();
  late_group uuid:=gen_random_uuid(); late_role_id uuid:=gen_random_uuid(); item uuid;
  copy jsonb; chosen_plan jsonb; late_plan jsonb; receipt jsonb; status jsonb; initial_access integer;
begin
  foreach actor in array array[owner_id,reviewer_id] loop
    session_id:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email,email_confirmed_at) values(actor,actor||'@example.invalid',now());
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
  separate_workspace:=public.st_v2_create_workspace('Disposable independent group namespace');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  w:=public.st_v2_create_workspace('Disposable archived group source');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(w,reviewer_id);
  set local role authenticated;
  foreach item in array array[archived_group,roster_group,late_group,live_group] loop
    perform public.st_v6_workspace_group_create(w,item,'group','Disposable group '||left(item::text,7),'Synthetic workspace group.');
  end loop;
  perform public.st_v6_workspace_group_change(w,roster_group,'member_added',p_user=>reviewer_id);
  foreach item in array array[archived_group,roster_group,late_group] loop
    perform public.st_v6_workspace_group_change(w,item,'archive');
  end loop;
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Review native archived access groups.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  case_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(case_id,w,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  begin
    perform public.st_v8_offboarding_archived_group(w,archived_group,'capture',w::text);
    raise exception 'Captured without exact group metadata copy';
  exception when sqlstate 'PT409' then null; end;
  status:=public.st_v8_offboarding_archived_group_status(w);
  if jsonb_array_length(status->'groups')<>2 or
    not exists(select 1 from jsonb_array_elements(status->'groups') x where x->>'id'=archived_group::text)
    or exists(select 1 from jsonb_array_elements(status->'groups') x where x->>'id' in (roster_group::text,live_group::text))
    then raise exception 'Archived group candidate list did not preserve existing roster or live groups'; end if;
  copy:=public.st_v8_offboarding_archived_group(w,archived_group,'copy',w::text);
  if copy->>'sha256' is distinct from encode(sha256(convert_to(copy->>'json','UTF8')),'hex')
    or (copy->>'json')::jsonb#>>'{group,id}' is distinct from archived_group::text
    or (copy->>'json')::jsonb#>>'{workspaceAudit,0,event}' is distinct from 'group.created'
    or (copy->>'json')::jsonb#>>'{workspaceAudit,1,event}' is distinct from 'group.archive'
    then raise exception 'Group copy failed exact native metadata or audit verification'; end if;
  chosen_plan:=public.st_v8_offboarding_archived_group(w,archived_group,'capture',w::text);
  perform public.st_v8_offboarding_archived_group(w,late_group,'copy',w::text);
  late_plan:=public.st_v8_offboarding_archived_group(w,late_group,'capture',w::text);
  begin
    perform public.st_v8_offboarding_archived_group(w,archived_group,'approve',w::text,(chosen_plan->>'plan')::uuid,chosen_plan->>'sha256');
    raise exception 'Owner self-approved the access group';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_offboarding_archived_group(w,archived_group,'delete',w::text,(chosen_plan->>'plan')::uuid,chosen_plan->>'sha256');
    raise exception 'Owner removed the group before independent approval';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  status:=public.st_v8_offboarding_archived_group_status(w);
  if jsonb_array_length(status->'groups')<>0 or not exists(select 1 from jsonb_array_elements(status->'plans') x
    where x->>'plan'=chosen_plan->>'plan' and x->>'group'=archived_group::text and x->>'copySha256'=copy->>'sha256')
    then raise exception 'Wrong independent role review or copy digest'; end if;
  perform public.st_v8_offboarding_archived_group(w,archived_group,'approve',w::text,(chosen_plan->>'plan')::uuid,chosen_plan->>'sha256');
  perform public.st_v8_offboarding_archived_group(w,late_group,'approve',w::text,(late_plan->>'plan')::uuid,late_plan->>'sha256');
  reset role;
  insert into sectalk_private.st_v7_custom_role_heads(workspace,id,revision) values(w,late_role_id,1);
  insert into sectalk_private.st_v7_custom_role_versions(workspace,role_id,revision,name,target,permissions,device,enabled,scope_type)
    values(w,late_role_id,1,'Late retained group role',late_group,array['group:read'],'any',false,'group');
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,w,owner_id,'Preserve disposable access group evidence during testing.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_archived_group(w,archived_group,'delete',w::text,(chosen_plan->>'plan')::uuid,chosen_plan->>'sha256');
    raise exception 'Removed an archived group with a preservation hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release this disposable group hold.' where h.id=hold_id;
  set local role authenticated;
  initial_access:=(public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,categories,access}')::integer;
  begin
    perform public.st_v8_offboarding_archived_group(w,late_group,'delete',w::text,(late_plan->>'plan')::uuid,late_plan->>'sha256');
    raise exception 'Removed a target referenced by a late custom role revision';
  exception when sqlstate 'PT409' then null; end;
  receipt:=public.st_v8_offboarding_archived_group(w,archived_group,'delete',w::text,(chosen_plan->>'plan')::uuid,chosen_plan->>'sha256');
  if receipt->>'deletedAt' is null or receipt is distinct from
    public.st_v8_offboarding_archived_group(w,archived_group,'delete',w::text,(chosen_plan->>'plan')::uuid,chosen_plan->>'sha256')
    or (public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,categories,access}')::integer<>initial_access-1
    then raise exception 'Exact group receipt or root access count failed'; end if;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v6_workspace_group_create(separate_workspace,archived_group,'group',
    (copy->>'json')::jsonb#>>'{group,name}','Same ID and name allowed outside the retired scope.');
  reset role;
  if exists(select 1 from public.st_v6_workspace_groups g where (g.workspace_id,g.id)=(w,archived_group))
    or not exists(select 1 from sectalk_private.st_v8_offboarding_retired_archived_group t where
      (t.plan,t.workspace,t.group_id,t.group_name,t.custody,t.sha256)=((chosen_plan->>'plan')::uuid,w,archived_group,
        (copy->>'json')::jsonb#>>'{group,name}',(copy->>'json')::jsonb,copy->>'sha256'))
    or not exists(select 1 from public.st_v6_workspace_group_members g where (g.workspace_id,g.group_id,g.user_id)=(w,roster_group,reviewer_id))
    or not exists(select 1 from sectalk_private.st_v7_custom_role_versions v where (v.workspace,v.role_id,v.target)=(w,late_role_id,late_group))
    or (select count(*) from public.st_v2_workspace_audit a where (a.workspace_id,a.target)=(w,archived_group)
      and a.event in ('group.created','group.archive'))<>2
    then raise exception 'Retirement altered a roster, role revision, original audit or another scope'; end if;
end $$;

select 'passed: scoped archived group removal, exact original audit, reserved ID and name, protected roster and late role evidence';
rollback;
