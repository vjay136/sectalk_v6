begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); recipient uuid:=gen_random_uuid();
  actor uuid; session_id uuid; factor_id uuid; claims jsonb:='{}'; w uuid; other_workspace uuid;
  request_id uuid:=gen_random_uuid(); hold_id uuid:=gen_random_uuid(); case_id uuid;
  expired_link uuid; active_link uuid; consumed_link uuid; changed_link uuid;
  expired_token text; active_token text; consumed_token text; changed_token text; address text;
  copy jsonb; selected_plan jsonb; changed_plan jsonb; receipt jsonb; status jsonb; initial_access integer;
begin
  foreach actor in array array[owner_id,reviewer_id,recipient] loop
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
  address:=recipient||'@example.invalid';
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  other_workspace:=public.st_v2_create_workspace('Disposable token reuse control');
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  w:=public.st_v2_create_workspace('Disposable expired link source');
  expired_token:=public.st_v6_workspace_link_create(w,address,1)->>'token';
  active_token:=public.st_v6_workspace_link_create(w,'active-link@example.invalid',1)->>'token';
  consumed_token:=public.st_v6_workspace_link_create(w,address,1)->>'token';
  changed_token:=public.st_v6_workspace_link_create(w,'changed-link@example.invalid',1)->>'token';
  perform set_config('request.jwt.claims',claims->>recipient::text,true);
  if public.st_v6_workspace_link_accept(consumed_token) is distinct from w then raise exception 'Native consume fixture failed'; end if;
  reset role;
  update sectalk_private.st_v6_workspace_link_invites i set expires_at=clock_timestamp()-interval '5 minutes'
    where i.token_hash in (sha256(convert_to(expired_token,'UTF8')),sha256(convert_to(changed_token,'UTF8')),
      sha256(convert_to(consumed_token,'UTF8')));
  select retirement_id into strict expired_link from sectalk_private.st_v6_workspace_link_invites where token_hash=sha256(convert_to(expired_token,'UTF8'));
  select retirement_id into strict active_link from sectalk_private.st_v6_workspace_link_invites where token_hash=sha256(convert_to(active_token,'UTF8'));
  select retirement_id into strict consumed_link from sectalk_private.st_v6_workspace_link_invites where token_hash=sha256(convert_to(consumed_token,'UTF8'));
  select retirement_id into strict changed_link from sectalk_private.st_v6_workspace_link_invites where token_hash=sha256(convert_to(changed_token,'UTF8'));
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(w,reviewer_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'requested',w::text,'Review exact expired invitation links.');
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'approved',w::text);
  case_id:=(public.st_v8_workspace_offboarding(w)#>>'{request,case}')::uuid;
  reset role;
  insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values(case_id,w,owner_id,'downloaded');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_workspace_offboarding_change(w,request_id,'read_only',w::text);
  begin
    perform public.st_v8_offboarding_expired_link(w,expired_link,'capture',w::text);
    raise exception 'Captured before issuing exact metadata copy';
  exception when sqlstate 'PT409' then null; end;
  status:=public.st_v8_offboarding_expired_link_status(w);
  if jsonb_array_length(status->'links')<>2 or not exists(select 1 from jsonb_array_elements(status->'links') x where x->>'id'=expired_link::text)
    or exists(select 1 from jsonb_array_elements(status->'links') x where x->>'id' in (active_link::text,consumed_link::text))
    then raise exception 'Active or consumed access link was listed for removal'; end if;
  copy:=public.st_v8_offboarding_expired_link(w,expired_link,'copy',w::text);
  if copy->>'sha256' is distinct from encode(sha256(convert_to(copy->>'json','UTF8')),'hex')
    or (copy->>'json')::jsonb#>>'{link,id}' is distinct from expired_link::text
    or (copy->>'json')::jsonb#>>'{link,state}' is distinct from 'expired-unused'
    or copy::text like '%'||address||'%' or copy::text like '%'||expired_token||'%'
    or copy::text like '%'||encode(sha256(convert_to(expired_token,'UTF8')),'hex')||'%'
    then raise exception 'Exact metadata copy leaked a token or email or did not match eligible source'; end if;
  selected_plan:=public.st_v8_offboarding_expired_link(w,expired_link,'capture',w::text);
  perform public.st_v8_offboarding_expired_link(w,changed_link,'copy',w::text);
  changed_plan:=public.st_v8_offboarding_expired_link(w,changed_link,'capture',w::text);
  begin
    perform public.st_v8_offboarding_expired_link(w,expired_link,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner self-approved';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_offboarding_expired_link(w,expired_link,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Owner removed before independent approval';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  status:=public.st_v8_offboarding_expired_link_status(w);
  if jsonb_array_length(status->'links')<>0 or not exists(select 1 from jsonb_array_elements(status->'plans') x
    where x->>'plan'=selected_plan->>'plan' and x->>'copySha256'=copy->>'sha256') then
    raise exception 'Independent reviewer scope or exact review fingerprint did not match'; end if;
  perform public.st_v8_offboarding_expired_link(w,expired_link,'approve',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  perform public.st_v8_offboarding_expired_link(w,changed_link,'approve',w::text,(changed_plan->>'plan')::uuid,changed_plan->>'sha256');
  reset role;
  update sectalk_private.st_v6_workspace_link_invites set email='changed-after-review@example.invalid' where retirement_id=changed_link;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,w,owner_id,'Protect disposable access evidence during testing.',owner_id);
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  begin
    perform public.st_v8_offboarding_expired_link(w,expired_link,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
    raise exception 'Removed an invitation link with an active hold';
  exception when insufficient_privilege then null; end;
  reset role;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=owner_id,
    release_reason='Release synthetic link evidence hold.' where h.id=hold_id;
  set local role authenticated;
  initial_access:=(public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,categories,access}')::integer;
  begin
    perform public.st_v8_offboarding_expired_link(w,changed_link,'delete',w::text,(changed_plan->>'plan')::uuid,changed_plan->>'sha256');
    raise exception 'Exact approval was reused after changing a redacted but privately bound field';
  exception when sqlstate 'PT409' then null; end;
  receipt:=public.st_v8_offboarding_expired_link(w,expired_link,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256');
  if receipt->>'deletedAt' is null or receipt is distinct from
    public.st_v8_offboarding_expired_link(w,expired_link,'delete',w::text,(selected_plan->>'plan')::uuid,selected_plan->>'sha256')
    or (public.st_v8_offboarding_reconciliation(w)#>>'{summary,workspaceRootDependencies,categories,access}')::integer<>initial_access-1
    then raise exception 'No exact receipt or workspace access dependency was reduced'; end if;
  reset role;
  begin
    insert into sectalk_private.st_v6_workspace_link_invites(token_hash,workspace_id,issued_by,email,expires_at)
      values(sha256(convert_to(expired_token,'UTF8')),other_workspace,reviewer_id,address,now()+interval '1 hour');
    raise exception 'Reused token verification data belonging to a retired link';
  exception when sqlstate 'PT409' then
    if sqlerrm<>'This invitation link is permanently retired' then raise; end if;
  end;
  if exists(select 1 from sectalk_private.st_v6_workspace_link_invites i where i.retirement_id=expired_link)
    or not exists(select 1 from sectalk_private.st_v8_offboarding_retired_expired_link t where
      (t.plan,t.link,t.custody,t.sha256)=((selected_plan->>'plan')::uuid,expired_link,(copy->>'json')::jsonb,copy->>'sha256'))
    or not exists(select 1 from sectalk_private.st_v6_workspace_link_invites i where i.retirement_id=active_link and i.expires_at>now())
    or not exists(select 1 from sectalk_private.st_v6_workspace_link_invites i where i.retirement_id=consumed_link and i.consumed_at is not null)
    or not exists(select 1 from public.st_v2_members m where (m.workspace_id,m.user_id)=(w,recipient))
    or (select count(*) from public.st_v2_workspace_audit a where (a.workspace_id,a.actor,a.event)=(w,owner_id,'workspace.link_invited'))<>4
    then raise exception 'Retirement changed active/consumed links, memberships, or original audit'; end if;
end $$;

select 'passed: expired unused link, redacted exact copy, stable hidden fields, independent approval, holds, original audit and token reservation';
rollback;