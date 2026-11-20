begin;
do $$
declare owner_id uuid:=gen_random_uuid(); member uuid:=gen_random_uuid(); outsider uuid:=gen_random_uuid();
  owner_session uuid:=gen_random_uuid(); member_session uuid:=gen_random_uuid(); outsider_session uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); workspace uuid; room uuid:=gen_random_uuid(); classroom uuid:=gen_random_uuid();
  file uuid:=gen_random_uuid(); post uuid:=gen_random_uuid(); rr uuid:=gen_random_uuid(); fr uuid:=gen_random_uuid(); d jsonb;
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  member_claim text:=jsonb_build_object('sub',member,'session_id',member_session,'role','authenticated','aal','aal1')::text;
  outsider_claim text:=jsonb_build_object('sub',outsider,'session_id',outsider_session,'role','authenticated','aal','aal1')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'scope-owner@example.invalid',now()),
    (member,'scope-member@example.invalid',now()),(outsider,'scope-other@example.invalid',now());
  insert into public.st_profiles values(owner_id,'scope_owner','Scope owner'),(member,'scope_member','Scope member'),(outsider,'scope_other','Scope outsider');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),
    (member_session,member,'aal1',null),(outsider_session,outsider,'aal1',null);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values(gen_random_uuid(),owner_session,'totp',now(),now());

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  workspace:=public.st_v2_create_workspace('Scope fixtures');
  perform public.st_v6_room_create(room,workspace,'Delegate private room','private','blank');
  perform public.st_v6_room_create(classroom,workspace,'Protected classroom','private','class');
  perform public.st_v6_room_post(room,post,'Prove limited pin');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,member,'member'),(workspace,outsider,'member');
  insert into public.st_v6_room_members(room_id,user_id,role) values(room,member,'member');
  insert into sectalk_private.st_v6_workspace_files(workspace,id,uploader,filename,size_bytes,published_at)
    values(workspace,file,owner_id,'proof.txt',12,now());
  set local role authenticated;
  d:=jsonb_build_object('name','Room moderator','target',room,'scope_type','room','permissions',array['room.pin','room.unpin','room.slow'],
    'enabled',true,'device','any');
  perform public.st_v7_workspace_custom_roles(workspace,'save',rr,0,d);
  begin
    perform public.st_v7_workspace_custom_roles(workspace,'save',gen_random_uuid(),0,d||jsonb_build_object('target',classroom));
    raise exception 'Classroom entered generic moderation';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_v7_workspace_custom_roles(workspace,'save',rr,0,d);
    raise exception 'Stale revision changed room role';
  exception when others then if sqlstate<>'PT409' then raise; end if; end;
  perform public.st_v7_workspace_custom_roles(workspace,'assign',rr,1,p_account=>member);
  perform public.st_v7_workspace_custom_roles(workspace,'assign',rr,1,p_account=>outsider);
  d:=jsonb_build_object('name','Compatible private file','target',file,'scope_type','file','permissions',array['file.download'],
    'enabled',true,'device','any');
  perform public.st_v7_workspace_custom_roles(workspace,'save',fr,0,d);
  perform public.st_v7_workspace_custom_roles(workspace,'gate',fr,1,'{"required":true}');
  perform public.st_v7_workspace_custom_roles(workspace,'assign',fr,1,p_account=>member);
  perform set_config('request.jwt.claims',outsider_claim,true);
  if cardinality(public.st_v7_custom_room_access(room))<>0 then raise exception 'Nonmember received room access'; end if;
  perform set_config('request.jwt.claims',member_claim,true);
  perform public.st_v6_room_settings(room,'pin',post);
  perform public.st_v6_room_settings(room,'slow',null,30);
  begin
    perform public.st_v6_room_settings(room,'lock');
    raise exception 'Room grant elevated unrelated control';
  exception when insufficient_privilege then null; end;
  if (public.st_v7_explain_file_egress('workspace',workspace,file,'download')->>'allowed')::boolean is not true
    or public.st_v7_explain_file_egress('workspace',workspace,file,'share')->'reasons'<>'["custom_role_required"]'::jsonb then
    raise exception 'File grants did not enforce independent actions';
  end if;
  perform set_config('request.jwt.claims',owner_claim,true);
  perform public.st_v7_save_file_egress_policy(workspace,0,'{"mode":"block"}');
  perform set_config('request.jwt.claims',member_claim,true);
  if public.st_v7_explain_file_egress('workspace',workspace,file,'download')->'reasons'<>'["tenant_block"]'::jsonb then
    raise exception 'Custom file role overrode SEC-02';
  end if;
  perform set_config('request.jwt.claims',owner_claim,true);
  perform public.st_v7_save_file_egress_policy(workspace,1,'{"mode":"inherit"}');
  perform public.st_v7_workspace_custom_roles(workspace,'revoke',rr,1,p_account=>member);
  perform public.st_v7_workspace_custom_roles(workspace,'revoke',fr,1,p_account=>member);
  perform set_config('request.jwt.claims',member_claim,true);
  if cardinality(public.st_v7_custom_room_access(room))<>0
    or public.st_v7_explain_file_egress('workspace',workspace,file,'download')->'reasons'<>'["custom_role_required"]'::jsonb then
    raise exception 'Revocation kept authority or reopened the gated file';
  end if;
end
$$;
select 'passed: separately granted room and file actions, live policy inheritance, revision conflict and revocation' as result;
rollback;
