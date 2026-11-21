begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid(); other uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid();
  sso_session uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid();
  workspace uuid; second_workspace uuid;
  room uuid:=gen_random_uuid(); sibling uuid:=gen_random_uuid(); file uuid:=gen_random_uuid(); room_file uuid:=gen_random_uuid();
  cleanup_file uuid:=gen_random_uuid(); cleanup_lease uuid;
  digest text:=repeat('a',64);
  provider text:='custom:entry-file-rollback'; domain text:='entry-file-sso.example.invalid';
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  plain_claim text:=jsonb_build_object('sub',actor,'session_id',password_session,'role','authenticated')::text;
  provider_claim text:=jsonb_build_object('sub',actor,'session_id',sso_session,'role','authenticated')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'owner@entry-file-sso.example.invalid',now()),
    (actor,'member@entry-file-sso.example.invalid',now()),(other,'other@entry-file-sso.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values(owner_id,'dir_'||left(replace(owner_id::text,'-',''),12),'File owner'),
    (actor,'dir_'||left(replace(actor::text,'-',''),12),'File member'),
    (other,'fso_'||left(replace(other::text,'-',''),12),'Other file member');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),
    (sso_session,actor,'aal1',null),(password_session,actor,'aal1',null);
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Fixture OIDC','fixture-client','isolated-placeholder','https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);

  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  workspace:=public.st_v2_create_workspace('Workspace file SSO fixture');
  second_workspace:=public.st_v2_create_workspace('Separate unprotected file');
  if public.st_v8_workspace_entry_policy(workspace,true)->>'access' is distinct from 'mfa' then
    raise exception 'Owner enabled file SSO without fresh TOTP'; end if;
  reset role;

  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(workspace,domain,now());
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,actor,'member'),(workspace,other,'member'),(second_workspace,actor,'member');
  set local role authenticated;
  perform public.st_v7_workspace_sso_settings(workspace,'save',domain,'oidc',true);
  if public.st_v8_workspace_entry_policy(workspace,true)->>'error' is distinct from 'verified_provider_session_required' then
    raise exception 'File SSO enabled without observed provider session'; end if;
  perform public.st_v6_room_create(room,workspace,'Enrolled file room','private','project');
  perform public.st_v6_room_create(sibling,workspace,'Independent private room','private','project');
  reset role;
  insert into public.st_v6_room_members(room_id,user_id,role) values(room,actor,'member');
  insert into sectalk_private.st_v6_workspace_files(workspace,id,uploader,filename,size_bytes,published_at,created_at)
    values(workspace,file,actor,'workspace-file-sso.txt',4,now(),'2000-01-01');
  insert into sectalk_private.st_v6_room_files(room,workspace,id,uploader,filename,size_bytes,published_at,sha256)
    values(room,workspace,room_file,actor,'room-file-sso.txt',4,now(),digest);
  insert into sectalk_private.st_v6_room_files(room,workspace,id,uploader,filename,size_bytes,sha256,created_at,deleted_at)
    values(room,workspace,cleanup_file,actor,'room-cleanup-sso.txt',4,digest,'2000-01-01',now());
  set local role authenticated;
  perform set_config('request.jwt.claims',plain_claim,true);
  if public.st_v8_app_file_context('workspace',workspace) is distinct from
    jsonb_build_object('access','allowed','session',password_session)
    or public.st_v8_app_file_context('room',room)->>'access' is distinct from 'allowed'
    or public.st_v7_explain_file_egress('workspace',workspace,file,'share')->>'allowed' is distinct from 'true' then
    raise exception 'Default file access unexpectedly unavailable'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(sso_session,workspace,actor,'oidc',provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_entry_policy(workspace,true)->>'required' is distinct from 'true' then
    raise exception 'Fresh owner could not require file SSO'; end if;
  perform set_config('request.jwt.claims',plain_claim,true);
  if public.st_v8_app_file_context('workspace',workspace)->>'access' is distinct from 'sso_required'
    or public.st_v8_app_file_context('room',room)->>'access' is distinct from 'unavailable'
    or public.st_v8_app_file_context('room',sibling)->>'access' is distinct from 'unavailable'
    or public.st_v8_app_file_context('workspace',second_workspace)->>'access' is distinct from 'allowed'
    or public.st_v8_scoped_file_context('workspace',workspace)->>'access' is distinct from 'allowed'
    or public.st_v7_explain_file_egress('room',room,room_file,'download')->>'allowed' is distinct from 'false'
    or public.st_v6_workspace_file_history_list(workspace)<>'[]'::jsonb
    or public.st_v6_workspace_file_access_history(workspace,file) is not null then
    raise exception 'Password session saw protected file information or lost independent access'; end if;
  perform set_config('request.jwt.claims',provider_claim,true);
  if public.st_v8_app_file_context('workspace',workspace) is distinct from jsonb_build_object('access','allowed','session',sso_session)
    or public.st_v7_explain_file_egress('room',room,room_file,'download')->>'allowed' is distinct from 'true'
    or public.st_v6_workspace_file_access_history(workspace,file)->>'filename' is distinct from 'workspace-file-sso.txt' then
    raise exception 'Live receipt lost file policy or history access'; end if;
  reset role;

  set local role service_role;
  if public.st_v8_app_file_command('workspace',workspace,actor,password_session,'get',file,null,null,null) is not null
    or public.st_v8_app_file_command('workspace',workspace,owner_id,sso_session,'get',file,null,null,null) is not null
    or public.st_v8_app_file_command('room',sibling,actor,sso_session,'list',null,null,null,null) is not null
    or public.st_v8_app_file_command('room',room,actor,sso_session,'get',room_file,null,null,null)->>'sha256' is distinct from digest
    or public.st_v8_app_file_command('workspace',workspace,actor,sso_session,'share',file,null,null,null) is null
    or public.st_v6_workspace_file_command(workspace,actor,'get',file,null,null,null) is null
    or public.st_v8_scoped_file_command('workspace',workspace,actor,password_session,'get',file,null,null,null) is null then
    raise exception 'Native session handoff leaked across sessions or blocked trusted system metadata'; end if;
  if not exists(select 1 from public.st_v6_workspace_file_maintenance_claim() job
    where job.id=file and job.task='index' and job.lease is not null) then
    raise exception 'Workspace maintenance could not index a file protected by SSO'; end if;
  select job.lease into cleanup_lease from public.st_v6_claim_room_file_cleanup() job where job.id=cleanup_file;
  if cleanup_lease is null or not public.st_v6_finish_room_file_cleanup(room,cleanup_file,cleanup_lease) then
    raise exception 'Room maintenance could not remove a deleted file protected by SSO'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role service_role;
  if public.st_v8_app_file_command('workspace',workspace,actor,sso_session,'download',file,null,null,null) is not null
    or public.st_v8_app_file_command('room',room,actor,sso_session,'get',room_file,null,null,null) is not null then
    raise exception 'Previously validated native session could still use storage after provider disablement'; end if;
  reset role;
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  if public.st_v8_workspace_entry_policy(workspace,false)->>'required' is distinct from 'false' then
    raise exception 'Fresh owner could not recover file access'; end if;
  if public.st_v8_app_file_context('workspace',workspace)->>'access' is distinct from 'allowed' then
    raise exception 'Current owner session stayed blocked after recovery'; end if;
  reset role;
  if has_function_privilege('authenticated','public.st_v8_app_file_command(text,uuid,uuid,uuid,text,uuid,text,integer,text)','execute')
    or has_function_privilege('service_role','public.st_v8_app_file_context(text,uuid)','execute')
    or has_function_privilege('anon','public.st_v8_app_file_context(text,uuid)','execute') then
    raise exception 'Scoped context or storage handoff has an unexpected grant'; end if;
end $$;
select 'passed: workspace entry file gates, trusted workflows, exact native sessions and maintenance';
rollback;
