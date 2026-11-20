begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); member_id uuid:=gen_random_uuid(); outsider_id uuid:=gen_random_uuid();
  owner_session uuid:=gen_random_uuid(); factor_id uuid:=gen_random_uuid(); tenant_id uuid; candidate_id uuid;
  starter_id uuid:=gen_random_uuid(); password_session uuid:=gen_random_uuid(); link_session uuid:=gen_random_uuid();
  starter_resource uuid; group_resource uuid; starter_email text:='starter@scim-rollback.example.invalid';
  proof jsonb; token_digest text;
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (owner_id,'owner@scim-rollback.example.invalid',now()),
    (member_id,'candidate@scim-rollback.example.invalid',now()),
    (outsider_id,'other@scim-outside.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values
    (owner_id,'scim_rollback_owner','Owner'),(member_id,'scim_rollback_member','Member'),(outsider_id,'scim_rollback_outside','Other');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor_id,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor_id);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),owner_session,'totp',now(),now());
  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text,true);
  tenant_id:=public.st_v2_create_workspace('SCIM rollback fixture');
  if has_function_privilege('authenticated','public.st_v8_scim_request(text,text,text,uuid,jsonb,text,text,int,int)','execute')
    or has_schema_privilege('authenticated','sectalk_private','USAGE') and has_table_privilege('authenticated','sectalk_private.st_v8_scim_keys','select')
    then raise exception 'Provisioning credential or worker available to ordinary authenticated role'; end if;
  reset role;
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at)
    values(tenant_id,'scim-rollback.example.invalid',now());
  set local role authenticated;
  proof:=public.st_v8_scim_settings(tenant_id,'rotate','scim-rollback.example.invalid');
  token_digest:=encode(extensions.digest(proof->>'token','sha256'),'hex');
  if proof->>'token' is null or public.st_v8_scim_settings(tenant_id)->>'token' is not null then
    raise exception 'Token was unavailable on issue or exposed again after issue';
  end if;
  reset role;
  set local role service_role;
  proof:=public.st_v8_scim_request(token_digest,'Users','POST',null,'{"userName":"other@scim-outside.example.invalid"}');
  if proof->>'status' is distinct from '403' then raise exception 'Unexpected scope result: %', proof; end if;
  proof:=public.st_v8_scim_request(token_digest,'Users','POST',null,'{"userName":"candidate@scim-rollback.example.invalid"}');
  if proof->>'status' is distinct from '201' then raise exception 'Provisioning did not create ordinary membership: %', proof; end if;
  candidate_id:=(proof->'resource'->>'id')::uuid;
  reset role;
  delete from public.st_v2_members m where m.workspace_id=tenant_id and m.user_id=member_id;
  begin
    insert into public.st_v2_members(workspace_id,user_id) values(tenant_id,member_id);
    raise exception 'Other membership entry point bypassed manual SCIM offboarding';
  exception when insufficient_privilege then null;
  end;
  set local role service_role;
  proof:=public.st_v8_scim_request(token_digest,'Users','PATCH',candidate_id,'{"active":true}');
  if proof->>'status' is distinct from '403' then raise exception 'Manual removal bypassed: %', proof; end if;
  proof:=public.st_v8_scim_request(token_digest,'Users','POST',null,jsonb_build_object('userName',starter_email));
  if proof->>'status' is distinct from '201' then raise exception 'Unknown user did not provision as pending: %', proof; end if;
  starter_resource:=(proof->'resource'->>'id')::uuid;
  proof:=public.st_v8_scim_request(token_digest,'Groups','POST',null,jsonb_build_object('displayName','New starters',
    'members',jsonb_build_array(jsonb_build_object('value',starter_resource))));
  if proof->>'status' is distinct from '201' or proof->'resource'->'members'->0->>'value' is distinct from starter_resource::text then
    raise exception 'Pending group member absent: %', proof; end if;
  group_resource:=(proof->'resource'->>'id')::uuid;
  reset role;
  insert into auth.users(id,email) values(starter_id,starter_email);
  insert into public.st_profiles(id,handle,name) values(starter_id,'scim_pending_starter','Starter');
  insert into auth.sessions(id,user_id,aal,created_at) values(password_session,starter_id,'aal1',now()),
    (link_session,starter_id,'aal1',now());
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),password_session,'password',now(),now()),(gen_random_uuid(),link_session,'magiclink',now(),now());
  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',starter_id,'session_id',link_session,
    'role','authenticated','aal','aal1','email',starter_email)::text,true);
  if public.st_v8_scim_claim(true)->>'state' is distinct from 'none' then raise exception 'Unconfirmed account obtained directory grant'; end if;
  reset role;
  update auth.users set email_confirmed_at=clock_timestamp() where id=starter_id;
  insert into auth.identities(id,provider_id,user_id,identity_data,provider)
    values(gen_random_uuid(),starter_id::text,starter_id,jsonb_build_object('email',starter_email,'email_verified',true),'email');
  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',starter_id,'session_id',password_session,
    'role','authenticated','aal','aal1','email',starter_email,'user_metadata',jsonb_build_object('method','magiclink'))::text,true);
  if public.st_v8_scim_claim(true)->>'state' is distinct from 'verify' then raise exception 'Password proof attached pending identity'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',starter_id,'session_id',link_session,
    'role','authenticated','aal','aal1','email','alias@scim-rollback.example.invalid')::text,true);
  if public.st_v8_scim_claim(true)->>'state' is distinct from 'none' then raise exception 'JWT email alias attached pending identity'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',starter_id,'session_id',link_session,
    'role','authenticated','aal','aal1','email',starter_email)::text,true);
  if public.st_v8_scim_claim(true)->>'state' is distinct from 'joined' then raise exception 'Verified mail session failed to attach'; end if;
  if public.st_v8_scim_claim(true)->>'state' is distinct from 'none' then raise exception 'Attached identity could be claimed twice'; end if;
  reset role;
  if not exists(select 1 from public.st_v6_workspace_group_members m where m.workspace_id=tenant_id
      and m.group_id=group_resource and m.user_id=starter_id) then raise exception 'Pending group was not materialized'; end if;
  update sectalk_private.st_v8_scim_keys set used=120 where workspace=tenant_id;
  set local role service_role;
  proof:=public.st_v8_scim_request(token_digest,'Users','GET',null);
  if proof->>'status' is distinct from '429' then raise exception 'Rate cap did not fail closed: %', proof; end if;
  reset role;
  update sectalk_private.st_v7_org_domains set verified_at=null where workspace=tenant_id;
  set local role service_role;
  proof:=public.st_v8_scim_request(token_digest,'Users','GET',null);
  if proof->>'status' is distinct from '401' then raise exception 'Unverified domain retained SCIM key use: %', proof; end if;
  reset role;
end $$;
select 'passed: scoped credentials, pending groups, confirmed-link enrollment, impostor denial, durable offboarding and rate limits' as result;
rollback;
