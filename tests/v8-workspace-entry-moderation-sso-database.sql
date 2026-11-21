begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); reporter_id uuid:=gen_random_uuid(); subject_id uuid:=gen_random_uuid();
  platform_id uuid:=gen_random_uuid(); platform_factor uuid:=gen_random_uuid(); platform_session uuid:=gen_random_uuid();
  candidate_id uuid:=gen_random_uuid(); candidate_factor uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid(); signed_session uuid:=gen_random_uuid();
  space uuid; other_space uuid; target_room uuid:=gen_random_uuid(); other_room uuid:=gen_random_uuid();
  target_case uuid; other_case uuid; assignment timestamptz;
  provider text:='custom:entry-moderation-rollback'; domain text:='entry-moderation.example.invalid';
  password_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  signed_claim text:=jsonb_build_object('sub',owner_id,'session_id',signed_session,'role','authenticated','aal','aal2')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (owner_id,'owner@entry-moderation.example.invalid',now()),
    (reporter_id,'reporter@entry-moderation.example.invalid',now()),
    (subject_id,'subject@entry-moderation.example.invalid',now()),
    (platform_id,'platform@entry-moderation.example.invalid',now()),
    (candidate_id,'candidate@entry-moderation.example.invalid',now());
  insert into public.st_profiles(id,handle,name) values
    (owner_id,'entry_mod_owner','Moderation owner'),(reporter_id,'entry_mod_reporter','Reporter'),
    (subject_id,'entry_mod_subject','Subject'),(platform_id,'entry_mod_platform','Platform reviewer'),
    (candidate_id,'entry_mod_candidate','Alternate workspace reviewer');
  insert into sectalk_private.staff values(platform_id);
  insert into sectalk_private.st_v6_case_on_call values(platform_id,3,now(),now()+interval '1 hour');
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,owner_id,'totp','verified',now(),now()),
      (platform_factor,platform_id,'totp','verified',now(),now()),
      (candidate_factor,candidate_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id)
    values(owner_session,owner_id,'aal2',factor),(signed_session,owner_id,'aal2',factor),
      (platform_session,platform_id,'aal2',platform_factor);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    select gen_random_uuid(),x,'totp',now(),now() from unnest(array[owner_session,signed_session,platform_session]) x;
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Moderation fixture','fixture-client','synthetic-placeholder',
      'https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);

  set local role authenticated;
  perform set_config('request.jwt.claims',password_claim,true);
  space:=public.st_v2_create_workspace('Protected managed room reports');
  other_space:=public.st_v2_create_workspace('Unprotected managed room reports');
  perform public.st_v8_managed_room_policy(space,true);
  perform public.st_v8_managed_room_policy(other_space,true);
  perform public.st_v6_room_create(target_room,space,'Protected room','private','blank');
  perform public.st_v6_room_create(other_room,other_space,'Unprotected room','private','blank');
  reset role;
  if not exists(select 1 from public.st_v6_rooms where id=target_room and encryption_mode='managed')
    or not exists(select 1 from public.st_v6_rooms where id=other_room and encryption_mode='managed') then
    raise exception 'Fixture requires two managed rooms'; end if;
  insert into public.st_v2_members(workspace_id,user_id,role) values(space,candidate_id,'admin');
  insert into public.st_v6_room_members(room_id,user_id,role) values(target_room,candidate_id,'moderator');
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(space,domain,now());
  insert into sectalk_private.st_v6_room_reports(workspace_id,room_id,post_id,reporter,subject,category,
    details,share_with_workspace,status,handed_off_at)
    values(space,target_room,gen_random_uuid(),reporter_id,subject_id,'spam','Private fixture',true,'reviewing',now())
    returning id into target_case;
  insert into sectalk_private.st_v6_room_reports(workspace_id,room_id,post_id,reporter,subject,category,
    details,share_with_workspace,status,handed_off_at)
    values(other_space,other_room,gen_random_uuid(),reporter_id,subject_id,'spam','Private control',true,'reviewing',now())
    returning id into other_case;
  insert into sectalk_private.st_v6_room_report_stages(report_id,stage,assignee,assigned_at,acknowledge_by,action_by)
    values(target_case,3,owner_id,now(),now()+interval '1 hour',now()+interval '1 day'),
      (other_case,3,owner_id,now(),now()+interval '1 hour',now()+interval '1 day');
  select assigned_at into assignment from sectalk_private.st_v6_room_report_stages where report_id=target_case;

  set local role authenticated;
  if not (public.st_v7_workspace_room_review_queue() @> jsonb_build_array(jsonb_build_object('id',target_case))) then
    raise exception 'Baseline owner session could not access managed review'; end if;
  perform public.st_v7_workspace_sso_settings(space,'save',domain,'oidc',false);
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(signed_session,space,owner_id,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_entry_policy(space,true)->>'required' is distinct from 'true' then
    raise exception 'Could not pin workspace entry SSO'; end if;
  if exists(select 1 from jsonb_array_elements(public.st_v7_workspace_room_review_queue()) row where row->>'id'=target_case::text)
    or exists(select 1 from jsonb_array_elements(public.st_v6_room_report_queue('workspace')) row where row->>'id'=target_case::text)
    or not (public.st_v7_workspace_room_review_queue() @> jsonb_build_array(jsonb_build_object('id',other_case))) then
    raise exception 'Workspace review queue leaked a protected report or removed the opt-out control'; end if;
  begin
    perform public.st_v6_review_room_report(target_case,'workspace','acknowledge','Review from password session',3::smallint);
    raise exception 'Password reviewer acknowledged the protected case';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',signed_claim,true);
  if not (public.st_v7_workspace_room_review_queue() @> jsonb_build_array(jsonb_build_object('id',target_case)))
    or not (public.st_v6_room_report_queue('workspace') @> jsonb_build_array(jsonb_build_object('id',target_case))) then
    raise exception 'Signed reviewer lost an assigned case'; end if;
  perform public.st_v6_review_room_report(target_case,'workspace','acknowledge','Review with workspace SSO',3::smallint);
  if not exists(select 1 from public.st_v7_workspace_room_reviewers(target_case) where id=candidate_id) then
    raise exception 'Signed reviewer lost an eligible alternate reviewer'; end if;
  perform set_config('request.jwt.claims',password_claim,true);
  begin
    perform public.st_v7_workspace_room_reviewers(target_case);
    raise exception 'Password reviewer located assignment candidates';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_workspace_room_case_action(target_case,'resolved','Password review should fail',assignment);
    raise exception 'Password reviewer resolved an acknowledged case';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',platform_id,'session_id',platform_session,'role','authenticated','aal','aal2')::text,true);
  if not (public.st_v6_room_report_queue('platform') @> jsonb_build_array(jsonb_build_object('id',target_case))) then
    raise exception 'Independent Platform queue lost a routed case'; end if;
  perform set_config('request.jwt.claims',signed_claim,true);
  perform public.st_v7_workspace_room_case_action(target_case,'resolved','Signed reviewer closed the case',assignment);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',reporter_id,'role','authenticated','aal','aal1')::text,true);
  if not exists(select 1 from public.st_v7_my_room_report_status() where id=target_case and status='resolved' and decision_scope='workspace') then
    raise exception 'Reporter could not independently track the case'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  perform set_config('request.jwt.claims',signed_claim,true);
  if public.st_v7_workspace_room_review_queue() @> jsonb_build_array(jsonb_build_object('id',target_case)) then
    raise exception 'Disabled provider left protected case access active'; end if;
  perform set_config('request.jwt.claims',password_claim,true);
  if public.st_v8_workspace_entry_policy(space,false)->>'required' is distinct from 'false' then
    raise exception 'Verified owner could not disable entry policy'; end if;
  if not (public.st_v7_workspace_room_review_queue() @> jsonb_build_array(jsonb_build_object('id',target_case,'status','resolved'))) then
    raise exception 'Verified owner recovery did not restore the existing case'; end if;
end
$$;
select 'passed: managed-room case workspace entry SSO, separate Platform and reporter access, and verified owner recovery' as result;
rollback;
