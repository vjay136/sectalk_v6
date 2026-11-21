begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); reporter_id uuid:=gen_random_uuid(); subject_id uuid:=gen_random_uuid();
  platform_id uuid:=gen_random_uuid(); account uuid; native uuid; factor uuid;
  signed_session uuid:=gen_random_uuid(); space uuid; channel uuid; post_id uuid:=gen_random_uuid();
  send_ticket uuid; capture_ticket uuid; report_id uuid;
  domain text:='entry-channel-report.example.invalid'; provider text:='custom:entry-channel-reports-qa';
  evidence constant text:='Synthetic managed report evidence';
  actors jsonb:='{}';
  packet jsonb:=jsonb_build_object('body','cHJvdGVjdGVkLWZpeHR1cmU','nonce',repeat('n',16),'tag',repeat('t',22),
    'wrapped_dek',repeat('k',80));
begin
  foreach account in array array[owner_id,reporter_id,subject_id,platform_id] loop
    native:=gen_random_uuid(); factor:=gen_random_uuid();
    insert into auth.users(id,email,email_confirmed_at) values(account,account||'@'||domain,now());
    insert into public.st_profiles(id,handle,name) values(account,'reportsqa_'||left(account::text,8),'Channel report QA');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor,account,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(native,account,'aal2',factor);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),native,'totp',now(),now());
    actors:=actors||jsonb_build_object(account::text,
      jsonb_build_object('sub',account,'session_id',native,'role','authenticated','aal','aal2'));
    if account=owner_id then
      insert into auth.sessions(id,user_id,aal,factor_id) values(signed_session,owner_id,'aal2',factor);
      insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
        values(gen_random_uuid(),signed_session,'totp',now(),now());
    end if;
  end loop;
  insert into sectalk_private.staff values(platform_id);
  insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values(owner_id,'enterprise','active',now()+interval '1 day');
  insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
    values('oidc',provider,'Channel report fixture','fixture-client','synthetic-placeholder',
      'https://provider.example.invalid',array['openid','email'],true);
  insert into sectalk_private.st_v7_oidc_domain_approvals values(domain,provider);
  set local role authenticated;
  perform set_config('request.jwt.claims',(actors->owner_id::text)::text,true);
  space:=public.st_v2_create_workspace('Managed channel report fixture');
  perform public.st_v8_set_channel_mode_policy(space,true);
  channel:=public.st_v2_create_channel(space,'managed-report-fixture');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(space,reporter_id,'member'),(space,subject_id,'member');
  insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values(space,domain,now());
  set local role authenticated;
  perform set_config('request.jwt.claims',(actors->subject_id::text)::text,true);
  send_ticket:=(public.st_v8_managed_channel_ticket(channel,'send',post_id,'Synthetic test post')->>'ticket')::uuid;
  reset role;
  if public.st_v8_channel_write_key(send_ticket,subject_id,repeat('a',80))->>'version' is distinct from '1'
    or public.st_v8_finish_managed_channel_send(send_ticket,subject_id,1,packet) is not true then
    raise exception 'Could not create managed post'; end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',(actors->reporter_id::text)::text,true);
  capture_ticket:=(public.st_v8_begin_managed_channel_report(channel,post_id,'spam','Private reporter note',true,true)->>'ticket')::uuid;
  reset role;
  report_id:=public.st_v8_finish_managed_channel_report(capture_ticket,reporter_id,evidence);
  if report_id is null then raise exception 'Could not capture the managed report'; end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',(actors->owner_id::text)::text,true);
  if (public.st_v7_workspace_sso_settings(space,'save',domain,'oidc',false)->'setup') is null then
    raise exception 'Workspace provider could not be saved'; end if;
  reset role;
  insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
    values(signed_session,space,owner_id,'oidc',provider);
  set local role authenticated;
  if public.st_v8_workspace_entry_policy(space,true)->>'required' is distinct from 'true' then
    raise exception 'Workspace SSO could not be required'; end if;
  perform set_config('request.jwt.claims',(actors->platform_id::text)::text,true);
  if public.st_v8_view_managed_channel_report(report_id,'platform') is distinct from evidence
    or not (public.st_v7_channel_report_queue('platform') @> jsonb_build_array(jsonb_build_object('id',report_id))) then
    raise exception 'Platform lost independent queue or evidence access'; end if;
  perform public.st_v7_review_channel_report(report_id,'platform','handoff','Consented workspace review');
  perform set_config('request.jwt.claims',(actors->owner_id::text)::text,true);
  if public.st_v7_channel_report_queue('workspace') @> jsonb_build_array(jsonb_build_object('id',report_id)) then
    raise exception 'Password owner saw a protected channel case'; end if;
  begin
    perform public.st_v8_view_managed_channel_report(report_id,'workspace');
    raise exception 'Password owner read managed evidence';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_review_channel_report(report_id,'workspace','resolved','Password decision');
    raise exception 'Password owner resolved a protected channel case';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',((actors->owner_id::text)||jsonb_build_object('session_id',signed_session))::text,true);
  if not (public.st_v7_channel_report_queue('workspace') @> jsonb_build_array(
      jsonb_build_object('id',report_id,'managed',true,'evidence',null,'details','')))
    or public.st_v8_view_managed_channel_report(report_id,'workspace') is distinct from evidence then
    raise exception 'Signed reviewer lost authorized evidence or received private details'; end if;
  perform public.st_v7_review_channel_report(report_id,'workspace','resolved','Verified signed decision');
  perform set_config('request.jwt.claims',(actors->reporter_id::text)::text,true);
  if not (public.st_v7_my_channel_reports() @> jsonb_build_array(jsonb_build_object('id',report_id,'state','resolved')))
    or public.st_v7_my_channel_reports()::text like '%Verified signed decision%' then
    raise exception 'Reporter status changed or leaked a private decision'; end if;
  reset role;
  update auth.custom_oauth_providers set enabled=false where identifier=provider;
  set local role authenticated;
  perform set_config('request.jwt.claims',((actors->owner_id::text)||jsonb_build_object('session_id',signed_session))::text,true);
  if public.st_v7_channel_report_queue('workspace') @> jsonb_build_array(jsonb_build_object('id',report_id)) then
    raise exception 'Stale provider retained access to the report'; end if;
  perform set_config('request.jwt.claims',(actors->owner_id::text)::text,true);
  if public.st_v8_workspace_entry_policy(space,false)->>'required' is distinct from 'false' then
    raise exception 'Verified owner could not restore standard access'; end if;
  if public.st_v8_view_managed_channel_report(report_id,'workspace') is distinct from evidence then
    raise exception 'Verified owner recovery did not restore managed evidence'; end if;
end $$;
select 'passed: workspace entry SSO for channel decisions and managed evidence, Platform handoff, reporter status, and owner recovery' as result;
rollback;
