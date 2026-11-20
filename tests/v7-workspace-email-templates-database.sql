begin;
do $$
declare
  owner_id uuid:=gen_random_uuid(); admin_id uuid:=gen_random_uuid(); peer_id uuid:=gen_random_uuid();
  owner_session uuid:=gen_random_uuid(); admin_session uuid:=gen_random_uuid(); peer_session uuid:=gen_random_uuid();
  ws uuid; foreign_ws uuid; settings jsonb;
  owner_claims text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'aal','aal1','role','authenticated')::text;
  admin_claims text:=jsonb_build_object('sub',admin_id,'session_id',admin_session,'aal','aal1','role','authenticated')::text;
  peer_claims text:=jsonb_build_object('sub',peer_id,'session_id',peer_session,'aal','aal1','role','authenticated')::text;
begin
  insert into auth.users(id,email) values(owner_id,'email-template-owner@example.invalid'),
    (admin_id,'email-template-admin@example.invalid'),(peer_id,'email-template-peer@example.invalid');
  insert into public.st_profiles(id,handle,name) values(owner_id,'mail_template_owner','Mail owner'),
    (admin_id,'mail_template_admin','Mail admin'),(peer_id,'mail_template_peer','Mail peer');
  insert into auth.sessions(id,user_id,aal) values(owner_session,owner_id,'aal1'),(admin_session,admin_id,'aal1'),
    (peer_session,peer_id,'aal1');
  if has_function_privilege('anon','public.st_v7_workspace_email_template(uuid,text,text,text,integer)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v7_workspace_email_versions','select') then
    raise exception 'Template data exposed outside authorized RPCs';
  end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claims,true);
  ws:=public.st_v2_create_workspace('Scoped email design');
  begin
    perform public.st_v7_workspace_email_template(ws,'publish','Denied','Denied');
    raise exception 'Stale owner could publish';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',peer_claims,true);
  foreign_ws:=public.st_v2_create_workspace('Independent email design');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(ws,admin_id,'admin'),(ws,peer_id,'member');
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
    (gen_random_uuid(),owner_session,'password',now(),now()),(gen_random_uuid(),admin_session,'password',now(),now());
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claims,true);
  begin
    perform public.st_v7_workspace_email_template(ws,'publish',E'Hello\r\nBCC: external@example.invalid','Denied');
    raise exception 'Mail header control characters accepted';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_v7_workspace_email_template(ws,'publish','Denied','Visit https://external.example.invalid/{{recipient}}');
    raise exception 'Disallowed variables and authored URLs accepted';
  exception when invalid_parameter_value then null; end;
  settings:=public.st_v7_workspace_email_template(ws,'publish','Join {{organization}}','First version');
  if settings->>'active'<>'1' then raise exception 'Initial publish failed'; end if;
  settings:=public.st_v7_workspace_email_template(ws,'publish','New subject','Second version');
  if settings->>'active'<>'2' or jsonb_array_length(settings->'versions')<>2 then raise exception 'Revision not preserved'; end if;
  if public.st_v7_workspace_email_template(ws,'activate',p_version=>1)->>'active'<>'1' then raise exception 'Rollback failed'; end if;
  perform set_config('request.jwt.claims',admin_claims,true);
  if public.st_v7_workspace_email_template(ws,'delivery')#>>'{template,body}'<>'First version' then
    raise exception 'Delivery did not resolve the active workspace revision';
  end if;
  begin
    perform public.st_v7_workspace_email_template(ws,'activate',p_version=>0);
    raise exception 'Admin modified owner settings';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_workspace_email_template(foreign_ws,'delivery');
    raise exception 'Cross-tenant template read';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',peer_claims,true);
  begin
    perform public.st_v7_workspace_email_template(ws,'delivery');
    raise exception 'Member accessed delivery template';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',owner_claims,true);
  if public.st_v7_workspace_email_template(ws,'activate',p_version=>0)->>'active'<>'0' then raise exception 'Default restore failed'; end if;
  reset role;
  if (select count(*) from public.st_v2_workspace_audit where workspace_id=ws and event in
      ('workspace.email_template_published','workspace.email_template_restored'))<>4 then raise exception 'Missing audit events'; end if;
end
$$;
select 'passed: workspace authorization, strict variables, immutable history, rollback and audit' as result;
rollback;
