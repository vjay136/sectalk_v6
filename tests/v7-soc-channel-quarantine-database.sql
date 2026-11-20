begin;

create function pg_temp.soc_channel_actor(id uuid,assurance text default 'aal2')
returns void language sql security definer set search_path='' as $$
  select set_config('request.jwt.claims',jsonb_build_object('sub',id,'aal',assurance,
    'session_id',(select s.id from auth.sessions s where s.user_id=$1 limit 1))::text,true)::text::void
$$;

do $$
declare
  platform uuid:=gen_random_uuid();
  requester uuid:=gen_random_uuid();
  approver uuid:=gen_random_uuid();
  sender_id uuid:=gen_random_uuid();
  reporter uuid:=gen_random_uuid();
  outsider uuid:=gen_random_uuid();
  actor uuid;
  active_session uuid;
  factor uuid;
  ws uuid;
  foreign_ws uuid;
  channel uuid;
  source_post uuid:=gen_random_uuid();
  neighbor uuid:=gen_random_uuid();
  report uuid;
  unconsented uuid;
  request_key uuid;
  hold_key uuid:=gen_random_uuid();
  original_moment timestamptz;
  readout jsonb;
  body_text constant text:='Original consented channel text';
  why constant text:='Reviewed the exact consented channel post';
begin
  foreach actor in array array[platform,requester,approver,sender_id,reporter,outsider] loop
    active_session:=gen_random_uuid(); factor:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'chqa_'||left(actor::text,8),'Channel quarantine QA');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(active_session,actor,'aal2',factor);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),active_session,'totp',now(),now());
  end loop;
  insert into sectalk_private.staff values(platform);
  perform pg_temp.soc_channel_actor(requester);
  ws:=public.st_v2_create_workspace('SOC channel fixture');
  channel:=public.st_v2_create_channel(ws,'scope-fixture');
  perform pg_temp.soc_channel_actor(outsider);
  foreign_ws:=public.st_v2_create_workspace('Outside channel fixture');
  insert into public.st_v2_members(workspace_id,user_id,role) values
    (ws,approver,'admin'),(ws,sender_id,'member'),(ws,reporter,'member');
  insert into sectalk_private.st_v7_soc_response_grants(actor,action,workspace,role) values
    (requester,'quarantine_channel_post',ws,'requester'),(requester,'quarantine_channel_post',ws,'approver'),
    (approver,'quarantine_channel_post',ws,'approver'),(outsider,'quarantine_channel_post',foreign_ws,'approver');

  perform pg_temp.soc_channel_actor(sender_id);
  perform public.st_v2_post(channel,source_post,body_text);
  perform public.st_v2_post(channel,neighbor,'Unrelated channel post');
  select p.created_at into original_moment from public.st_v2_posts p where p.id=source_post;
  perform pg_temp.soc_channel_actor(reporter);
  set local role authenticated;
  report:=public.st_v7_submit_channel_report(channel,source_post,'spam','Private report note',true,true);
  unconsented:=public.st_v7_submit_channel_report(channel,neighbor,'other','',true,false);
  perform pg_temp.soc_channel_actor(requester);
  begin
    perform public.st_v7_request_soc_response('quarantine_channel_post',ws,report,null,null,why);
    raise exception 'An unhanded report was actionable';
  exception when insufficient_privilege then null; end;
  perform pg_temp.soc_channel_actor(platform);
  perform public.st_v7_review_channel_report(report,'platform','handoff',why);
  perform pg_temp.soc_channel_actor(requester);
  begin
    perform public.st_v7_request_soc_response('quarantine_channel_post',ws,unconsented,null,null,why);
    raise exception 'A nonconsented report was actionable';
  exception when insufficient_privilege then null; end;
  request_key:=public.st_v7_request_soc_response('quarantine_channel_post',ws,report,null,null,why);
  begin
    perform public.st_v7_decide_soc_response(request_key,true,why);
    raise exception 'Self-approval executed';
  exception when insufficient_privilege then null; end;
  perform pg_temp.soc_channel_actor(outsider);
  if public.st_v7_soc_response_queue()<>'[]'::jsonb then raise exception 'Outsider saw case metadata'; end if;
  begin
    perform public.st_v7_decide_soc_response(request_key,true,why);
    raise exception 'Cross-tenant approval executed';
  exception when insufficient_privilege then null; end;
  reset role;

  update public.st_v2_posts set created_at=original_moment+interval '1 second' where id=source_post;
  perform pg_temp.soc_channel_actor(approver);
  set local role authenticated;
  begin
    perform public.st_v7_decide_soc_response(request_key,true,why);
    raise exception 'Stale revision executed';
  exception when sqlstate 'PT409' then null; end;
  reset role;
  update public.st_v2_posts set created_at=original_moment where id=source_post;
  update public.st_v2_channels set visibility='private' where id=channel;
  set local role authenticated;
  if public.st_v7_soc_response_queue()<>'[]'::jsonb then raise exception 'Removed channel access did not clear queue'; end if;
  begin
    perform public.st_v7_decide_soc_response(request_key,true,why);
    raise exception 'Revoked private channel access accepted';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into sectalk_private.st_v6_channel_members(channel_id,user_id)
    values(channel,approver),(channel,sender_id),(channel,reporter) on conflict do nothing;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_key,ws,sender_id,'Fixture mandatory preservation hold',requester);

  set local role authenticated;
  if public.st_v7_decide_soc_response(request_key,true,why)<>'executed'
    or public.st_v7_decide_soc_response(request_key,true,why)<>'executed' then raise exception 'Approval did not execute idempotently'; end if;
  readout:=public.st_v7_channel_report_queue('workspace');
  if not exists(select 1 from jsonb_array_elements(readout) r where r->>'id'=report::text and r->>'evidence'=body_text) then
    raise exception 'Authorized reviewer lost the consented evidence'; end if;
  perform pg_temp.soc_channel_actor(reporter);
  if not exists(select 1 from public.st_v2_posts p where p.id=source_post and p.body='Message quarantined' and p.quarantined_at is not null)
    or not exists(select 1 from public.st_v2_posts p where p.id=neighbor and p.body='Unrelated channel post' and p.quarantined_at is null) then
    raise exception 'Ordinary channel reads exposed the body or lost its neighbor'; end if;
  readout:=public.st_v7_my_channel_reports();
  if not exists(select 1 from jsonb_array_elements(readout) r, jsonb_array_elements(r->'timeline') a
    where r->>'id'=report::text and a->>'action'='quarantined')
    or readout::text like '%'||why||'%' or readout::text like '%'||body_text||'%' then
    raise exception 'Reporter timeline lost the safe summary or exposed private content'; end if;
  if public.st_v7_submit_channel_report(channel,source_post,'spam','',true,false) is distinct from report then
    raise exception 'Existing reporter receipt was lost'; end if;
  reset role;
  if not exists(select 1 from sectalk_private.st_v6_preserved_post_versions v
    join vault.decrypted_secrets k on k.name='sectalk_v6_hold_archive_key'
    where v.hold_id=hold_key and v.source='channel' and v.post_id=source_post
      and extensions.pgp_sym_decrypt(v.encrypted_body,k.decrypted_secret)=body_text) then
    raise exception 'Existing legal-hold archival lost the original post'; end if;
  if (select count(*) from sectalk_private.st_v7_channel_report_actions a where a.report_id=report and a.action='quarantined')<>1 then
    raise exception 'Approval wrote duplicate channel audit actions'; end if;
end $$;

rollback;
