begin;

insert into auth.users(id,email)
select ('a1190000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'emergency-sql-'||n||'@example.invalid'
from generate_series(1,4) n;
insert into public.st_profiles(id,handle,name)
select ('a1190000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'emergency_sql_'||n,'Emergency SQL fixture'
from generate_series(1,4) n;
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
select ('a1190001-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('a1190000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'totp','verified',now(),now()
from generate_series(1,4) n;
insert into auth.sessions(id,user_id,aal,factor_id)
select ('a1190002-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('a1190000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'aal2',
  ('a1190001-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid
from generate_series(1,4) n;
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
select gen_random_uuid(),('a1190002-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'totp',now(),now()
from generate_series(1,4) n;
insert into sectalk_private.staff(user_id) values
 ('a1190000-0000-4000-8000-000000000002'),('a1190000-0000-4000-8000-000000000003');
insert into sectalk_private.st_v6_tenant_operators(account_id) values
 ('a1190000-0000-4000-8000-000000000002'),('a1190000-0000-4000-8000-000000000003');

do $$
declare
  owner_id constant uuid:='a1190000-0000-4000-8000-000000000001';
  operator_id constant uuid:='a1190000-0000-4000-8000-000000000002';
  outsider constant uuid:='a1190000-0000-4000-8000-000000000003';
  reporter constant uuid:='a1190000-0000-4000-8000-000000000004';
  owner_claims constant text:=jsonb_build_object('sub',owner_id,'aal','aal2','session_id','a1190002-0000-4000-8000-000000000001')::text;
  operator_claims constant text:=jsonb_build_object('sub',operator_id,'aal','aal2','session_id','a1190002-0000-4000-8000-000000000002')::text;
  outsider_claims constant text:=jsonb_build_object('sub',outsider,'aal','aal2','session_id','a1190002-0000-4000-8000-000000000003')::text;
  workspace uuid;
  room uuid:=gen_random_uuid();
  post uuid:=gen_random_uuid();
  report uuid;
  no_consent uuid;
  grant_id uuid;
  later_grant uuid;
  notice_id uuid;
  value text;
begin
  if has_table_privilege('authenticated','sectalk_private.st_v6_break_glass_requests','select')
    or has_table_privilege('authenticated','sectalk_private.st_v6_break_glass_audit','delete')
    or has_function_privilege('anon','public.st_v6_read_break_glass(uuid)','execute') then
    raise exception 'Emergency access is misconfigured';
  end if;
  perform set_config('request.jwt.claims',owner_claims,true);
  workspace:=public.st_v2_create_workspace('Emergency SQL fixture');
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,reporter,'member');
  perform public.st_v6_room_create(room,workspace,'Protected room','public','blank');
  perform public.st_v6_room_post(room,post,'Original approved case source');
  insert into sectalk_private.st_v6_room_reports(workspace_id,room_id,post_id,reporter,subject,category,details,share_with_workspace)
  values(workspace,room,post,reporter,owner_id,'threat','Confidential reporter note',true) returning id into report;
  insert into sectalk_private.st_v6_room_reports(workspace_id,room_id,post_id,reporter,subject,category,details,share_with_workspace)
  values(workspace,room,post,outsider,owner_id,'threat','Platform-only reporter note',false) returning id into no_consent;

  perform set_config('request.jwt.claims',operator_claims,true);
  begin
    perform public.st_v6_request_break_glass(no_consent,'This case opted out of workspace sharing.');
    raise exception 'Reporter opt-out was ignored';
  exception when insufficient_privilege then null; end;
  grant_id:=public.st_v6_request_break_glass(report,'Urgent safety issue needs one view of this post.');
  begin
    perform public.st_v6_review_break_glass(grant_id,'approved','Operator self approval is forbidden.');
    raise exception 'Self approval was accepted';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_read_break_glass(grant_id);
    raise exception 'Pending request returned plaintext';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',outsider_claims,true);
  if public.st_v6_break_glass_list(null)<>'[]'::jsonb then raise exception 'Operator could view another operator request'; end if;
  begin
    perform public.st_v6_break_glass_list(workspace);
    raise exception 'Unrelated staff could list tenant review cases';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',owner_claims,true);
  perform public.st_v6_review_break_glass(grant_id,'approved','Verify the exact approved evidence revision.');
  update public.st_v6_room_posts set body='Changed evidence',edited_at=clock_timestamp() where room_id=room and id=post;
  perform set_config('request.jwt.claims',operator_claims,true);
  begin
    perform public.st_v6_read_break_glass(grant_id);
    raise exception 'Edited evidence bypassed approval';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',owner_claims,true);
  perform public.st_v6_review_break_glass(grant_id,'revoked','The source changed after the first approval.');

  perform set_config('request.jwt.claims',operator_claims,true);
  later_grant:=public.st_v6_request_break_glass(report,'The updated source now requires a separate approval.');
  perform set_config('request.jwt.claims',owner_claims,true);
  perform public.st_v6_review_break_glass(later_grant,'approved','Approve the revised source for one review.');
  update sectalk_private.st_v6_break_glass_requests set grant_expires_at=now()-interval '1 second' where id=later_grant;
  perform set_config('request.jwt.claims',operator_claims,true);
  begin
    perform public.st_v6_read_break_glass(later_grant);
    raise exception 'Expired approval returned evidence';
  exception when insufficient_privilege then null; end;

  later_grant:=public.st_v6_request_break_glass(report,'A current investigation still needs that exact revision.');
  perform set_config('request.jwt.claims',owner_claims,true);
  perform public.st_v6_review_break_glass(later_grant,'approved','Approve this exact source for one review.');
  update public.st_v6_rooms set classification='restricted' where id=room;
  perform set_config('request.jwt.claims',operator_claims,true);
  begin
    perform public.st_v6_read_break_glass(later_grant);
    raise exception 'A restricted transition returned evidence';
  exception when insufficient_privilege then null; end;
  update public.st_v6_rooms set classification='internal' where id=room;
  value:=public.st_v6_read_break_glass(later_grant);
  if value is distinct from 'Changed evidence' then raise exception 'Wrong approved evidence returned'; end if;
  begin
    perform public.st_v6_read_break_glass(later_grant);
    raise exception 'One-time grant replay succeeded';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',owner_claims,true);
  perform public.st_v6_review_break_glass(later_grant,'closed','Review the evidence access and close the case.');
  if (select array_agg(a.action order by a.id) from sectalk_private.st_v6_break_glass_audit a where a.grant_id=later_grant)
      is distinct from array['requested','approved','accessed','closed']
    or public.st_v6_break_glass_list(workspace)::text like '%Confidential reporter note%' then
    raise exception 'Audit history is incomplete or disclosed reporter notes';
  end if;
  select n.id into notice_id from public.st_v6_my_emergency_notices() n where n.stage='accessed';
  if notice_id is null or (select count(*) from public.st_v6_my_emergency_notices() n where n.stage='closed')<>1
    or has_table_privilege('authenticated','sectalk_private.st_v6_emergency_notices','select') then
    raise exception 'Customer notice history did not match the actual access';
  end if;
  perform set_config('request.jwt.claims',operator_claims,true);
  perform public.st_v6_read_emergency_notice(notice_id);
  if exists(select from public.st_v6_my_emergency_notices()) then raise exception 'Operator saw tenant customer notices'; end if;
  perform set_config('request.jwt.claims',owner_claims,true);
  if exists(select from public.st_v6_my_emergency_notices() n where n.id=notice_id and n.read_at is not null) then
    raise exception 'Unrelated operator acknowledged the customer notice';
  end if;
  perform public.st_v6_read_emergency_notice(notice_id);
  if not exists(select from public.st_v6_my_emergency_notices() n where n.id=notice_id and n.read_at is not null) then
    raise exception 'Current tenant owner could not acknowledge the notice';
  end if;
end $$;

select 'passed: emergency dual control, expiry, revocation, reporter consent, exact source and one-time evidence' as result;
rollback;
