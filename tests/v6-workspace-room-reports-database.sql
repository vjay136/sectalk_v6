begin;
insert into auth.users(id,email)
select ('7fa00000-0000-4000-8000-00000000000'||n)::uuid,'room-review-'||n||'@example.invalid' from generate_series(1,9) n;
insert into public.st_profiles(id,handle,name)
select ('7fa00000-0000-4000-8000-00000000000'||n)::uuid,'room_review_'||n,'Room review fixture' from generate_series(1,9) n;
insert into sectalk_private.staff values('7fa00000-0000-4000-8000-000000000001'),
 ('7fa00000-0000-4000-8000-000000000008'),('7fa00000-0000-4000-8000-000000000009');
insert into sectalk_private.st_v6_case_on_call values
 ('7fa00000-0000-4000-8000-000000000001',1,now(),now()+interval '1 hour'),
 ('7fa00000-0000-4000-8000-000000000008',2,now(),now()+interval '1 hour'),
 ('7fa00000-0000-4000-8000-000000000009',3,now(),now()+interval '1 hour');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
select ('7fa10000-0000-4000-8000-00000000000'||n)::uuid,('7fa00000-0000-4000-8000-00000000000'||n)::uuid,
  'totp','verified',now(),now() from generate_series(1,9) n;
insert into auth.sessions(id,user_id,aal,factor_id)
select ('7fa20000-0000-4000-8000-00000000000'||n)::uuid,('7fa00000-0000-4000-8000-00000000000'||n)::uuid,
  'aal2',('7fa10000-0000-4000-8000-00000000000'||n)::uuid from generate_series(1,9) n;
create function pg_temp.room_actor(n integer,assurance text default 'aal2') returns void language sql as $$
 select set_config('request.jwt.claims',jsonb_build_object('sub','7fa00000-0000-4000-8000-00000000000'||n,
  'aal',assurance,'session_id','7fa20000-0000-4000-8000-00000000000'||n)::text,true)::text::void
$$;

do $$
declare
 workspace uuid;
 other_workspace uuid;
 room constant uuid:='7fa30000-0000-4000-8000-000000000001';
 other_room constant uuid:='7fa30000-0000-4000-8000-000000000002';
 private_post constant uuid:='7fa40000-0000-4000-8000-000000000001';
 shared_post constant uuid:='7fa40000-0000-4000-8000-000000000002';
 removed_post constant uuid:='7fa40000-0000-4000-8000-000000000003';
 foreign_post constant uuid:='7fa40000-0000-4000-8000-000000000004';
 personal constant uuid:='7fa50000-0000-4000-8000-000000000001';
 private_report uuid;
 shared_report uuid;
 snapshot jsonb;
 n integer;
begin
 set local role authenticated;
 perform pg_temp.room_actor(2);
 workspace:=public.st_v2_create_workspace('Primary room review fixture');
 perform public.st_v6_room_create(room,workspace,'Scoped room review','private','blank');
 perform pg_temp.room_actor(3);
 other_workspace:=public.st_v2_create_workspace('Other room review fixture');
 perform public.st_v6_room_create(other_room,other_workspace,'Other review room','private','blank');
 reset role;
 insert into public.st_v2_members(workspace_id,user_id,role) values
   (workspace,'7fa00000-0000-4000-8000-000000000004','member'),
   (workspace,'7fa00000-0000-4000-8000-000000000005','member'),
   (workspace,'7fa00000-0000-4000-8000-000000000006','admin'),
   (workspace,'7fa00000-0000-4000-8000-000000000007','admin');
 insert into public.st_v6_room_members(room_id,user_id,role) values
   (room,'7fa00000-0000-4000-8000-000000000004','member'),
   (room,'7fa00000-0000-4000-8000-000000000005','member'),
   (room,'7fa00000-0000-4000-8000-000000000007','moderator');
 update public.st_v2_members set suspended_at=now()
   where workspace_id=workspace and user_id='7fa00000-0000-4000-8000-000000000007';
 insert into public.st_v6_room_posts(room_id,id,sender,body,kind,removed_at) values
   (room,private_post,'7fa00000-0000-4000-8000-000000000005','Platform only post','message',null),
   (room,shared_post,'7fa00000-0000-4000-8000-000000000005','Scoped shared post','message',null),
   (room,removed_post,'7fa00000-0000-4000-8000-000000000005','Message removed','message',now()),
   (other_room,foreign_post,'7fa00000-0000-4000-8000-000000000003','Foreign post','message',null);
 insert into public.st_chats(id,member_a,member_b,requester,status) values
   ('7fa60000-0000-4000-8000-000000000001','7fa00000-0000-4000-8000-000000000004',
    '7fa00000-0000-4000-8000-000000000005','7fa00000-0000-4000-8000-000000000004','accepted');
 insert into public.st_reports(id,reporter,subject,chat_id,category,details) values
   (personal,'7fa00000-0000-4000-8000-000000000004','7fa00000-0000-4000-8000-000000000005',
    '7fa60000-0000-4000-8000-000000000001','threat','Private direct report');

 set local role authenticated;
 perform pg_temp.room_actor(4,'aal1');
 private_report:=public.st_v6_submit_room_report(room,private_post,'harassment','Private report details',false);
 shared_report:=public.st_v6_submit_room_report(room,shared_post,'threat','Private shared-case details',true);
 if public.st_v6_submit_room_report(room,private_post,'harassment','Private report details',true)<>private_report
 or (select share_with_workspace from public.st_v6_my_room_reports() where id=private_report) then
   raise exception 'Replayed submission changed the original consent'; end if;
 begin perform public.st_v6_submit_room_report(other_room,foreign_post,'harassment','',true);
   raise exception 'Report from a hidden room accepted'; exception when insufficient_privilege then null; end;
 begin perform public.st_v6_submit_room_report(room,foreign_post,'harassment','',true);
   raise exception 'Post from another room accepted'; exception when insufficient_privilege then null; end;
 begin perform public.st_v6_submit_room_report(room,removed_post,'harassment','',true);
   raise exception 'Removed post accepted'; exception when insufficient_privilege then null; end;
 begin perform public.st_v6_room_report_queue('workspace'); raise exception 'Regular member accessed review';
 exception when insufficient_privilege then null; end;

 perform pg_temp.room_actor(2);
 if public.st_v6_room_report_queue('workspace')<>'[]' then raise exception 'Pre-handoff workspace disclosure'; end if;
 perform pg_temp.room_actor(1);
 begin perform public.st_v6_review_room_report(personal,'platform','route','Test',0::smallint);
   raise exception 'Direct chat entered workspace route'; exception when insufficient_privilege then null; end;
 begin perform public.st_v6_review_room_report(private_report,'platform','route','Test',0::smallint);
   raise exception 'Handoff without consent'; exception when insufficient_privilege then null; end;
 perform public.st_v6_review_room_report(shared_report,'platform','route','Start L1',0::smallint);
 begin perform public.st_v6_review_room_report(shared_report,'platform','resolved','Skip stages');
   raise exception 'L1 decided before the required stages'; exception when insufficient_privilege then null; end;
 begin perform public.st_v6_review_room_report(shared_report,'platform','route','Stale attempt',0::smallint);
   raise exception 'Stale initial route advanced'; exception when serialization_failure then null; end;
 begin perform public.st_v6_review_room_report(shared_report,'platform','route','Premature attempt',1::smallint);
   raise exception 'Unacknowledged stage advanced'; exception when invalid_parameter_value then null; end;
 perform public.st_v6_review_room_report(shared_report,'platform','acknowledge','Accept L1',1::smallint);
 perform public.st_v6_review_room_report(shared_report,'platform','route','Assign L2',1::smallint);
 perform pg_temp.room_actor(8);
 perform public.st_v6_review_room_report(shared_report,'platform','acknowledge','Accept L2',2::smallint);
 perform public.st_v6_review_room_report(shared_report,'platform','route','Scoped handoff',2::smallint);
 perform pg_temp.room_actor(2,'aal1');
 if public.st_v6_room_report_review_access()<>'mfa' then raise exception 'Expected MFA gate'; end if;
 begin perform public.st_v6_room_report_queue('workspace'); raise exception 'AAL1 owner accessed review';
 exception when insufficient_privilege then null; end;
 foreach n in array array[3,6] loop
   perform pg_temp.room_actor(n);
   if public.st_v6_room_report_queue('workspace')<>'[]' then raise exception 'Unscoped admin observed the handoff'; end if;
   begin perform public.st_v6_review_room_report(shared_report,'workspace','resolved','Cross-scope attempt');
     raise exception 'Unscoped owner changed the report'; exception when insufficient_privilege then null; end;
 end loop;
 perform pg_temp.room_actor(7);
 begin perform public.st_v6_room_report_queue('workspace'); raise exception 'Suspended admin accessed review';
 exception when insufficient_privilege then null; end;
 perform pg_temp.room_actor(2);
 snapshot:=public.st_v6_room_report_queue('workspace');
 if jsonb_array_length(snapshot)<>1 or snapshot#>>'{0,id}' is distinct from shared_report::text
 or snapshot#>>'{0,evidence}' is distinct from 'Scoped shared post'
 or snapshot::text like '%Private shared-case details%' or snapshot::text like '%7fa00000-%'
 or snapshot->0 ? 'details' then raise exception 'Bad workspace report projection: %',snapshot; end if;
 reset role;
 delete from public.st_v6_room_members where room_id=room and user_id='7fa00000-0000-4000-8000-000000000002';
 set local role authenticated;
 if public.st_v6_room_report_queue('workspace')<>'[]' then raise exception 'Room scope revocation did not hide the handoff'; end if;
 begin perform public.st_v6_review_room_report(shared_report,'workspace','resolved','Previously scoped decision');
   raise exception 'Stale room scope authorized a decision'; exception when insufficient_privilege then null; end;
 reset role;
 insert into public.st_v6_room_members(room_id,user_id,role) values
   (room,'7fa00000-0000-4000-8000-000000000002','owner');
 set local role authenticated;
 perform public.st_v6_review_room_report(shared_report,'workspace','acknowledge','Accept workspace handoff',3::smallint);
 begin perform public.st_v6_review_room_report(shared_report,'workspace','resolved','Skip Platform');
   raise exception 'Workspace review skipped Platform'; exception when insufficient_privilege then null; end;
 perform public.st_v6_review_room_report(shared_report,'workspace','route','Return to platform',3::smallint);
 if public.st_v6_room_report_queue('workspace')<>'[]' then raise exception 'Workspace retained access after return'; end if;
 perform pg_temp.room_actor(9);
 perform public.st_v6_review_room_report(shared_report,'platform','acknowledge','Accept Platform',4::smallint);
 perform public.st_v6_review_room_report(shared_report,'platform','resolved','Scope-matched review');
 perform pg_temp.room_actor(4,'aal1');
 if (select status from public.st_v6_my_room_reports() where id=shared_report) is distinct from 'resolved' then
   raise exception 'Reporter did not see the room case decision'; end if;
 perform pg_temp.room_actor(5);
 if exists(select from public.st_v6_my_room_reports()) then raise exception 'Subject saw reporter status'; end if;
 reset role;
 if (select count(*) from sectalk_private.st_v6_room_report_audit where report_id=shared_report)<>9 then
   raise exception 'Routing and decision were not audited once each'; end if;
 if (select count(*) from realtime.messages where event='workspace_room_report'
   and topic='st:account:7fa00000-0000-4000-8000-000000000002' and private and payload-'id'='{}')<>1
 or exists (select from realtime.messages where event='workspace_room_report'
   and topic in ('st:account:7fa00000-0000-4000-8000-000000000003',
     'st:account:7fa00000-0000-4000-8000-000000000006','st:account:7fa00000-0000-4000-8000-000000000007')) then
   raise exception 'Unexpected private room handoff delivery'; end if;
 if (select array_agg(stage order by stage) from sectalk_private.st_v6_room_report_stages
     where report_id=shared_report and acknowledged_at is not null and action_by>acknowledge_by)
   is distinct from array[1,2,3,4]::smallint[] then raise exception 'Missing ordered assignments or SLA clocks'; end if;
end $$;
rollback;
