begin;
insert into auth.users(id,email)
select ('7f600000-0000-4000-8000-00000000000'||n)::uuid,'case-'||n||'@example.invalid' from generate_series(1,6) n;
insert into public.st_profiles(id,handle,name)
select id, 'case_'||split_part(split_part(email,'@',1),'-',2),'Case fixture'
from auth.users where email ~ '^case-[1-6]@example\.invalid$';
insert into sectalk_private.staff(user_id)
select id from public.st_profiles where handle in ('case_1','case_2','case_3','case_4','case_5');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
select ('7f610000-0000-4000-8000-00000000000'||n)::uuid, ('7f600000-0000-4000-8000-00000000000'||n)::uuid,
'totp','verified',now(),now() from generate_series(1,6) n;
insert into auth.sessions(id,user_id,aal,factor_id)
select ('7f620000-0000-4000-8000-00000000000'||n)::uuid,('7f600000-0000-4000-8000-00000000000'||n)::uuid,
'aal2',('7f610000-0000-4000-8000-00000000000'||n)::uuid from generate_series(1,6) n;

insert into public.st_chats(id,member_a,member_b,requester,status)
values('7f630000-0000-4000-8000-000000000001','7f600000-0000-4000-8000-000000000004',
 '7f600000-0000-4000-8000-000000000005','7f600000-0000-4000-8000-000000000004','accepted');
insert into public.st_reports(id,reporter,subject,chat_id,category,details,evidence)
select ('7f640000-0000-4000-8000-00000000000'||n)::uuid,c.member_a,c.member_b,c.id,
 'threat','Private reporter details',case when n=1 then 'Private shared excerpt' end
from public.st_chats c cross join generate_series(1,2)n where c.id='7f630000-0000-4000-8000-000000000001';
insert into public.st_messages(id,chat_id,sender,body) values
 ('7f650000-0000-4000-8000-000000000001','7f630000-0000-4000-8000-000000000001',
  '7f600000-0000-4000-8000-000000000004','Shared attachment');
insert into public.st_v5_files(id,chat_id,uploader,message_id,filename,size_bytes) values
 ('7f650000-0000-4000-8000-000000000001','7f630000-0000-4000-8000-000000000001',
  '7f600000-0000-4000-8000-000000000004','7f650000-0000-4000-8000-000000000001','shared.txt',18);
insert into sectalk_private.st_v5_attachment_reports(report_id,file_id) values
 ('7f640000-0000-4000-8000-000000000001','7f650000-0000-4000-8000-000000000001');

create function pg_temp.case_actor(n integer,assurance text default 'aal2', session_n integer default null) returns void
language sql as $$
 select set_config('request.jwt.claims',jsonb_build_object(
  'sub','7f600000-0000-4000-8000-00000000000'||n,'aal',assurance,
  'session_id','7f620000-0000-4000-8000-00000000000'||coalesce(session_n,n))::text,true)::text::void
$$;

do $$
begin
 if has_table_privilege('authenticated','sectalk_private.st_v6_case_notes','update')
 or has_function_privilege('anon','public.st_v6_case_collaboration(uuid)','execute') then
   raise exception 'Case notes can be changed or read directly'; end if;
end $$;
set local role authenticated;
do $$
declare
 report uuid:='7f640000-0000-4000-8000-000000000001';
 other uuid:='7f640000-0000-4000-8000-000000000002';
 note uuid:='7f660000-0000-4000-8000-000000000001';
 content text:='Review @CASE_2, @case_2 @case_4 @case_5 @case_6';
 snapshot jsonb;
 n integer;
begin
 foreach n in array array[1,4,5,6] loop
   perform pg_temp.case_actor(n,case when n=1 then 'aal1' else 'aal2' end);
   begin perform public.st_v6_case_collaboration(report); raise exception 'Unauthorized case read';
   exception when insufficient_privilege then null; end;
   begin perform public.st_v6_append_case_note(report,note,content,true,true); raise exception 'Unauthorized write';
   exception when insufficient_privilege then null; end;
 end loop;
 perform pg_temp.case_actor(1,'aal2',2);
 begin perform public.st_v6_case_collaboration(report); raise exception 'Unbound MFA session allowed';
 exception when insufficient_privilege then null; end;

 perform pg_temp.case_actor(1);
 if public.st_v6_append_case_note(report,note,content,true,true)<>note
 or public.st_v6_append_case_note(report,note,content,true,true)<>note then raise exception 'Retry failed'; end if;
 begin perform public.st_v6_append_case_note(report,note,'Overwrite',true,true); raise exception 'Token mutated note' using errcode='XX000';
 exception when raise_exception then null; end;
 begin perform public.st_v6_append_case_note(report,gen_random_uuid(),'@one @two @three @four @five @six',false,false);
   raise exception 'Mention limit bypassed' using errcode='XX000';
 exception when raise_exception then null; end;
 begin perform public.st_v6_append_case_note(other,note,'Use unrelated evidence',true,true);
   raise exception 'Unshared evidence accepted' using errcode='XX000';
 exception when raise_exception then null; end;
 if exists(select from public.st_v6_case_collaboration_alerts(false)) then raise exception 'Author saw recipient alerts'; end if;
 perform pg_temp.case_actor(3);
 if exists(select from public.st_v6_case_collaboration_alerts(false)) then raise exception 'Unmentioned staff saw alerts'; end if;
 perform public.st_v6_read_case_collaboration_alert(report,note);

 perform pg_temp.case_actor(2);
 if (select count(*) from public.st_v6_case_collaboration_alerts(true) a where a.report_id=report and a.note_id=note)<>1 then
   raise exception 'Recipient missed private deduplicated alert'; end if;
 snapshot:=public.st_v6_case_collaboration(report);
 if snapshot#>>'{notes,0,body}' is distinct from content or jsonb_array_length(snapshot->'notes')<>1
 or snapshot::text like '%Private shared excerpt%' or snapshot::text like '%Private reporter details%'
 or snapshot::text like '%7f600000-%' then raise exception 'Case links leaked context: %',snapshot; end if;
 if public.st_v6_case_note_evidence(report,note,'message') is distinct from '{"excerpt":"Private shared excerpt"}'
 or public.st_v6_case_note_evidence(report,note,'file')->>'filename' is distinct from 'shared.txt' then
   raise exception 'Current staff could not open explicitly shared evidence'; end if;
 begin perform public.st_v6_case_note_evidence(other,note,'file'); raise exception 'Link crossed cases';
 exception when insufficient_privilege then null; end;
 perform public.st_v6_read_case_collaboration_alert(report,note);
 if exists(select from public.st_v6_case_collaboration_alerts(true))
 or (select count(*) from public.st_v6_case_collaboration_alerts(false) where read_at is not null)<>1 then
   raise exception 'Recipient did not mark own alert read'; end if;
end $$;
reset role;

insert into sectalk_private.st_v6_notification_preferences(user_id,category,enabled)
values ('7f600000-0000-4000-8000-000000000003','mention',false);
set local role authenticated;
do $$
begin
 perform pg_temp.case_actor(1);
 perform public.st_v6_append_case_note('7f640000-0000-4000-8000-000000000001',
   '7f660000-0000-4000-8000-000000000002','Check this @case_3',false,false);
 perform pg_temp.case_actor(3);
 if not exists(select from public.st_v6_case_collaboration_alerts(true)
   where note_id='7f660000-0000-4000-8000-000000000002') then raise exception 'Disabled popups hid the durable mention'; end if;
end $$;
reset role;

delete from sectalk_private.st_v5_attachment_reports where report_id='7f640000-0000-4000-8000-000000000001';
delete from sectalk_private.staff where user_id='7f600000-0000-4000-8000-000000000002';
do $$
declare
 report uuid:='7f640000-0000-4000-8000-000000000001';
 note uuid:='7f660000-0000-4000-8000-000000000001';
begin
 if (select count(*) from sectalk_private.st_v6_case_mentions where note_id=note)<>1
 or (select count(*) from sectalk_private.audit where report_id=report and action='case_note_added'
     and sectalk_private.audit.note='Staff collaboration note added')<>2
 or (select count(*) from sectalk_private.audit where report_id=report and action='case_note_evidence_viewed')<>2 then
   raise exception 'Expected bounded private audience and append-only metadata audit'; end if;
 if (select count(*) from realtime.messages where event='case_collaboration'
     and topic='st:account:7f600000-0000-4000-8000-000000000002' and private and payload-'id'='{}')<>1 then
   raise exception 'Realtime did not use the empty private recipient envelope'; end if;
 if exists(select from realtime.messages where event='case_collaboration'
     and topic='st:account:7f600000-0000-4000-8000-000000000003') then
   raise exception 'A disabled mention preference received a popup'; end if;
end $$;

set local role authenticated;
do $$
declare report uuid:='7f640000-0000-4000-8000-000000000001';
 note uuid:='7f660000-0000-4000-8000-000000000001';
begin
 perform pg_temp.case_actor(2);
 begin perform public.st_v6_case_collaboration_alerts(false); raise exception 'Revoked staff read alerts';
 exception when insufficient_privilege then null; end;
 perform pg_temp.case_actor(1);
 if (select value->>'has_file' from jsonb_array_elements(public.st_v6_case_collaboration(report)->'notes')
     where value->>'id'=note::text) is distinct from 'false' then
   raise exception 'Removed attachment remains visible'; end if;
 begin perform public.st_v6_case_note_evidence(report,note,'file'); raise exception 'Removed link still opens';
 exception when insufficient_privilege then null; end;
end $$;
rollback;
