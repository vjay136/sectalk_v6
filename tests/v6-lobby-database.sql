begin;
insert into auth.users(id,email,aud,role)
select format('63000000-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  format('lobby-%s@example.invalid',n),'authenticated','authenticated' from generate_series(1,16) n;
insert into public.st_profiles(id,handle,name)
select id,'lobby_fixture_'||replace(split_part(email,'@',1),'-','_'),'Lobby participant'
  from auth.users where email like 'lobby-%@example.invalid';
insert into public.st_v2_workspaces(id,name,owner) values
  ('63000000-0001-4000-8000-000000000001','Lobby fixture','63000000-0000-4000-8000-000000000001');
insert into public.st_v2_members(workspace_id,user_id,role)
select '63000000-0001-4000-8000-000000000001',
  format('63000000-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  case when n=1 then 'owner' else 'member' end from generate_series(1,15) n;
insert into public.st_v3_meetings(id,workspace_id,title,host_id,starts_at,ends_at) values
  ('63000000-0002-4000-8000-000000000001','63000000-0001-4000-8000-000000000001','Lobby fixture',
    '63000000-0000-4000-8000-000000000001',now(),now()+interval '1 hour');
insert into public.st_v3_attendance(meeting_id,user_id,status,requested_at)
select '63000000-0002-4000-8000-000000000001',
  format('63000000-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  'waiting',now()+n*interval '1 millisecond' from generate_series(2,16) n;
insert into public.st_blocks(actor,target) values
  ('63000000-0000-4000-8000-000000000001','63000000-0000-4000-8000-000000000002');

set local role authenticated;
do $$
declare
  host_id constant uuid:='63000000-0000-4000-8000-000000000001';
  member_id constant uuid:='63000000-0000-4000-8000-000000000004';
  meeting_id constant uuid:='63000000-0002-4000-8000-000000000001';
  space constant uuid:='63000000-0001-4000-8000-000000000001';
begin
  perform set_config('request.jwt.claims',json_build_object('sub',host_id,'role','authenticated')::text,true);
  perform public.st_v3_meeting_state(meeting_id,'live');

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if public.st_v3_media_access(meeting_id) or (select count(*) from public.st_v3_attendance)<>1
    then raise exception 'Waiting member accessed media or the private roster'; end if;
  begin
    perform public.st_v6_admit_all(meeting_id);
    raise exception 'Member bypassed host admission' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',host_id,'role','authenticated')::text,true);
  perform public.st_v3_admit(meeting_id,'63000000-0000-4000-8000-000000000003',false);
  if public.st_v6_admit_all(meeting_id)<>11 or public.st_v6_admit_all(meeting_id)<>0
    then raise exception 'Bulk admission exceeded capacity or changed on retry'; end if;
  if exists(select 1 from public.st_v3_attendance a where a.user_id in
    ('63000000-0000-4000-8000-000000000002','63000000-0000-4000-8000-000000000003',
     '63000000-0000-4000-8000-000000000015','63000000-0000-4000-8000-000000000016') and a.status='admitted')
    then raise exception 'Bulk admission bypassed ordering, membership, a block, or a decline'; end if;
  if (select count(*) from public.st_v2_workspace_audit where workspace_id=space and event='meeting.admitted')<>11
    then raise exception 'Bulk admission did not audit each decision'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if not public.st_v3_media_access(meeting_id)
    or (select count(*) from public.st_v3_notifications where kind='meeting.admitted')<>1
    then raise exception 'Admitted member lacked media access or a private notice'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',host_id,'role','authenticated')::text,true);
  perform public.st_v3_meeting_state(meeting_id,'ended');
  begin
    perform public.st_v6_admit_all(meeting_id);
    raise exception 'Closed lobby accepted admission' using errcode='P0004';
  exception when raise_exception then null; end;
end $$;

reset role;
select 'passed: host-only lobby, individual decline, bulk admission, capacity, blocked and unrelated users, audits and private notices' as result;
rollback;
