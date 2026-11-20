begin;
do $$
declare manager uuid:=gen_random_uuid(); teacher uuid:=gen_random_uuid(); student uuid:=gen_random_uuid(); outsider uuid:=gen_random_uuid();
  manager_session uuid:=gen_random_uuid(); teacher_session uuid:=gen_random_uuid(); student_session uuid:=gen_random_uuid();
  manager_claim text:=jsonb_build_object('sub',manager,'session_id',manager_session,'aal','aal1','role','authenticated')::text;
  teacher_claim text:=jsonb_build_object('sub',teacher,'session_id',teacher_session,'aal','aal1','role','authenticated')::text;
  student_claim text:=jsonb_build_object('sub',student,'session_id',student_session,'aal','aal1','role','authenticated')::text;
  school uuid; class_a uuid:=gen_random_uuid(); class_b uuid:=gen_random_uuid();
  room_a uuid; room_b uuid; snapshot jsonb;
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (manager,'school-manager@example.invalid',now()),(teacher,'school-teacher@example.invalid',now()),
    (student,'school-student@example.invalid',now()),(outsider,'school-outsider@example.invalid',now());
  insert into public.st_profiles values(manager,'org11_manager','Manager'),(teacher,'org11_teacher','Teacher'),
    (student,'org11_student','Student'),(outsider,'org11_outsider','Outsider');
  insert into auth.sessions(id,user_id,aal) values(manager_session,manager,'aal1'),(teacher_session,teacher,'aal1'),(student_session,student,'aal1');
  set local role authenticated;
  perform set_config('request.jwt.claims',manager_claim,true);
  school:=public.st_v6_create_typed_workspace(gen_random_uuid(),'Synthetic school','school');
  begin
    perform public.st_v7_school_classes(school,'create',class_a,'Denied until fresh');
    raise exception 'Stale sign-in created a class';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(school,teacher,'member'),(school,student,'member'),(school,outsider,'member');
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
    (gen_random_uuid(),manager_session,'password',now(),now()),(gen_random_uuid(),teacher_session,'password',now(),now()),
    (gen_random_uuid(),student_session,'password',now(),now());
  set local role authenticated;
  snapshot:=public.st_v7_school_classes(school,'create',class_a,'First class');
  room_a:=(snapshot#>>'{0,room}')::uuid;
  snapshot:=public.st_v7_school_classes(school,'create',class_b,'Second class');
  room_b:=(snapshot#>>'{1,room}')::uuid;
  if not exists(select 1 from public.st_v6_rooms where id=room_a and kind='private' and classification='confidential'
    and template='class' and slow_seconds=15 and not forwarding_allowed) then raise exception 'Class safety defaults not persisted'; end if;
  begin
    perform public.st_v6_workspace_group_change(school,class_a,'rename','Bypassed classroom');
    raise exception 'Generic group action changed a classroom';
  exception when insufficient_privilege then null; end;
  perform public.st_v7_school_classes(school,'enroll',class_a,p_person=>teacher,p_role=>'teacher');
  perform set_config('request.jwt.claims',teacher_claim,true);
  snapshot:=public.st_v7_school_classes(school);
  if jsonb_array_length(snapshot)<>1 or snapshot#>>'{0,myRole}'<>'teacher' then raise exception 'Teacher read unrelated class'; end if;
  if exists(select 1 from public.st_v6_room_posts where room_id=room_b) then raise exception 'Teacher read unrelated room'; end if;
  begin
    perform public.st_v7_school_classes(school,'enroll',class_b,p_person=>student,p_role=>'student');
    raise exception 'Teacher enrolled in unrelated class';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_school_classes(school,'enroll',class_a,p_person=>outsider,p_role=>'teacher');
    raise exception 'Teacher granted staff authority';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_room_membership(room_a,'invite',outsider,'guest');
    raise exception 'Room generic invite bypassed classroom roster';
  exception when insufficient_privilege then null; end;
  perform public.st_v7_school_classes(school,'enroll',class_a,p_person=>student,p_role=>'student');
  perform set_config('request.jwt.claims',student_claim,true);
  if not exists(select 1 from public.st_v6_room_posts where room_id=room_a)
    or exists(select 1 from public.st_v6_room_posts where room_id=room_b) then
    raise exception 'Wrong scoped room feed';
  end if;
  perform public.st_v6_room_post(room_a,gen_random_uuid(),'Student can post to the assigned classroom');
  reset role;
  begin
    update public.st_v6_rooms set slow_seconds=0 where id=room_a;
    raise exception 'Classroom slow mode could be removed';
  exception when insufficient_privilege then null; end;
  update public.st_v2_members set suspended_at=clock_timestamp() where workspace_id=school and user_id=student;
  update public.st_v2_members set suspended_at=null where workspace_id=school and user_id=student;
  set local role authenticated;
  if public.st_v7_school_classes(school)<>'[]'::jsonb or exists(select 1 from public.st_v6_room_posts where room_id=room_a) then
    raise exception 'Restore improperly reinstated revoked classroom access';
  end if;
end
$$;
select 'passed: class defaults, fresh roster changes, room privacy, scoped teachers and permanent roster revocation' as result;
rollback;
