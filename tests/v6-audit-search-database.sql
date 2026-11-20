begin;

insert into auth.users(id,email,aud,role) values
  ('66000000-0000-4000-8000-000000000001','audit-owner@example.invalid','authenticated','authenticated'),
  ('66000000-0000-4000-8000-000000000002','audit-admin@example.invalid','authenticated','authenticated'),
  ('66000000-0000-4000-8000-000000000003','audit-member@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('66000000-0000-4000-8000-000000000001','audit_fixture_owner','Audit owner'),
  ('66000000-0000-4000-8000-000000000002','audit_fixture_admin','Audit admin'),
  ('66000000-0000-4000-8000-000000000003','audit_fixture_member','Audit member');
insert into public.st_v2_workspaces(id,name,owner) values
  ('66000000-0001-4000-8000-000000000001','Audit fixture A','66000000-0000-4000-8000-000000000001'),
  ('66000000-0001-4000-8000-000000000002','Audit fixture B','66000000-0000-4000-8000-000000000003');
insert into public.st_v2_members(workspace_id,user_id,role) values
  ('66000000-0001-4000-8000-000000000001','66000000-0000-4000-8000-000000000001','owner'),
  ('66000000-0001-4000-8000-000000000001','66000000-0000-4000-8000-000000000002','admin'),
  ('66000000-0001-4000-8000-000000000001','66000000-0000-4000-8000-000000000003','member'),
  ('66000000-0001-4000-8000-000000000002','66000000-0000-4000-8000-000000000003','owner');
insert into public.st_v2_workspace_audit(workspace_id,actor,event) values
  ('66000000-0001-4000-8000-000000000001','66000000-0000-4000-8000-000000000001','workspace.created'),
  ('66000000-0001-4000-8000-000000000002','66000000-0000-4000-8000-000000000003','workspace.created');

set local role authenticated;
do $$
declare
  owner_id constant uuid:='66000000-0000-4000-8000-000000000001';
  admin_id constant uuid:='66000000-0000-4000-8000-000000000002';
  member_id constant uuid:='66000000-0000-4000-8000-000000000003';
  space_a constant uuid:='66000000-0001-4000-8000-000000000001';
  space_b constant uuid:='66000000-0001-4000-8000-000000000002';
  room constant uuid:='66000000-0002-4000-8000-000000000001';
begin
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v6_room_create(room,space_a,'Private audit fixture','private','project');
  if not exists(select 1 from public.st_v6_audit_search(space_a,'PRIVATE AUDIT','room') l
      where l.event='room.created' and l.room_name='Private audit fixture')
    or not exists(select 1 from public.st_v6_audit_search(space_a,'workspace created','workspace'))
    or exists(select 1 from public.st_v6_audit_search(space_a,'',null,p_before=>now()-interval '1 day'))
    then raise exception 'Audit role, search phrase, source or timestamp filtering failed'; end if;
  if exists(select 1 from public.st_v6_search('Private audit fixture',null))
    then raise exception 'Audit result leaked into general search'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',admin_id,'role','authenticated')::text,true);
  if not exists(select 1 from public.st_v6_audit_search(space_a,'workspace.created','workspace'))
    or exists(select 1 from public.st_v6_audit_search(space_a,'private audit','room'))
    then raise exception 'Workspace admin could not search, or saw a room outside their room role'; end if;
  begin
    perform public.st_v6_audit_search(space_b);
    raise exception 'Administrator searched a different tenant';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if (select array_agg(w.id) from public.st_v6_audit_workspaces() w) is distinct from array[space_b]
    then raise exception 'Workspace chooser included a workspace with a non-admin role'; end if;
  begin
    perform public.st_v6_audit_search(space_a);
    raise exception 'A member searched workspace audit entries';
  exception when insufficient_privilege then null; end;
end $$;
reset role;
select 'passed: separate audit search, admin permissions, tenant and private room isolation, date and source filters' as result;
rollback;
