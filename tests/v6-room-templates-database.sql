begin;

insert into auth.users(id,email,aud,role) values
  ('69000000-0000-4000-8000-000000000001','template-owner@example.invalid','authenticated','authenticated'),
  ('69000000-0000-4000-8000-000000000002','template-member@example.invalid','authenticated','authenticated'),
  ('69000000-0000-4000-8000-000000000003','template-outsider@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('69000000-0000-4000-8000-000000000001','template_owner','Template owner'),
  ('69000000-0000-4000-8000-000000000002','template_member','Template member'),
  ('69000000-0000-4000-8000-000000000003','template_outsider','Template outsider');

set local role authenticated;
do $$
declare
  owner_id constant uuid:='69000000-0000-4000-8000-000000000001';
  member_id constant uuid:='69000000-0000-4000-8000-000000000002';
  outsider_id constant uuid:='69000000-0000-4000-8000-000000000003';
  blank_id constant uuid:=gen_random_uuid();
  class_id constant uuid:=gen_random_uuid();
  incident_id constant uuid:=gen_random_uuid();
  family_id constant uuid:=gen_random_uuid();
  project_id constant uuid:=gen_random_uuid();
  private_project_id constant uuid:=gen_random_uuid();
  workspace uuid;
  invite_id uuid;
  template_row record;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  workspace:=public.st_v2_create_workspace('Room template fixture');
  perform public.st_v2_invite(workspace,'template_member');
  perform public.st_v6_room_create(blank_id,workspace,'Empty room','announcement','blank');
  perform public.st_v6_room_create(class_id,workspace,'Training room','private','class');
  perform public.st_v6_room_create(incident_id,workspace,'Incident room','admin','incident');
  perform public.st_v6_room_create(family_id,workspace,'Household room','private','family');
  perform public.st_v6_room_create(project_id,workspace,'Project room','public','project');
  perform public.st_v6_room_create(private_project_id,workspace,'Private project','private','project');

  if (select slow_seconds from public.st_v6_rooms where id=class_id) is distinct from 15
    then raise exception 'Class template is missing its posting interval'; end if;
  perform public.st_v6_room_settings(class_id,'slow',null,30);
  perform public.st_v6_room_create(class_id,workspace,'Training room','private','class');
  if (select slow_seconds from public.st_v6_rooms where id=class_id) is distinct from 30
    then raise exception 'Retry overwrote the customized class moderation policy'; end if;
  perform public.st_v6_room_settings(class_id,'slow',null,15);

  for template_row in select * from (values
      (class_id,'Class starter'),(incident_id,'Incident starter'),(family_id,'Family starter'),
      (project_id,'Project starter'),(private_project_id,'Project starter')) expected(room,heading)
  loop
    if (select count(*) from public.st_v6_room_posts p
        join public.st_v6_room_pins i on i.room_id=p.room_id and i.post_id=p.id
        join public.st_v6_room_audit a on a.room_id=p.room_id and a.target=p.id and a.action='room.template_applied'
        where p.room_id=template_row.room and p.kind='announcement' and split_part(p.body,chr(10),1)=template_row.heading)<>1
      then raise exception 'Expected one pinned and audited starter in room %',template_row.room; end if;
  end loop;
  if exists(select 1 from public.st_v6_room_posts where room_id=blank_id)
    then raise exception 'Blank room unexpectedly has starter posts'; end if;
  begin
    perform public.st_v6_room_create(gen_random_uuid(),workspace,'Exposed incident','public','incident');
    raise exception 'A public incident template was accepted' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_room_create(gen_random_uuid(),workspace,'Exposed family','public','family');
    raise exception 'A public family template was accepted' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  select id into invite_id from public.st_v2_invites where workspace_id=workspace and invitee=member_id;
  perform public.st_v2_reply_invite(invite_id,true);
  if exists(select 1 from public.st_v6_rooms where id in (class_id,incident_id,family_id,private_project_id))
    or exists(select 1 from public.st_v6_room_posts)
    then raise exception 'Template directory privacy or pre-join content visibility failed'; end if;
  begin
    perform public.st_v6_room_create(gen_random_uuid(),workspace,'Unauthorized project','public','project');
    raise exception 'A regular member created a template room' using errcode='P0004';
  exception when raise_exception then null; end;
  perform public.st_v6_room_membership(project_id,'join');
  if not exists(select 1 from public.st_v6_room_pins where room_id=project_id)
    or exists(select 1 from public.st_v6_room_posts where room_id in (incident_id,family_id,class_id,private_project_id))
    then raise exception 'Project join did not preserve scoped starter visibility'; end if;

  perform public.st_v6_room_membership(class_id,'request');
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v6_room_membership(class_id,'approve',member_id);
  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if not exists(select 1 from public.st_v6_room_pins where room_id=class_id)
    then raise exception 'Approved class member cannot read the starter'; end if;
  perform public.st_v6_room_post(class_id,gen_random_uuid(),'Student question');
  begin
    perform public.st_v6_room_post(class_id,gen_random_uuid(),'Second question');
    raise exception 'Class template posting interval was not enforced' using errcode='P0004';
  exception when raise_exception then
    if sqlerrm not like 'Slow mode is on.%' then raise; end if;
  end;

  perform set_config('request.jwt.claims',json_build_object('sub',outsider_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_rooms where workspace_id=workspace) or exists(select 1 from public.st_v6_room_posts)
    then raise exception 'Room template content crossed a workspace boundary'; end if;
end $$;

reset role;
select 'passed: class, incident, family and project template defaults, pinned starters, idempotency, audit and workspace privacy' as result;
rollback;
