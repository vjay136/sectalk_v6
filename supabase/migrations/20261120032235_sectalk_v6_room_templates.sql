begin;

create or replace function public.st_v6_room_create(p_id uuid,p_workspace uuid,p_name text,p_kind text,p_template text)
returns uuid language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  allowed_kinds text[];
  starter text;
  starter_id uuid;
  initial_slow_seconds integer:=0;
begin
  perform sectalk_private.limit_action('v6_room_create',8);
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor) then raise exception 'Room unavailable'; end if;
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if exists(select 1 from public.st_v6_rooms where id=p_id and workspace_id=p_workspace and creator=actor
      and name=btrim(p_name) and kind=p_kind and template=p_template) then return p_id; end if;

  case p_template
    when 'blank' then allowed_kinds:=array['public','private','admin','announcement','broadcast'];
    when 'class' then
      allowed_kinds:=array['private'];
      initial_slow_seconds:=15;
      starter:='Class starter'||chr(10)||'Post the syllabus or learning goals, keep each lesson in a separate thread, and share assignments in Tasks. Add learners only after confirming their workspace accounts.';
    when 'incident' then
      allowed_kinds:=array['admin'];
      starter:='Incident starter'||chr(10)||'Record the incident lead, status, scope, and next update time. Keep a timestamped timeline and assign authorized follow-up in Tasks. Keep credentials and personal data out of room messages.';
    when 'family' then
      allowed_kinds:=array['private'];
      starter:='Family starter'||chr(10)||'Agree on shared plans, use threads for individual topics, and invite only the workspace members you want here. Ask before posting someone else’s photo or personal details.';
    when 'project' then
      allowed_kinds:=array['public','private'];
      starter:='Project starter'||chr(10)||'Define the goal, owner, and next milestone. Use Tasks for assignments and due dates, and put decisions or blockers in their own threads.';
    else raise exception 'Room template unavailable';
  end case;
  if p_kind is null or not (p_kind=any(allowed_kinds))
    then raise exception 'Choose a room type allowed by this template'; end if;
  if (select count(*) from public.st_v6_rooms where workspace_id=p_workspace)>=100 then raise exception 'Workspace room limit reached'; end if;

  insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator,slow_seconds)
    values(p_id,p_workspace,btrim(p_name),p_kind,p_template,actor,initial_slow_seconds);
  if p_kind<>'admin' then
    insert into public.st_v6_room_members(room_id,user_id,role) values(p_id,actor,'owner');
  end if;
  insert into public.st_v6_room_audit(room_id,actor,action) values(p_id,actor,'room.created');
  if starter is not null then
    starter_id:=gen_random_uuid();
    insert into public.st_v6_room_posts(room_id,id,sender,body,kind)
      values(p_id,starter_id,actor,starter,'announcement');
    insert into public.st_v6_room_pins(room_id,post_id) values(p_id,starter_id);
    insert into public.st_v6_room_audit(room_id,actor,action,target)
      values(p_id,actor,'room.template_applied',starter_id);
  end if;
  return p_id;
end $$;

commit;
