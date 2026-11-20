begin;

insert into auth.users(id,email,aud,role) values
 ('40000000-0000-4000-8000-000000000001','st-v4-owner@example.invalid','authenticated','authenticated'),
 ('40000000-0000-4000-8000-000000000002','st-v4-member@example.invalid','authenticated','authenticated'),
 ('40000000-0000-4000-8000-000000000003','st-v4-guest@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
 ('40000000-0000-4000-8000-000000000001','sectalk_v4_owner','Owner fixture'),
 ('40000000-0000-4000-8000-000000000002','sectalk_v4_member','Member fixture'),
 ('40000000-0000-4000-8000-000000000003','sectalk_v4_guest','Outside fixture');

set local role authenticated;
do $$
declare
  host constant uuid:='40000000-0000-4000-8000-000000000001';
  member constant uuid:='40000000-0000-4000-8000-000000000002';
  guest constant uuid:='40000000-0000-4000-8000-000000000003';
  workspace uuid;
  invitation uuid;
  task uuid;
  check_id uuid:=gen_random_uuid();
begin
  perform set_config('request.jwt.claims',json_build_object('sub',host,'role','authenticated')::text,true);
  workspace:=public.st_v2_create_workspace('v4 permissions');
  perform public.st_v2_invite(workspace,'sectalk_v4_member');
  select id into invitation from public.st_v2_invites where workspace_id=workspace and invitee=member;
  task:=public.st_v2_add_item(workspace,'task','Review access','',null);
  perform public.st_v4_task_change(task,'checklist.add',p_item=>check_id,p_label=>'Check visibility');
  perform public.st_v4_task_change(task,'checklist.add',p_item=>check_id,p_label=>'Check visibility');
  if (select count(*) from public.st_v4_checklist where task_id=task)<>1 then raise exception 'Checklist retry duplicated an item'; end if;
  begin
    perform public.st_v4_task_change(task,'assign',p_person=>guest);
    raise exception 'Outside workspace assignment succeeded' using errcode='P0004';
  exception when raise_exception then null;
  end;

  perform set_config('request.jwt.claims',json_build_object('sub',member,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v4_checklist where task_id=task) then raise exception 'An invite alone exposed a task'; end if;
  perform public.st_v2_reply_invite(invitation,true);
  begin
    perform public.st_v4_task_change(task,'checklist.toggle',p_item=>check_id,p_done=>true);
    raise exception 'An unassigned member edited a checklist' using errcode='P0004';
  exception when raise_exception then null;
  end;

  perform set_config('request.jwt.claims',json_build_object('sub',host,'role','authenticated')::text,true);
  perform public.st_v4_task_change(task,'assign',p_person=>member);
  perform set_config('request.jwt.claims',json_build_object('sub',member,'role','authenticated')::text,true);
  perform public.st_v4_task_change(task,'checklist.toggle',p_item=>check_id,p_done=>true);
  perform public.st_v4_task_change(task,'complete',p_done=>true);
  if not exists(select 1 from public.st_v4_checklist where id=check_id and completed)
    or not exists(select 1 from public.st_v2_items where id=task and completed) then raise exception 'Assignee changes not saved'; end if;
  begin
    perform public.st_v4_task_change(task,'assign',p_person=>null);
    raise exception 'Assignee changed ownership' using errcode='P0004';
  exception when raise_exception then null;
  end;

  perform set_config('request.jwt.claims',json_build_object('sub',guest,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v4_task_assignments where task_id=task)
    or exists(select 1 from public.st_v4_checklist where task_id=task) then raise exception 'Outside account saw task metadata'; end if;
  if has_function_privilege('anon','public.st_v4_task_change(uuid,text,uuid,uuid,text,boolean)','execute')
    then raise exception 'Anonymous callers can edit tasks'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',host,'role','authenticated')::text,true);
  if not exists(select 1 from public.st_v2_workspace_audit where workspace_id=workspace and actor=member
    and target=task and event='task.checklist.toggle') then raise exception 'Checklist audit action missing'; end if;
end $$;
reset role;
select 'passed: task assignment, checklist idempotency, tenant isolation and audit' as result;
rollback;
