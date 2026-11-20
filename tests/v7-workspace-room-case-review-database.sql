begin;
insert into auth.users(id,email)
select ('7fb00000-0000-4000-8000-00000000000'||n)::uuid,'tenant-case-'||n||'@example.invalid' from generate_series(1,9) n;
insert into public.st_profiles(id,handle,name)
select ('7fb00000-0000-4000-8000-00000000000'||n)::uuid,'tenant_case_'||n,'Room review fixture' from generate_series(1,9) n;
insert into sectalk_private.staff values('7fb00000-0000-4000-8000-000000000001'),
 ('7fb00000-0000-4000-8000-000000000008'),('7fb00000-0000-4000-8000-000000000009');
insert into sectalk_private.st_v6_case_on_call values
 ('7fb00000-0000-4000-8000-000000000001',1,now(),now()+interval '1 hour'),
 ('7fb00000-0000-4000-8000-000000000008',2,now(),now()+interval '1 hour'),
 ('7fb00000-0000-4000-8000-000000000009',3,now(),now()+interval '1 hour');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
select ('7fb10000-0000-4000-8000-00000000000'||n)::uuid,('7fb00000-0000-4000-8000-00000000000'||n)::uuid,
  'totp','verified',now(),now() from generate_series(1,9) n;
insert into auth.sessions(id,user_id,aal,factor_id)
select ('7fb20000-0000-4000-8000-00000000000'||n)::uuid,('7fb00000-0000-4000-8000-00000000000'||n)::uuid,
  'aal2',('7fb10000-0000-4000-8000-00000000000'||n)::uuid from generate_series(1,9) n;
create function pg_temp.tenant_case_actor(n integer,assurance text default 'aal2') returns void language sql as $$
 select set_config('request.jwt.claims',jsonb_build_object('sub','7fb00000-0000-4000-8000-00000000000'||n,
  'aal',assurance,'session_id','7fb20000-0000-4000-8000-00000000000'||n)::text,true)::text::void
$$;

do $$
declare
  workspace uuid;
  room uuid:=gen_random_uuid();
  content uuid:=gen_random_uuid();
  severe_content uuid:=gen_random_uuid();
  item uuid;
  severe uuid;
  assignment timestamptz;
  reread timestamptz;
  old_owner constant uuid:='7fb00000-0000-4000-8000-000000000002';
  new_owner constant uuid:='7fb00000-0000-4000-8000-000000000006';
  outsider constant uuid:='7fb00000-0000-4000-8000-000000000003';
  participant constant uuid:='7fb00000-0000-4000-8000-000000000004';
  subject_id constant uuid:='7fb00000-0000-4000-8000-000000000005';
  result jsonb;
begin
  set local role authenticated;
  perform pg_temp.tenant_case_actor(2);
  workspace:=public.st_v2_create_workspace('Assigned room case fixture');
  perform public.st_v6_room_create(room,workspace,'Managed review room','public','blank');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(workspace,new_owner,'admin'),
    (workspace,participant,'member'),(workspace,subject_id,'member');
  insert into public.st_v6_room_members(room_id,user_id,role) values(room,new_owner,'moderator'),
    (room,participant,'member'),(room,subject_id,'member');
  insert into public.st_v6_room_posts(room_id,id,sender,body,kind) values
    (room,content,subject_id,'Synthetic ordinary case content','message'),
    (room,severe_content,subject_id,'Synthetic severe case content','message');
  set local role authenticated;
  perform pg_temp.tenant_case_actor(4,'aal1');
  item:=public.st_v6_submit_room_report(room,content,'spam','Privately shared with Platform only.',true);
  severe:=public.st_v6_submit_room_report(room,severe_content,'threat','Sensitive reporter notes.',true);
  reset role;
  update sectalk_private.st_v6_room_reports set handed_off_at=now(),status='reviewing' where id in(item,severe);
  insert into sectalk_private.st_v6_room_report_stages(report_id,stage,assignee,assigned_at,acknowledge_by,action_by)
    values(item,3,old_owner,now(),now()+interval '2 hours',now()+interval '1 day'),
      (severe,3,old_owner,now(),now()+interval '2 hours',now()+interval '1 day');
  -- Unrelated recent assignments must not consume this assignee's queue page.
  with seeds as (
    insert into sectalk_private.st_v6_room_reports(workspace_id,room_id,post_id,reporter,subject,category,details,
      share_with_workspace,status,created_at,handed_off_at)
      select workspace,room,gen_random_uuid(),'7fb00000-0000-4000-8000-000000000007'::uuid,subject_id,'other','',true,'reviewing',now()+interval '1 hour',now()
      from generate_series(1,105) returning id
  ) insert into sectalk_private.st_v6_room_report_stages(report_id,stage,assignee,assigned_at,acknowledge_by,action_by)
    select id,3,outsider,now(),now()+interval '2 hours',now()+interval '1 day' from seeds;
  select assigned_at into assignment from sectalk_private.st_v6_room_report_stages where report_id=item;

  set local role authenticated;
  perform pg_temp.tenant_case_actor(2,'aal1');
  begin
    perform public.st_v7_workspace_room_review_queue();
    raise exception 'An AAL1 owner could open the tenant queue';
  exception when insufficient_privilege then null; end;
  perform pg_temp.tenant_case_actor(2);
  result:=public.st_v7_workspace_room_review_queue();
  if not exists(select 1 from jsonb_array_elements(result) row where (row->>'id')::uuid=item
    and row->>'evidence'='Synthetic ordinary case content' and not (row ? 'details')) then
    raise exception 'Assigned report disappeared behind unrelated cases or leaked private notes';
  end if;
  begin
    perform public.st_v7_workspace_room_case_action(item,'resolved','Premature decision',assignment);
    raise exception 'Unacknowledged assignee closed a case';
  exception when insufficient_privilege then null; end;
  perform public.st_v6_review_room_report(item,'workspace','acknowledge','Claim case for human review',3::smallint);
  perform public.st_v6_review_room_report(severe,'workspace','acknowledge','Claim intake for Platform',3::smallint);
  begin
    perform public.st_v7_workspace_room_case_action(severe,'dismissed','Requires Platform',assignment);
    raise exception 'Tenant dismissed a serious alert';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_workspace_room_case_action(item,'delegate','Cross-tenant assignment',assignment,outsider);
    raise exception 'Cross-tenant assignment accepted';
  exception when insufficient_privilege then null; end;
  if not exists(select 1 from public.st_v7_workspace_room_reviewers(item) where id=new_owner) then
    raise exception 'Verified tenant reviewer was unavailable';
  end if;
  perform public.st_v7_workspace_room_case_action(item,'delegate','Assign coverage to moderator',assignment,new_owner);
  if exists(select 1 from jsonb_array_elements(public.st_v7_workspace_room_review_queue()) row where (row->>'id')::uuid=item) then
    raise exception 'Previous reviewer retained access after reassignment';
  end if;
  perform pg_temp.tenant_case_actor(6);
  select (row->>'assigned_at')::timestamptz into reread from jsonb_array_elements(public.st_v7_workspace_room_review_queue()) row
    where (row->>'id')::uuid=item;
  if reread is null or reread=assignment then raise exception 'New reviewer did not receive a new assignment'; end if;
  perform public.st_v6_review_room_report(item,'workspace','acknowledge','Accept reassignment',3::smallint);
  begin
    perform public.st_v7_workspace_room_case_action(item,'resolved','Stale branch close',assignment);
    raise exception 'A stale assignment could close the case';
  exception when serialization_failure then null; end;
  perform public.st_v7_workspace_room_case_action(item,'resolved','Reviewed the context and closed the ordinary case',reread);
  perform pg_temp.tenant_case_actor(4,'aal1');
  if not exists(select 1 from public.st_v7_my_room_report_status() r where r.id=item and r.status='resolved'
    and r.decision_scope='workspace' and r.decided_at is not null
    and not(to_jsonb(r) ?| array['reason','evidence','actor','assignee'])) then
    raise exception 'Reporter lost the status or received private review details';
  end if;
  reset role;
  if not exists(select 1 from sectalk_private.st_v7_room_review_assignments where report_id=item
    and previous=old_owner and assigned=new_owner and reason='Assign coverage to moderator')
    or not exists(select 1 from sectalk_private.st_v6_room_report_audit where report_id=item
      and action='resolved' and actor=new_owner and source='workspace')
    or not exists(select 1 from public.st_v6_room_posts where id=content and removed_at is null)
    or exists(select 1 from sectalk_private.suspensions where user_id=subject_id) then
    raise exception 'Missing audit or an unrelated moderation action was applied';
  end if;
end
$$;
select 'passed: consented assigned workspace queue, cross-scope denial, reassignment, human closure, and private reporter status' as result;
rollback;
