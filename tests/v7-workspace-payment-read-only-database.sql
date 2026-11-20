begin;
insert into auth.users(id,email,email_confirmed_at) values
 ('b1150000-0000-4000-8000-000000000001','readonly-owner@example.invalid',now()),
 ('b1150000-0000-4000-8000-000000000002','readonly-member@example.invalid',now());
insert into public.st_profiles(id,handle,name) values
 ('b1150000-0000-4000-8000-000000000001','read_only_owner','Readonly owner'),
 ('b1150000-0000-4000-8000-000000000002','read_only_member','Readonly member');
insert into auth.sessions(id,user_id,aal) values
 ('b1150000-0000-4000-8000-000000000003','b1150000-0000-4000-8000-000000000002','aal1');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
 ('b1150000-0000-4000-8000-000000000004','b1150000-0000-4000-8000-000000000001','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
 ('b1150000-0000-4000-8000-000000000005','b1150000-0000-4000-8000-000000000001','aal2','b1150000-0000-4000-8000-000000000004');
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
 ('b1150000-0000-4000-8000-000000000006','b1150000-0000-4000-8000-000000000005','totp',now(),now());
insert into public.st_v2_workspaces(id,name,owner) values
 ('b1150000-0000-4000-8000-000000000011','Read-only fixture','b1150000-0000-4000-8000-000000000001'),
 ('b1150000-0000-4000-8000-000000000012','Independent fixture','b1150000-0000-4000-8000-000000000002');
insert into public.st_v2_members(workspace_id,user_id,role) values
 ('b1150000-0000-4000-8000-000000000011','b1150000-0000-4000-8000-000000000001','owner'),
 ('b1150000-0000-4000-8000-000000000011','b1150000-0000-4000-8000-000000000002','member'),
 ('b1150000-0000-4000-8000-000000000012','b1150000-0000-4000-8000-000000000002','owner');
insert into public.st_v6_workspace_groups(workspace_id,id,kind,name) values
 ('b1150000-0000-4000-8000-000000000011','b1150000-0000-4000-8000-000000000040','team','Delinquent tenant team'),
 ('b1150000-0000-4000-8000-000000000012','b1150000-0000-4000-8000-000000000040','team','Independent tenant team');
insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator) values
 ('b1150000-0000-4000-8000-000000000021','b1150000-0000-4000-8000-000000000011','Existing room','public','blank','b1150000-0000-4000-8000-000000000001');
insert into public.st_v6_room_members(room_id,user_id,role) values
 ('b1150000-0000-4000-8000-000000000021','b1150000-0000-4000-8000-000000000001','owner'),
 ('b1150000-0000-4000-8000-000000000021','b1150000-0000-4000-8000-000000000002','member');
insert into public.st_v2_channels(id,workspace_id,name,owner) values
 ('b1150000-0000-4000-8000-000000000022','b1150000-0000-4000-8000-000000000011','existing-channel','b1150000-0000-4000-8000-000000000001');
insert into public.st_v6_room_posts(room_id,id,sender,body,kind) values
 ('b1150000-0000-4000-8000-000000000021','b1150000-0000-4000-8000-000000000031','b1150000-0000-4000-8000-000000000001','Keep this room record','message');
insert into public.st_v2_posts(id,channel_id,sender,body) values
 ('b1150000-0000-4000-8000-000000000032','b1150000-0000-4000-8000-000000000022','b1150000-0000-4000-8000-000000000001','Protected channel record');
insert into public.st_v3_meetings(id,workspace_id,host_id,title,starts_at,ends_at)
values('b1150000-0000-4000-8000-000000000033','b1150000-0000-4000-8000-000000000011',
 'b1150000-0000-4000-8000-000000000001','Previously scheduled meeting',now()-interval '1 minute',now()+interval '1 hour');
select public.st_v2_sync_billing('evt_readonly_fixture','b1150000-0000-4000-8000-000000000001','cus_ReadonlySQL',
  'sub_ReadonlySQL','business','past_due',now()-interval '1 hour',false,now());

do $$
declare
  owner_id constant uuid:='b1150000-0000-4000-8000-000000000001';
  member_id constant uuid:='b1150000-0000-4000-8000-000000000002';
  tenant constant uuid:='b1150000-0000-4000-8000-000000000011';
  independent constant uuid:='b1150000-0000-4000-8000-000000000012';
  room constant uuid:='b1150000-0000-4000-8000-000000000021';
  channel constant uuid:='b1150000-0000-4000-8000-000000000022';
  shared_group_key constant uuid:='b1150000-0000-4000-8000-000000000040';
  details jsonb;
  prior_hour constant timestamptz:=date_trunc('hour',now(),'UTC')-interval '1 hour';
begin
  if sectalk_private.st_v7_workspace_payment_mode(tenant)->>'mode'<>'grace' then
    raise exception 'Expected grace when configured period has time left'; end if;
  insert into public.st_v2_items(workspace_id,kind,title,created_by) values(tenant,'task','Grace period write',owner_id);
  update public.st_v2_subscriptions set period_end=now()-interval '30 days' where user_id=owner_id;
  if sectalk_private.st_v7_workspace_payment_mode(tenant)->>'mode'<>'read_only'
    or sectalk_private.st_v7_workspace_payment_mode(independent)->>'mode'<>'active' then
    raise exception 'Delinquency did not scope to the owning payer'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',member_id,'role','authenticated','aal','aal1',
    'session_id','b1150000-0000-4000-8000-000000000003')::text,true);
  set local role authenticated;
  details:=public.st_v7_workspace_payment_state(tenant);
  if details->>'mode'<>'read_only' then raise exception 'Member cannot see workspace mode'; end if;
  begin
    perform public.st_v6_room_post(room,gen_random_uuid(),'Blocked RPC write');
    raise exception 'Room RPC bypassed payment guard';
  exception when sqlstate 'PT423' then null; end;
  reset role;
  begin
    insert into public.st_v6_workspace_group_members(workspace_id,group_id,user_id) values(tenant,shared_group_key,member_id);
    raise exception 'A reused group identifier bypassed the owning workspace payment guard';
  exception when sqlstate 'PT423' then null; end;
  insert into public.st_v6_workspace_group_members(workspace_id,group_id,user_id) values(independent,shared_group_key,member_id);
  begin
    insert into public.st_v6_tasks(id,room_id,author_id,title) values(gen_random_uuid(),room,owner_id,'Direct insert');
    raise exception 'Direct task table bypassed payment guard';
  exception when sqlstate 'PT423' then null; end;
  begin
    update public.st_v2_items set title='Change existing task' where workspace_id=tenant;
    raise exception 'Task edits bypassed payment guard';
  exception when sqlstate 'PT423' then null; end;
  begin
    update public.st_v2_posts set body='Ordinary change' where channel_id=channel;
    raise exception 'Channel edits bypassed payment guard';
  exception when sqlstate 'PT423' then null; end;
  if (select body from public.st_v6_room_posts where room_id=room)<>'Keep this room record' then
    raise exception 'Read-only mode lost existing content'; end if;
  update public.st_v3_meetings set status='live' where id='b1150000-0000-4000-8000-000000000033';
  if not exists(select 1 from public.st_v3_meetings where id='b1150000-0000-4000-8000-000000000033' and status='live')
    then raise exception 'Previously scheduled meeting was blocked'; end if;
  update public.st_v2_posts set body='Message quarantined',quarantined_at=now() where channel_id=channel;
  update public.st_v2_members set suspended_at=now() where workspace_id=tenant and user_id=member_id;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(tenant,owner_id,'workspace.audit_export_requested');
  insert into public.st_v2_items(workspace_id,kind,title,created_by) values(independent,'task','Independent workspace write',member_id);
  update public.st_v2_subscriptions set status='canceled' where user_id=owner_id;
  if sectalk_private.st_v7_workspace_payment_mode(tenant)->>'mode'<>'active' then raise exception 'Voluntary cancellation locked workspace'; end if;
  insert into sectalk_private.st_v7_nonpayment_cancellations values('sub_ReadonlySQL',owner_id,'cus_ReadonlySQL',now());
  if sectalk_private.st_v7_workspace_payment_mode(tenant)->>'mode'<>'read_only' then raise exception 'Provider non-payment cancellation ignored'; end if;
  update public.st_v2_subscriptions set status='active',period_end=now()+interval '1 month' where user_id=owner_id;
  insert into public.st_v2_items(workspace_id,kind,title,created_by) values(tenant,'task','Recovered workspace write',owner_id);
  update public.st_v2_subscriptions set plan='enterprise',status='past_due',period_end=now()-interval '30 days' where user_id=owner_id;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'role','authenticated','aal','aal2',
    'session_id','b1150000-0000-4000-8000-000000000005')::text,true);
  set local role authenticated;
  if public.st_v7_siem_batch(tenant,prior_hour,'download') is null then raise exception 'Existing SIEM export unavailable'; end if;
  begin
    perform public.st_v7_siem_batch(tenant,prior_hour,'webhook');
    raise exception 'New SIEM connector send was accepted';
  exception when sqlstate 'PT423' then null; end;
  reset role;
end $$;
rollback;
