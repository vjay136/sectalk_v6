begin;

-- Set up a fresh TOTP session for a roster mutation in this SQL fixture.
create function pg_temp.set_verified_member(p_workspace uuid,p_member uuid,p_role text)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); session_id uuid:=gen_random_uuid(); factor_id uuid;
  prior text:=current_setting('request.jwt.claims',true);
begin
  select f.id into factor_id from auth.mfa_factors f
    where f.user_id=actor and f.status='verified' and f.factor_type='totp' limit 1;
  if factor_id is null then
    factor_id:=gen_random_uuid();
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor,'totp','verified',now(),now());
  end if;
  insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor,'aal2',factor_id);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),session_id,'totp',now(),now());
  perform set_config('request.jwt.claims',jsonb_build_object('sub',actor,'role','authenticated','session_id',session_id,'aal','aal2')::text,true);
  perform public.st_v2_set_member(p_workspace,p_member,p_role);
  perform set_config('request.jwt.claims',coalesce(prior,''),true);
end $$;


insert into auth.users(id,email) values
  ('7b000000-0000-4000-8000-000000000001','audit-admin-owner@example.invalid'),
  ('7b000000-0000-4000-8000-000000000002','audit-admin-recipient@example.invalid'),
  ('7b000000-0000-4000-8000-000000000003','audit-admin-quiet@example.invalid'),
  ('7b000000-0000-4000-8000-000000000004','audit-admin-outsider@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('7b000000-0000-4000-8000-000000000001','audit_admin_owner','Owner'),
  ('7b000000-0000-4000-8000-000000000002','audit_admin_recipient','Recipient'),
  ('7b000000-0000-4000-8000-000000000003','audit_admin_quiet','Quiet'),
  ('7b000000-0000-4000-8000-000000000004','audit_admin_outsider','Outsider');

do $$
declare
  owner_id constant uuid:='7b000000-0000-4000-8000-000000000001';
  recipient_id constant uuid:='7b000000-0000-4000-8000-000000000002';
  quiet_id constant uuid:='7b000000-0000-4000-8000-000000000003';
  outsider_id constant uuid:='7b000000-0000-4000-8000-000000000004';
  admin_room constant uuid:=gen_random_uuid();
  ordinary_room constant uuid:=gen_random_uuid();
  announced_post constant uuid:=gen_random_uuid();
  small_post constant uuid:=gen_random_uuid();
  workspace uuid;
  receipt_id uuid;
  acknowledged_at timestamptz;
begin
  if has_function_privilege('anon','public.st_v6_admin_notification_audit(uuid)','execute')
    or has_function_privilege('anon','public.st_v6_ack_admin_notification(uuid)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v6_admin_notification_receipts','select,insert,update,delete')
    or has_table_privilege('authenticated','sectalk_private.st_v6_admin_notification_runs','select,insert,update,delete') then
    raise exception 'Admin notification audit grants are too broad';
  end if;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  workspace:=public.st_v2_create_workspace('Admin delivery audit workspace');
  insert into public.st_v2_members(workspace_id,user_id,role)
    values(workspace,recipient_id,'admin'),(workspace,quiet_id,'admin'),(workspace,outsider_id,'member');
  perform public.st_v6_room_create(admin_room,workspace,'Admin room','admin','blank');
  perform public.st_v6_room_create(ordinary_room,workspace,'Public room','public','blank');
  perform public.st_v6_room_post(ordinary_room,gen_random_uuid(),'Ordinary room post');
  perform set_config('request.jwt.claim.sub',quiet_id::text,true);
  perform public.st_v6_set_notification_preference('admin',false);
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform public.st_v6_room_post(admin_room,announced_post,'Admin message content');

  select r.id into receipt_id from sectalk_private.st_v6_admin_notification_receipts r
  where r.room_id=admin_room and r.post_id=announced_post and r.recipient=recipient_id;
  if receipt_id is null
    or (select count(*) from sectalk_private.st_v6_admin_notification_receipts r where r.room_id=admin_room)<>1
    or exists(select 1 from sectalk_private.st_v6_admin_notification_runs r where r.room_id=ordinary_room)
    or not exists(select 1 from realtime.messages message where message.event='category_alert'
      and message.private and message.topic='st:account:'||recipient_id and message.payload->>'receipt_id'=receipt_id::text
      and message.payload-'id' = jsonb_build_object('receipt_id',receipt_id,'kind','admin.room','priority','normal')) then
    raise exception 'Incorrect receipt generation, privacy, or alert routing';
  end if;

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',outsider_id::text,true);
  perform public.st_v6_ack_admin_notification(receipt_id);
  if exists(select 1 from public.st_v6_admin_notification_audit(admin_room)) then
    raise exception 'A non-admin can inspect admin notification delivery';
  end if;
  perform set_config('request.jwt.claim.sub',quiet_id::text,true);
  perform public.st_v6_ack_admin_notification(receipt_id);
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  if not exists(select 1 from public.st_v6_admin_notification_audit(admin_room) a where a.post_id=announced_post
    and a.sender=owner_id and a.status='unconfirmed') then
    raise exception 'A different account acknowledged the receipt';
  end if;
  perform set_config('request.jwt.claim.sub',recipient_id::text,true);
  perform public.st_v6_ack_admin_notification(receipt_id);
  reset role;
  select received_at into acknowledged_at from sectalk_private.st_v6_admin_notification_receipts where id=receipt_id;
  if acknowledged_at is null then raise exception 'The recipient receipt did not persist'; end if;
  perform public.st_v6_ack_admin_notification(receipt_id);
  if (select received_at from sectalk_private.st_v6_admin_notification_receipts where id=receipt_id)
    is distinct from acknowledged_at then raise exception 'Receipt replay changed its timestamp'; end if;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform pg_temp.set_verified_member(workspace,quiet_id,'member');
  perform public.st_v6_room_post(admin_room,small_post,'Small audience');
  select r.id into receipt_id from sectalk_private.st_v6_admin_notification_receipts r
  where r.room_id=admin_room and r.post_id=small_post and r.recipient=recipient_id;
  set local role authenticated;
  perform set_config('request.jwt.claim.sub',recipient_id::text,true);
  perform public.st_v6_ack_admin_notification(receipt_id);
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  if not exists(select 1 from public.st_v6_admin_notification_audit(admin_room) a
      where a.post_id=announced_post and a.status='acknowledged')
    or not exists(select 1 from public.st_v6_admin_notification_audit(admin_room) a
      where a.post_id=small_post and a.status='processed') then
    raise exception 'Confirmed or single-recipient audit status is incorrect';
  end if;
  perform set_config('request.jwt.claim.sub',quiet_id::text,true);
  if exists(select 1 from public.st_v6_admin_notification_audit(admin_room)) then
    raise exception 'A demoted admin retained audit access';
  end if;
end $$;

select 'passed: admin delivery audit, receipt ownership, durable status, and small-audience privacy' as result;
rollback;
