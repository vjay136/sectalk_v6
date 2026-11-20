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


insert into auth.users(id,email,aud,role) values
 ('67000000-0000-4000-8000-000000000001','lifecycle-owner@example.invalid','authenticated','authenticated'),
 ('67000000-0000-4000-8000-000000000002','lifecycle-admin@example.invalid','authenticated','authenticated'),
 ('67000000-0000-4000-8000-000000000003','lifecycle-member@example.invalid','authenticated','authenticated'),
 ('67000000-0000-4000-8000-000000000004','lifecycle-outsider@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
 ('67000000-0000-4000-8000-000000000001','lifecycle_qa_owner','Lifecycle owner'),
 ('67000000-0000-4000-8000-000000000002','lifecycle_qa_admin','Lifecycle admin'),
 ('67000000-0000-4000-8000-000000000003','lifecycle_qa_member','Lifecycle member'),
 ('67000000-0000-4000-8000-000000000004','lifecycle_qa_outsider','Lifecycle outsider');

set local role authenticated;
do $$
declare
  owner_id constant uuid:='67000000-0000-4000-8000-000000000001';
  admin_id constant uuid:='67000000-0000-4000-8000-000000000002';
  member_id constant uuid:='67000000-0000-4000-8000-000000000003';
  outsider_id constant uuid:='67000000-0000-4000-8000-000000000004';
  room constant uuid:=gen_random_uuid();
  restricted_room constant uuid:=gen_random_uuid();
  admin_room constant uuid:=gen_random_uuid();
  workspace uuid;
  restricted_workspace uuid;
  invitation uuid;
begin
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  workspace:=public.st_v2_create_workspace('Room lifecycle acceptance');
  perform public.st_v2_invite(workspace,'lifecycle_qa_admin');
  perform public.st_v2_invite(workspace,'lifecycle_qa_member');
  perform public.st_v6_room_create(room,workspace,'Room lifecycle','public','blank');
  perform public.st_v6_room_create(admin_room,workspace,'Admin room lifecycle','admin','incident');
  perform public.st_v6_room_post(room,gen_random_uuid(),'Room lifecycle retention fixture');
  perform set_config('request.jwt.claim.sub',outsider_id::text,true);
  restricted_workspace:=public.st_v6_create_typed_workspace(gen_random_uuid(),'Restricted room lifecycle','school');
  perform public.st_v6_room_create(restricted_room,restricted_workspace,'Restricted room','private','blank');
  begin
    perform public.st_v6_manage_room(restricted_room,'visibility','public');
    raise exception 'Expected policy to prevent public visibility';
  exception when raise_exception then
    if sqlerrm not like 'This workspace policy requires%' then raise; end if;
  end;

  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  select id into invitation from public.st_v2_invites where workspace_id=workspace and invitee=admin_id;
  perform public.st_v2_reply_invite(invitation,true);
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  select id into invitation from public.st_v2_invites where workspace_id=workspace and invitee=member_id;
  perform public.st_v2_reply_invite(invitation,true);
  perform public.st_v6_room_membership(room,'join');
  if exists(select 1 from public.st_v6_room_audit where room_id=room)
    or exists(select 1 from public.st_v6_room_management_audit(room)) then raise exception 'Member audit exposure'; end if;
  begin
    perform public.st_v6_manage_room(room,'archive');
    raise exception 'Expected member archive rejection';
  exception when raise_exception then
    if sqlerrm<>'Room management unavailable' then raise; end if;
  end;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform pg_temp.set_verified_member(workspace,admin_id,'admin');
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  perform public.st_v6_manage_room(room,'visibility','private');
  perform public.st_v6_manage_room(room,'visibility','private');
  if not exists(select 1 from public.st_v6_rooms where id=room and kind='private')
    or not exists(select 1 from public.st_v6_room_members where room_id=room and user_id=owner_id and role='owner')
    or not exists(select 1 from public.st_v6_room_management_audit(room) where action='membership.join' and target=member_id)
    or (select count(*) from public.st_v6_room_management_audit(room) where action='room.visibility'
      and details='{"from":"public","to":"private"}'::jsonb)<>1
    or exists(select 1 from public.st_v6_room_audit where room_id=room)
    or exists(select 1 from public.st_v6_room_posts where room_id=room)
    or public.st_v6_room_my_role(room) is not null then
    raise exception 'Manager directory, audit, or room content boundaries failed';
  end if;
  begin
    perform public.st_v6_manage_room(room,'transfer_owner',p_target=>admin_id);
    raise exception 'Expected transfer to non-member rejection';
  exception when raise_exception then
    if sqlerrm<>'Choose an active room member as the new owner' then raise; end if;
  end;
  perform public.st_v6_manage_room(room,'transfer_owner',p_target=>member_id);
  if not exists(select 1 from public.st_v6_room_members where room_id=room and user_id=owner_id and role='moderator')
    or (select count(*) from public.st_v6_room_members where room_id=room and role='owner')<>1
    or not exists(select 1 from public.st_v6_room_management_audit(room) where action='membership.transfer_owner'
      and actor=admin_id and target=member_id and details->'previous_owners'=jsonb_build_array(owner_id)) then
    raise exception 'Ownership transfer or audit failed';
  end if;
  perform public.st_v6_manage_room(admin_room,'archive');
  perform public.st_v6_manage_room(admin_room,'restore');
  perform public.st_v6_manage_room(room,'archive');

  perform set_config('request.jwt.claim.sub',outsider_id::text,true);
  if exists(select 1 from public.st_v6_rooms where id=room)
    or exists(select 1 from public.st_v6_room_members where room_id=room)
    or exists(select 1 from public.st_v6_room_management_audit(room))
    or exists(select 1 from public.st_v6_room_audit where room_id=room) then raise exception 'Cross-workspace metadata exposure'; end if;
  begin
    perform public.st_v6_manage_room(room,'restore');
    raise exception 'Expected outside workspace restore rejection';
  exception when raise_exception then
    if sqlerrm<>'Room management unavailable' then raise; end if;
  end;

  perform set_config('request.jwt.claim.sub',member_id::text,true);
  if public.st_v6_room_my_role(room) is distinct from 'owner'
    or not exists(select 1 from public.st_v6_room_posts where room_id=room) then raise exception 'Archived room access changed'; end if;
  begin
    perform public.st_v6_room_post(room,gen_random_uuid(),'Archived post');
    raise exception 'Expected archived post rejection';
  exception when raise_exception then
    if sqlerrm<>'Posting is unavailable' then raise; end if;
  end;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  perform public.st_v6_manage_room(room,'restore');
  if not exists(select 1 from public.st_v6_rooms where id=room and not archived)
    or not exists(select 1 from public.st_v6_room_management_audit(room) where action='room.restore') then
    raise exception 'Restore or restore audit failed';
  end if;
end $$;

rollback;
