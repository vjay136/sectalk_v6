begin;

insert into auth.users(id,email,aud,role) values
 ('d2100000-0000-4000-8000-000000000001','room-guest-owner@example.invalid','authenticated','authenticated'),
 ('d2100000-0000-4000-8000-000000000002','room-guest-other@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
 ('d2100000-0000-4000-8000-000000000001','roomguest_owner','Room guest test owner'),
 ('d2100000-0000-4000-8000-000000000002','roomguest_other','Room guest test other');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
 ('d2100000-0000-4000-8000-000000000011','d2100000-0000-4000-8000-000000000001','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
 ('d2100000-0000-4000-8000-000000000021','d2100000-0000-4000-8000-000000000001','aal2','d2100000-0000-4000-8000-000000000011');

do $$
declare
  owner_id constant uuid:='d2100000-0000-4000-8000-000000000001';
  other_id constant uuid:='d2100000-0000-4000-8000-000000000002';
  workspace uuid;
  room_id uuid:=gen_random_uuid();
  another_room uuid:=gen_random_uuid();
  shared uuid:=gen_random_uuid();
  not_shared uuid:=gen_random_uuid();
  foreign_post uuid:=gen_random_uuid();
  filtered jsonb;
  link uuid;
  ticket constant text:=repeat('1',64);
  cap constant text:=repeat('2',64);
begin
  if has_function_privilege('anon','public.st_v6_room_guest_command(text,uuid,uuid,uuid,text,text,uuid[])','execute')
    or has_function_privilege('authenticated','public.st_v6_room_guest_command(text,uuid,uuid,uuid,text,text,uuid[])','execute')
    or not has_function_privilege('service_role','public.st_v6_room_guest_command(text,uuid,uuid,uuid,text,text,uuid[])','execute')
    or has_table_privilege('anon','sectalk_private.st_v6_room_guest_capability','select')
    then raise exception 'Room guest service role boundary failed'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated','aal','aal2',
    'session_id','d2100000-0000-4000-8000-000000000021')::text,true);
  workspace:=public.st_v2_create_workspace('Rollback guest link fixture');
  perform public.st_v6_room_create(room_id,workspace,'Guest room fixture','public','blank');
  perform public.st_v6_room_create(another_room,workspace,'Other room fixture','public','blank');
  perform public.st_v6_room_post(room_id,shared,'Shared content');
  perform public.st_v6_room_post(room_id,not_shared,'Owner did not select this');
  perform public.st_v6_room_post(another_room,foreign_post,'Other room data');
  if public.st_v6_room_guest_command('create',room_id,owner_id,p_digest=>ticket,p_posts=>array[shared]) is not null
    then raise exception 'Default policy allowed guest creation'; end if;
  perform public.st_v6_set_room_classification(room_id,'public');
  perform public.st_v6_set_room_forwarding(room_id,true);
  if public.st_v6_room_guest_command('create',room_id,other_id,p_digest=>ticket,p_posts=>array[shared]) is not null
    or public.st_v6_room_guest_command('create',room_id,owner_id,p_digest=>ticket,p_posts=>array[foreign_post]) is not null
    then raise exception 'Non-owner or cross-room scope accepted'; end if;
  filtered:=public.st_v6_room_guest_command('create',room_id,owner_id,p_digest=>ticket,p_posts=>array[shared]);
  link:=(filtered->>'created')::uuid;
  if link is null or (filtered->'links'->0->>'expires_at')::timestamptz>clock_timestamp()+interval '10 minutes'
    or filtered::text like '%'||ticket||'%' then raise exception 'Link lease or digest exposure failed'; end if;
  filtered:=public.st_v6_room_guest_command('redeem',p_digest=>ticket,p_capability=>cap);
  if filtered->'posts' is distinct from '["Shared content"]'::jsonb
    or (filtered->>'expiresAt')::timestamptz>clock_timestamp()+interval '2 minutes' then raise exception 'Guest projection failed'; end if;
  if public.st_v6_room_guest_command('read',another_room,p_capability=>cap) is not null then raise exception 'Cross-room read accepted'; end if;
  if public.st_v6_room_guest_command('revoke',room_id,other_id,p_link=>link) is not null
    or public.st_v6_room_guest_command('revoke',another_room,owner_id,p_link=>link) is not null
    then raise exception 'Non-owner or cross-room revocation accepted'; end if;
  perform public.st_v6_room_post_action(room_id,shared,'edit','Changed after release');
  filtered:=public.st_v6_room_guest_command('read',p_capability=>cap);
  if filtered->'posts' is distinct from '[]'::jsonb then raise exception 'Changed post was still exposed'; end if;
  update sectalk_private.st_v6_room_guest_capability set expires_at=now()-interval '1 second' where secret_digest=cap;
  if public.st_v6_room_guest_command('read',p_capability=>cap) is not null then raise exception 'Expired capability accepted'; end if;
  perform public.st_v6_set_room_forwarding(room_id,false);
  perform public.st_v6_set_room_forwarding(room_id,true);
  if public.st_v6_room_guest_command('redeem',p_digest=>ticket,p_capability=>repeat('3',64)) is not null
    or (select revoked_at from sectalk_private.st_v6_room_guest_link where id=link) is null
    then raise exception 'Policy restoration revived an invalidated link'; end if;
  filtered:=public.st_v6_room_guest_command('create',room_id,owner_id,p_digest=>repeat('4',64),p_posts=>array[shared]);
  link:=(filtered->>'created')::uuid;
  if link is null or public.st_v6_room_guest_command('revoke',room_id,owner_id,p_link=>link) is null then
    raise exception 'Owner revocation failed';
  end if;
  if public.st_v6_room_guest_command('redeem',p_digest=>repeat('4',64),p_capability=>repeat('5',64)) is not null
    then raise exception 'Revoked link accepted'; end if;
  filtered:=public.st_v6_room_guest_command('create',room_id,owner_id,p_digest=>repeat('6',64),p_posts=>array[shared]);
  link:=(filtered->>'created')::uuid;
  update sectalk_private.st_v6_room_guest_link set expires_at=now()-interval '1 second' where id=link;
  if public.st_v6_room_guest_command('redeem',p_digest=>repeat('6',64),p_capability=>repeat('7',64)) is not null
    then raise exception 'Expired link accepted'; end if;
  filtered:=public.st_v6_room_guest_command('create',room_id,owner_id,p_digest=>repeat('8',64),p_posts=>array[shared]);
  link:=(filtered->>'created')::uuid;
  update public.st_v6_room_members m set role='member'
    where m.room_id=(select room from sectalk_private.st_v6_room_guest_link where id=link) and m.user_id=owner_id;
  update public.st_v6_room_members m set role='owner'
    where m.room_id=(select room from sectalk_private.st_v6_room_guest_link where id=link) and m.user_id=owner_id;
  if public.st_v6_room_guest_command('redeem',p_digest=>repeat('8',64),p_capability=>repeat('9',64)) is not null
    or (select revoked_at from sectalk_private.st_v6_room_guest_link where id=link) is null
    then raise exception 'Ownership restoration revived an invalidated link'; end if;
end
$$;

rollback;
