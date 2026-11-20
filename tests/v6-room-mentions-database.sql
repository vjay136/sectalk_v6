begin;

insert into auth.users(id,email,aud,role)
select id,handle||'@example.invalid','authenticated','authenticated'
from (values
  ('71000000-0000-4000-8000-000000000001'::uuid,'mention_owner'),
  ('71000000-0000-4000-8000-000000000002','mention_online'),
  ('71000000-0000-4000-8000-000000000003','mention_offline'),
  ('71000000-0000-4000-8000-000000000004','mention_muted'),
  ('71000000-0000-4000-8000-000000000005','mention_outside'),
  ('71000000-0000-4000-8000-000000000006','mention_blocked')
) fixture(id,handle);

insert into public.st_profiles(id,handle,name)
select id,split_part(email,'@',1),split_part(email,'@',1)
from auth.users where id::text like '71000000-0000-4000-8000-%';

do $$
declare
  owner_id constant uuid:='71000000-0000-4000-8000-000000000001';
  online_id constant uuid:='71000000-0000-4000-8000-000000000002';
  offline_id constant uuid:='71000000-0000-4000-8000-000000000003';
  muted_id constant uuid:='71000000-0000-4000-8000-000000000004';
  outside_id constant uuid:='71000000-0000-4000-8000-000000000005';
  blocked_id constant uuid:='71000000-0000-4000-8000-000000000006';
  room constant uuid:=gen_random_uuid();
  group_id constant uuid:=gen_random_uuid();
  overlap_post constant uuid:=gen_random_uuid();
  here_post constant uuid:=gen_random_uuid();
  channel_post constant uuid:=gen_random_uuid();
  member_post constant uuid:=gen_random_uuid();
  edge_post constant uuid:=gen_random_uuid();
  workspace uuid;
  other_workspace uuid;
begin
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  workspace:=public.st_v2_create_workspace('Mentions fixture workspace');
  perform set_config('request.jwt.claim.sub',outside_id::text,true);
  other_workspace:=public.st_v2_create_workspace('Other tenant fixture');
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform public.st_v6_room_create(room,workspace,'Mention fixture room','public','blank');

  insert into public.st_v2_members(workspace_id,user_id,role) values
    (workspace,online_id,'member'),(workspace,offline_id,'member'),(workspace,muted_id,'member'),
    (workspace,blocked_id,'member');
  insert into public.st_v6_room_members(room_id,user_id,role) values
    (room,online_id,'member'),(room,offline_id,'member'),(room,muted_id,'member'),
    (room,outside_id,'member'),(room,blocked_id,'member');
  insert into public.st_v6_workspace_groups(workspace_id,id,kind,name) values
    (workspace,group_id,'group','On Call "Ops"'),(other_workspace,group_id,'group','On Call "Ops"');
  insert into public.st_v6_workspace_group_members(workspace_id,group_id,user_id) values
    (workspace,group_id,online_id),(workspace,group_id,offline_id),(other_workspace,group_id,outside_id);
  insert into public.st_v3_presence(user_id,state,expires_at) values
    (online_id,'online',now()+interval '10 minutes'),(offline_id,'online',now()-interval '1 second');
  insert into public.st_blocks(actor,target) values(blocked_id,owner_id);

  perform set_config('request.jwt.claim.sub',muted_id::text,true);
  perform public.st_v6_set_room_quiet(room,'mute',true);
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform public.st_v6_room_post(room,overlap_post,
    '@MENTION_ONLINE, @group:"On Call ""Ops""" @here @channel @mention_muted @mention_outside @mention_blocked');
  perform public.st_v6_room_post(room,overlap_post,
    '@MENTION_ONLINE, @group:"On Call ""Ops""" @here @channel @mention_muted @mention_outside @mention_blocked');
  perform public.st_v6_room_post(room,here_post,'@here',p_parent=>overlap_post);
  perform public.st_v6_room_post(room,channel_post,'@channel');
  perform public.st_v6_room_post(room,edge_post,'mail@mention_online @@mention_online @mention_online_suffix');
  perform set_config('request.jwt.claim.sub',offline_id::text,true);
  perform public.st_v6_room_post(room,member_post,'@channel @here @group:"On Call ""Ops""" @mention_owner');

  if (select jsonb_object_agg(recipient,kind) from public.st_v3_notifications where room_post_id=overlap_post)
       is distinct from jsonb_build_object(online_id,'mention.user',offline_id,'mention.group')
     or (select count(*) from public.st_v3_notifications where room_post_id=overlap_post)<>2
     or (select jsonb_object_agg(recipient,kind) from public.st_v3_notifications where room_post_id=here_post)
       is distinct from jsonb_build_object(online_id,'mention.here')
     or (select jsonb_object_agg(recipient,kind) from public.st_v3_notifications where room_post_id=channel_post)
       is distinct from jsonb_build_object(online_id,'mention.channel',offline_id,'mention.channel')
     or exists(select 1 from public.st_v3_notifications where room_post_id=edge_post)
     or (select jsonb_object_agg(recipient,kind) from public.st_v3_notifications where room_post_id=member_post)
       is distinct from jsonb_build_object(owner_id,'mention.user') then
    raise exception 'Incorrect mention routing, deduplication, permissions, priority, quiet hours, or boundaries';
  end if;

  if (select count(*) from realtime.messages where event='room_activity' and topic='st:account:'||online_id
    and payload->>'room_id'=room::text and payload->>'mention_kind'='mention.user' and private)<>1 then
    raise exception 'Expected one private direct-mention alert';
  end if;

  perform set_config('request.jwt.claim.sub',online_id::text,true);
  set local role authenticated;
  if (select count(*) from public.st_v3_notifications where room_id=room)<>3 then
    raise exception 'Recipient could not read their own notifications or read another user''s notifications';
  end if;
  perform public.st_v3_mark_notification(null,'meeting');
  if exists(select 1 from public.st_v3_notifications where room_id=room and read_at is not null) then
    raise exception 'Meeting read action also marked mentions';
  end if;
  perform public.st_v3_mark_notification(null,'mention');
  if exists(select 1 from public.st_v3_notifications where room_id=room and read_at is null) then
    raise exception 'Mention read action failed';
  end if;
  reset role;

  update public.st_v6_room_posts set body='Message removed',removed_at=clock_timestamp() where id=here_post and room_id=room;
  set local role authenticated;
  if exists(select 1 from public.st_v3_notifications where room_post_id=here_post) then
    raise exception 'A removed post remained visible in notifications';
  end if;
  reset role;
  delete from public.st_v6_room_members where room_id=room and user_id=online_id;
  set local role authenticated;
  if exists(select 1 from public.st_v3_notifications where room_id=room) then
    raise exception 'A former room member could still read room notifications';
  end if;
end $$;

select 'passed: mention routing, priority, permissions, tenant isolation, quiet hours, and notification access' as result;
rollback;
