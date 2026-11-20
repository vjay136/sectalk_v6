begin;

insert into auth.users(id,email,aud,role) values
 ('70000000-0000-4000-8000-000000000001','room-quiet-sender@example.invalid','authenticated','authenticated'),
 ('70000000-0000-4000-8000-000000000002','room-quiet-recipient@example.invalid','authenticated','authenticated'),
 ('70000000-0000-4000-8000-000000000003','room-quiet-outsider@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
 ('70000000-0000-4000-8000-000000000001','room_quiet_sender','Sender'),
 ('70000000-0000-4000-8000-000000000002','room_quiet_recipient','Recipient'),
 ('70000000-0000-4000-8000-000000000003','room_quiet_outsider','Outsider');

do $$
declare
  sender constant uuid:='70000000-0000-4000-8000-000000000001';
  recipient constant uuid:='70000000-0000-4000-8000-000000000002';
  outsider constant uuid:='70000000-0000-4000-8000-000000000003';
  room constant uuid:=gen_random_uuid();
  workspace uuid;
  channel uuid;
  invitation uuid;
  first_post uuid:=gen_random_uuid();
  local_time time:=(now() at time zone 'UTC')::time;
begin
  perform set_config('request.jwt.claim.sub',sender::text,true);
  workspace:=public.st_v2_create_workspace('Quiet preferences test');
  select id into channel from public.st_v2_channels where workspace_id=workspace and name='general';
  perform public.st_v2_invite(workspace,'room_quiet_recipient');
  perform public.st_v6_room_create(room,workspace,'Quiet room','public','blank');
  select id into invitation from public.st_v2_invites where workspace_id=workspace;

  perform set_config('request.jwt.claim.sub',outsider::text,true);
  begin
    perform public.st_v6_set_room_quiet(room,'mute',true);
    raise exception 'Outsider changed quiet rules' using errcode='P0100';
  exception when sqlstate 'P0001' then null; end;
  begin
    perform public.st_v6_set_channel_quiet(channel,'mute',true);
    raise exception 'Outsider changed channel quiet rules' using errcode='P0100';
  exception when sqlstate 'P0001' then null; end;

  perform set_config('request.jwt.claim.sub',recipient::text,true);
  perform public.st_v2_reply_invite(invitation,true);
  perform public.st_v6_room_membership(room,'join');
  perform public.st_v6_set_room_quiet(room,'mute',true);
  if not (public.st_v6_room_quiet_settings(room)->>'active')::boolean then
    raise exception 'Room mute was ineffective';
  end if;
  perform set_config('request.jwt.claim.sub',sender::text,true);
  if (public.st_v6_room_quiet_settings(room)->>'active')::boolean then
    raise exception 'Another user inherited the room mute';
  end if;
  perform public.st_v6_room_post(room,first_post,'Secret fixture text');

  perform set_config('request.jwt.claim.sub',recipient::text,true);
  perform public.st_v6_set_room_quiet(room,'mute',false);
  perform public.st_v6_set_room_quiet(room,'snooze',p_minutes=>30);
  if not (public.st_v6_room_quiet_settings(room)->>'active')::boolean then
    raise exception 'Room snooze was ineffective';
  end if;
  perform public.st_v6_set_room_quiet(room,'snooze',p_minutes=>0);
  perform public.st_v6_set_room_quiet(room,'schedule',p_days=>array[1,2,3,4,5,6,7]::smallint[],
    p_start=>local_time-interval '1 hour',p_end=>local_time+interval '1 hour',p_zone=>'UTC');
  if not (public.st_v6_room_quiet_settings(room)->>'active')::boolean then
    raise exception 'Room schedule was ineffective';
  end if;
  perform public.st_v6_set_room_quiet(room,'schedule');
  perform public.st_v6_set_quiet_mute(null,true);
  perform set_config('request.jwt.claim.sub',sender::text,true);
  perform public.st_v6_room_post(room,gen_random_uuid(),'Quiet global message');
  perform set_config('request.jwt.claim.sub',recipient::text,true);
  perform public.st_v6_set_quiet_mute(null,false);
  perform set_config('request.jwt.claim.sub',sender::text,true);
  perform public.st_v6_room_post(room,gen_random_uuid(),'Visible reply',p_parent=>first_post);
  perform set_config('request.jwt.claim.sub',recipient::text,true);
  perform public.st_v6_set_channel_quiet(channel,'mute',true);
  if not (public.st_v6_channel_quiet_settings(channel)->>'active')::boolean
    or (public.st_v6_room_quiet_settings(room)->>'active')::boolean then
    raise exception 'Channel quiet rule crossed scopes';
  end if;
  perform set_config('request.jwt.claim.sub',sender::text,true);
  perform public.st_v2_post(channel,gen_random_uuid(),'Muted channel message');
  perform set_config('request.jwt.claim.sub',recipient::text,true);
  perform public.st_v6_set_channel_quiet(channel,'mute',false);
  perform set_config('request.jwt.claim.sub',sender::text,true);
  perform public.st_v2_post(channel,gen_random_uuid(),'Visible channel message');

  if (select count(*) from realtime.messages where event='room_activity' and payload->>'room_id'=room::text)<>1
    or not exists(select 1 from realtime.messages where event='room_activity' and private
      and topic='st:account:'||recipient and payload-'id'=jsonb_build_object('room_id',room))
    then raise exception 'Room alert recipients, suppression, or metadata retention were incorrect'; end if;
  if (select count(*) from realtime.messages where event='channel_activity' and payload->>'channel_id'=channel::text)<>1
    or not exists(select 1 from realtime.messages where event='channel_activity' and private
      and topic='st:account:'||recipient and payload-'id'=jsonb_build_object('channel_id',channel))
    then raise exception 'Channel alert recipients, suppression, or metadata retention were incorrect'; end if;
  if (select count(*) from public.st_v6_room_posts where room_id=room)<>3 then
    raise exception 'Quiet notifications unexpectedly suppressed room messages';
  end if;
end $$;

select 'passed: room quiet scope, recipient-only minimal broadcast, and retained posts' as result;
rollback;
