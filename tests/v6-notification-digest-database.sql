begin;

insert into auth.users(id,email,aud,role) values
  ('72000000-0000-4000-8000-000000000001','digest-caller@example.invalid','authenticated','authenticated'),
  ('72000000-0000-4000-8000-000000000002','digest-recipient@example.invalid','authenticated','authenticated'),
  ('72000000-0000-4000-8000-000000000003','digest-outsider@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('72000000-0000-4000-8000-000000000001','digest_caller','Digest Caller'),
  ('72000000-0000-4000-8000-000000000002','digest_recipient','Digest Recipient'),
  ('72000000-0000-4000-8000-000000000003','digest_outsider','Digest Outsider');

do $$
declare
  caller_id constant uuid:='72000000-0000-4000-8000-000000000001';
  recipient_id constant uuid:='72000000-0000-4000-8000-000000000002';
  outsider_id constant uuid:='72000000-0000-4000-8000-000000000003';
  chat constant uuid:=gen_random_uuid();
  room constant uuid:=gen_random_uuid();
  recent_call constant uuid:=gen_random_uuid();
  older_call constant uuid:=gen_random_uuid();
  newer_mention constant uuid:=gen_random_uuid();
  older_mention constant uuid:=gen_random_uuid();
  workspace uuid;
begin
  if has_function_privilege('anon','public.st_v6_notification_digest(integer)','execute') then
    raise exception 'Anonymous digest execution is available';
  end if;

  insert into public.st_chats(id,member_a,member_b,requester,status)
  values(chat,caller_id,recipient_id,caller_id,'accepted');
  insert into public.st_calls(id,chat_id,caller,callee,status,end_reason,video,expires_at,created_at)
  values(recent_call,chat,caller_id,recipient_id,'ringing',null,true,now()-interval '1 minute',now()-interval '2 minutes'),
    (older_call,chat,caller_id,recipient_id,'ended','missed',false,now()-interval '2 days',now()-interval '2 days'),
    (gen_random_uuid(),chat,caller_id,recipient_id,'ended','missed',false,now()-interval '8 days',now()-interval '8 days'),
    (gen_random_uuid(),chat,recipient_id,caller_id,'ended','missed',false,now()-interval '1 day',now()-interval '1 day'),
    (gen_random_uuid(),chat,caller_id,recipient_id,'ringing',null,false,now()+interval '1 minute',now()),
    (gen_random_uuid(),chat,caller_id,recipient_id,'ended','declined',false,now(),now());

  perform set_config('request.jwt.claim.sub',caller_id::text,true);
  workspace:=public.st_v2_create_workspace('Digest workspace');
  perform public.st_v6_room_create(room,workspace,'Digest room','private','blank');
  insert into public.st_v2_members(workspace_id,user_id,role)
  values(workspace,recipient_id,'member'),(workspace,outsider_id,'member');
  insert into public.st_v6_room_members(room_id,user_id,role) values(room,recipient_id,'member');
  perform public.st_v6_room_post(room,newer_mention,'Hi @digest_recipient');
  perform public.st_v6_room_post(room,older_mention,'Older note for @digest_recipient');
  update public.st_v3_notifications set created_at=now()-interval '2 days'
  where room_post_id=older_mention;

  set local role authenticated;
  perform set_config('request.jwt.claim.sub',recipient_id::text,true);
  if (select count(*) from public.st_v6_notification_digest(1))<>2
    or (select count(*) from public.st_v6_notification_digest(7))<>4
    or not exists(select 1 from public.st_v6_notification_digest(1) d
      where d.id=recent_call::text and d.kind='call.missed' and d.video and d.chat_id=chat and d.label='Digest Caller')
    or not exists(select 1 from public.st_v6_notification_digest(1) d
      where d.kind='mention.user' and d.room_id=room and d.workspace_id=workspace and d.label='Digest room')
    or exists(select 1 from public.st_v6_notification_digest(99)) then
    raise exception 'Digest buckets, periods, or navigation details are incorrect';
  end if;

  perform set_config('request.jwt.claim.sub',caller_id::text,true);
  if (select count(*) from public.st_v6_notification_digest(7))<>1 then
    raise exception 'The caller can see outgoing missed calls or someone else''s mentions';
  end if;
  perform set_config('request.jwt.claim.sub',outsider_id::text,true);
  if exists(select 1 from public.st_v6_notification_digest(7)) then
    raise exception 'A workspace peer could read someone else''s digest';
  end if;
  reset role;
  delete from public.st_v6_room_members where room_id=room and user_id=recipient_id;
  set local role authenticated;
  perform set_config('request.jwt.claim.sub',recipient_id::text,true);
  if exists(select 1 from public.st_v6_notification_digest(7) where kind like 'mention.%') then
    raise exception 'Room mentions remained visible after room access was revoked';
  end if;
end $$;

select 'passed: digest periods, incoming missed-call semantics, private mention access and recipient isolation' as result;
rollback;
