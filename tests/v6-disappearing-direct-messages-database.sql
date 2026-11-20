begin;
insert into auth.users(id,email) values
 ('7fb00000-0000-4000-8000-000000000001','expiry-first@example.invalid'),
 ('7fb00000-0000-4000-8000-000000000002','expiry-second@example.invalid'),
 ('7fb00000-0000-4000-8000-000000000003','expiry-other@example.invalid');
insert into public.st_profiles(id,handle,name) values
 ('7fb00000-0000-4000-8000-000000000001','expiry_first','Expiry first'),
 ('7fb00000-0000-4000-8000-000000000002','expiry_second','Expiry second'),
 ('7fb00000-0000-4000-8000-000000000003','expiry_other','Expiry other');
insert into public.st_chats(id,member_a,member_b,requester,status) values
 ('7fb10000-0000-4000-8000-000000000001','7fb00000-0000-4000-8000-000000000001',
  '7fb00000-0000-4000-8000-000000000002','7fb00000-0000-4000-8000-000000000001','accepted'),
 ('7fb10000-0000-4000-8000-000000000002','7fb00000-0000-4000-8000-000000000001',
  '7fb00000-0000-4000-8000-000000000003','7fb00000-0000-4000-8000-000000000001','accepted');
create function pg_temp.expiry_actor(n integer) returns void language sql as $$
 select set_config('request.jwt.claims',jsonb_build_object('sub','7fb00000-0000-4000-8000-00000000000'||n,'aal','aal1')::text,true)::text::void
$$;

do $$
declare
 chat constant uuid:='7fb10000-0000-4000-8000-000000000001';
 other constant uuid:='7fb10000-0000-4000-8000-000000000002';
 message constant uuid:='7fb20000-0000-4000-8000-000000000001';
 ordinary constant uuid:='7fb20000-0000-4000-8000-000000000002';
 past constant uuid:='7fb20000-0000-4000-8000-000000000003';
 longest constant uuid:='7fb20000-0000-4000-8000-000000000004';
 author constant uuid:='7fb00000-0000-4000-8000-000000000001';
 recipient constant uuid:='7fb00000-0000-4000-8000-000000000002';
 report_key uuid;
 seconds integer;
begin
 set local role authenticated;
 if has_column_privilege('authenticated','public.st_messages','expires_at','update') then
   raise exception 'Participants can rewrite expiry directly'; end if;
 perform pg_temp.expiry_actor(3);
 begin perform public.st_v6_send_disappearing_message(chat,message,'Unrelated message',60);
   raise exception 'Outsider sent a timed message'; exception when insufficient_privilege then null; end;
 perform pg_temp.expiry_actor(1);
 foreach seconds in array array[0,59,604801] loop
   begin perform public.st_v6_send_disappearing_message(chat,message,'Invalid duration',seconds);
     raise exception 'Duration exceeded the bounds'; exception when invalid_parameter_value then null; end;
 end loop;
 perform public.st_v6_send_disappearing_message(chat,message,'Unique transient content',60);
 perform public.st_v6_send_disappearing_message(chat,message,'Unique transient content',60);
 if (select count(*) from public.st_messages m where m.id=message and m.expires_at-m.created_at=interval '60 seconds')<>1 then
   raise exception 'Retry duplicated the message or changed its deadline'; end if;
 begin perform public.st_v6_send_disappearing_message(chat,message,'Unique transient content',604800);
   raise exception 'Retry extended the deadline'; exception when invalid_parameter_value then null; end;
 perform public.st_v6_send_disappearing_message(chat,longest,'Maximum timer fixture',604800);
 if (select m.expires_at-m.created_at from public.st_messages m where m.id=longest) is distinct from interval '7 days' then
   raise exception 'Maximum policy timer was not allowed'; end if;
 perform public.st_v2_send_reply(chat,ordinary,'Durable response',message);
 begin perform public.st_v2_edit_message(message,'Stored history');
   raise exception 'Ephemeral edit was accepted' using errcode='XX000'; exception when raise_exception then null; end;
 begin perform public.st_v6_forward_direct(chat,message,other,gen_random_uuid());
   raise exception 'Ephemeral body could be forwarded' using errcode='XX000'; exception when raise_exception then null; end;
 begin perform public.st_v6_task_create(gen_random_uuid(),null,chat,'Copy ephemeral',message);
   raise exception 'Ephemeral body copied into a task' using errcode='XX000'; exception when raise_exception then null; end;
 begin insert into public.st_v6_saved_messages(message_id) values(message);
   raise exception 'Ephemeral message was saved'; exception when insufficient_privilege then null; end;
 perform pg_temp.expiry_actor(2);
 if (select body from public.st_v6_reply_quotes(chat,array[message])) is distinct from 'Unique transient content'
 or (select expires_at from public.st_v6_reply_quotes(chat,array[message])) is null then
   raise exception 'Active quotes lack a time boundary'; end if;
 if exists(select from public.st_v6_search('Unique transient content','direct','{}'))
 or exists(select from public.st_v2_search_messages(chat,'Unique transient content'))
 or exists(select from public.st_v3_search('Unique transient content','direct')) then raise exception 'A search indexed ephemeral plaintext'; end if;
 report_key:=public.st_v5_report(chat,message,'harassment','Safety report without transient text');
 reset role;
 if (select r.evidence from public.st_reports r where r.id=report_key) is not null then
   raise exception 'A direct report persisted the transient message body'; end if;
 insert into public.st_messages(id,chat_id,sender,body,created_at,expires_at)
   values(past,chat,author,'Expired plaintext',statement_timestamp()-interval '61 seconds',statement_timestamp()-interval '1 second');
 if (select m.revoked_at from public.st_messages m where m.id=past) is not null then raise exception 'Fixture was already scrubbed'; end if;
 set local role authenticated;
 perform pg_temp.expiry_actor(2);
 if exists(select from public.st_messages m where m.id=past)
 or exists(select from public.st_v6_reply_quotes(chat,array[past]))
 or exists(select from public.st_v2_inbox_status() where latest_id=past) then
   raise exception 'Expired data leaked before the worker ran'; end if;
 begin perform public.st_v2_send_reply(chat,gen_random_uuid(),'Reply to expired text',past);
   raise exception 'Reply accepted expired source' using errcode='XX000'; exception when raise_exception then null; end;
 begin perform sectalk_private.st_v6_expire_direct_messages();
   raise exception 'Ordinary peer ran worker'; exception when insufficient_privilege then null; end;
 reset role;
 perform sectalk_private.st_v6_expire_direct_messages();
 perform sectalk_private.st_v6_expire_direct_messages();
 if not exists(select from public.st_messages m where m.id=past and m.body='Message removed' and m.revoked_at is not null)
 or not exists(select from public.st_messages m where m.id=ordinary and m.body='Durable response' and m.revoked_at is null)
 or exists(select from realtime.messages where topic in ('st:account:'||author,'st:account:'||recipient)
   and (payload::text like '%Unique transient content%' or payload::text like '%Expired plaintext%')) then
   raise exception 'Expiry failed to scrub text, preserved the wrong row, or disclosed plaintext in notifications'; end if;
 if not exists(select from cron.job where jobname='sectalk-v6-disappear-direct-messages' and active) then
   raise exception 'Disappearance worker is not scheduled'; end if;
end $$;
rollback;
