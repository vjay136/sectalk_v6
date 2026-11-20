begin;
insert into auth.users(id,email) values
  ('79000000-0000-4000-8000-000000000001','sequence-alex@example.invalid'),
  ('79000000-0000-4000-8000-000000000002','sequence-billie@example.invalid'),
  ('79000000-0000-4000-8000-000000000003','sequence-casey@example.invalid');
insert into public.st_profiles(id,name,handle) values
  ('79000000-0000-4000-8000-000000000001','Sequence Alex','sequence_alex'),
  ('79000000-0000-4000-8000-000000000002','Sequence Billie','sequence_billie'),
  ('79000000-0000-4000-8000-000000000003','Sequence Casey','sequence_casey');

do $$
declare
  alex constant uuid:='79000000-0000-4000-8000-000000000001';
  billie constant uuid:='79000000-0000-4000-8000-000000000002';
  casey constant uuid:='79000000-0000-4000-8000-000000000003';
  first_msg constant uuid:='79000001-0000-4000-8000-000000000002';
  reply_msg constant uuid:='79000001-0000-4000-8000-000000000001';
  schedule_msg constant uuid:='79000001-0000-4000-8000-000000000003';
  attachment_msg constant uuid:='79000001-0000-4000-8000-000000000004';
  before_remove constant uuid:='79000001-0000-4000-8000-000000000005';
  after_remove constant uuid:='79000001-0000-4000-8000-000000000006';
  other_msg constant uuid:='79000001-0000-4000-8000-000000000007';
  conversation uuid;
  other uuid;
begin
  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',alex,'role','authenticated')::text,true);
  conversation:=public.st_request('sequence_billie');
  other:=public.st_request('sequence_casey');
  perform set_config('request.jwt.claims',json_build_object('sub',billie,'role','authenticated')::text,true);
  perform public.st_respond(conversation,true);
  perform set_config('request.jwt.claims',json_build_object('sub',casey,'role','authenticated')::text,true);
  perform public.st_respond(other,true);
  perform set_config('request.jwt.claims',json_build_object('sub',alex,'role','authenticated')::text,true);
  perform public.st_send(conversation,first_msg,'Ordered first');
  perform public.st_send(conversation,first_msg,'Ordered first');
  perform public.st_v2_send_reply(conversation,reply_msg,'Ordered reply',first_msg);
  perform public.st_v2_send_reply(conversation,reply_msg,'Ordered reply',first_msg);
  perform public.st_v6_schedule_message(conversation,schedule_msg,'Ordered scheduled',now()+interval '1 hour');
  perform public.st_v5_stage_file(conversation,attachment_msg,'proof.txt',10);
  insert into storage.objects(bucket_id,name,metadata) values('sectalk-chat-files',attachment_msg::text,'{"size":10}'::jsonb);
  begin
    perform public.st_send(other,first_msg,'Other conversation');
    raise exception 'Cross-conversation ID collision was accepted' using errcode='P0004';
  exception when raise_exception then null;
  end;
  perform public.st_send(other,other_msg,'Independent sequence');
  if (select sequence from public.st_messages where id=other_msg) is distinct from 1::bigint
    then raise exception 'Collision consumed a sequence or counters were shared'; end if;

  reset role;
  update public.st_v6_scheduled_messages set send_at=now()-interval '1 minute' where id=schedule_msg;
  perform sectalk_private.st_v6_dispatch_scheduled_messages();
  set local role service_role;
  perform public.st_v6_publish_validated_file(attachment_msg,alex,'Ordered attachment');
  reset role;
  -- Conflicting creation times leave server sequence and the read cursor unchanged.
  update public.st_messages set created_at=now()-interval '1 hour' where id=reply_msg;
  if (select array_agg(id order by sequence) from public.st_messages where chat_id=conversation)
    is distinct from array[first_msg,reply_msg,schedule_msg,attachment_msg]
    or (select array_agg(sequence order by sequence) from public.st_messages where chat_id=conversation)
    is distinct from array[1,2,3,4]::bigint[]
    then raise exception 'Normal, duplicate, reply, scheduled, or attachment writes did not form a contiguous timeline'; end if;

  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',billie,'role','authenticated')::text,true);
  perform public.st_v2_read(conversation,reply_msg);
  perform public.st_v2_read(conversation,first_msg);
  perform set_config('request.jwt.claims',json_build_object('sub',alex,'role','authenticated')::text,true);
  if public.st_v2_chat_status(conversation)->>'read_sequence' is distinct from '2'
    then raise exception 'An older message moved the read sequence backward'; end if;
  perform public.st_send(conversation,before_remove,'Removed sequence will not be reused');
  reset role;
  delete from public.st_messages where id=before_remove;
  set local role authenticated;
  perform public.st_send(conversation,after_remove,'Ordered after removal');
  if (select sequence from public.st_messages where id=after_remove) is distinct from 6::bigint
    then raise exception 'A removed sequence was reused'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',casey,'role','authenticated')::text,true);
  if exists(select 1 from public.st_messages where chat_id=conversation)
    then raise exception 'A nonparticipant could recover this conversation'; end if;
  reset role;
end
$$;

select 'passed: stable sequence allocation, collisions, direct, reply, scheduled and file writes, monotonic receipts and scoped recovery' as result;
rollback;
