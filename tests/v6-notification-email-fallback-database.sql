begin;

insert into auth.users(id,email,email_confirmed_at) values
  ('7f100000-0000-4000-8000-000000000001','email-fallback-sender@example.invalid',now()),
  ('7f100000-0000-4000-8000-000000000002','email-fallback-recipient@example.invalid',now());
insert into public.st_profiles(id,handle,name) values
  ('7f100000-0000-4000-8000-000000000001','email_fallback_sender','Sender'),
  ('7f100000-0000-4000-8000-000000000002','email_fallback_peer','Recipient');

do $$
declare
  sender_id constant uuid:='7f100000-0000-4000-8000-000000000001';
  recipient_id constant uuid:='7f100000-0000-4000-8000-000000000002';
  room constant uuid:=gen_random_uuid();
  workspace uuid;
  post uuid:=gen_random_uuid();
  delivery record;
  first_event uuid;
  expired_event uuid;
  reclaimed uuid;
  fallback record;
begin
  if has_function_privilege('authenticated','public.st_v6_finish_notification_email(uuid,uuid,text)','execute')
    or has_function_privilege('authenticated','public.st_v6_notification_dead_letter_summary()','execute')
    or has_table_privilege('service_role','sectalk_private.st_v6_notification_delivery_events','select') then
    raise exception 'Provider jobs or internal notification payloads are exposed';
  end if;
  perform set_config('request.jwt.claim.sub',sender_id::text,true);
  workspace:=public.st_v2_create_workspace('Email fallback workspace');
  perform public.st_v6_room_create(room,workspace,'Private fallback room','private','blank');
  insert into public.st_v2_members(workspace_id,user_id) values(workspace,recipient_id);
  insert into public.st_v6_room_members(room_id,user_id,role) values(room,recipient_id,'member');
  perform public.st_v6_room_post(room,post,'Private payload @email_fallback_peer');
  update public.st_v3_notifications set created_at=now()-interval '3 minutes' where room_post_id=post;

  perform set_config('request.jwt.claim.sub',recipient_id::text,true);
  perform public.st_v6_set_notification_email(true,'prompt',array['mention']);
  update sectalk_private.st_v6_notification_email set scanned_at=now()-interval '1 hour' where recipient=recipient_id;
  for attempt in 1..3 loop
    select * into delivery from public.st_v6_claim_notification_email() job where job.recipient=recipient_id;
    if delivery.email is null or delivery.mentions<>1 then raise exception 'Email retry did not reclaim the original eligible activity'; end if;
    if attempt=1 then first_event:=delivery.delivery_id; end if;
    if first_event is distinct from delivery.delivery_id
      or exists(select 1 from public.st_v6_claim_notification_email() job where job.recipient=recipient_id) then
      raise exception 'Email deduplication or lease exclusivity failed';
    end if;
    perform public.st_v6_finish_notification_email(recipient_id,gen_random_uuid(),'rejected');
    if exists(select 1 from sectalk_private.st_v6_notification_dead_letters where email_event_id=first_event) then
      raise exception 'A stale lease created a dead letter';
    end if;
    perform public.st_v6_finish_notification_email(recipient_id,delivery.lease,'retry');
    update sectalk_private.st_v6_notification_email set next_at=now() where recipient=recipient_id;
  end loop;
  if not exists(select 1 from sectalk_private.st_v6_notification_dead_letters
      where channel='email' and email_event_id=first_event and reason='retry_exhausted') then
    raise exception 'Email retry exhaustion did not create a durable email dead letter';
  end if;
  set local role authenticated;
  select * into fallback from public.st_v6_notification_fallbacks() e where e.id=first_event;
  if fallback.kind is distinct from 'email.digest' or fallback.read_at is not null then
    raise exception 'An eligible email failure did not produce a generic fallback';
  end if;
  perform set_config('request.jwt.claim.sub',sender_id::text,true);
  if exists(select 1 from public.st_v6_notification_fallbacks() e where e.id=first_event) then
    raise exception 'Another account read the email fallback';
  end if;
  reset role;

  perform set_config('request.jwt.claim.sub',recipient_id::text,true);
  perform public.st_v6_set_notification_email(true,'weekly',array['mention']);
  perform set_config('request.jwt.claim.sub',sender_id::text,true);
  post:=gen_random_uuid();
  perform public.st_v6_room_post(room,post,'Private older fixture @email_fallback_peer');
  update public.st_v3_notifications set created_at=now()-interval '3 days' where room_post_id=post;
  update sectalk_private.st_v6_notification_email set scanned_at=now()-interval '4 days',
    window_end=now()-interval '2 days',next_at=now() where recipient=recipient_id;
  select * into delivery from public.st_v6_claim_notification_email() job where job.recipient=recipient_id;
  expired_event:=delivery.delivery_id;
  update sectalk_private.st_v6_notification_email set next_at=now() where recipient=recipient_id;
  select job.delivery_id into reclaimed from public.st_v6_claim_notification_email() job where job.recipient=recipient_id;
  if expired_event is null or reclaimed is not null
    or not exists(select 1 from sectalk_private.st_v6_notification_dead_letters
      where channel='email' and email_event_id=expired_event and reason='expired') then
    raise exception 'A stale email worker window was still dispatched or lost before dead lettering';
  end if;
  perform public.st_v6_unsubscribe_notification_email(delivery.unsubscribe_key);
  perform set_config('request.jwt.claim.sub',recipient_id::text,true);
  if exists(select 1 from public.st_v6_notification_fallbacks() e where e.kind='email.digest') then
    raise exception 'A cancelled email opt-in still exposed its fallback';
  end if;
end $$;

select 'passed: email retries, lease expiry, channel deduplication, dead letters, and private opt-in fallback' as result;
rollback;
