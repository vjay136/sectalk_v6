\set ON_ERROR_STOP on
begin;

insert into auth.users(id,email) values
  ('6f100000-0000-4000-8000-000000000001','file-history-owner@example.invalid'),
  ('6f100000-0000-4000-8000-000000000002','file-history-recipient@example.invalid'),
  ('6f100000-0000-4000-8000-000000000003','file-history-moderator@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('6f100000-0000-4000-8000-000000000001','history_file_owner','File owner'),
  ('6f100000-0000-4000-8000-000000000002','history_file_recipient','File recipient'),
  ('6f100000-0000-4000-8000-000000000003','history_file_moderator','File moderator');
insert into sectalk_private.staff values('6f100000-0000-4000-8000-000000000003');
insert into public.st_chats(id,member_a,member_b,requester,status) values
  ('6f100000-0001-4000-8000-000000000001','6f100000-0000-4000-8000-000000000001',
   '6f100000-0000-4000-8000-000000000002','6f100000-0000-4000-8000-000000000001','accepted');
insert into public.st_messages(id,chat_id,sender,body,created_at) values
  ('6f100000-0002-4000-8000-000000000001','6f100000-0001-4000-8000-000000000001',
   '6f100000-0000-4000-8000-000000000001','Case content is private',now()-interval '10 minutes');
insert into public.st_v5_files(id,chat_id,uploader,message_id,filename,size_bytes) values
  ('6f100000-0002-4000-8000-000000000001','6f100000-0001-4000-8000-000000000001',
  '6f100000-0000-4000-8000-000000000001','6f100000-0002-4000-8000-000000000001','report-proof.txt',18);

set local role service_role;
select public.st_v6_log_file_download('6f100000-0002-4000-8000-000000000001',
  '6f100000-0000-4000-8000-000000000002',gen_random_uuid());
select public.st_v6_log_file_download('6f100000-0002-4000-8000-000000000001',
  '6f100000-0000-4000-8000-000000000003',gen_random_uuid());
reset role;

set local role authenticated;
do $$
declare
  attachment constant uuid:='6f100000-0002-4000-8000-000000000001';
  owner_id constant uuid:='6f100000-0000-4000-8000-000000000001';
  recipient_id constant uuid:='6f100000-0000-4000-8000-000000000002';
  moderator_id constant uuid:='6f100000-0000-4000-8000-000000000003';
  details jsonb;
begin
  perform set_config('request.jwt.claims',jsonb_build_object('sub',recipient_id,'aal','aal1')::text,true);
  select to_jsonb(d) into details from public.st_v6_view_file_details(attachment) d;
  if details-'shared_at' is distinct from '{"filename":"report-proof.txt","size_bytes":18,"can_view_history":false}'::jsonb
    then raise exception 'A recipient did not get only the expected details'; end if;
  perform public.st_v6_view_file_details(attachment);
  begin
    perform public.st_v6_file_access_history(attachment);
    raise exception 'Recipient read uploader-only history';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',moderator_id,'aal','aal2')::text,true);
  if exists(select 1 from public.st_v6_view_file_details(attachment)) then
    raise exception 'An unrelated moderator could view direct attachment details';
  end if;
  begin
    perform public.st_v6_file_access_history(attachment);
    raise exception 'An unrelated moderator read uploader-only history';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'aal','aal1')::text,true);
  if (select d.can_view_history from public.st_v6_view_file_details(attachment) d) is not true then
    raise exception 'The uploader could not view file details and history';
  end if;
  if (select count(*) from public.st_v6_file_access_history(attachment))<>4
    or not exists(select 1 from public.st_v6_file_access_history(attachment) h where h.event='share' and h.participant='owner')
    or not exists(select 1 from public.st_v6_file_access_history(attachment) h where h.event='download' and h.participant='recipient')
    or (select count(*) from public.st_v6_file_access_history(attachment) h where h.event='view' and h.participant='recipient')<>1
    or exists(select 1 from public.st_v6_file_access_history(attachment) h
      where to_jsonb(h)-array['event','participant','occurred_at']<>'{}'::jsonb)
    then raise exception 'Access events, view deduplication, or moderation confidentiality failed'; end if;
end
$$;
reset role;

insert into sectalk_private.st_v6_file_downloads(file_id,actor_id,ticket_id)
select '6f100000-0002-4000-8000-000000000001','6f100000-0000-4000-8000-000000000002',gen_random_uuid()
  from generate_series(1,60);
update public.st_messages set revoked_at=now() where id='6f100000-0002-4000-8000-000000000001';
set local role authenticated;
do $$
declare attachment constant uuid:='6f100000-0002-4000-8000-000000000001';
begin
  if (select count(*) from public.st_v6_file_access_history(attachment))<>50
    or exists(select 1 from public.st_v6_view_file_details(attachment))
  then raise exception 'History cap or revoked detail access failed'; end if;
end
$$;
reset role;

select 'passed: recorded details and downloads, direct share event, uploader-only history, protected staff activity and cap' as result;
rollback;
