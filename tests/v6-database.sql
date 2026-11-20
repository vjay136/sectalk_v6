begin;

insert into auth.users(id,email,aud,role) values
 ('60000000-0000-4000-8000-000000000001','st-v6-alex@example.invalid','authenticated','authenticated'),
 ('60000000-0000-4000-8000-000000000002','st-v6-billie@example.invalid','authenticated','authenticated'),
 ('60000000-0000-4000-8000-000000000003','st-v6-casey@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
 ('60000000-0000-4000-8000-000000000001','sectalk_v6_alex','Fixture Alex'),
 ('60000000-0000-4000-8000-000000000002','sectalk_v6_billie','Fixture Billie'),
 ('60000000-0000-4000-8000-000000000003','sectalk_v6_casey','Fixture Casey');

set local role anon;
select public.st_v6_ready() as anon_ready;
reset role;

set local role authenticated;
do $$
declare
  sender constant uuid:='60000000-0000-4000-8000-000000000001';
  receiver constant uuid:='60000000-0000-4000-8000-000000000002';
  outside_user constant uuid:='60000000-0000-4000-8000-000000000003';
  m constant uuid:=gen_random_uuid();
  m2 constant uuid:=gen_random_uuid();
  chat uuid;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',sender,'role','authenticated')::text,true);
  chat:=public.st_request('sectalk_v6_billie');
  perform set_config('request.jwt.claims',json_build_object('sub',receiver,'role','authenticated')::text,true);
  perform public.st_respond(chat,true);
  perform set_config('request.jwt.claims',json_build_object('sub',sender,'role','authenticated')::text,true);
  perform public.st_send(chat,m,'First saved sample');
  perform public.st_send(chat,m2,'Second saved sample');
  insert into public.st_v6_saved_messages(message_id) values(m),(m2) on conflict(user_id,message_id) do nothing;
  insert into public.st_v6_saved_messages(message_id) values(m) on conflict(user_id,message_id) do nothing;
  if (select count(*) from public.st_v6_saved_messages)<>2 then raise exception 'Save failed or duplicated'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',receiver,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_saved_messages) then raise exception 'Another participant saw these bookmarks'; end if;
  insert into public.st_v6_saved_messages(message_id) values(m) on conflict(user_id,message_id) do nothing;
  delete from public.st_v6_saved_messages where message_id=m;
  if exists(select 1 from public.st_v6_saved_messages) then raise exception 'Remove saved message failed'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',outside_user,'role','authenticated')::text,true);
  begin
    insert into public.st_v6_saved_messages(message_id) values(m);
    raise exception 'Outside account saved an inaccessible message' using errcode='P0004';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',json_build_object('sub',sender,'role','authenticated')::text,true);
  perform public.st_v5_message_action(m,'revoke');
  perform public.st_v5_message_action(m2,'hide');
  if exists(select 1 from public.st_v6_saved_messages) then raise exception 'Hidden or revoked content remained visible'; end if;
  begin
    insert into public.st_v6_saved_messages(message_id) values(m);
    raise exception 'Revoked content could be saved again' using errcode='P0004';
  exception when insufficient_privilege then null;
  end;
end $$;
reset role;
select 'passed: private saves, idempotent writes, removal, inaccessible chats, hide, revoke, readiness' as result;
rollback;
