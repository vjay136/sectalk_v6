begin;

insert into auth.users(id,email,aud,role) values
  ('66000000-0000-4000-8000-000000000001','presence-owner@example.invalid','authenticated','authenticated'),
  ('66000000-0000-4000-8000-000000000002','presence-contact@example.invalid','authenticated','authenticated'),
  ('66000000-0000-4000-8000-000000000003','presence-pending@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('66000000-0000-4000-8000-000000000001','presence_owner','Presence owner'),
  ('66000000-0000-4000-8000-000000000002','presence_contact','Presence contact'),
  ('66000000-0000-4000-8000-000000000003','presence_pending','Presence pending');
insert into public.st_chats(id,member_a,member_b,requester,status) values
  ('66000000-0001-4000-8000-000000000001',
   '66000000-0000-4000-8000-000000000001','66000000-0000-4000-8000-000000000002',
   '66000000-0000-4000-8000-000000000001','accepted'),
  ('66000000-0001-4000-8000-000000000002',
   '66000000-0000-4000-8000-000000000001','66000000-0000-4000-8000-000000000003',
   '66000000-0000-4000-8000-000000000001','pending');

set local role authenticated;
do $$
declare
  owner_id constant uuid:='66000000-0000-4000-8000-000000000001';
  peer_id constant uuid:='66000000-0000-4000-8000-000000000002';
  pending_id constant uuid:='66000000-0000-4000-8000-000000000003';
  available_state text;
  expiry timestamptz;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v3_ping();
  if exists(select 1 from public.st_v3_presence where user_id=owner_id)
    then raise exception 'Heartbeat opted in a new account'; end if;

  foreach available_state in array array['online','away','busy','offline'] loop
    perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
    perform public.st_v3_set_presence(available_state);
    perform set_config('request.jwt.claims',json_build_object('sub',peer_id,'role','authenticated')::text,true);
    if exists(select 1 from public.st_v3_presence where user_id=owner_id and state=available_state)
      is distinct from (available_state<>'offline') then
      raise exception 'Accepted-contact visibility incorrect for %',available_state;
    end if;
  end loop;

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  select expires_at into expiry from public.st_v3_presence where user_id=owner_id;
  perform public.st_v3_ping();
  if expiry is distinct from (select expires_at from public.st_v3_presence where user_id=owner_id)
    then raise exception 'Heartbeat renewed a deliberately hidden account'; end if;
  perform public.st_v3_set_presence('online');
  select expires_at into expiry from public.st_v3_presence where user_id=owner_id;
  for i in 1..10 loop
    perform public.st_v3_ping();
  end loop;
  if expiry is distinct from (select expires_at from public.st_v3_presence where user_id=owner_id)
    then raise exception 'Rapid heartbeats repeatedly wrote presence'; end if;
  begin
    perform public.st_v3_ping();
    raise exception 'Heartbeat exceeded the request cap';
  exception when sqlstate 'PT429' then null;
  end;

  perform set_config('request.jwt.claims',json_build_object('sub',pending_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v3_presence where user_id=owner_id)
    then raise exception 'Pending contact could read presence'; end if;
end $$;
reset role;

update public.st_v3_presence set expires_at=now()-interval '1 second'
where user_id='66000000-0000-4000-8000-000000000001';
delete from sectalk_private.limits where actor='66000000-0000-4000-8000-000000000001' and action='v6_presence_ping';

set local role authenticated;
do $$
declare
  owner_id constant uuid:='66000000-0000-4000-8000-000000000001';
  peer_id constant uuid:='66000000-0000-4000-8000-000000000002';
  chat_id constant uuid:='66000000-0001-4000-8000-000000000001';
begin
  perform set_config('request.jwt.claims',json_build_object('sub',peer_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v3_presence where user_id=owner_id)
    then raise exception 'Expired presence was visible'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v3_ping();
  if not exists(select 1 from public.st_v3_presence where user_id=owner_id and state='online' and expires_at>now()+interval '90 seconds')
    then raise exception 'Eligible heartbeat did not renew the selected state'; end if;
  perform public.st_set_block(chat_id,true);
  perform set_config('request.jwt.claims',json_build_object('sub',peer_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v3_presence where user_id=owner_id)
    then raise exception 'Blocked contact could read presence'; end if;
end $$;

reset role;
select 'passed: presence visibility, four states, rate limit, expiry and heartbeat renewal' as result;
rollback;
